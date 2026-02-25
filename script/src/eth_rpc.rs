//! Ethereum JSON-RPC client for fetching storage proofs (EIP-1186).
//!
//! Provides `eth_getProof` support for verifying account state and storage
//! slots against execution layer state roots.

use crate::beacon_api::parse_bytes32;
use eth_lc_lib::types::*;
use serde::{Deserialize, Serialize};

// =============================================================================
// JSON-RPC Types
// =============================================================================

/// JSON-RPC request envelope.
#[derive(Debug, Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: serde_json::Value,
    id: u64,
}

/// JSON-RPC response envelope.
#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    #[allow(dead_code)]
    jsonrpc: String,
    result: Option<T>,
    error: Option<JsonRpcError>,
    #[allow(dead_code)]
    id: u64,
}

/// JSON-RPC error.
#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl core::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RPC error {}: {}", self.code, self.message)
    }
}

// =============================================================================
// EIP-1186 Response Types
// =============================================================================

/// `eth_getProof` response — account + storage proofs.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EthGetProofResponse {
    address: String,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    balance: String,
    storage_hash: String,
    code_hash: String,
    account_proof: Vec<String>,
    storage_proof: Vec<EthStorageProofEntry>,
}

/// Single storage slot proof from `eth_getProof`.
#[derive(Debug, Deserialize)]
struct EthStorageProofEntry {
    key: String,
    value: String,
    proof: Vec<String>,
}

// =============================================================================
// Ethereum RPC Client
// =============================================================================

/// Client for Ethereum JSON-RPC calls.
pub struct EthRpcClient {
    /// JSON-RPC endpoint URL.
    pub rpc_url: String,
    /// HTTP client.
    client: reqwest::blocking::Client,
}

impl EthRpcClient {
    /// Create a new client.
    pub fn new(rpc_url: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self {
            rpc_url: rpc_url.to_string(),
            client,
        }
    }

    /// Call `eth_getProof` (EIP-1186) for an account and set of storage keys.
    ///
    /// # Arguments
    /// * `address` — Hex-encoded address (with or without 0x prefix).
    /// * `storage_keys` — Hex-encoded storage slot keys.
    /// * `block` — Block identifier ("latest", "finalized", or hex block number).
    ///
    /// # Returns
    /// Parsed `EIP1186Proof` with account proof and storage proofs.
    pub fn get_proof(
        &self,
        address: &str,
        storage_keys: &[String],
        block: &str,
    ) -> Result<EIP1186Proof, String> {
        let address_hex = if address.starts_with("0x") {
            address.to_string()
        } else {
            format!("0x{address}")
        };

        let keys_json: Vec<serde_json::Value> = storage_keys
            .iter()
            .map(|k| {
                let hex = if k.starts_with("0x") {
                    k.clone()
                } else {
                    format!("0x{k}")
                };
                serde_json::Value::String(hex)
            })
            .collect();

        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_getProof",
            params: serde_json::json!([address_hex, keys_json, block]),
            id: 1,
        };

        let resp: JsonRpcResponse<EthGetProofResponse> = self
            .client
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?
            .json()
            .map_err(|e| format!("JSON parse failed: {e}"))?;

        if let Some(err) = resp.error {
            return Err(format!("{err}"));
        }

        let data = resp
            .result
            .ok_or("eth_getProof returned null result")?;

        self.convert_proof_response(data)
    }

    /// Convert the JSON-RPC response into our internal types.
    fn convert_proof_response(
        &self,
        data: EthGetProofResponse,
    ) -> Result<EIP1186Proof, String> {
        // Parse address.
        let address = parse_address(&data.address)?;

        // Parse nonce.
        let nonce = parse_hex_u64(&data.nonce)?;

        // Parse balance (variable length big-endian bytes).
        let balance = parse_hex_bytes_var(&data.balance)?;

        // Parse storage root and code hash.
        let storage_root = parse_bytes32(&data.storage_hash)?;
        let code_hash = parse_bytes32(&data.code_hash)?;

        // Parse account proof nodes.
        let account_proof = data
            .account_proof
            .iter()
            .map(|s| parse_hex_vec(s))
            .collect::<Result<Vec<_>, _>>()?;

        // Parse storage proofs.
        let storage_proofs = data
            .storage_proof
            .iter()
            .map(|sp| {
                let key = parse_bytes32(&sp.key)?;
                let value = parse_bytes32_or_short(&sp.value)?;
                let proof = sp
                    .proof
                    .iter()
                    .map(|s| parse_hex_vec(s))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(StorageProofEntry { key, value, proof })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(EIP1186Proof {
            address,
            nonce,
            balance,
            storage_root,
            code_hash,
            account_proof,
            storage_proofs,
        })
    }

    /// Get the execution state root for a given block.
    ///
    /// Calls `eth_getBlockByNumber` and extracts the state root.
    pub fn get_state_root(&self, block: &str) -> Result<Bytes32, String> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_getBlockByNumber",
            params: serde_json::json!([block, false]),
            id: 1,
        };

        let resp: JsonRpcResponse<serde_json::Value> = self
            .client
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?
            .json()
            .map_err(|e| format!("JSON parse failed: {e}"))?;

        if let Some(err) = resp.error {
            return Err(format!("{err}"));
        }

        let block = resp.result.ok_or("null block")?;
        let state_root = block
            .get("stateRoot")
            .and_then(|v| v.as_str())
            .ok_or("missing stateRoot")?;

        parse_bytes32(state_root)
    }
}

// =============================================================================
// Hex Parsing Helpers
// =============================================================================

/// Parse a hex-encoded address (20 bytes).
fn parse_address(hex_str: &str) -> Result<Address, String> {
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex).map_err(|e| format!("address parse: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!("address wrong length: {}", bytes.len()));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Parse a hex-encoded u64 (e.g., "0x1", "0x0", "").
fn parse_hex_u64(hex_str: &str) -> Result<u64, String> {
    if hex_str.is_empty() || hex_str == "0x0" || hex_str == "0x" {
        return Ok(0);
    }
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    u64::from_str_radix(hex, 16).map_err(|e| format!("u64 parse: {e}"))
}

/// Parse hex bytes with variable length (for balance).
fn parse_hex_bytes_var(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.is_empty() || hex_str == "0x0" || hex_str == "0x" {
        return Ok(Vec::new());
    }
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    // Pad to even length if needed.
    let padded = if hex.len() % 2 != 0 {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    hex::decode(&padded).map_err(|e| format!("hex bytes parse: {e}"))
}

/// Parse a hex string as raw bytes.
fn parse_hex_vec(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(hex).map_err(|e| format!("hex parse: {e}"))
}

/// Parse a bytes32, allowing shorter values (left-padded to 32 bytes).
fn parse_bytes32_or_short(hex_str: &str) -> Result<Bytes32, String> {
    if hex_str.is_empty() || hex_str == "0x0" || hex_str == "0x" {
        return Ok([0u8; 32]);
    }
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let padded = if hex.len() % 2 != 0 {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    let bytes = hex::decode(&padded).map_err(|e| format!("bytes32 parse: {e}"))?;
    let mut result = [0u8; 32];
    if bytes.len() <= 32 {
        let offset = 32 - bytes.len();
        result[offset..].copy_from_slice(&bytes);
    } else {
        return Err(format!("value too long for bytes32: {} bytes", bytes.len()));
    }
    Ok(result)
}

// =============================================================================
// Well-Known Ethereum RPC Endpoints
// =============================================================================

/// Infura mainnet RPC URL (requires API key).
pub fn infura_mainnet_url(api_key: &str) -> String {
    format!("https://mainnet.infura.io/v3/{api_key}")
}

/// Infura Sepolia RPC URL.
pub fn infura_sepolia_url(api_key: &str) -> String {
    format!("https://sepolia.infura.io/v3/{api_key}")
}

/// Infura Base mainnet RPC URL.
pub fn infura_base_mainnet_url(api_key: &str) -> String {
    format!("https://base-mainnet.infura.io/v3/{api_key}")
}

/// Infura Base Sepolia RPC URL.
pub fn infura_base_sepolia_url(api_key: &str) -> String {
    format!("https://base-sepolia.infura.io/v3/{api_key}")
}

/// Public Base mainnet RPC.
pub const BASE_MAINNET_PUBLIC_RPC: &str = "https://mainnet.base.org";

/// Public Base Sepolia RPC.
pub const BASE_SEPOLIA_PUBLIC_RPC: &str = "https://sepolia.base.org";
