//! Beacon Chain API client for fetching real light client data.
//!
//! Supports fetching:
//! - Light client finality updates
//! - Light client updates by sync committee period
//! - Light client bootstrap data
//! - Genesis information
//! - Finality checkpoints
//!
//! Works with any standard Ethereum Beacon API endpoint (Lodestar, Lighthouse, etc.)

use eth_lc_lib::types::*;
use serde::Deserialize;

/// Beacon API client for fetching light client data.
pub struct BeaconClient {
    /// Base URL of the beacon API (e.g., "https://lodestar-mainnet.chainsafe.io")
    base_url: String,
    /// HTTP client
    client: reqwest::blocking::Client,
}

// =============================================================================
// API Response Types (JSON deserialization)
// =============================================================================

/// Wrapper for beacon API responses.
#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub data: T,
    #[serde(default)]
    pub version: Option<String>,
}

/// Beacon block header as returned by the API (all fields are strings).
#[derive(Debug, Deserialize)]
pub struct ApiBeaconBlockHeader {
    pub slot: String,
    pub proposer_index: String,
    pub parent_root: String,
    pub state_root: String,
    pub body_root: String,
}

/// Execution payload header (post-Capella).
#[derive(Debug, Deserialize)]
pub struct ApiExecutionPayloadHeader {
    pub block_number: String,
    pub block_hash: String,
    pub state_root: String,
    // We don't need all execution fields for light client verification,
    // but we capture block_number and block_hash for L2 cross-referencing.
}

/// Light client header (contains beacon + optional execution).
#[derive(Debug, Deserialize)]
pub struct ApiLightClientHeader {
    pub beacon: ApiBeaconBlockHeader,
    #[serde(default)]
    pub execution: Option<ApiExecutionPayloadHeader>,
    #[serde(default)]
    pub execution_branch: Option<Vec<String>>,
}

/// Sync aggregate as returned by the API.
#[derive(Debug, Deserialize)]
pub struct ApiSyncAggregate {
    pub sync_committee_bits: String,
    pub sync_committee_signature: String,
}

/// Complete finality update response.
#[derive(Debug, Deserialize)]
pub struct ApiFinalityUpdate {
    pub attested_header: ApiLightClientHeader,
    pub finalized_header: ApiLightClientHeader,
    pub finality_branch: Vec<String>,
    pub sync_aggregate: ApiSyncAggregate,
    pub signature_slot: String,
}

/// Complete light client update (includes next_sync_committee data).
#[derive(Debug, Deserialize)]
pub struct ApiLightClientUpdate {
    pub attested_header: ApiLightClientHeader,
    pub finalized_header: ApiLightClientHeader,
    pub finality_branch: Vec<String>,
    pub sync_aggregate: ApiSyncAggregate,
    pub signature_slot: String,
    #[serde(default)]
    pub next_sync_committee: Option<ApiSyncCommittee>,
    #[serde(default)]
    pub next_sync_committee_branch: Option<Vec<String>>,
}

/// Sync committee data.
#[derive(Debug, Deserialize)]
pub struct ApiSyncCommittee {
    pub pubkeys: Vec<String>,
    pub aggregate_pubkey: String,
}

/// Genesis response.
#[derive(Debug, Deserialize)]
pub struct ApiGenesis {
    pub genesis_time: String,
    pub genesis_validators_root: String,
    pub genesis_fork_version: String,
}

/// Finality checkpoint data.
#[derive(Debug, Deserialize)]
pub struct ApiFinalityCheckpoints {
    pub finalized: ApiCheckpoint,
    pub current_justified: ApiCheckpoint,
    pub previous_justified: ApiCheckpoint,
}

/// A single finality checkpoint.
#[derive(Debug, Deserialize)]
pub struct ApiCheckpoint {
    pub epoch: String,
    pub root: String,
}

/// Bootstrap response.
#[derive(Debug, Deserialize)]
pub struct ApiBootstrap {
    pub header: ApiLightClientHeader,
    pub current_sync_committee: ApiSyncCommittee,
    pub current_sync_committee_branch: Vec<String>,
}

// =============================================================================
// Hex Parsing Utilities
// =============================================================================

/// Parse a 0x-prefixed hex string into a Bytes32.
pub fn parse_bytes32(hex_str: &str) -> Result<Bytes32, String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode error: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Parse a 0x-prefixed hex string into a Vec<u8>.
pub fn parse_hex_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(hex_str).map_err(|e| format!("hex decode error: {e}"))
}

/// Parse the sync_committee_bits hex string into a Vec<bool>.
///
/// The bits are encoded as a hex bitvector in little-endian byte order,
/// where each byte contains 8 bits (LSB first within each byte).
pub fn parse_sync_committee_bits(hex_str: &str) -> Result<Vec<bool>, String> {
    let bytes = parse_hex_bytes(hex_str)?;
    let mut bits = Vec::with_capacity(SYNC_COMMITTEE_SIZE);
    for byte in &bytes {
        for bit_idx in 0..8 {
            if bits.len() >= SYNC_COMMITTEE_SIZE {
                break;
            }
            bits.push((byte >> bit_idx) & 1 == 1);
        }
    }
    if bits.len() != SYNC_COMMITTEE_SIZE {
        return Err(format!(
            "expected {} bits, got {}",
            SYNC_COMMITTEE_SIZE,
            bits.len()
        ));
    }
    Ok(bits)
}

/// Parse a Merkle branch (array of hex strings) into Vec<Bytes32>.
pub fn parse_branch(branch: &[String]) -> Result<Vec<Bytes32>, String> {
    branch.iter().map(|s| parse_bytes32(s)).collect()
}

// =============================================================================
// Type Conversion
// =============================================================================

/// Convert an API beacon block header to our internal type.
pub fn convert_header(api: &ApiBeaconBlockHeader) -> Result<BeaconBlockHeader, String> {
    Ok(BeaconBlockHeader {
        slot: api.slot.parse().map_err(|e| format!("slot parse: {e}"))?,
        proposer_index: api
            .proposer_index
            .parse()
            .map_err(|e| format!("proposer_index parse: {e}"))?,
        parent_root: parse_bytes32(&api.parent_root)?,
        state_root: parse_bytes32(&api.state_root)?,
        body_root: parse_bytes32(&api.body_root)?,
    })
}

/// Convert an API sync aggregate to our internal type.
pub fn convert_sync_aggregate(api: &ApiSyncAggregate) -> Result<SyncAggregate, String> {
    Ok(SyncAggregate {
        sync_committee_bits: parse_sync_committee_bits(&api.sync_committee_bits)?,
        sync_committee_signature: parse_hex_bytes(&api.sync_committee_signature)?,
    })
}

/// Convert an API sync committee to our internal SyncCommitteeData type.
///
/// Parses all 512 pubkeys and the aggregate pubkey from hex strings
/// into flat byte arrays.
pub fn convert_sync_committee(api: &ApiSyncCommittee) -> Result<SyncCommitteeData, String> {
    if api.pubkeys.len() != SYNC_COMMITTEE_SIZE {
        return Err(format!(
            "expected {} pubkeys, got {}",
            SYNC_COMMITTEE_SIZE,
            api.pubkeys.len()
        ));
    }

    let mut pubkeys = Vec::with_capacity(SYNC_COMMITTEE_SIZE * BYTES_PER_PUBKEY);
    for (i, pk_hex) in api.pubkeys.iter().enumerate() {
        let pk_bytes = parse_hex_bytes(pk_hex)?;
        if pk_bytes.len() != BYTES_PER_PUBKEY {
            return Err(format!(
                "pubkey[{i}] has {} bytes, expected {BYTES_PER_PUBKEY}",
                pk_bytes.len()
            ));
        }
        pubkeys.extend_from_slice(&pk_bytes);
    }

    let aggregate_pubkey = parse_hex_bytes(&api.aggregate_pubkey)?;
    if aggregate_pubkey.len() != BYTES_PER_PUBKEY {
        return Err(format!(
            "aggregate_pubkey has {} bytes, expected {BYTES_PER_PUBKEY}",
            aggregate_pubkey.len()
        ));
    }

    Ok(SyncCommitteeData {
        pubkeys,
        aggregate_pubkey,
    })
}

/// Convert an API sync committee directly to its hash_tree_root.
///
/// Convenience wrapper: parses the committee and computes the SSZ hash.
pub fn convert_sync_committee_to_hash(api: &ApiSyncCommittee) -> Result<Bytes32, String> {
    use eth_lc_lib::bls::compute_sync_committee_hash;

    let sc_data = convert_sync_committee(api)?;
    let mut agg_pk = [0u8; BYTES_PER_PUBKEY];
    agg_pk.copy_from_slice(&sc_data.aggregate_pubkey);
    Ok(compute_sync_committee_hash(&sc_data.pubkeys, &agg_pk))
}

/// Normalize a finality branch.
///
/// The Beacon API may return branches with extra elements for post-Capella/Deneb/Electra
/// state trees. Following `is_valid_normalized_merkle_branch` from the spec:
/// - Extra prefix elements (beyond depth) must be zero hashes
/// - We strip them and return only the `depth` elements needed
pub fn normalize_finality_branch(branch: &[Bytes32]) -> Vec<Bytes32> {
    let depth = FINALIZED_ROOT_DEPTH;
    if branch.len() <= depth {
        return branch.to_vec();
    }
    let num_extra = branch.len() - depth;
    // Verify extra elements are zero (as per spec)
    for i in 0..num_extra {
        if branch[i] != [0u8; 32] {
            // Non-zero extra element — this shouldn't happen with conformant APIs
            // but we log a warning and still strip
            eprintln!(
                "WARNING: finality_branch has non-zero extra element at index {i}"
            );
        }
    }
    branch[num_extra..].to_vec()
}

/// Normalize a sync committee branch similarly.
pub fn normalize_sync_committee_branch(branch: &[Bytes32]) -> Vec<Bytes32> {
    let depth = NEXT_SYNC_COMMITTEE_DEPTH;
    if branch.len() <= depth {
        return branch.to_vec();
    }
    let num_extra = branch.len() - depth;
    branch[num_extra..].to_vec()
}

// =============================================================================
// BeaconClient Implementation
// =============================================================================

impl BeaconClient {
    /// Create a new beacon client.
    ///
    /// `base_url` should be a Beacon API endpoint, e.g.:
    /// - "https://lodestar-mainnet.chainsafe.io" (public, free)
    /// - "https://eth2-beacon-mainnet.infura.io" (requires auth)
    pub fn new(base_url: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self { base_url, client }
    }

    /// Fetch the latest light client finality update.
    ///
    /// Endpoint: `GET /eth/v1/beacon/light_client/finality_update`
    pub fn get_finality_update(&self) -> Result<ApiFinalityUpdate, String> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/finality_update",
            self.base_url
        );
        println!("[*] Fetching finality update from: {url}");

        let resp: ApiResponse<ApiFinalityUpdate> = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?
            .json()
            .map_err(|e| format!("JSON parse failed: {e}"))?;

        if let Some(ref version) = resp.version {
            println!("[*] Response version: {version}");
        }

        Ok(resp.data)
    }

    /// Fetch light client updates for a given sync committee period range.
    ///
    /// Endpoint: `GET /eth/v1/beacon/light_client/updates?start_period={}&count={}`
    pub fn get_updates(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<ApiLightClientUpdate>, String> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.base_url, start_period, count
        );
        println!("[*] Fetching updates for period {start_period} (count={count})");

        let resp: Vec<ApiResponse<ApiLightClientUpdate>> = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?
            .json()
            .map_err(|e| format!("JSON parse failed: {e}"))?;

        Ok(resp.into_iter().map(|r| r.data).collect())
    }

    /// Fetch genesis data.
    ///
    /// Endpoint: `GET /eth/v1/beacon/genesis`
    pub fn get_genesis(&self) -> Result<ApiGenesis, String> {
        let url = format!("{}/eth/v1/beacon/genesis", self.base_url);
        println!("[*] Fetching genesis data");

        let resp: ApiResponse<ApiGenesis> = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?
            .json()
            .map_err(|e| format!("JSON parse failed: {e}"))?;

        Ok(resp.data)
    }

    /// Fetch finality checkpoints for a given state.
    ///
    /// Endpoint: `GET /eth/v1/beacon/states/{state_id}/finality_checkpoints`
    pub fn get_finality_checkpoints(
        &self,
        state_id: &str,
    ) -> Result<ApiFinalityCheckpoints, String> {
        let url = format!(
            "{}/eth/v1/beacon/states/{}/finality_checkpoints",
            self.base_url, state_id
        );

        let resp: ApiResponse<ApiFinalityCheckpoints> = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?
            .json()
            .map_err(|e| format!("JSON parse failed: {e}"))?;

        Ok(resp.data)
    }

    /// Fetch light client bootstrap for a given block root.
    ///
    /// Endpoint: `GET /eth/v1/beacon/light_client/bootstrap/{block_root}`
    pub fn get_bootstrap(&self, block_root: &str) -> Result<ApiBootstrap, String> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/{}",
            self.base_url, block_root
        );
        println!("[*] Fetching bootstrap for block root: {block_root}");

        let resp: ApiResponse<ApiBootstrap> = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?
            .json()
            .map_err(|e| format!("JSON parse failed: {e}"))?;

        Ok(resp.data)
    }

    /// Fetch the current sync committee pubkeys via the bootstrap endpoint.
    ///
    /// Flow: get finality checkpoints → get finalized root → bootstrap → extract committee.
    ///
    /// Returns `(SyncCommitteeData, sync_committee_hash)` where the hash is the SSZ
    /// hash_tree_root of the sync committee, computed using our BLS module.
    pub fn fetch_current_sync_committee(&self) -> Result<(SyncCommitteeData, Bytes32), String> {
        use eth_lc_lib::bls::compute_sync_committee_hash;

        println!("[*] Fetching current sync committee...");

        // Step 1: Get finalized block root
        let checkpoints = self.get_finality_checkpoints("head")?;
        let finalized_root = &checkpoints.finalized.root;
        println!("[+] Finalized root: {finalized_root}");

        // Step 2: Bootstrap from finalized root to get sync committee
        let bootstrap = self.get_bootstrap(finalized_root)?;
        let sc_data = convert_sync_committee(&bootstrap.current_sync_committee)?;
        println!(
            "[+] Got {} sync committee pubkeys ({} bytes)",
            SYNC_COMMITTEE_SIZE,
            sc_data.pubkeys.len()
        );

        // Step 3: Compute the SSZ hash_tree_root of the sync committee
        let mut agg_pk = [0u8; BYTES_PER_PUBKEY];
        agg_pk.copy_from_slice(&sc_data.aggregate_pubkey);
        let sc_hash = compute_sync_committee_hash(&sc_data.pubkeys, &agg_pk);
        println!("[+] Sync committee hash: 0x{}", hex::encode(sc_hash));

        Ok((sc_data, sc_hash))
    }

    /// Convert a finality update from the API into ProofInputs.
    ///
    /// This is the main entry point: fetch real data → convert to our internal types
    /// that can be passed to the zkVM program.
    ///
    /// When `sync_committee` is provided, the zkVM will perform full BLS12-381
    /// aggregate signature verification. Otherwise BLS is skipped.
    pub fn finality_update_to_proof_inputs(
        &self,
        update: &ApiFinalityUpdate,
        config: &NetworkConfig,
        sync_committee: Option<(SyncCommitteeData, Bytes32)>,
    ) -> Result<ProofInputs, String> {
        let attested_header = convert_header(&update.attested_header.beacon)?;
        let finalized_header = convert_header(&update.finalized_header.beacon)?;
        let sync_aggregate = convert_sync_aggregate(&update.sync_aggregate)?;
        let signature_slot: u64 = update
            .signature_slot
            .parse()
            .map_err(|e| format!("signature_slot parse: {e}"))?;

        // Parse the finality branch — pass as-is; consensus.rs uses
        // branch.len() as the depth, so it adapts across forks automatically.
        let finality_branch = parse_branch(&update.finality_branch)?;

        // Compute fork version for the signature slot
        // Per spec: fork_version_slot = max(signature_slot, 1) - 1
        let fork_version_slot = if signature_slot > 0 {
            signature_slot - 1
        } else {
            0
        };
        let fork_version = config.fork_version_for_slot(fork_version_slot);

        // Derive sync committee hash and data from the parameter
        let (current_sc_hash, sc_data) = if let Some((sc, hash)) = sync_committee {
            (hash, Some(sc))
        } else {
            // Placeholder SC hash: period-based deterministic value
            let period = attested_header.slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD;
            let mut hash = [0u8; 32];
            hash[0..8].copy_from_slice(&period.to_le_bytes());
            (hash, None)
        };

        Ok(ProofInputs {
            update: LightClientUpdate {
                attested_header,
                sync_aggregate,
                signature_slot,
                finality_update: Some(FinalityUpdate {
                    finalized_header,
                    finality_branch,
                }),
                sync_committee_update: None, // Finality updates don't include SC rotation
            },
            current_sync_committee_hash: current_sc_hash,
            sync_committee: sc_data,
            genesis_validators_root: config.genesis_validators_root,
            genesis_time: config.genesis_time,
            fork_version,
            storage_proof: None,
            l2_storage_proof: None,
        })
    }

    /// Convert a full light client update (with sync committee) into ProofInputs.
    pub fn full_update_to_proof_inputs(
        &self,
        update: &ApiLightClientUpdate,
        config: &NetworkConfig,
        sync_committee: Option<(SyncCommitteeData, Bytes32)>,
    ) -> Result<ProofInputs, String> {
        let attested_header = convert_header(&update.attested_header.beacon)?;
        let finalized_header = convert_header(&update.finalized_header.beacon)?;
        let sync_aggregate = convert_sync_aggregate(&update.sync_aggregate)?;
        let signature_slot: u64 = update
            .signature_slot
            .parse()
            .map_err(|e| format!("signature_slot parse: {e}"))?;

        // Parse branches — pass as-is; consensus.rs uses branch.len() as depth
        let finality_branch = parse_branch(&update.finality_branch)?;

        let sync_committee_update = if let Some(ref sc_branch) = update.next_sync_committee_branch {
            let sc_branch_parsed = parse_branch(sc_branch)?;

            // Compute the SSZ hash_tree_root of the next sync committee.
            // This must match the leaf used in the Merkle proof.
            if let Some(ref sc) = update.next_sync_committee {
                let next_sc_data = convert_sync_committee(sc)?;
                let mut agg_pk = [0u8; BYTES_PER_PUBKEY];
                agg_pk.copy_from_slice(&next_sc_data.aggregate_pubkey);

                use eth_lc_lib::bls::compute_sync_committee_hash;
                let hash = compute_sync_committee_hash(&next_sc_data.pubkeys, &agg_pk);

                Some(SyncCommitteeUpdate {
                    next_sync_committee_hash: hash,
                    next_sync_committee_branch: sc_branch_parsed,
                })
            } else {
                None
            }
        } else {
            None
        };

        let fork_version_slot = if signature_slot > 0 {
            signature_slot - 1
        } else {
            0
        };
        let fork_version = config.fork_version_for_slot(fork_version_slot);

        // Derive sync committee hash and data from the parameter
        let (current_sc_hash, sc_data) = if let Some((sc, hash)) = sync_committee {
            (hash, Some(sc))
        } else {
            let period = attested_header.slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD;
            let mut hash = [0u8; 32];
            hash[0..8].copy_from_slice(&period.to_le_bytes());
            (hash, None)
        };

        Ok(ProofInputs {
            update: LightClientUpdate {
                attested_header,
                sync_aggregate,
                signature_slot,
                finality_update: Some(FinalityUpdate {
                    finalized_header,
                    finality_branch,
                }),
                sync_committee_update,
            },
            current_sync_committee_hash: current_sc_hash,
            sync_committee: sc_data,
            genesis_validators_root: config.genesis_validators_root,
            genesis_time: config.genesis_time,
            fork_version,
            storage_proof: None,
            l2_storage_proof: None,
        })
    }
}

// =============================================================================
// Network-specific constructors
// =============================================================================

/// Default Beacon API URLs.
pub const LODESTAR_MAINNET_URL: &str = "https://lodestar-mainnet.chainsafe.io";
pub const LODESTAR_SEPOLIA_URL: &str = "https://lodestar-sepolia.chainsafe.io";

impl BeaconClient {
    /// Create a client for Ethereum mainnet using the public Lodestar endpoint.
    pub fn mainnet() -> Self {
        Self::new(LODESTAR_MAINNET_URL)
    }

    /// Create a client for Sepolia testnet using the public Lodestar endpoint.
    pub fn sepolia() -> Self {
        Self::new(LODESTAR_SEPOLIA_URL)
    }

    /// Create a client from a BEACON_API_URL environment variable,
    /// falling back to the Lodestar mainnet endpoint.
    pub fn from_env() -> Self {
        let url = std::env::var("BEACON_API_URL")
            .unwrap_or_else(|_| LODESTAR_MAINNET_URL.to_string());
        println!("[*] Using Beacon API: {url}");
        Self::new(&url)
    }
}
