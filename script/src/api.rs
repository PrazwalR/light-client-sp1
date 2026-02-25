//! Proof Server REST API handlers.
//!
//! Provides HTTP endpoints for requesting and retrieving light client proofs,
//! storage proofs, and chain status.

use crate::sync::LightClientStore;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// =============================================================================
// Application State
// =============================================================================

/// Shared application state for the proof server.
#[derive(Clone)]
pub struct AppState {
    /// Light client store (shared, mutable).
    pub store: Arc<Mutex<LightClientStore>>,
    /// Pending/completed proof jobs.
    pub jobs: Arc<Mutex<HashMap<String, ProofJob>>>,
    /// Beacon API URL.
    pub beacon_url: String,
    /// Network name.
    pub network: String,
}

// =============================================================================
// Proof Job Types
// =============================================================================

/// Status of a proof generation job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

/// A proof generation job tracked by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofJob {
    /// Unique job ID.
    pub id: String,
    /// Job type.
    pub job_type: String,
    /// Current status.
    pub status: JobStatus,
    /// When the job was created (Unix timestamp).
    pub created_at: u64,
    /// When the job completed (Unix timestamp, 0 if not done).
    pub completed_at: u64,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Proof bytes (hex-encoded) if completed.
    pub proof: Option<String>,
    /// Public values (hex-encoded) if completed.
    pub public_values: Option<String>,
}

impl ProofJob {
    fn new(job_type: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            job_type: job_type.to_string(),
            status: JobStatus::Pending,
            created_at: now_unix(),
            completed_at: 0,
            error: None,
            proof: None,
            public_values: None,
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// =============================================================================
// Request / Response Types
// =============================================================================

/// Health check response.
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub network: String,
    pub version: String,
}

/// Current head info response.
#[derive(Serialize)]
pub struct HeadResponse {
    pub finalized_slot: u64,
    pub finalized_header_root: String,
    pub finalized_state_root: String,
    pub current_sync_committee_hash: String,
    pub next_sync_committee_hash: String,
    pub sync_period: u64,
    pub updates_processed: u64,
    pub last_updated: u64,
}

/// Request to generate a finality proof.
#[derive(Deserialize, Default)]
pub struct ProveRequest {
    /// Whether to include BLS verification (default: false).
    #[serde(default)]
    pub verify_bls: bool,
    /// Whether to do a full update with sync committee rotation.
    #[serde(default)]
    pub full_update: bool,
}

/// Generic job submission response.
#[derive(Serialize)]
pub struct JobResponse {
    pub job_id: String,
    pub status: String,
    pub message: String,
}

/// Storage proof request.
#[derive(Deserialize)]
pub struct StorageProofRequest {
    /// Target chain (e.g., "ethereum-mainnet", "base-mainnet").
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Contract address (hex, with 0x prefix).
    pub address: String,
    /// Storage slot keys to prove (hex, with 0x prefix).
    pub storage_keys: Vec<String>,
    /// Block identifier (default: "latest").
    #[serde(default = "default_block")]
    pub block: String,
}

fn default_chain() -> String {
    "ethereum-mainnet".to_string()
}

fn default_block() -> String {
    "latest".to_string()
}

/// Supported chains response.
#[derive(Serialize)]
pub struct ChainsResponse {
    pub chains: Vec<ChainInfo>,
}

/// Information about a supported chain.
#[derive(Serialize)]
pub struct ChainInfo {
    pub chain_id: String,
    pub chain_type: String,
    pub rpc_url: String,
}

// =============================================================================
// Route Handlers
// =============================================================================

/// GET /health
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        network: state.network.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// GET /head
pub async fn head(State(state): State<AppState>) -> Result<Json<HeadResponse>, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(HeadResponse {
        finalized_slot: store.finalized_slot,
        finalized_header_root: format!("0x{}", hex::encode(store.finalized_header_root)),
        finalized_state_root: format!("0x{}", hex::encode(store.finalized_state_root)),
        current_sync_committee_hash: format!(
            "0x{}",
            hex::encode(store.current_sync_committee_hash)
        ),
        next_sync_committee_hash: format!(
            "0x{}",
            hex::encode(store.next_sync_committee_hash)
        ),
        sync_period: store.current_period(),
        updates_processed: store.updates_processed,
        last_updated: store.last_updated,
    }))
}

/// POST /prove/finality — submit a finality proof generation job.
///
/// Accepts an optional JSON body. If no body is provided, defaults to
/// `verify_bls=false, full_update=false`.
pub async fn prove_finality(
    State(state): State<AppState>,
    body: Option<Json<ProveRequest>>,
) -> Result<Json<JobResponse>, StatusCode> {
    let req = body.map(|j| j.0).unwrap_or_default();
    let job_type = if req.full_update {
        "finality-full"
    } else {
        "finality"
    };
    let job = ProofJob::new(job_type);
    let job_id = job.id.clone();

    {
        let mut jobs = state.jobs.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        jobs.insert(job_id.clone(), job);
    }

    // Spawn background proof generation.
    let jobs = state.jobs.clone();
    let beacon_url = state.beacon_url.clone();
    let network = state.network.clone();
    let verify_bls = req.verify_bls;
    let full_update = req.full_update;
    let job_id_clone = job_id.clone();

    tokio::task::spawn_blocking(move || {
        // Mark as running.
        if let Ok(mut jobs_lock) = jobs.lock() {
            if let Some(job) = jobs_lock.get_mut(&job_id_clone) {
                job.status = JobStatus::Running;
            }
        }

        // Run proof generation.
        let result = run_proof_generation(&beacon_url, &network, verify_bls, full_update);

        // Update job with result.
        if let Ok(mut jobs_lock) = jobs.lock() {
            if let Some(job) = jobs_lock.get_mut(&job_id_clone) {
                match result {
                    Ok((proof_hex, public_values_hex)) => {
                        job.status = JobStatus::Completed;
                        job.proof = Some(proof_hex);
                        job.public_values = Some(public_values_hex);
                    }
                    Err(e) => {
                        job.status = JobStatus::Failed;
                        job.error = Some(e);
                    }
                }
                job.completed_at = now_unix();
            }
        }
    });

    Ok(Json(JobResponse {
        job_id,
        status: "pending".to_string(),
        message: format!("Proof generation started (bls={verify_bls}, full={full_update})"),
    }))
}

/// GET /proof/:id — get the status and result of a proof job.
pub async fn get_proof(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<ProofJob>, StatusCode> {
    let jobs = state.jobs.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match jobs.get(&id) {
        Some(job) => Ok(Json(job.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// POST /prove/storage — request a storage proof verification.
pub async fn prove_storage(
    State(state): State<AppState>,
    Json(req): Json<StorageProofRequest>,
) -> Result<Json<JobResponse>, StatusCode> {
    let job = ProofJob::new("storage");
    let job_id = job.id.clone();

    {
        let mut jobs = state.jobs.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        jobs.insert(job_id.clone(), job);
    }

    // Spawn background storage proof job.
    let jobs = state.jobs.clone();
    let job_id_clone = job_id.clone();
    let chain = req.chain;
    let address = req.address;
    let storage_keys = req.storage_keys;
    let block = req.block;

    // Clone for the response message (values move into the closure).
    let chain_display = chain.clone();
    let address_display = address.clone();

    tokio::task::spawn_blocking(move || {
        if let Ok(mut jobs_lock) = jobs.lock() {
            if let Some(job) = jobs_lock.get_mut(&job_id_clone) {
                job.status = JobStatus::Running;
            }
        }

        let result = run_storage_proof(&chain, &address, &storage_keys, &block);

        if let Ok(mut jobs_lock) = jobs.lock() {
            if let Some(job) = jobs_lock.get_mut(&job_id_clone) {
                match result {
                    Ok(proof_json) => {
                        job.status = JobStatus::Completed;
                        job.proof = Some(proof_json);
                    }
                    Err(e) => {
                        job.status = JobStatus::Failed;
                        job.error = Some(e);
                    }
                }
                job.completed_at = now_unix();
            }
        }
    });

    Ok(Json(JobResponse {
        job_id,
        status: "pending".to_string(),
        message: format!("Storage proof requested for {chain_display} {address_display}"),
    }))
}

/// GET /chains — list supported chains.
pub async fn list_chains() -> Json<ChainsResponse> {
    Json(ChainsResponse {
        chains: vec![
            ChainInfo {
                chain_id: "ethereum-mainnet".to_string(),
                chain_type: "L1".to_string(),
                rpc_url: "https://mainnet.infura.io/v3/...".to_string(),
            },
            ChainInfo {
                chain_id: "ethereum-sepolia".to_string(),
                chain_type: "L1".to_string(),
                rpc_url: "https://sepolia.infura.io/v3/...".to_string(),
            },
            ChainInfo {
                chain_id: "base-mainnet".to_string(),
                chain_type: "L2 (OP Stack)".to_string(),
                rpc_url: "https://mainnet.base.org".to_string(),
            },
            ChainInfo {
                chain_id: "base-sepolia".to_string(),
                chain_type: "L2 (OP Stack)".to_string(),
                rpc_url: "https://sepolia.base.org".to_string(),
            },
        ],
    })
}

/// GET /jobs — list all proof jobs.
pub async fn list_jobs(
    State(state): State<AppState>,
) -> Result<Json<Vec<ProofJob>>, StatusCode> {
    let jobs = state.jobs.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut all_jobs: Vec<ProofJob> = jobs.values().cloned().collect();
    all_jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(Json(all_jobs))
}

// =============================================================================
// Proof Generation (Placeholder Implementation)
// =============================================================================

/// Run SP1 proof generation for a finality update.
///
/// Returns (proof_hex, public_values_hex).
fn run_proof_generation(
    beacon_url: &str,
    network: &str,
    verify_bls: bool,
    full_update: bool,
) -> Result<(String, String), String> {
    let _ = verify_bls; // Reserved for future use with BLS-enabled proving.
    use crate::beacon_api::BeaconClient;
    use sp1_sdk::{
        blocking::{ProveRequest, Prover, ProverClient},
        include_elf, Elf, SP1Stdin,
    };

    const LC_ELF: Elf = include_elf!("eth-lc-program");

    let beacon = BeaconClient::new(beacon_url);
    let config = match network {
        "mainnet" => eth_lc_lib::config::mainnet_config(),
        "sepolia" => eth_lc_lib::config::sepolia_config(),
        _ => return Err(format!("unknown network: {network}")),
    };

    // Fetch finality update.
    let finality = beacon
        .get_finality_update()
        .map_err(|e| format!("fetch finality: {e}"))?;

    // Optionally fetch sync committee for full update.
    let sync_committee = if full_update {
        let (sc_data, sc_hash) = beacon
            .fetch_current_sync_committee()
            .map_err(|e| format!("fetch SC: {e}"))?;
        Some((sc_data, sc_hash))
    } else {
        None
    };

    // Convert to proof inputs.
    let proof_inputs = beacon
        .finality_update_to_proof_inputs(&finality, &config, sync_committee)
        .map_err(|e| format!("convert inputs: {e}"))?;

    // Serialize inputs to SP1Stdin.
    let mut stdin = SP1Stdin::new();
    stdin.write(&proof_inputs);

    // Generate proof.
    let client = ProverClient::from_env();
    let pk = client.setup(LC_ELF).map_err(|e| format!("setup failed: {e}"))?;

    let proof = client
        .prove(&pk, stdin)
        .run()
        .map_err(|e| format!("prove failed: {e}"))?;

    let public_values = proof.public_values.as_slice();
    let public_values_hex = hex::encode(public_values);

    // For the proof itself, serialize as JSON (SP1ProofWithPublicValues implements Serialize).
    let proof_json = serde_json::to_string(&proof)
        .map_err(|e| format!("serialize proof: {e}"))?;

    Ok((proof_json, public_values_hex))
}

/// Run a storage proof fetch and verification.
///
/// Returns the verified proof as JSON string.
fn run_storage_proof(
    chain: &str,
    address: &str,
    storage_keys: &[String],
    block: &str,
) -> Result<String, String> {
    use crate::eth_rpc::EthRpcClient;

    // Determine RPC URL based on chain.
    let rpc_url = match chain {
        "ethereum-mainnet" => {
            let key = std::env::var("INFURA_API_KEY")
                .map_err(|_| "INFURA_API_KEY env var not set".to_string())?;
            crate::eth_rpc::infura_mainnet_url(&key)
        }
        "ethereum-sepolia" => {
            let key = std::env::var("INFURA_API_KEY")
                .map_err(|_| "INFURA_API_KEY env var not set".to_string())?;
            crate::eth_rpc::infura_sepolia_url(&key)
        }
        "base-mainnet" => crate::eth_rpc::BASE_MAINNET_PUBLIC_RPC.to_string(),
        "base-sepolia" => crate::eth_rpc::BASE_SEPOLIA_PUBLIC_RPC.to_string(),
        _ => return Err(format!("unsupported chain: {chain}")),
    };

    let client = EthRpcClient::new(&rpc_url);

    // Pin to a specific block number to ensure state_root and proof are consistent.
    let pinned_block = if block == "latest" || block == "finalized" || block == "safe" {
        // Get block number first, then use it for both calls.
        let block_num: serde_json::Value = reqwest::blocking::Client::new()
            .post(&rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id": 1
            }))
            .send()
            .map_err(|e| format!("get block number: {e}"))?
            .json()
            .map_err(|e| format!("parse block number: {e}"))?;
        block_num["result"]
            .as_str()
            .unwrap_or(block)
            .to_string()
    } else {
        block.to_string()
    };

    let proof = client.get_proof(address, storage_keys, &pinned_block)?;

    // Verify the proof against the state root.
    let state_root = client.get_state_root(&pinned_block)?;
    let _account = eth_lc_lib::mpt::verify_account_proof(
        &proof.address,
        &proof.account_proof,
        &state_root,
    )
    .map_err(|e| format!("account proof verification failed: {e:?}"))?;

    // Verify each storage proof.
    for sp in &proof.storage_proofs {
        eth_lc_lib::mpt::verify_storage_proof(&sp.key, &sp.proof, &proof.storage_root)
            .map_err(|e| format!("storage proof verification failed for slot 0x{}: {e:?}", hex::encode(sp.key)))?;
    }

    // Return the verified proof as JSON.
    serde_json::to_string_pretty(&proof)
        .map_err(|e| format!("serialize proof: {e}"))
}
