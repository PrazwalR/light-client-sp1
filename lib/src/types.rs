//! Core types for the Ethereum Light Client.
//!
//! Defines all Ethereum consensus types needed for light client verification,
//! following the Ethereum Altair/Bellatrix/Capella/Deneb specifications.

use serde::{Deserialize, Serialize};

// =============================================================================
// Constants
// =============================================================================

/// Number of validators in a sync committee.
pub const SYNC_COMMITTEE_SIZE: usize = 512;

/// Bytes per BLS public key.
pub const BYTES_PER_PUBKEY: usize = 48;

/// Bytes per BLS signature.
pub const BYTES_PER_SIGNATURE: usize = 96;

/// Slots per epoch in the Ethereum beacon chain.
pub const SLOTS_PER_EPOCH: u64 = 32;

/// Epochs per sync committee period.
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

/// Slots per sync committee period.
pub const SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 =
    SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

/// Minimum number of sync committee participants for a valid update.
pub const MIN_SYNC_COMMITTEE_PARTICIPANTS: usize = 1;

/// Supermajority threshold denominator (need > 2/3 participation for safety).
pub const SUPERMAJORITY_THRESHOLD_DENOMINATOR: usize = 3;

/// Supermajority threshold numerator.
pub const SUPERMAJORITY_THRESHOLD_NUMERATOR: usize = 2;

// =============================================================================
// Generalized Indices & Merkle Proof Depths
// =============================================================================

/// Generalized index of `finalized_checkpoint.root` in `BeaconState`.
///
/// This varies by fork:
///   Altair-Deneb:  105 (depth=6, BeaconState ≤ 32 fields)
///   Electra-Fulu:  169 (depth=7, BeaconState > 32 fields)
///
/// The subtree index (41) is the same across all forks because
/// `finalized_checkpoint` is at the same relative position.
/// The verification code uses branch.len() as depth dynamically.
pub const FINALIZED_ROOT_GINDEX: usize = 105;
pub const FINALIZED_ROOT_GINDEX_ELECTRA: usize = 169;

/// Depth of the finality Merkle proof (Altair-Deneb).
/// NOTE: consensus.rs uses branch.len() dynamically, so this constant
/// is kept for documentation and mock data generation only.
pub const FINALIZED_ROOT_DEPTH: usize = 6;

/// Subtree index of the finalized root (same across all forks).
pub const FINALIZED_ROOT_SUBTREE_INDEX: usize = 41;

/// Generalized index of `next_sync_committee` in `BeaconState`.
///
///   Altair-Deneb:  55 (depth=5)
///   Electra-Fulu:  87 (depth=6)
pub const NEXT_SYNC_COMMITTEE_GINDEX: usize = 55;
pub const NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA: usize = 87;

/// Depth of the next sync committee Merkle proof (Altair-Deneb).
/// NOTE: consensus.rs uses branch.len() dynamically.
pub const NEXT_SYNC_COMMITTEE_DEPTH: usize = 5;

/// Subtree index of the next sync committee (same across all forks).
pub const NEXT_SYNC_COMMITTEE_SUBTREE_INDEX: usize = 23;

// =============================================================================
// Domain Types
// =============================================================================

/// Domain type for sync committee signatures (DOMAIN_SYNC_COMMITTEE).
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

// =============================================================================
// Primitive Aliases
// =============================================================================

/// 32-byte hash type (used for roots, hashes, etc.).
pub type Bytes32 = [u8; 32];

/// BLS public key (48 bytes, compressed G1 point).
pub type BLSPubkey = [u8; BYTES_PER_PUBKEY];

/// BLS signature (96 bytes, compressed G2 point).
/// Using Vec<u8> for serde compatibility — validated at runtime.
pub type BLSSignature = Vec<u8>;

// =============================================================================
// Beacon Chain Types
// =============================================================================

/// Beacon block header — the core authenticated data structure.
///
/// The `hash_tree_root` of this header is used as the block hash in the beacon chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    /// Slot number of this block.
    pub slot: u64,
    /// Index of the validator who proposed this block.
    pub proposer_index: u64,
    /// Root hash of the parent block.
    pub parent_root: Bytes32,
    /// Root hash of the beacon state after this block.
    pub state_root: Bytes32,
    /// Root hash of the block body.
    pub body_root: Bytes32,
}

/// Sync committee aggregate — contains participation bits and aggregate signature.
///
/// The sync committee is a group of 512 validators that sign each slot's block header.
/// This allows light clients to verify the chain with minimal data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncAggregate {
    /// Bitvector indicating which committee members participated (true = signed).
    /// Length must equal `SYNC_COMMITTEE_SIZE` (512).
    pub sync_committee_bits: Vec<bool>,
    /// Aggregate BLS signature from all participating committee members.
    pub sync_committee_signature: BLSSignature,
}

/// Finality proof data — proves a finalized header against the attested state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityUpdate {
    /// The finalized beacon block header.
    pub finalized_header: BeaconBlockHeader,
    /// Merkle branch proving `hash_tree_root(finalized_header)` is at
    /// `FINALIZED_ROOT_GINDEX` in the attested header's state.
    pub finality_branch: Vec<Bytes32>,
}

/// Sync committee rotation proof data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeUpdate {
    /// Hash of the next sync committee (`hash_tree_root(next_sync_committee)`).
    pub next_sync_committee_hash: Bytes32,
    /// Merkle branch proving the next sync committee hash is at
    /// `NEXT_SYNC_COMMITTEE_GINDEX` in the attested header's state.
    pub next_sync_committee_branch: Vec<Bytes32>,
}

/// A complete light client update — one step of the light client protocol.
///
/// Contains all data needed to advance the light client's view of the chain:
/// an attested header signed by the sync committee, with optional finality
/// and sync committee rotation proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientUpdate {
    /// Header attested to by the sync committee.
    pub attested_header: BeaconBlockHeader,
    /// Sync committee aggregate signature and participation bits.
    pub sync_aggregate: SyncAggregate,
    /// Slot at which the aggregate signature was created.
    /// Must be greater than `attested_header.slot`.
    pub signature_slot: u64,
    /// Optional finality proof (proves a finalized header).
    pub finality_update: Option<FinalityUpdate>,
    /// Optional sync committee rotation proof.
    pub sync_committee_update: Option<SyncCommitteeUpdate>,
}

// =============================================================================
// Light Client State
// =============================================================================

/// Light client store — the persistent state maintained by the light client.
///
/// This tracks the latest verified headers and sync committees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientStore {
    /// The latest verified finalized header.
    pub finalized_header: BeaconBlockHeader,
    /// Hash of the current sync committee.
    pub current_sync_committee_hash: Bytes32,
    /// Hash of the next sync committee (if known).
    pub next_sync_committee_hash: Option<Bytes32>,
    /// The latest optimistic (unfinalized but attested) header.
    pub optimistic_header: BeaconBlockHeader,
    /// Maximum active participants seen in the previous period.
    pub previous_max_active_participants: u64,
    /// Maximum active participants seen in the current period.
    pub current_max_active_participants: u64,
}

// =============================================================================
// Network Configuration
// =============================================================================

/// Network-specific configuration for the beacon chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Genesis validators root (domain separation).
    pub genesis_validators_root: Bytes32,
    /// Genesis time (Unix timestamp).
    pub genesis_time: u64,
    /// Altair fork version bytes.
    pub altair_fork_version: [u8; 4],
    /// Altair fork epoch.
    pub altair_fork_epoch: u64,
    /// Bellatrix fork version bytes.
    pub bellatrix_fork_version: [u8; 4],
    /// Bellatrix fork epoch.
    pub bellatrix_fork_epoch: u64,
    /// Capella fork version bytes.
    pub capella_fork_version: [u8; 4],
    /// Capella fork epoch.
    pub capella_fork_epoch: u64,
    /// Deneb fork version bytes.
    pub deneb_fork_version: [u8; 4],
    /// Deneb fork epoch.
    pub deneb_fork_epoch: u64,
    /// Electra fork version bytes.
    pub electra_fork_version: [u8; 4],
    /// Electra fork epoch.
    pub electra_fork_epoch: u64,
    /// Fulu fork version bytes.
    pub fulu_fork_version: [u8; 4],
    /// Fulu fork epoch.
    pub fulu_fork_epoch: u64,
}

// =============================================================================
// Sync Committee Data
// =============================================================================

/// Sync committee pubkey data for BLS signature verification.
///
/// When provided, the zkVM will perform full BLS12-381 aggregate signature
/// verification. When absent (None), BLS verification is skipped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeData {
    /// Flat concatenation of all 512 compressed pubkeys (512 × 48 = 24,576 bytes).
    pub pubkeys: Vec<u8>,
    /// The aggregate pubkey of the full committee (48 bytes, compressed G1).
    /// Used for SSZ hash_tree_root computation of the SyncCommittee.
    pub aggregate_pubkey: Vec<u8>,
}

// =============================================================================
// Proof I/O Types
// =============================================================================

/// Inputs passed from the host (script) to the zkVM program.
///
/// Contains all data the zkVM needs to verify a light client update,
/// plus optional storage proofs and L2 state verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofInputs {
    /// The light client update to verify.
    pub update: LightClientUpdate,
    /// Hash of the current sync committee (for context/commitment).
    pub current_sync_committee_hash: Bytes32,
    /// Sync committee pubkeys for BLS verification.
    /// When `Some`, full BLS12-381 aggregate signature verification is performed.
    /// When `None`, BLS verification is skipped (development/testing mode).
    pub sync_committee: Option<SyncCommitteeData>,
    /// Genesis validators root (for domain computation).
    pub genesis_validators_root: Bytes32,
    /// Genesis time of the beacon chain.
    pub genesis_time: u64,
    /// Fork version for the signature domain.
    pub fork_version: [u8; 4],
    /// Optional L1 storage proof inputs to verify inside the zkVM.
    /// When present, account + storage proofs are verified against the
    /// finalized state root, and results are committed as public values.
    #[serde(default)]
    pub storage_proof: Option<StorageProofInputs>,
    /// Optional L2 storage proof inputs for cross-chain verification.
    /// Verifies L2 state via L1's L2OutputOracle.
    #[serde(default)]
    pub l2_storage_proof: Option<L2StorageProofInputs>,
}

// =============================================================================
// Ethereum Address
// =============================================================================

/// 20-byte Ethereum address.
pub type Address = [u8; 20];

// =============================================================================
// Chain Identifiers
// =============================================================================

/// Identifies a supported chain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ChainId {
    EthereumMainnet,
    EthereumSepolia,
    BaseMainnet,
    BaseSepolia,
}

impl core::fmt::Display for ChainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EthereumMainnet => write!(f, "ethereum-mainnet"),
            Self::EthereumSepolia => write!(f, "ethereum-sepolia"),
            Self::BaseMainnet => write!(f, "base-mainnet"),
            Self::BaseSepolia => write!(f, "base-sepolia"),
        }
    }
}

// =============================================================================
// Storage Proof Types (EIP-1186)
// =============================================================================

/// EIP-1186 storage proof for a single slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProofEntry {
    /// The storage slot key (32 bytes).
    pub key: Bytes32,
    /// The proven storage value (32 bytes, big-endian).
    pub value: Bytes32,
    /// MPT proof nodes (RLP-encoded) from storage root to leaf.
    pub proof: Vec<Vec<u8>>,
}

/// EIP-1186 account + storage proof bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EIP1186Proof {
    /// The account address.
    pub address: Address,
    /// Account nonce.
    pub nonce: u64,
    /// Account balance (big-endian bytes, variable length).
    pub balance: Vec<u8>,
    /// Storage root of the account.
    pub storage_root: Bytes32,
    /// Code hash of the account.
    pub code_hash: Bytes32,
    /// MPT proof nodes for the account (against the state root).
    pub account_proof: Vec<Vec<u8>>,
    /// Storage proofs for requested slots.
    pub storage_proofs: Vec<StorageProofEntry>,
}

// =============================================================================
// L2 / Multichain Types
// =============================================================================

/// Configuration for an OP Stack L2 chain verified via L1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2ChainConfig {
    /// Chain identifier.
    pub chain_id: ChainId,
    /// L1 contract address holding L2 output roots.
    pub l2_output_oracle: Address,
    /// L1 chain ID (the "anchor" chain).
    pub l1_chain_id: ChainId,
    /// L2 JSON-RPC endpoint URL.
    pub l2_rpc_url: String,
}

/// OP Stack L2 output root components.
///
/// `output_root = keccak256(version ++ state_root ++ withdrawal_root ++ latest_block_hash)`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2OutputRoot {
    /// Version byte (currently 0).
    pub version: u8,
    /// L2 state root (MPT root of all L2 account states).
    pub state_root: Bytes32,
    /// L2 withdrawal storage root.
    pub withdrawal_storage_root: Bytes32,
    /// Hash of the latest L2 block.
    pub latest_block_hash: Bytes32,
}

// =============================================================================
// Storage Proof Inputs for zkVM
// =============================================================================

/// A single storage slot to verify inside the zkVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSlotProof {
    /// Storage slot key (32 bytes).
    pub key: Bytes32,
    /// MPT proof nodes for this slot.
    pub proof: Vec<Vec<u8>>,
}

/// Inputs for verifying an L1 account + storage proofs inside the zkVM.
///
/// The account proof is verified against the `finalized_state_root` from consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProofInputs {
    /// Target contract address (20 bytes).
    pub address: Address,
    /// MPT proof nodes for the account (against execution state root).
    pub account_proof: Vec<Vec<u8>>,
    /// Storage slot proofs to verify against the account's storage root.
    pub storage_proofs: Vec<StorageSlotProof>,
}

/// Inputs for verifying L2 state via L1's L2OutputOracle inside the zkVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2StorageProofInputs {
    /// L2OutputOracle address on L1.
    pub oracle_address: Address,
    /// Account proof for the oracle on L1.
    pub oracle_account_proof: Vec<Vec<u8>>,
    /// Output index in the l2Outputs array.
    pub output_index: u64,
    /// Storage proof for the output root slot.
    pub output_root_storage_proof: Vec<Vec<u8>>,
    /// L2 output root components for verification.
    pub l2_output: L2OutputRoot,
    /// L2 target account address.
    pub l2_address: Address,
    /// L2 account proof (against L2 state root from output).
    pub l2_account_proof: Vec<Vec<u8>>,
    /// L2 storage slot proofs.
    pub l2_storage_proofs: Vec<StorageSlotProof>,
}

/// Result of a verified storage slot (committed as public values).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedStorageSlot {
    /// Storage slot key.
    pub key: Bytes32,
    /// Verified storage value.
    pub value: Bytes32,
}

/// Cross-chain message proof — verifies a message on one chain using another chain's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMessageProof {
    /// Source chain identifier.
    pub source_chain: ChainId,
    /// Destination chain identifier.
    pub dest_chain: ChainId,
    /// The contract address holding the message on the source chain.
    pub message_contract: Address,
    /// Storage slot containing the message hash/nonce.
    pub message_slot: Bytes32,
    /// Proven message value.
    pub message_value: Bytes32,
}
