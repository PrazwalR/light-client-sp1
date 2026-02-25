//! Ethereum Light Client library for SP1 zkVM.
//!
//! This crate contains all shared types and verification logic used by both
//! the zkVM program (guest) and the host script. It implements:
//! - Ethereum consensus types (BeaconBlockHeader, SyncCommittee, etc.)
//! - SSZ Merkle proof verification
//! - Light client update verification logic
//! - Network configurations (Sepolia, Mainnet)

#[cfg(feature = "bls")]
pub mod bls;
pub mod config;
pub mod consensus;
pub mod cross_chain;
pub mod l2;
pub mod merkle;
pub mod mpt;
pub mod types;

use alloy_sol_types::sol;

sol! {
    /// Public values committed by the zkVM light client program.
    ///
    /// These values are ABI-encoded and can be decoded/verified in Solidity.
    /// They represent the verified state after processing a light client update,
    /// plus optional storage proof results.
    struct LightClientPublicValues {
        /// Slot number of the finalized header.
        uint64 finalizedSlot;
        /// hash_tree_root of the finalized beacon block header.
        bytes32 finalizedHeaderRoot;
        /// Beacon state root from the finalized header.
        bytes32 finalizedStateRoot;
        /// Hash of the current sync committee.
        bytes32 currentSyncCommitteeHash;
        /// Hash of the next sync committee (zero if no rotation).
        bytes32 nextSyncCommitteeHash;
        /// Number of sync committee members that participated.
        uint32 participation;
        /// Number of verified L1 storage slots (0 if no storage proof).
        uint32 numStorageSlots;
        /// Contract address that was proven (zero if no storage proof).
        address storageProofAddress;
        /// Storage root of the proven account (zero if no proof).
        bytes32 storageProofStorageRoot;
        /// Number of verified L2 storage slots (0 if no L2 proof).
        uint32 numL2StorageSlots;
        /// L2 state root (zero if no L2 proof).
        bytes32 l2StateRoot;
    }
}
