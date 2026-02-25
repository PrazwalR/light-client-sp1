//! OP Stack L2 output root verification.
//!
//! Verifies L2 state by proving L2 output roots are recorded in the
//! L2OutputOracle contract on L1, then validates L2 storage proofs
//! against the proven L2 state root.
//!
//! Flow:
//! 1. Verify L2OutputOracle account exists on L1 (via account proof against L1 state root).
//! 2. Read the L2 output root from the oracle's storage (via storage proof).
//! 3. Decompose output root → L2 state root.
//! 4. Verify L2 account/storage proofs against the L2 state root.

use crate::mpt::{self, keccak256, AccountState, MPTError};
use crate::types::{Address, Bytes32, L2OutputRoot};

// =============================================================================
// Errors
// =============================================================================

/// Errors from L2 verification.
#[derive(Debug)]
pub enum L2Error {
    /// MPT proof verification failed.
    MPT(MPTError),
    /// The computed output root doesn't match the proven value.
    OutputRootMismatch,
    /// The L2OutputOracle account proof is invalid.
    OracleAccountInvalid(String),
    /// A storage proof against the oracle failed.
    OracleStorageInvalid(String),
    /// L2 account proof failed.
    L2AccountInvalid(String),
    /// L2 storage proof failed.
    L2StorageInvalid(String),
}

impl From<MPTError> for L2Error {
    fn from(e: MPTError) -> Self {
        L2Error::MPT(e)
    }
}

impl core::fmt::Display for L2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MPT(e) => write!(f, "MPT error: {e:?}"),
            Self::OutputRootMismatch => write!(f, "L2 output root mismatch"),
            Self::OracleAccountInvalid(s) => write!(f, "oracle account invalid: {s}"),
            Self::OracleStorageInvalid(s) => write!(f, "oracle storage invalid: {s}"),
            Self::L2AccountInvalid(s) => write!(f, "L2 account invalid: {s}"),
            Self::L2StorageInvalid(s) => write!(f, "L2 storage invalid: {s}"),
        }
    }
}

// =============================================================================
// OP Stack Output Root
// =============================================================================

/// Compute the OP Stack output root from its components.
///
/// `output_root = keccak256(version_byte ++ state_root ++ withdrawal_root ++ block_hash)`
pub fn compute_output_root(output: &L2OutputRoot) -> Bytes32 {
    let mut preimage = [0u8; 128];
    // version is a single byte, left-padded to 32 bytes
    preimage[31] = output.version;
    preimage[32..64].copy_from_slice(&output.state_root);
    preimage[64..96].copy_from_slice(&output.withdrawal_storage_root);
    preimage[96..128].copy_from_slice(&output.latest_block_hash);
    keccak256(&preimage)
}

/// Verify an L2OutputRoot against a known output root hash.
pub fn verify_output_root(output: &L2OutputRoot, expected_root: &Bytes32) -> Result<(), L2Error> {
    let computed = compute_output_root(output);
    if computed != *expected_root {
        return Err(L2Error::OutputRootMismatch);
    }
    Ok(())
}

// =============================================================================
// L2OutputOracle Storage Slot Computation
// =============================================================================

/// Compute the storage slot for `l2Outputs[index]`.
///
/// In Solidity, `l2Outputs` is a dynamic array at storage slot 3.
/// Element layout: each element is 2 slots (outputRoot + timestamp+l2BlockNumber).
/// `l2Outputs[i].outputRoot = keccak256(uint256(3)) + i * 2`
pub fn l2_output_slot(index: u64) -> Bytes32 {
    // keccak256(abi.encode(3))
    let mut slot_bytes = [0u8; 32];
    slot_bytes[31] = 3;
    let base = keccak256(&slot_bytes);

    // Add index * 2 to the base
    let offset = index * 2;
    add_u256_u64(&base, offset)
}

/// Compute the storage slot for the latest output index.
///
/// `latestOutputIndex` is at slot 4 in the L2OutputOracle (post-Bedrock).
pub fn latest_output_index_slot() -> Bytes32 {
    let mut slot = [0u8; 32];
    slot[31] = 4;
    slot
}

/// Simple u256 + u64 addition (big-endian).
fn add_u256_u64(base: &Bytes32, addend: u64) -> Bytes32 {
    let mut result = *base;
    let add_bytes = addend.to_be_bytes();
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let add_byte = if i >= 24 { add_bytes[i - 24] } else { 0 };
        let sum = result[i] as u16 + add_byte as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

// =============================================================================
// End-to-End L2 State Verification
// =============================================================================

/// Verify the L2OutputOracle account on L1 and return its storage root.
///
/// # Arguments
/// * `oracle_address` — L2OutputOracle contract address on L1.
/// * `account_proof` — MPT proof nodes for the oracle account.
/// * `l1_state_root` — L1 execution state root.
pub fn verify_oracle_account(
    oracle_address: &Address,
    account_proof: &[Vec<u8>],
    l1_state_root: &Bytes32,
) -> Result<AccountState, L2Error> {
    mpt::verify_account_proof(oracle_address, account_proof, l1_state_root)
        .map_err(|e| L2Error::OracleAccountInvalid(format!("{e:?}")))
}

/// Read the L2 output root from the oracle's storage.
///
/// # Arguments
/// * `output_index` — Index in the `l2Outputs` array.
/// * `storage_proof` — MPT proof for the output root slot.
/// * `oracle_storage_root` — Storage root of the oracle account.
pub fn verify_oracle_output_root(
    output_index: u64,
    storage_proof: &[Vec<u8>],
    oracle_storage_root: &Bytes32,
) -> Result<Bytes32, L2Error> {
    let slot = l2_output_slot(output_index);
    mpt::verify_storage_proof(&slot, storage_proof, oracle_storage_root)
        .map_err(|e| L2Error::OracleStorageInvalid(format!("{e:?}")))
}

/// Full L2 state verification pipeline:
///
/// 1. Verify oracle account on L1.
/// 2. Prove the output root from oracle storage.
/// 3. Decompose output root → L2 state root.
/// 4. Verify L2 account proof against L2 state root.
/// 5. Optionally verify L2 storage proofs.
///
/// Returns the verified L2 `AccountState`.
pub fn verify_l2_account(
    // L1 inputs
    oracle_address: &Address,
    oracle_account_proof: &[Vec<u8>],
    l1_state_root: &Bytes32,
    // Oracle storage
    output_index: u64,
    output_root_storage_proof: &[Vec<u8>],
    // L2 output root components
    l2_output: &L2OutputRoot,
    // L2 account to verify
    l2_address: &Address,
    l2_account_proof: &[Vec<u8>],
) -> Result<AccountState, L2Error> {
    // Step 1: Verify oracle exists on L1.
    let oracle = verify_oracle_account(oracle_address, oracle_account_proof, l1_state_root)?;

    // Step 2: Read output root from oracle storage.
    let proven_output_root =
        verify_oracle_output_root(output_index, output_root_storage_proof, &oracle.storage_root)?;

    // Step 3: Verify L2OutputRoot components match the proven output root.
    verify_output_root(l2_output, &proven_output_root)?;

    // Step 4: Verify L2 account against the L2 state root.
    mpt::verify_account_proof(l2_address, l2_account_proof, &l2_output.state_root)
        .map_err(|e| L2Error::L2AccountInvalid(format!("{e:?}")))
}

/// Verify an L2 storage slot value given a proven L2 account's storage root.
pub fn verify_l2_storage(
    slot: &Bytes32,
    storage_proof: &[Vec<u8>],
    l2_storage_root: &Bytes32,
) -> Result<Bytes32, L2Error> {
    mpt::verify_storage_proof(slot, storage_proof, l2_storage_root)
        .map_err(|e| L2Error::L2StorageInvalid(format!("{e:?}")))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_output_root() {
        // Known OP Stack output root computation.
        let output = L2OutputRoot {
            version: 0,
            state_root: [0xaa; 32],
            withdrawal_storage_root: [0xbb; 32],
            latest_block_hash: [0xcc; 32],
        };
        let root = compute_output_root(&output);
        // Verify it's deterministic.
        let root2 = compute_output_root(&output);
        assert_eq!(root, root2);
        // Verify it's non-zero.
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_verify_output_root() {
        let output = L2OutputRoot {
            version: 0,
            state_root: [0x11; 32],
            withdrawal_storage_root: [0x22; 32],
            latest_block_hash: [0x33; 32],
        };
        let correct_root = compute_output_root(&output);
        assert!(verify_output_root(&output, &correct_root).is_ok());

        let wrong_root = [0xff; 32];
        assert!(verify_output_root(&output, &wrong_root).is_err());
    }

    #[test]
    fn test_l2_output_slot() {
        // Slot for index 0: keccak256(uint256(3)) + 0
        let slot0 = l2_output_slot(0);
        let mut slot_bytes = [0u8; 32];
        slot_bytes[31] = 3;
        let expected = keccak256(&slot_bytes);
        assert_eq!(slot0, expected);

        // Slot for index 1: keccak256(uint256(3)) + 2
        let slot1 = l2_output_slot(1);
        let expected1 = add_u256_u64(&expected, 2);
        assert_eq!(slot1, expected1);
    }

    #[test]
    fn test_latest_output_index_slot() {
        let slot = latest_output_index_slot();
        let mut expected = [0u8; 32];
        expected[31] = 4;
        assert_eq!(slot, expected);
    }

    #[test]
    fn test_add_u256_u64_no_overflow() {
        let base = [0u8; 32];
        let result = add_u256_u64(&base, 42);
        assert_eq!(result[31], 42);
        assert_eq!(result[30], 0);
    }

    #[test]
    fn test_add_u256_u64_with_carry() {
        let mut base = [0u8; 32];
        base[31] = 0xff;
        let result = add_u256_u64(&base, 1);
        assert_eq!(result[31], 0);
        assert_eq!(result[30], 1);
    }
}
