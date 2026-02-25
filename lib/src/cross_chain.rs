//! Cross-chain message verification.
//!
//! Verifies messages sent between L1 (Ethereum) and L2 (OP Stack) by proving
//! storage slot values in bridge/messenger contracts on each chain.
//!
//! **L1 → L2 message flow:**
//! 1. Message is sent via L1CrossDomainMessenger (or OptimismPortal) on L1.
//! 2. The message hash is stored in a mapping on L1.
//! 3. We prove the message hash via L1 storage proof (against beacon state root).
//!
//! **L2 → L1 message flow (withdrawal):**
//! 1. Message is sent via L2ToL1MessagePasser on L2.
//! 2. The message hash is stored in L2's sentMessages mapping.
//! 3. We prove L2 state via L2OutputOracle on L1 (L1 storage proof).
//! 4. Then prove the message hash in L2 state (L2 storage proof).
//!
//! Both flows use MPT storage proofs verified inside the zkVM.

use crate::mpt::{self, keccak256};
use crate::types::{Address, Bytes32, ChainId, CrossChainMessageProof};

// =============================================================================
// Well-Known Contract Addresses
// =============================================================================

/// OP Mainnet L2ToL1MessagePasser (predeploy on L2).
pub const L2_TO_L1_MESSAGE_PASSER: [u8; 20] = {
    let mut addr = [0u8; 20];
    // 0x4200000000000000000000000000000000000016
    addr[0] = 0x42;
    addr[19] = 0x16;
    addr
};

/// OP Mainnet L1CrossDomainMessenger on L1.
/// Mainnet: 0x25ace71c97B33Cc4729CF772ae268934F7ab5fA1
pub const L1_CROSS_DOMAIN_MESSENGER_MAINNET: [u8; 20] = [
    0x25, 0xac, 0xe7, 0x1c, 0x97, 0xB3, 0x3C, 0xc4, 0x72, 0x9C,
    0xF7, 0x72, 0xae, 0x26, 0x89, 0x34, 0xF7, 0xab, 0x5f, 0xA1,
];

// =============================================================================
// Errors
// =============================================================================

/// Errors from cross-chain message verification.
#[derive(Debug)]
pub enum CrossChainError {
    /// Storage proof verification failed.
    StorageProofFailed(String),
    /// Message value mismatch.
    MessageMismatch {
        expected: Bytes32,
        got: Bytes32,
    },
    /// Account proof verification failed.
    AccountProofFailed(String),
}

impl core::fmt::Display for CrossChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StorageProofFailed(s) => write!(f, "storage proof failed: {s}"),
            Self::MessageMismatch { expected, got } => write!(
                f,
                "message mismatch: expected {:?}, got {:?}",
                &expected[..4],
                &got[..4],
            ),
            Self::AccountProofFailed(s) => write!(f, "account proof failed: {s}"),
        }
    }
}

// =============================================================================
// Solidity Storage Slot Computation
// =============================================================================

/// Compute the Solidity `mapping(bytes32 => ...)` storage slot.
///
/// For a mapping at base slot `p` with key `k`:
///   `keccak256(k ++ p)`
///
/// where `++` is concatenation and both are left-padded to 32 bytes.
pub fn compute_mapping_slot(key: &Bytes32, base_slot: &Bytes32) -> Bytes32 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(key);
    preimage[32..].copy_from_slice(base_slot);
    let hash = keccak256(&preimage);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Compute the storage slot for L2ToL1MessagePasser.sentMessages mapping.
///
/// The sentMessages mapping is at slot 0:
///   `sentMessages[msgHash]` → `keccak256(msgHash ++ 0x00...00)`
pub fn l2_sent_messages_slot(message_hash: &Bytes32) -> Bytes32 {
    let base_slot = [0u8; 32]; // slot 0
    compute_mapping_slot(message_hash, &base_slot)
}

/// Compute the withdrawal message hash for OP Stack.
///
/// `keccak256(abi.encode(nonce, sender, target, value, gasLimit, data))`
///
/// This is a simplified version; the full withdrawal hash includes
/// all fields of the `WithdrawalTransaction` struct.
pub fn compute_withdrawal_hash(
    nonce: &Bytes32,
    sender: &Address,
    target: &Address,
    value: &Bytes32,
    gas_limit: &Bytes32,
    data: &[u8],
) -> Bytes32 {
    // ABI-encode the fields (simplified: each field is 32 bytes, left-padded)
    let mut preimage = Vec::with_capacity(32 * 5 + data.len());

    // nonce (uint256)
    preimage.extend_from_slice(nonce);

    // sender (address, left-padded to 32 bytes)
    let mut sender_padded = [0u8; 32];
    sender_padded[12..].copy_from_slice(sender);
    preimage.extend_from_slice(&sender_padded);

    // target (address, left-padded to 32 bytes)
    let mut target_padded = [0u8; 32];
    target_padded[12..].copy_from_slice(target);
    preimage.extend_from_slice(&target_padded);

    // value (uint256)
    preimage.extend_from_slice(value);

    // gasLimit (uint256)
    preimage.extend_from_slice(gas_limit);

    // data (dynamic, but we hash the raw bytes for simplicity)
    preimage.extend_from_slice(data);

    let hash = keccak256(&preimage);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

// =============================================================================
// Verification
// =============================================================================

/// Verify an L1 message (stored on L1 in a messenger/bridge contract).
///
/// Proves that `storage_slot` in `contract_address` has `expected_value`
/// using the provided account and storage proofs against the L1 state root.
///
/// Returns the verified `CrossChainMessageProof` on success.
pub fn verify_l1_message(
    state_root: &Bytes32,
    contract_address: &Address,
    account_proof: &[Vec<u8>],
    storage_slot: &Bytes32,
    storage_proof: &[Vec<u8>],
    expected_value: &Bytes32,
    source_chain: ChainId,
    dest_chain: ChainId,
) -> Result<CrossChainMessageProof, CrossChainError> {
    // Step 1: Verify account exists and get its storage root
    let account = mpt::verify_account_proof(contract_address, account_proof, state_root)
        .map_err(|e| CrossChainError::AccountProofFailed(format!("{e:?}")))?;

    // Step 2: Verify storage slot value
    let proven_value = mpt::verify_storage_proof(storage_slot, storage_proof, &account.storage_root)
        .map_err(|e| CrossChainError::StorageProofFailed(format!("{e:?}")))?;

    // Step 3: Check the value matches
    if proven_value != *expected_value {
        return Err(CrossChainError::MessageMismatch {
            expected: *expected_value,
            got: proven_value,
        });
    }

    Ok(CrossChainMessageProof {
        source_chain,
        dest_chain,
        message_contract: *contract_address,
        message_slot: *storage_slot,
        message_value: proven_value,
    })
}

/// Verify an L2 → L1 withdrawal message.
///
/// This is a two-step proof:
/// 1. Prove the L2 state root via L2OutputOracle on L1.
/// 2. Prove the message hash in L2ToL1MessagePasser on L2.
///
/// The L2 state root verification should be done separately via `l2::verify_l2_output_root`.
/// This function handles step 2: proving the message in L2 state.
pub fn verify_l2_withdrawal_message(
    l2_state_root: &Bytes32,
    message_passer_address: &Address,
    account_proof: &[Vec<u8>],
    message_hash: &Bytes32,
    storage_proof: &[Vec<u8>],
) -> Result<CrossChainMessageProof, CrossChainError> {
    // Verify L2ToL1MessagePasser account on L2
    let account = mpt::verify_account_proof(message_passer_address, account_proof, l2_state_root)
        .map_err(|e| CrossChainError::AccountProofFailed(format!("{e:?}")))?;

    // Compute the storage slot for sentMessages[messageHash]
    let slot = l2_sent_messages_slot(message_hash);

    // Verify the storage slot — for sentMessages, the value is 1 (true) if sent
    let proven_value = mpt::verify_storage_proof(&slot, storage_proof, &account.storage_root)
        .map_err(|e| CrossChainError::StorageProofFailed(format!("{e:?}")))?;

    // sentMessages mapping stores `true` (1) for sent messages
    let expected_true = {
        let mut v = [0u8; 32];
        v[31] = 1;
        v
    };
    if proven_value != expected_true {
        return Err(CrossChainError::MessageMismatch {
            expected: expected_true,
            got: proven_value,
        });
    }

    Ok(CrossChainMessageProof {
        source_chain: ChainId::BaseMainnet, // default L2 source
        dest_chain: ChainId::EthereumMainnet,
        message_contract: *message_passer_address,
        message_slot: slot,
        message_value: proven_value,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_mapping_slot() {
        // Known test: mapping at slot 0 with key all-zeros
        let key = [0u8; 32];
        let base = [0u8; 32];
        let slot = compute_mapping_slot(&key, &base);
        // keccak256(64 zero bytes)
        let expected = keccak256(&[0u8; 64]);
        assert_eq!(&slot[..], &expected[..]);
    }

    #[test]
    fn test_l2_sent_messages_slot() {
        let msg_hash = [0x42u8; 32];
        let slot = l2_sent_messages_slot(&msg_hash);

        // Should be keccak256(msg_hash ++ slot_0)
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&msg_hash);
        // base slot is 0, so preimage[32..64] = 0
        let expected = keccak256(&preimage);
        assert_eq!(&slot[..], &expected[..]);
    }

    #[test]
    fn test_compute_withdrawal_hash() {
        let nonce = [0u8; 32];
        let sender = [0x42u8; 20];
        let target = [0x43u8; 20];
        let value = [0u8; 32];
        let gas_limit = {
            let mut g = [0u8; 32];
            g[31] = 100;
            g
        };
        let data = b"hello";

        let hash = compute_withdrawal_hash(&nonce, &sender, &target, &value, &gas_limit, data);
        // Just verify it's deterministic
        let hash2 = compute_withdrawal_hash(&nonce, &sender, &target, &value, &gas_limit, data);
        assert_eq!(hash, hash2);

        // Different data produces different hash
        let hash3 = compute_withdrawal_hash(&nonce, &sender, &target, &value, &gas_limit, b"world");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_l2_message_passer_address() {
        // 0x4200000000000000000000000000000000000016
        assert_eq!(L2_TO_L1_MESSAGE_PASSER[0], 0x42);
        assert_eq!(L2_TO_L1_MESSAGE_PASSER[19], 0x16);
        assert_eq!(L2_TO_L1_MESSAGE_PASSER[1], 0x00);
    }
}
