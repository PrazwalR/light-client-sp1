//! SHA-256 based Merkle proof utilities for the Ethereum beacon chain.
//!
//! Implements SSZ Merkleization and generalized-index Merkle branch verification
//! as specified in the Ethereum consensus specs.

use sha2::{Digest, Sha256};

use crate::types::{BeaconBlockHeader, Bytes32};

/// Zero hash constant (32 zero bytes).
pub const ZERO_HASH: Bytes32 = [0u8; 32];

// =============================================================================
// Core Hashing
// =============================================================================

/// Compute SHA-256 hash of two 32-byte values concatenated.
///
/// This is the core operation for Merkle tree construction in SSZ.
pub fn sha256_pair(a: &Bytes32, b: &Bytes32) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA-256 hash of arbitrary data.
pub fn sha256(data: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

// =============================================================================
// SSZ Primitives
// =============================================================================

/// Convert a `u64` to its SSZ `hash_tree_root`.
///
/// For basic types, the hash_tree_root is the little-endian encoding
/// zero-padded to 32 bytes.
pub fn uint64_to_leaf(value: u64) -> Bytes32 {
    let mut leaf = [0u8; 32];
    leaf[..8].copy_from_slice(&value.to_le_bytes());
    leaf
}

// =============================================================================
// SSZ Merkleization
// =============================================================================

/// Merkleize an array of 32-byte chunks into a single root.
///
/// The number of chunks must be a power of 2. Pairs of chunks are
/// hashed together to form the next layer, repeated until the root is reached.
pub fn merkleize_chunks(chunks: &[Bytes32]) -> Bytes32 {
    assert!(
        chunks.len().is_power_of_two(),
        "chunks length must be power of 2, got {}",
        chunks.len()
    );

    if chunks.len() == 1 {
        return chunks[0];
    }

    let mut layer: Vec<Bytes32> = chunks.to_vec();
    while layer.len() > 1 {
        let mut next_layer = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next_layer.push(sha256_pair(&pair[0], &pair[1]));
        }
        layer = next_layer;
    }
    layer[0]
}

/// Compute the SSZ `hash_tree_root` of a `BeaconBlockHeader`.
///
/// `BeaconBlockHeader` is a container with 5 fields. Per SSZ spec, it is
/// Merkleized with `chunk_count = next_power_of_two(5) = 8` leaves:
///
/// ```text
/// leaves[0] = hash_tree_root(slot)            = le_bytes(slot) padded to 32
/// leaves[1] = hash_tree_root(proposer_index)  = le_bytes(proposer_index) padded to 32
/// leaves[2] = parent_root                     = already 32 bytes
/// leaves[3] = state_root                      = already 32 bytes
/// leaves[4] = body_root                       = already 32 bytes
/// leaves[5..7] = zero hashes                  = padding to power of 2
/// ```
pub fn beacon_header_root(header: &BeaconBlockHeader) -> Bytes32 {
    let leaves = [
        uint64_to_leaf(header.slot),
        uint64_to_leaf(header.proposer_index),
        header.parent_root,
        header.state_root,
        header.body_root,
        ZERO_HASH,
        ZERO_HASH,
        ZERO_HASH,
    ];
    merkleize_chunks(&leaves)
}

// =============================================================================
// Merkle Branch Verification
// =============================================================================

/// Verify an SSZ Merkle branch (generalized-index based).
///
/// This implements the `is_valid_merkle_branch` function from the Ethereum
/// consensus spec. Given a leaf, a branch of sibling hashes, a depth, a subtree
/// index, and the expected root, it recomputes the root from the leaf up and
/// checks that it matches.
///
/// # Arguments
/// * `leaf` — The leaf value to verify
/// * `branch` — Sibling hashes from leaf to root (`branch.len() >= depth`)
/// * `depth` — Depth of the Merkle proof (`floor(log2(generalized_index))`)
/// * `index` — Subtree index (`generalized_index % 2^depth`)
/// * `root` — Expected Merkle root to verify against
///
/// # Returns
/// `true` if the branch is valid
pub fn is_valid_merkle_branch(
    leaf: &Bytes32,
    branch: &[Bytes32],
    depth: usize,
    index: usize,
    root: &Bytes32,
) -> bool {
    if branch.len() < depth {
        return false;
    }

    let mut computed = *leaf;
    for i in 0..depth {
        if (index >> i) & 1 == 0 {
            computed = sha256_pair(&computed, &branch[i]);
        } else {
            computed = sha256_pair(&branch[i], &computed);
        }
    }
    computed == *root
}

// =============================================================================
// Test Utilities
// =============================================================================

/// Build a mock Merkle branch for testing purposes.
///
/// Creates a valid branch from a leaf to a root, where all sibling nodes
/// are zero hashes. Returns `(branch, root)`.
///
/// # Arguments
/// * `leaf` — The leaf value
/// * `depth` — Depth of the proof
/// * `index` — Subtree index of the leaf
pub fn build_mock_merkle_branch(
    leaf: &Bytes32,
    depth: usize,
    index: usize,
) -> (Vec<Bytes32>, Bytes32) {
    let mut current = *leaf;
    let mut branch = Vec::with_capacity(depth);

    for i in 0..depth {
        let sibling = ZERO_HASH;
        branch.push(sibling);
        if (index >> i) & 1 == 0 {
            current = sha256_pair(&current, &sibling);
        } else {
            current = sha256_pair(&sibling, &current);
        }
    }
    (branch, current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_pair() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let result = sha256_pair(&a, &b);
        assert_ne!(result, ZERO_HASH);
        // Deterministic
        assert_eq!(result, sha256_pair(&a, &b));
        // Order matters
        assert_ne!(sha256_pair(&a, &b), sha256_pair(&b, &a));
    }

    #[test]
    fn test_uint64_to_leaf() {
        let leaf = uint64_to_leaf(42);
        assert_eq!(leaf[0], 42);
        assert_eq!(leaf[1..8], [0u8; 7]);
        assert_eq!(leaf[8..32], [0u8; 24]);
    }

    #[test]
    fn test_beacon_header_root_deterministic() {
        let header = BeaconBlockHeader {
            slot: 100,
            proposer_index: 5,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body_root: [3u8; 32],
        };
        let root1 = beacon_header_root(&header);
        let root2 = beacon_header_root(&header);
        assert_eq!(root1, root2);
        assert_ne!(root1, ZERO_HASH);
    }

    #[test]
    fn test_valid_merkle_branch() {
        let leaf = [42u8; 32];
        let depth = 6;
        let index = 41;
        let (branch, root) = build_mock_merkle_branch(&leaf, depth, index);
        assert!(is_valid_merkle_branch(&leaf, &branch, depth, index, &root));
    }

    #[test]
    fn test_invalid_merkle_branch_wrong_leaf() {
        let leaf = [42u8; 32];
        let wrong_leaf = [99u8; 32];
        let depth = 6;
        let index = 41;
        let (branch, root) = build_mock_merkle_branch(&leaf, depth, index);
        assert!(!is_valid_merkle_branch(
            &wrong_leaf, &branch, depth, index, &root
        ));
    }

    #[test]
    fn test_merkleize_single_chunk() {
        let chunks = [[7u8; 32]];
        assert_eq!(merkleize_chunks(&chunks), [7u8; 32]);
    }

    #[test]
    fn test_merkleize_two_chunks() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let chunks = [a, b];
        assert_eq!(merkleize_chunks(&chunks), sha256_pair(&a, &b));
    }
}
