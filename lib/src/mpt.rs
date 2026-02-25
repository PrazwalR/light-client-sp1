//! Merkle Patricia Trie (MPT) proof verification and RLP decoding.
//!
//! Implements verification of Ethereum state/storage proofs (EIP-1186):
//! - RLP decoding of trie nodes and account state
//! - MPT branch/extension/leaf node traversal
//! - Keccak256-based trie hashing
//!
//! This module runs inside the SP1 zkVM and uses the SP1-patched `tiny-keccak`
//! crate for accelerated keccak256 computation.

use crate::types::Bytes32;
use tiny_keccak::{Hasher, Keccak};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during MPT proof verification or RLP decoding.
#[derive(Debug, Clone)]
pub enum MPTError {
    /// The proof is empty.
    EmptyProof,
    /// A proof node hash does not match the expected hash.
    InvalidNodeHash { depth: usize },
    /// RLP data is malformed or truncated.
    InvalidRLP,
    /// An unexpected node type was encountered in the trie.
    UnexpectedNodeType { depth: usize, items: usize },
    /// The nibble path in an extension/leaf node doesn't match the key.
    NibbleMismatch { depth: usize },
    /// The proof terminates at a branch node but the value is empty.
    EmptyValueAtBranch,
    /// Account RLP does not contain exactly 4 items.
    InvalidAccountRLP { items: usize },
    /// Key exhausted before reaching a leaf.
    IncompleteProof,
}

impl core::fmt::Display for MPTError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyProof => write!(f, "empty proof"),
            Self::InvalidNodeHash { depth } => {
                write!(f, "invalid node hash at depth {depth}")
            }
            Self::InvalidRLP => write!(f, "invalid RLP encoding"),
            Self::UnexpectedNodeType { depth, items } => {
                write!(f, "unexpected node type at depth {depth}: {items} items")
            }
            Self::NibbleMismatch { depth } => {
                write!(f, "nibble mismatch at depth {depth}")
            }
            Self::EmptyValueAtBranch => write!(f, "empty value at branch node"),
            Self::InvalidAccountRLP { items } => {
                write!(f, "account RLP has {items} items, expected 4")
            }
            Self::IncompleteProof => write!(f, "proof incomplete, key not fully consumed"),
        }
    }
}

// =============================================================================
// Keccak256
// =============================================================================

/// Compute keccak256 hash of input data.
pub fn keccak256(data: &[u8]) -> Bytes32 {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

// =============================================================================
// RLP Decoding
// =============================================================================

/// Decoded RLP item — either a single byte string or a list of items.
#[derive(Debug, Clone)]
pub enum RLPItem<'a> {
    /// A single byte string (can be empty).
    Bytes(&'a [u8]),
    /// A list of RLP items.
    List(Vec<RLPItem<'a>>),
}

/// Decode the length and offset of an RLP item at the given position.
///
/// Returns `(data_offset, data_length, total_consumed)`.
fn rlp_decode_length(data: &[u8]) -> Result<(usize, usize, usize), MPTError> {
    if data.is_empty() {
        return Err(MPTError::InvalidRLP);
    }

    let prefix = data[0];

    if prefix < 0x80 {
        // Single byte: the byte itself is the data.
        Ok((0, 1, 1))
    } else if prefix <= 0xb7 {
        // Short string: 0-55 bytes. Length = prefix - 0x80.
        let len = (prefix - 0x80) as usize;
        Ok((1, len, 1 + len))
    } else if prefix <= 0xbf {
        // Long string: length of length = prefix - 0xb7.
        let len_of_len = (prefix - 0xb7) as usize;
        if data.len() < 1 + len_of_len {
            return Err(MPTError::InvalidRLP);
        }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((1 + len_of_len, len, 1 + len_of_len + len))
    } else if prefix <= 0xf7 {
        // Short list: total payload length = prefix - 0xc0.
        let len = (prefix - 0xc0) as usize;
        Ok((1, len, 1 + len))
    } else {
        // Long list: length of length = prefix - 0xf7.
        let len_of_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_of_len {
            return Err(MPTError::InvalidRLP);
        }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((1 + len_of_len, len, 1 + len_of_len + len))
    }
}

/// Decode an RLP item from raw bytes.
pub fn rlp_decode(data: &[u8]) -> Result<RLPItem<'_>, MPTError> {
    if data.is_empty() {
        return Ok(RLPItem::Bytes(&[]));
    }

    let prefix = data[0];

    if prefix < 0xc0 {
        // It's a byte string.
        let (offset, len, _total) = rlp_decode_length(data)?;
        if data.len() < offset + len {
            return Err(MPTError::InvalidRLP);
        }
        Ok(RLPItem::Bytes(&data[offset..offset + len]))
    } else {
        // It's a list.
        let (offset, payload_len, _total) = rlp_decode_length(data)?;
        if data.len() < offset + payload_len {
            return Err(MPTError::InvalidRLP);
        }
        let payload = &data[offset..offset + payload_len];
        let mut items = Vec::new();
        let mut pos = 0;
        while pos < payload.len() {
            let (_inner_off, _inner_len, consumed) = rlp_decode_length(&payload[pos..])?;
            let item = rlp_decode(&payload[pos..pos + consumed])?;
            items.push(item);
            pos += consumed;
        }
        Ok(RLPItem::List(items))
    }
}

/// Decode a list of RLP items from raw bytes. Returns the items in the list.
pub fn rlp_decode_list(data: &[u8]) -> Result<Vec<RLPItem<'_>>, MPTError> {
    match rlp_decode(data)? {
        RLPItem::List(items) => Ok(items),
        RLPItem::Bytes(_) => Err(MPTError::InvalidRLP),
    }
}

/// Extract bytes from an RLP item.
pub fn rlp_as_bytes<'a>(item: &RLPItem<'a>) -> Result<&'a [u8], MPTError> {
    match item {
        RLPItem::Bytes(b) => Ok(b),
        RLPItem::List(_) => Err(MPTError::InvalidRLP),
    }
}

/// Decode a u64 from an RLP-encoded byte string.
pub fn rlp_to_u64(data: &[u8]) -> u64 {
    if data.is_empty() {
        return 0;
    }
    let mut result = 0u64;
    for &b in data {
        result = (result << 8) | (b as u64);
    }
    result
}

// =============================================================================
// Nibble Helpers (Hex-Prefix Encoding)
// =============================================================================

/// Convert a byte slice to nibbles (half-bytes).
pub fn bytes_to_nibbles(data: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    nibbles
}

/// Decode a Hex-Prefix (HP) encoded path.
///
/// Returns `(nibbles, is_leaf)`.
///
/// HP encoding:
/// - First nibble flags: bit 1 = odd length, bit 0 = leaf
/// - If even length, a padding 0 nibble follows the flag nibble
pub fn decode_hp_path(data: &[u8]) -> Result<(Vec<u8>, bool), MPTError> {
    if data.is_empty() {
        return Ok((Vec::new(), false));
    }

    let first_nibble = data[0] >> 4;
    let is_leaf = first_nibble >= 2;
    let is_odd = (first_nibble & 1) == 1;

    let nibbles = if is_odd {
        // Odd: first byte's lower nibble is the start of the path.
        let mut n = Vec::with_capacity(data.len() * 2 - 1);
        n.push(data[0] & 0x0f);
        for &b in &data[1..] {
            n.push(b >> 4);
            n.push(b & 0x0f);
        }
        n
    } else {
        // Even: skip the first byte entirely (flag + padding nibble).
        let mut n = Vec::with_capacity((data.len() - 1) * 2);
        for &b in &data[1..] {
            n.push(b >> 4);
            n.push(b & 0x0f);
        }
        n
    };

    Ok((nibbles, is_leaf))
}

// =============================================================================
// Account State Decoding
// =============================================================================

/// Ethereum account state (the 4 fields stored in the state trie leaf).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountState {
    /// Transaction count.
    pub nonce: u64,
    /// Balance in wei (big-endian, up to 32 bytes).
    pub balance: Vec<u8>,
    /// Root of the account's storage trie.
    pub storage_root: Bytes32,
    /// Keccak256 hash of the account's EVM bytecode.
    pub code_hash: Bytes32,
}

/// RLP-decode an Ethereum account: `RLP([nonce, balance, storageRoot, codeHash])`.
pub fn rlp_decode_account(data: &[u8]) -> Result<AccountState, MPTError> {
    let items = rlp_decode_list(data)?;
    if items.len() != 4 {
        return Err(MPTError::InvalidAccountRLP { items: items.len() });
    }

    let nonce_bytes = rlp_as_bytes(&items[0])?;
    let balance_bytes = rlp_as_bytes(&items[1])?;
    let storage_root_bytes = rlp_as_bytes(&items[2])?;
    let code_hash_bytes = rlp_as_bytes(&items[3])?;

    let nonce = rlp_to_u64(nonce_bytes);

    let mut storage_root = [0u8; 32];
    if storage_root_bytes.len() == 32 {
        storage_root.copy_from_slice(storage_root_bytes);
    } else {
        return Err(MPTError::InvalidRLP);
    }

    let mut code_hash = [0u8; 32];
    if code_hash_bytes.len() == 32 {
        code_hash.copy_from_slice(code_hash_bytes);
    } else {
        return Err(MPTError::InvalidRLP);
    }

    Ok(AccountState {
        nonce,
        balance: balance_bytes.to_vec(),
        storage_root,
        code_hash,
    })
}

// =============================================================================
// MPT Proof Verification
// =============================================================================

/// Verify a Merkle Patricia Trie proof and return the proven leaf value.
///
/// # Arguments
/// * `key` — The full key (will be keccak256-hashed to get the trie path for
///   account proofs; for storage proofs, pass the already-hashed key).
/// * `proof` — Vec of RLP-encoded trie nodes from root to leaf.
/// * `root` — The expected trie root hash.
/// * `key_is_hashed` — If true, `key` is already keccak256-hashed (storage keys).
///
/// # Returns
/// The RLP-encoded leaf value, or empty vec if the key doesn't exist.
pub fn verify_mpt_proof(
    key: &[u8],
    proof: &[Vec<u8>],
    root: &Bytes32,
    key_is_hashed: bool,
) -> Result<Vec<u8>, MPTError> {
    if proof.is_empty() {
        return Err(MPTError::EmptyProof);
    }

    // Compute the trie path (nibbles of the keccak256 hash).
    let key_hash = if key_is_hashed {
        let mut h = [0u8; 32];
        h.copy_from_slice(&key[..32]);
        h
    } else {
        keccak256(key)
    };
    let path = bytes_to_nibbles(&key_hash);
    let mut path_offset = 0;

    let mut expected_hash = *root;

    for (depth, node_rlp) in proof.iter().enumerate() {
        // Verify node hash matches expected.
        // Exception: if the RLP is < 32 bytes, it's embedded inline (no hash check).
        if node_rlp.len() >= 32 {
            let node_hash = keccak256(node_rlp);
            if node_hash != expected_hash {
                return Err(MPTError::InvalidNodeHash { depth });
            }
        }

        // Decode the node.
        let items = rlp_decode_list(node_rlp)?;

        match items.len() {
            17 => {
                // Branch node: 16 children + value.
                if path_offset >= path.len() {
                    // We've consumed the entire key — the value is at items[16].
                    let value = rlp_as_bytes(&items[16])?;
                    return Ok(value.to_vec());
                }

                let nibble = path[path_offset] as usize;
                path_offset += 1;

                let child = rlp_as_bytes(&items[nibble])?;
                if child.is_empty() {
                    // Key doesn't exist in this trie — return empty.
                    return Ok(Vec::new());
                }
                if child.len() == 32 {
                    expected_hash.copy_from_slice(child);
                } else {
                    // Embedded node — handled in the next iteration if needed.
                    // For short nodes, hash them.
                    expected_hash = keccak256(child);
                }
            }
            2 => {
                // Extension or Leaf node.
                let encoded_path = rlp_as_bytes(&items[0])?;
                let (node_nibbles, is_leaf) = decode_hp_path(encoded_path)?;

                // Check that the nibbles match our remaining key path.
                if path_offset + node_nibbles.len() > path.len() {
                    return Err(MPTError::NibbleMismatch { depth });
                }
                for (i, &nibble) in node_nibbles.iter().enumerate() {
                    if path[path_offset + i] != nibble {
                        // Key diverges — doesn't exist.
                        return Ok(Vec::new());
                    }
                }
                path_offset += node_nibbles.len();

                if is_leaf {
                    // Leaf node — items[1] is the RLP-encoded value.
                    let value = rlp_as_bytes(&items[1])?;
                    return Ok(value.to_vec());
                } else {
                    // Extension node — items[1] is the next node hash.
                    let next = rlp_as_bytes(&items[1])?;
                    if next.len() == 32 {
                        expected_hash.copy_from_slice(next);
                    } else {
                        expected_hash = keccak256(next);
                    }
                }
            }
            _ => {
                return Err(MPTError::UnexpectedNodeType {
                    depth,
                    items: items.len(),
                });
            }
        }
    }

    Err(MPTError::IncompleteProof)
}

// =============================================================================
// High-Level Proof Verification
// =============================================================================

/// Verify an account proof against an execution state root.
///
/// # Arguments
/// * `address` — 20-byte Ethereum address.
/// * `proof_nodes` — RLP-encoded MPT proof nodes.
/// * `state_root` — The execution layer (EL) state root.
///
/// # Returns
/// The decoded `AccountState` if the account exists.
pub fn verify_account_proof(
    address: &[u8; 20],
    proof_nodes: &[Vec<u8>],
    state_root: &Bytes32,
) -> Result<AccountState, MPTError> {
    // Account trie key = keccak256(address)
    let leaf_rlp = verify_mpt_proof(address, proof_nodes, state_root, false)?;

    if leaf_rlp.is_empty() {
        // Account doesn't exist — return empty account.
        return Ok(AccountState {
            nonce: 0,
            balance: Vec::new(),
            storage_root: [0u8; 32], // Empty trie root
            code_hash: keccak256(&[]),
        });
    }

    rlp_decode_account(&leaf_rlp)
}

/// Verify a storage proof against an account's storage root.
///
/// # Arguments
/// * `slot` — 32-byte storage slot key.
/// * `proof_nodes` — RLP-encoded MPT proof nodes.
/// * `storage_root` — The account's storage trie root.
///
/// # Returns
/// The 32-byte storage value (big-endian, zero-padded).
pub fn verify_storage_proof(
    slot: &Bytes32,
    proof_nodes: &[Vec<u8>],
    storage_root: &Bytes32,
) -> Result<Bytes32, MPTError> {
    // Storage trie key = keccak256(slot)
    let key_hash = keccak256(slot);
    let leaf_rlp = verify_mpt_proof(&key_hash, proof_nodes, storage_root, true)?;

    if leaf_rlp.is_empty() {
        return Ok([0u8; 32]);
    }

    // The value is RLP-encoded. Decode the bytes.
    let item = rlp_decode(&leaf_rlp)?;
    let value_bytes = rlp_as_bytes(&item)?;

    // Left-pad to 32 bytes (big-endian).
    let mut result = [0u8; 32];
    if value_bytes.len() <= 32 {
        let start = 32 - value_bytes.len();
        result[start..].copy_from_slice(value_bytes);
    } else {
        return Err(MPTError::InvalidRLP);
    }

    Ok(result)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256() {
        let result = keccak256(b"");
        assert_eq!(
            hex::encode(result),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );

        let result = keccak256(b"hello");
        assert_eq!(
            hex::encode(result),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_rlp_decode_single_byte() {
        // Single byte < 0x80 is self-encoding.
        let data = [0x42];
        let item = rlp_decode(&data).unwrap();
        let bytes = rlp_as_bytes(&item).unwrap();
        assert_eq!(bytes, &[0x42]);
    }

    #[test]
    fn test_rlp_decode_short_string() {
        // 0x83 followed by 3 bytes = string "dog".
        let data = [0x83, b'd', b'o', b'g'];
        let item = rlp_decode(&data).unwrap();
        let bytes = rlp_as_bytes(&item).unwrap();
        assert_eq!(bytes, b"dog");
    }

    #[test]
    fn test_rlp_decode_empty_string() {
        let data = [0x80];
        let item = rlp_decode(&data).unwrap();
        let bytes = rlp_as_bytes(&item).unwrap();
        assert_eq!(bytes, &[]);
    }

    #[test]
    fn test_rlp_decode_list() {
        // RLP encoding of ["cat", "dog"]
        // 0xc8 = list, total payload length 8
        // 0x83 "cat" 0x83 "dog"
        let data = [0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
        let items = rlp_decode_list(&data).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(rlp_as_bytes(&items[0]).unwrap(), b"cat");
        assert_eq!(rlp_as_bytes(&items[1]).unwrap(), b"dog");
    }

    #[test]
    fn test_rlp_decode_empty_list() {
        let data = [0xc0];
        let items = rlp_decode_list(&data).unwrap();
        assert_eq!(items.len(), 0);
    }

    #[test]
    fn test_bytes_to_nibbles() {
        let nibbles = bytes_to_nibbles(&[0xab, 0xcd]);
        assert_eq!(nibbles, vec![0xa, 0xb, 0xc, 0xd]);
    }

    #[test]
    fn test_hp_decode_leaf_even() {
        // HP-encoded leaf with even path: prefix 0x20, then path bytes.
        let data = [0x20, 0xab, 0xcd];
        let (nibbles, is_leaf) = decode_hp_path(&data).unwrap();
        assert!(is_leaf);
        assert_eq!(nibbles, vec![0xa, 0xb, 0xc, 0xd]);
    }

    #[test]
    fn test_hp_decode_extension_odd() {
        // HP-encoded extension with odd path: prefix 0x1n where n is first nibble.
        let data = [0x1a, 0xbc];
        let (nibbles, is_leaf) = decode_hp_path(&data).unwrap();
        assert!(!is_leaf);
        assert_eq!(nibbles, vec![0xa, 0xb, 0xc]);
    }

    #[test]
    fn test_hp_decode_leaf_odd() {
        // HP-encoded leaf with odd path: prefix 0x3n where n is first nibble.
        let data = [0x3f, 0xab];
        let (nibbles, is_leaf) = decode_hp_path(&data).unwrap();
        assert!(is_leaf);
        assert_eq!(nibbles, vec![0xf, 0xa, 0xb]);
    }

    #[test]
    fn test_rlp_decode_account() {
        // Build a minimal account RLP: [nonce=1, balance=0x100, storageRoot=32bytes, codeHash=32bytes]
        let nonce = vec![0x01]; // RLP: 0x01
        let balance = vec![0x82, 0x01, 0x00]; // RLP: short string 2 bytes = 0x0100
        let storage_root_bytes = [0xAA; 32];
        let code_hash_bytes = [0xBB; 32];

        // Encode storage root: 0xa0 + 32 bytes
        let mut sr = vec![0xa0];
        sr.extend_from_slice(&storage_root_bytes);
        // Encode code hash: 0xa0 + 32 bytes
        let mut ch = vec![0xa0];
        ch.extend_from_slice(&code_hash_bytes);

        // Total payload: 1 + 3 + 33 + 33 = 70 bytes
        let payload_len = nonce.len() + balance.len() + sr.len() + ch.len();
        let mut data = vec![0xf8, payload_len as u8]; // long list (payload > 55)
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&balance);
        data.extend_from_slice(&sr);
        data.extend_from_slice(&ch);

        let account = rlp_decode_account(&data).unwrap();
        assert_eq!(account.nonce, 1);
        assert_eq!(account.balance, vec![0x01, 0x00]);
        assert_eq!(account.storage_root, [0xAA; 32]);
        assert_eq!(account.code_hash, [0xBB; 32]);
    }

    #[test]
    fn test_rlp_to_u64() {
        assert_eq!(rlp_to_u64(&[]), 0);
        assert_eq!(rlp_to_u64(&[0x01]), 1);
        assert_eq!(rlp_to_u64(&[0x01, 0x00]), 256);
        assert_eq!(rlp_to_u64(&[0xff]), 255);
    }
}
