//! BLS12-381 aggregate signature verification for Ethereum sync committees.
//!
//! Implements the BLS signature scheme used by Ethereum's beacon chain:
//! - Aggregate pubkey computation from participating sync committee members
//! - Hash-to-curve (signing root → G2 point) using the Ethereum DST
//! - Pairing-based aggregate signature verification
//!
//! Uses the SP1-patched `bls12_381` crate for precompile-accelerated
//! field arithmetic when running inside the zkVM.

use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective,
};
use group::Group;

use crate::types::{Bytes32, BYTES_PER_PUBKEY, BYTES_PER_SIGNATURE, SYNC_COMMITTEE_SIZE};

// =============================================================================
// Constants
// =============================================================================

/// Domain Separation Tag for Ethereum BLS signatures.
///
/// From the Ethereum 2.0 spec: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
pub const ETH2_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// =============================================================================
// Error Types
// =============================================================================

/// Errors during BLS verification.
#[derive(Debug, Clone)]
pub enum BLSError {
    /// A pubkey could not be decompressed from its 48-byte compressed form.
    InvalidPubkey(usize),
    /// The signature could not be decompressed from its 96-byte compressed form.
    InvalidSignature,
    /// The aggregate signature verification (pairing check) failed.
    PairingCheckFailed,
    /// The pubkeys data has wrong length.
    InvalidPubkeysLength { got: usize, expected: usize },
    /// The signature data has wrong length.
    InvalidSignatureLength { got: usize, expected: usize },
    /// No participants (can't form an aggregate).
    NoParticipants,
}

impl core::fmt::Display for BLSError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPubkey(idx) => write!(f, "invalid pubkey at index {idx}"),
            Self::InvalidSignature => write!(f, "invalid BLS signature"),
            Self::PairingCheckFailed => write!(f, "BLS pairing check failed"),
            Self::InvalidPubkeysLength { got, expected } => {
                write!(f, "pubkeys length {got}, expected {expected}")
            }
            Self::InvalidSignatureLength { got, expected } => {
                write!(f, "signature length {got}, expected {expected}")
            }
            Self::NoParticipants => write!(f, "no sync committee participants"),
        }
    }
}

// =============================================================================
// Point Decompression
// =============================================================================

/// Decompress a 48-byte compressed G1 point (BLS pubkey).
pub fn decompress_pubkey(compressed: &[u8; BYTES_PER_PUBKEY]) -> Option<G1Affine> {
    Option::from(G1Affine::from_compressed(compressed))
}

/// Decompress a 96-byte compressed G2 point (BLS signature).
pub fn decompress_signature(compressed: &[u8; BYTES_PER_SIGNATURE]) -> Option<G2Affine> {
    Option::from(G2Affine::from_compressed(compressed))
}

// =============================================================================
// Pubkey Aggregation
// =============================================================================

/// Aggregate participating sync committee pubkeys.
///
/// Filters pubkeys by the participation bitvector, decompresses each
/// participating pubkey, and sums them to produce the aggregate pubkey.
///
/// # Arguments
/// * `pubkeys_flat` — Flat concatenation of 512 compressed pubkeys (512 × 48 bytes)
/// * `bits` — Participation bitvector (512 bools)
///
/// # Returns
/// The aggregate G1 point of all participating pubkeys.
pub fn aggregate_participating_pubkeys(
    pubkeys_flat: &[u8],
    bits: &[bool],
) -> Result<G1Projective, BLSError> {
    let expected_len = SYNC_COMMITTEE_SIZE * BYTES_PER_PUBKEY;
    if pubkeys_flat.len() != expected_len {
        return Err(BLSError::InvalidPubkeysLength {
            got: pubkeys_flat.len(),
            expected: expected_len,
        });
    }
    if bits.len() != SYNC_COMMITTEE_SIZE {
        return Err(BLSError::InvalidPubkeysLength {
            got: bits.len(),
            expected: SYNC_COMMITTEE_SIZE,
        });
    }

    let mut aggregate = G1Projective::identity();
    let mut has_participant = false;

    for (i, participated) in bits.iter().enumerate() {
        if !participated {
            continue;
        }

        let start = i * BYTES_PER_PUBKEY;
        let end = start + BYTES_PER_PUBKEY;
        let mut pk_bytes = [0u8; BYTES_PER_PUBKEY];
        pk_bytes.copy_from_slice(&pubkeys_flat[start..end]);

        let pubkey = decompress_pubkey(&pk_bytes)
            .ok_or(BLSError::InvalidPubkey(i))?;

        aggregate += G1Projective::from(pubkey);
        has_participant = true;
    }

    if !has_participant {
        return Err(BLSError::NoParticipants);
    }

    Ok(aggregate)
}

// =============================================================================
// Hash-to-Curve
// =============================================================================

/// Hash the signing root to a G2 point using the Ethereum BLS DST.
///
/// Uses the hash_to_curve algorithm: SHA-256 XMD + SSWU map.
pub fn hash_signing_root_to_g2(signing_root: &Bytes32) -> G2Projective {
    use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        [signing_root.as_ref()],
        ETH2_BLS_DST,
    )
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Verify a BLS aggregate signature using the pairing check.
///
/// Verifies: `e(aggregate_pubkey, H(signing_root)) == e(G1::generator, signature)`
///
/// This is equivalent to checking:
/// `e(aggregate_pubkey, H(msg)) · e(-G1::generator, signature) == 1`
///
/// # Arguments
/// * `aggregate_pk` — The aggregate public key (sum of participating pubkeys)
/// * `signing_root` — The message that was signed (32 bytes)
/// * `signature_bytes` — The compressed aggregate signature (96 bytes)
pub fn verify_aggregate_signature(
    aggregate_pk: &G1Projective,
    signing_root: &Bytes32,
    signature_bytes: &[u8],
) -> Result<(), BLSError> {
    if signature_bytes.len() != BYTES_PER_SIGNATURE {
        return Err(BLSError::InvalidSignatureLength {
            got: signature_bytes.len(),
            expected: BYTES_PER_SIGNATURE,
        });
    }

    // Decompress the signature
    let mut sig_bytes = [0u8; BYTES_PER_SIGNATURE];
    sig_bytes.copy_from_slice(signature_bytes);
    let signature = decompress_signature(&sig_bytes)
        .ok_or(BLSError::InvalidSignature)?;

    // Hash the signing root to G2
    let msg_point = hash_signing_root_to_g2(signing_root);
    let msg_point_affine = G2Affine::from(msg_point);

    // Convert aggregate pubkey to affine
    let agg_pk_affine = G1Affine::from(*aggregate_pk);

    // Negate G1 generator for the pairing check
    let neg_g1 = -G1Affine::generator();

    // Pairing check: e(agg_pk, H(msg)) · e(-G1, sig) == 1
    let result = multi_miller_loop(&[
        (&agg_pk_affine, &G2Prepared::from(msg_point_affine)),
        (&neg_g1, &G2Prepared::from(signature)),
    ])
    .final_exponentiation();

    if bool::from(result.is_identity()) {
        Ok(())
    } else {
        Err(BLSError::PairingCheckFailed)
    }
}

// =============================================================================
// High-Level Verification
// =============================================================================

/// Verify a sync committee aggregate BLS signature end-to-end.
///
/// This is the main entry point for BLS verification in the light client.
/// It performs:
/// 1. Aggregate participating pubkeys from the committee
/// 2. Hash the signing root to G2
/// 3. Verify the aggregate signature via pairing check
///
/// # Arguments
/// * `pubkeys_flat` — Flat concatenation of 512 compressed pubkeys
/// * `sync_committee_bits` — Participation bitvector (512 bools)
/// * `signing_root` — The signed message (32 bytes)
/// * `signature_bytes` — The compressed aggregate signature
pub fn verify_sync_committee_signature(
    pubkeys_flat: &[u8],
    sync_committee_bits: &[bool],
    signing_root: &Bytes32,
    signature_bytes: &[u8],
) -> Result<(), BLSError> {
    // Step 1: Aggregate participating pubkeys
    let aggregate_pk = aggregate_participating_pubkeys(pubkeys_flat, sync_committee_bits)?;

    // Step 2+3: Verify the aggregate signature
    verify_aggregate_signature(&aggregate_pk, signing_root, signature_bytes)
}

// =============================================================================
// Sync Committee SSZ Hashing
// =============================================================================

/// Compute the SSZ `hash_tree_root` of a SyncCommittee.
///
/// The SyncCommittee is a Container with two fields:
/// - `pubkeys: Vector[BLSPubkey, 512]`
/// - `aggregate_pubkey: BLSPubkey`
///
/// hash_tree_root(SyncCommittee) = SHA256(pubkeys_root || agg_pk_root)
///
/// Where:
/// - `pubkeys_root = Merkleize([hash_tree_root(pk) for pk in pubkeys])`
/// - `agg_pk_root = hash_tree_root(aggregate_pubkey)`
/// - `hash_tree_root(BLSPubkey)` = SHA256(pk[0:32] || pk[32:48]||zeros[16])
///
/// # Arguments
/// * `pubkeys_flat` — 512 compressed pubkeys (512 × 48 bytes)
/// * `aggregate_pubkey` — The aggregate pubkey (48 bytes)
pub fn compute_sync_committee_hash(
    pubkeys_flat: &[u8],
    aggregate_pubkey: &[u8; BYTES_PER_PUBKEY],
) -> Bytes32 {
    use crate::merkle::{merkleize_chunks, sha256_pair};

    // Hash each pubkey: SHA256(pk[0:32] || pk[32:48] ++ zeros[16])
    let mut pubkey_hashes = Vec::with_capacity(SYNC_COMMITTEE_SIZE);
    for i in 0..SYNC_COMMITTEE_SIZE {
        let start = i * BYTES_PER_PUBKEY;
        let pk = &pubkeys_flat[start..start + BYTES_PER_PUBKEY];

        let mut chunk0 = [0u8; 32];
        let mut chunk1 = [0u8; 32];
        chunk0.copy_from_slice(&pk[0..32]);
        chunk1[0..16].copy_from_slice(&pk[32..48]);
        // chunk1[16..32] remains zero (padding)

        pubkey_hashes.push(sha256_pair(&chunk0, &chunk1));
    }

    // Merkleize 512 pubkey hashes (512 is already a power of 2)
    let pubkeys_root = merkleize_chunks(&pubkey_hashes);

    // Hash the aggregate pubkey the same way
    let mut agg_chunk0 = [0u8; 32];
    let mut agg_chunk1 = [0u8; 32];
    agg_chunk0.copy_from_slice(&aggregate_pubkey[0..32]);
    agg_chunk1[0..16].copy_from_slice(&aggregate_pubkey[32..48]);
    let agg_pk_root = sha256_pair(&agg_chunk0, &agg_chunk1);

    // Container root = SHA256(pubkeys_root || agg_pk_root)
    sha256_pair(&pubkeys_root, &agg_pk_root)
}
