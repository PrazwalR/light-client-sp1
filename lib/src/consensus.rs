//! Consensus verification logic for the Ethereum light client.
//!
//! Implements the core verification steps from the Ethereum light client spec:
//! - Sync committee participation counting & threshold checks
//! - Finality Merkle proof verification
//! - Sync committee rotation proof verification
//! - Domain & signing root computation (for BLS context)
//! - BLS aggregate signature verification (via bls module)

use crate::merkle::*;
use crate::types::*;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during light client update verification.
#[derive(Debug, Clone)]
pub enum VerificationError {
    /// Not enough sync committee members participated.
    InsufficientParticipation {
        got: usize,
        min: usize,
    },
    /// The finality Merkle proof is invalid.
    InvalidFinalityProof,
    /// The sync committee rotation Merkle proof is invalid.
    InvalidSyncCommitteeProof,
    /// `signature_slot` must be strictly greater than `attested_header.slot`.
    InvalidSignatureSlot,
    /// The attested header slot must be >= the finalized header slot.
    InvalidAttestedSlot,
    /// Sync committee bits vector has wrong length.
    InvalidSyncCommitteeBitsLength {
        got: usize,
        expected: usize,
    },
    /// BLS aggregate signature verification failed.
    BLSVerificationFailed,
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientParticipation { got, min } => {
                write!(f, "insufficient participation: got {got}, need >= {min}")
            }
            Self::InvalidFinalityProof => write!(f, "invalid finality Merkle proof"),
            Self::InvalidSyncCommitteeProof => {
                write!(f, "invalid sync committee rotation Merkle proof")
            }
            Self::InvalidSignatureSlot => {
                write!(f, "signature_slot must be > attested_header.slot")
            }
            Self::InvalidAttestedSlot => {
                write!(f, "attested_header.slot must be >= finalized_header.slot")
            }
            Self::InvalidSyncCommitteeBitsLength { got, expected } => {
                write!(
                    f,
                    "sync_committee_bits length mismatch: got {got}, expected {expected}"
                )
            }
            Self::BLSVerificationFailed => write!(f, "BLS signature verification failed"),
        }
    }
}

// =============================================================================
// Verification Result
// =============================================================================

/// The output of a successful light client update verification.
///
/// These values are committed as public values in the ZK proof.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Number of sync committee members that participated.
    pub participation: u32,
    /// `hash_tree_root` of the finalized header.
    pub finalized_header_root: Bytes32,
    /// Slot number of the finalized header.
    pub finalized_slot: u64,
    /// Beacon state root from the finalized header.
    pub finalized_state_root: Bytes32,
    /// Hash of the current sync committee.
    pub current_sync_committee_hash: Bytes32,
    /// Hash of the next sync committee (zero if no rotation).
    pub next_sync_committee_hash: Bytes32,
    /// Whether a sync committee rotation was included.
    pub has_sync_committee_update: bool,
    /// Whether finality was proven.
    pub has_finality: bool,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Count the number of `true` bits in the sync committee participation bitvector.
pub fn count_participation(sync_committee_bits: &[bool]) -> usize {
    sync_committee_bits.iter().filter(|&&b| b).count()
}

/// Compute the sync committee period for a given slot.
pub fn compute_sync_committee_period(slot: u64) -> u64 {
    slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD
}

/// Compute the epoch for a given slot.
pub fn compute_epoch(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

/// Check if participation meets the safety (supermajority) threshold.
///
/// Returns `true` if `participation >= SYNC_COMMITTEE_SIZE * 2 / 3`.
pub fn has_supermajority(participation: usize) -> bool {
    participation * SUPERMAJORITY_THRESHOLD_DENOMINATOR
        >= SYNC_COMMITTEE_SIZE * SUPERMAJORITY_THRESHOLD_NUMERATOR
}

// =============================================================================
// Domain & Signing Root Computation
// =============================================================================

/// Compute the signing domain.
///
/// ```text
/// domain = domain_type ++ fork_data_root[0..28]
/// ```
///
/// Where `fork_data_root = hash_tree_root(ForkData(fork_version, genesis_validators_root))`.
pub fn compute_domain(
    domain_type: &[u8; 4],
    fork_version: &[u8; 4],
    genesis_validators_root: &Bytes32,
) -> Bytes32 {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[0..4].copy_from_slice(domain_type);
    domain[4..32].copy_from_slice(&fork_data_root[0..28]);
    domain
}

/// Compute the fork data root.
///
/// ```text
/// hash_tree_root(ForkData { current_version, genesis_validators_root })
/// ```
///
/// ForkData has 2 fields → Merkleized with 2 leaves (already power of 2).
fn compute_fork_data_root(
    fork_version: &[u8; 4],
    genesis_validators_root: &Bytes32,
) -> Bytes32 {
    let mut version_leaf = [0u8; 32];
    version_leaf[0..4].copy_from_slice(fork_version);
    sha256_pair(&version_leaf, genesis_validators_root)
}

/// Compute the signing root for signature verification.
///
/// ```text
/// hash_tree_root(SigningData { object_root, domain })
/// ```
///
/// SigningData has 2 fields → Merkleized as `SHA256(object_root || domain)`.
pub fn compute_signing_root(header: &BeaconBlockHeader, domain: &Bytes32) -> Bytes32 {
    let header_root = beacon_header_root(header);
    sha256_pair(&header_root, domain)
}

// =============================================================================
// Main Verification Function
// =============================================================================

/// Verify a light client update.
///
/// Performs all verification steps of the Ethereum light client protocol:
///
/// 1. **Participation check** — Ensures enough sync committee members signed
/// 2. **Signature slot validation** — `signature_slot > attested_header.slot`
/// 3. **Attested header hashing** — Computes `hash_tree_root(attested_header)`
/// 4. **Finality verification** — If present, verifies the finality Merkle proof
/// 5. **Sync committee rotation** — If present, verifies the rotation Merkle proof
/// 6. **Domain & signing root** — Computes the signing context for BLS
/// 7. **BLS verification** — (STUB: Phase 2 will add BLS12-381 signature checking)
///
/// # Returns
/// `Ok(VerificationResult)` on success, `Err(VerificationError)` on failure.
pub fn verify_light_client_update(
    inputs: &ProofInputs,
) -> Result<VerificationResult, VerificationError> {
    let update = &inputs.update;

    // -------------------------------------------------------------------------
    // Step 1: Verify sync committee participation
    // -------------------------------------------------------------------------
    if update.sync_aggregate.sync_committee_bits.len() != SYNC_COMMITTEE_SIZE {
        return Err(VerificationError::InvalidSyncCommitteeBitsLength {
            got: update.sync_aggregate.sync_committee_bits.len(),
            expected: SYNC_COMMITTEE_SIZE,
        });
    }

    let participation = count_participation(&update.sync_aggregate.sync_committee_bits);
    if participation < MIN_SYNC_COMMITTEE_PARTICIPANTS {
        return Err(VerificationError::InsufficientParticipation {
            got: participation,
            min: MIN_SYNC_COMMITTEE_PARTICIPANTS,
        });
    }

    // Log supermajority status (informational — not a hard requirement for all updates)
    let _is_supermajority = has_supermajority(participation);

    // -------------------------------------------------------------------------
    // Step 2: Validate signature slot
    // -------------------------------------------------------------------------
    if update.signature_slot <= update.attested_header.slot {
        return Err(VerificationError::InvalidSignatureSlot);
    }

    // -------------------------------------------------------------------------
    // Step 3: Compute attested header root
    // -------------------------------------------------------------------------
    let _attested_header_root = beacon_header_root(&update.attested_header);

    // -------------------------------------------------------------------------
    // Step 4: Verify finality (if present)
    // -------------------------------------------------------------------------
    let (finalized_header_root, finalized_slot, finalized_state_root, has_finality) =
        if let Some(ref finality) = update.finality_update {
            // attested_header.slot must be >= finalized_header.slot
            if update.attested_header.slot < finality.finalized_header.slot {
                return Err(VerificationError::InvalidAttestedSlot);
            }

            // Compute hash_tree_root of the finalized header
            let fin_header_root = beacon_header_root(&finality.finalized_header);

            // Verify Merkle branch: finalized_header_root is at FINALIZED_ROOT_GINDEX
            // in the beacon state rooted at attested_header.state_root.
            // Use branch length as depth — this adapts across forks:
            //   Altair-Deneb: gindex=105, depth=6
            //   Electra-Fulu: gindex=169, depth=7
            // The subtree index (41) remains the same across all forks.
            let finality_depth = finality.finality_branch.len();
            if !is_valid_merkle_branch(
                &fin_header_root,
                &finality.finality_branch,
                finality_depth,
                FINALIZED_ROOT_SUBTREE_INDEX,
                &update.attested_header.state_root,
            ) {
                return Err(VerificationError::InvalidFinalityProof);
            }

            (
                fin_header_root,
                finality.finalized_header.slot,
                finality.finalized_header.state_root,
                true,
            )
        } else {
            // No finality update — use attested header as the "finalized" reference
            (
                _attested_header_root,
                update.attested_header.slot,
                update.attested_header.state_root,
                false,
            )
        };

    // -------------------------------------------------------------------------
    // Step 5: Verify sync committee rotation (if present)
    // -------------------------------------------------------------------------
    let (next_sync_committee_hash, has_sync_committee_update) =
        if let Some(ref sc_update) = update.sync_committee_update {
            // Verify Merkle branch: next_sync_committee_hash is at
            // NEXT_SYNC_COMMITTEE_GINDEX in the attested header's state.
            // Use branch length as depth — adapts across forks:
            //   Altair-Deneb: gindex=55, depth=5
            //   Electra-Fulu: gindex=87, depth=6
            let sc_depth = sc_update.next_sync_committee_branch.len();
            if !is_valid_merkle_branch(
                &sc_update.next_sync_committee_hash,
                &sc_update.next_sync_committee_branch,
                sc_depth,
                NEXT_SYNC_COMMITTEE_SUBTREE_INDEX,
                &update.attested_header.state_root,
            ) {
                return Err(VerificationError::InvalidSyncCommitteeProof);
            }

            (sc_update.next_sync_committee_hash, true)
        } else {
            ([0u8; 32], false)
        };

    // -------------------------------------------------------------------------
    // Step 6: Compute domain and signing root (for BLS context)
    // -------------------------------------------------------------------------
    let domain = compute_domain(
        &DOMAIN_SYNC_COMMITTEE,
        &inputs.fork_version,
        &inputs.genesis_validators_root,
    );
    let _signing_root = compute_signing_root(&update.attested_header, &domain);

    // -------------------------------------------------------------------------
    // Step 7: BLS signature verification
    // -------------------------------------------------------------------------
    // If sync committee pubkeys are provided, perform full BLS12-381 aggregate
    // signature verification. Otherwise, skip BLS (development/testing mode).
    #[cfg(feature = "bls")]
    if let Some(ref sc_data) = inputs.sync_committee {
        use crate::bls;

        let signing_root = _signing_root;

        // 7a. Verify the sync committee pubkeys hash to the committed committee hash.
        // This ensures the pubkeys we use for BLS verification are authentic
        // (they match the committee committed in the beacon state).
        let mut agg_pk_bytes = [0u8; BYTES_PER_PUBKEY];
        if sc_data.aggregate_pubkey.len() != BYTES_PER_PUBKEY {
            return Err(VerificationError::BLSVerificationFailed);
        }
        agg_pk_bytes.copy_from_slice(&sc_data.aggregate_pubkey);

        let computed_sc_hash =
            bls::compute_sync_committee_hash(&sc_data.pubkeys, &agg_pk_bytes);

        if computed_sc_hash != inputs.current_sync_committee_hash {
            return Err(VerificationError::BLSVerificationFailed);
        }

        // 7b. Verify the aggregate BLS signature.
        // Filter participating pubkeys, aggregate them, hash the signing root
        // to G2, and perform the pairing check.
        bls::verify_sync_committee_signature(
            &sc_data.pubkeys,
            &update.sync_aggregate.sync_committee_bits,
            &signing_root,
            &update.sync_aggregate.sync_committee_signature,
        )
        .map_err(|_| VerificationError::BLSVerificationFailed)?;
    }

    // -------------------------------------------------------------------------
    // Result
    // -------------------------------------------------------------------------
    Ok(VerificationResult {
        participation: participation as u32,
        finalized_header_root,
        finalized_slot,
        finalized_state_root,
        current_sync_committee_hash: inputs.current_sync_committee_hash,
        next_sync_committee_hash,
        has_sync_committee_update,
        has_finality,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::build_mock_merkle_branch;

    fn create_test_inputs() -> ProofInputs {
        // Create a finalized header
        let finalized_header = BeaconBlockHeader {
            slot: 1000,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body_root: [3u8; 32],
        };

        // Compute its hash_tree_root
        let fin_root = beacon_header_root(&finalized_header);

        // Build a valid Merkle branch for the finality proof
        let (finality_branch, state_root) = build_mock_merkle_branch(
            &fin_root,
            FINALIZED_ROOT_DEPTH,
            FINALIZED_ROOT_SUBTREE_INDEX,
        );

        // Create the attested header with the computed state root
        let attested_header = BeaconBlockHeader {
            slot: 1032,
            proposer_index: 55,
            parent_root: [4u8; 32],
            state_root,
            body_root: [5u8; 32],
        };

        ProofInputs {
            update: LightClientUpdate {
                attested_header,
                sync_aggregate: SyncAggregate {
                    sync_committee_bits: vec![true; SYNC_COMMITTEE_SIZE],
                    sync_committee_signature: vec![0u8; BYTES_PER_SIGNATURE],
                },
                signature_slot: 1033,
                finality_update: Some(FinalityUpdate {
                    finalized_header,
                    finality_branch,
                }),
                sync_committee_update: None,
            },
            current_sync_committee_hash: [7u8; 32],
            sync_committee: None, // No BLS verification in unit tests
            genesis_validators_root: [0u8; 32],
            genesis_time: 1655733600,
            fork_version: [0x90, 0x00, 0x00, 0x74],
            storage_proof: None,
            l2_storage_proof: None,
        }
    }

    #[test]
    fn test_verify_valid_update() {
        let inputs = create_test_inputs();
        let result = verify_light_client_update(&inputs);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.participation, SYNC_COMMITTEE_SIZE as u32);
        assert_eq!(r.finalized_slot, 1000);
        assert!(r.has_finality);
        assert!(!r.has_sync_committee_update);
    }

    #[test]
    fn test_insufficient_participation() {
        let mut inputs = create_test_inputs();
        inputs.update.sync_aggregate.sync_committee_bits = vec![false; SYNC_COMMITTEE_SIZE];
        let result = verify_light_client_update(&inputs);
        assert!(matches!(
            result,
            Err(VerificationError::InsufficientParticipation { .. })
        ));
    }

    #[test]
    fn test_invalid_signature_slot() {
        let mut inputs = create_test_inputs();
        inputs.update.signature_slot = inputs.update.attested_header.slot; // must be strictly >
        let result = verify_light_client_update(&inputs);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidSignatureSlot)
        ));
    }

    #[test]
    fn test_invalid_finality_branch() {
        let mut inputs = create_test_inputs();
        if let Some(ref mut fin) = inputs.update.finality_update {
            fin.finality_branch[0] = [0xFFu8; 32]; // corrupt the branch
        }
        let result = verify_light_client_update(&inputs);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidFinalityProof)
        ));
    }

    #[test]
    fn test_count_participation() {
        let bits = vec![true, false, true, true, false];
        assert_eq!(count_participation(&bits), 3);
    }

    #[test]
    fn test_has_supermajority() {
        assert!(has_supermajority(342)); // 342 >= 512 * 2/3 = 341.3
        assert!(!has_supermajority(341)); // 341 * 3 = 1023 < 1024
        assert!(has_supermajority(512)); // 100%
        assert!(!has_supermajority(0));
    }

    #[test]
    fn test_compute_sync_committee_period() {
        assert_eq!(compute_sync_committee_period(0), 0);
        assert_eq!(compute_sync_committee_period(8191), 0);
        assert_eq!(compute_sync_committee_period(8192), 1);
    }

    #[test]
    fn test_domain_computation_deterministic() {
        let domain_type = DOMAIN_SYNC_COMMITTEE;
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let genesis_root = [0xABu8; 32];

        let d1 = compute_domain(&domain_type, &fork_version, &genesis_root);
        let d2 = compute_domain(&domain_type, &fork_version, &genesis_root);
        assert_eq!(d1, d2);
        assert_eq!(&d1[0..4], &domain_type);
    }
}
