//! Light Client Store — persistent state for continuous syncing.
//!
//! Maintains the light client head (finalized slot, header root, state root,
//! current/next sync committee hashes) and persists to JSON between runs.
//! Also provides a sync loop that polls the beacon API for new updates,
//! and historical sync that walks through sync committee periods.

use crate::beacon_api::{BeaconClient, parse_bytes32};
use eth_lc_lib::types::Bytes32;
use serde::{Deserialize, Serialize};
use std::path::Path;

// =============================================================================
// Light Client Store
// =============================================================================

/// Persistent state for the light client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientStore {
    /// Network name (e.g., "mainnet", "sepolia").
    pub network: String,

    /// Latest finalized slot.
    pub finalized_slot: u64,

    /// hash_tree_root of the finalized beacon block header.
    pub finalized_header_root: Bytes32,

    /// Beacon state root from the finalized header.
    pub finalized_state_root: Bytes32,

    /// Hash of the current sync committee.
    pub current_sync_committee_hash: Bytes32,

    /// Hash of the next sync committee (zero if unknown).
    pub next_sync_committee_hash: Bytes32,

    /// Total number of updates processed.
    pub updates_processed: u64,

    /// Last time an update was applied (Unix timestamp).
    pub last_updated: u64,
}

impl LightClientStore {
    /// Create a new empty store for a given network.
    pub fn new(network: &str) -> Self {
        Self {
            network: network.to_string(),
            finalized_slot: 0,
            finalized_header_root: [0u8; 32],
            finalized_state_root: [0u8; 32],
            current_sync_committee_hash: [0u8; 32],
            next_sync_committee_hash: [0u8; 32],
            updates_processed: 0,
            last_updated: 0,
        }
    }

    /// Load from a JSON file, or create a new one if the file doesn't exist.
    pub fn load_or_create(path: &str, network: &str) -> Result<Self, String> {
        if Path::new(path).exists() {
            let data =
                std::fs::read_to_string(path).map_err(|e| format!("read store: {e}"))?;
            let store: Self =
                serde_json::from_str(&data).map_err(|e| format!("parse store: {e}"))?;
            if store.network != network {
                return Err(format!(
                    "store network mismatch: file={}, expected={network}",
                    store.network
                ));
            }
            Ok(store)
        } else {
            Ok(Self::new(network))
        }
    }

    /// Save state to a JSON file.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize store: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("write store: {e}"))?;
        Ok(())
    }

    /// Apply a verified finality update to the store.
    pub fn apply_finality_update(
        &mut self,
        finalized_slot: u64,
        finalized_header_root: Bytes32,
        finalized_state_root: Bytes32,
        current_sc_hash: Bytes32,
        next_sc_hash: Bytes32,
        participation: u32,
    ) -> Result<(), String> {
        // Sanity checks.
        if finalized_slot <= self.finalized_slot && self.finalized_slot != 0 {
            return Err(format!(
                "update slot {} <= current slot {}",
                finalized_slot, self.finalized_slot
            ));
        }
        if participation == 0 {
            return Err("zero participation".to_string());
        }

        // If we have a known next_sc_hash, the new update's current must match
        // (unless we're bootstrapping or on the same period).
        if self.next_sync_committee_hash != [0u8; 32]
            && current_sc_hash != self.current_sync_committee_hash
            && current_sc_hash != self.next_sync_committee_hash
        {
            return Err(format!(
                "sync committee mismatch: expected current={} or next={}, got={}",
                hex::encode(self.current_sync_committee_hash),
                hex::encode(self.next_sync_committee_hash),
                hex::encode(current_sc_hash)
            ));
        }

        self.finalized_slot = finalized_slot;
        self.finalized_header_root = finalized_header_root;
        self.finalized_state_root = finalized_state_root;
        self.current_sync_committee_hash = current_sc_hash;
        self.next_sync_committee_hash = next_sc_hash;
        self.updates_processed += 1;
        self.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(())
    }

    /// Current sync committee period.
    pub fn current_period(&self) -> u64 {
        if self.finalized_slot == 0 {
            return 0;
        }
        self.finalized_slot / (32 * 256) // SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD
    }

    /// Whether the store has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.finalized_slot > 0
    }

    /// Format a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "Network: {}\n\
             Finalized slot: {}\n\
             Period: {}\n\
             Header root: 0x{}\n\
             State root: 0x{}\n\
             Current SC hash: 0x{}\n\
             Next SC hash: 0x{}\n\
             Updates: {}\n\
             Last updated: {}",
            self.network,
            self.finalized_slot,
            self.current_period(),
            hex::encode(self.finalized_header_root),
            hex::encode(self.finalized_state_root),
            hex::encode(self.current_sync_committee_hash),
            hex::encode(self.next_sync_committee_hash),
            self.updates_processed,
            self.last_updated,
        )
    }
}

// =============================================================================
// Sync Loop
// =============================================================================

/// Configuration for the sync loop.
pub struct SyncConfig {
    /// Beacon API endpoint.
    pub beacon_url: String,
    /// Network name.
    pub network: String,
    /// Path to persist the store.
    pub store_path: String,
    /// Poll interval in seconds.
    pub poll_interval_secs: u64,
    /// Whether to enable BLS verification.
    pub verify_bls: bool,
    /// Whether to fetch full updates (with sync committee rotation).
    pub full_updates: bool,
    /// Maximum number of updates to process (0 = unlimited).
    pub max_updates: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            beacon_url: "https://lodestar-mainnet.chainsafe.io".to_string(),
            network: "mainnet".to_string(),
            store_path: "light_client_store.json".to_string(),
            poll_interval_secs: 384, // ~1 epoch (32 slots × 12 seconds)
            verify_bls: false,
            full_updates: false,
            max_updates: 0,
        }
    }
}

/// Result of a single sync step.
#[derive(Debug)]
pub enum SyncResult {
    /// A new finality update was applied.
    Updated {
        old_slot: u64,
        new_slot: u64,
        participation: u32,
    },
    /// No new finality update available (head hasn't advanced).
    NoUpdate,
    /// An error occurred during sync.
    Error(String),
}

/// Perform a single sync step: fetch latest finality update from beacon API
/// and apply it to the store if it advances the head.
///
/// Returns the sync result.
pub fn sync_step(
    store: &mut LightClientStore,
    config: &SyncConfig,
) -> SyncResult {
    // Fetch the latest finality update via BeaconClient.
    let beacon = BeaconClient::new(&config.beacon_url);
    let update = match beacon.get_finality_update() {
        Ok(u) => u,
        Err(e) => return SyncResult::Error(format!("fetch finality update: {e}")),
    };

    // Extract slot from the parsed finality update.
    let slot = update.finalized_header.beacon.slot
        .parse::<u64>()
        .unwrap_or(0);

    // Skip if not advancing.
    if slot <= store.finalized_slot && store.is_initialized() {
        return SyncResult::NoUpdate;
    }

    // Parse header root for the finalized header.
    let header_root = match parse_beacon_header_fields(&update.finalized_header.beacon) {
        Ok(r) => r,
        Err(e) => return SyncResult::Error(format!("parse header root: {e}")),
    };

    let state_root = match parse_bytes32(&update.finalized_header.beacon.state_root) {
        Ok(r) => r,
        Err(e) => return SyncResult::Error(format!("parse state root: {e}")),
    };

    // Count participation from sync aggregate bits.
    let participation = count_sync_bits(&update.sync_aggregate.sync_committee_bits);

    let old_slot = store.finalized_slot;

    // Apply the update.
    // For now, we carry forward SC hashes from the store (a full verification
    // would run the zkVM program). This lightweight mode tracks head progression.
    let current_sc = if store.current_sync_committee_hash == [0u8; 32] {
        // Bootstrap: set a placeholder.
        [0x01; 32]
    } else {
        store.current_sync_committee_hash
    };

    match store.apply_finality_update(
        slot,
        header_root,
        state_root,
        current_sc,
        store.next_sync_committee_hash,
        participation,
    ) {
        Ok(()) => {}
        Err(e) => return SyncResult::Error(format!("apply update: {e}")),
    }

    SyncResult::Updated {
        old_slot,
        new_slot: slot,
        participation,
    }
}

/// Run the sync loop: poll for updates, apply them, persist state.
///
/// This blocks the current thread. Use `max_updates` in config to limit iterations.
pub fn run_sync_loop(config: SyncConfig) -> Result<LightClientStore, String> {
    let mut store = LightClientStore::load_or_create(&config.store_path, &config.network)?;

    println!("=== Light Client Sync Loop ===");
    if store.is_initialized() {
        println!("Resuming from slot {}", store.finalized_slot);
    } else {
        println!("Starting fresh sync for {}", config.network);
    }

    let mut iterations = 0u64;
    loop {
        if config.max_updates > 0 && iterations >= config.max_updates {
            println!("Reached max updates ({}), stopping.", config.max_updates);
            break;
        }

        match sync_step(&mut store, &config) {
            SyncResult::Updated {
                old_slot,
                new_slot,
                participation,
            } => {
                println!(
                    "[update #{}] slot {} → {} (participation: {}/512)",
                    store.updates_processed, old_slot, new_slot, participation
                );
                // Persist after each successful update.
                store.save(&config.store_path)?;
                iterations += 1;
            }
            SyncResult::NoUpdate => {
                println!(
                    "[no update] head at slot {}, waiting {}s...",
                    store.finalized_slot, config.poll_interval_secs
                );
            }
            SyncResult::Error(e) => {
                eprintln!("[error] {e}");
            }
        }

        if config.max_updates > 0 && iterations >= config.max_updates {
            continue; // will break at top of loop
        }

        std::thread::sleep(std::time::Duration::from_secs(config.poll_interval_secs));
    }

    Ok(store)
}

// =============================================================================
// Historical Sync — Walk Through Sync Committee Periods
// =============================================================================

/// Configuration for historical sync.
pub struct HistoricalSyncConfig {
    /// Beacon API endpoint.
    pub beacon_url: String,
    /// Network name.
    pub network: String,
    /// Path to persist the store.
    pub store_path: String,
    /// Starting sync committee period (0 = auto-detect from bootstrap).
    pub start_period: u64,
    /// Ending sync committee period (0 = current period).
    pub end_period: u64,
    /// Number of updates to fetch per request (max usually 128).
    pub batch_size: u64,
}

impl Default for HistoricalSyncConfig {
    fn default() -> Self {
        Self {
            beacon_url: "https://lodestar-mainnet.chainsafe.io".to_string(),
            network: "mainnet".to_string(),
            store_path: "light_client_store.json".to_string(),
            start_period: 0,
            end_period: 0,
            batch_size: 1,
        }
    }
}

/// Result of a historical sync operation.
#[derive(Debug)]
pub struct HistoricalSyncResult {
    /// Number of periods synced.
    pub periods_synced: u64,
    /// Starting period.
    pub start_period: u64,
    /// Ending period.
    pub end_period: u64,
    /// Number of sync committee rotations observed.
    pub rotations: u64,
    /// Final finalized slot.
    pub final_slot: u64,
}

/// Run historical sync: walk through sync committee periods from start to end.
///
/// This fetches full light client updates (which include next_sync_committee)
/// for each period and applies them to the store, tracking sync committee
/// rotations along the way.
pub fn run_historical_sync(
    config: HistoricalSyncConfig,
) -> Result<HistoricalSyncResult, String> {
    let beacon = BeaconClient::new(&config.beacon_url);
    let mut store = LightClientStore::load_or_create(&config.store_path, &config.network)?;

    println!("=== Historical Sync: Walking Sync Committee Periods ===\n");

    // Determine current period from the beacon chain
    let finality_update = beacon.get_finality_update()
        .map_err(|e| format!("fetch finality: {e}"))?;
    let current_slot: u64 = finality_update.finalized_header.beacon.slot
        .parse()
        .map_err(|e| format!("parse slot: {e}"))?;
    let current_period = current_slot / (32 * 256); // SLOTS_PER_EPOCH * EPOCHS_PER_PERIOD
    println!("[*] Current chain period: {current_period} (slot {current_slot})");

    // Determine start period
    let start = if config.start_period > 0 {
        config.start_period
    } else if store.is_initialized() {
        store.current_period()
    } else {
        // Altair activation period (mainnet: 290, sepolia varies)
        match config.network.as_str() {
            "mainnet" => 290,
            "sepolia" => 23,
            _ => 0,
        }
    };

    // Determine end period
    let end = if config.end_period > 0 {
        config.end_period
    } else {
        current_period
    };

    if start > end {
        return Err(format!("start period ({start}) > end period ({end})"));
    }

    println!("[*] Syncing periods {start} → {end} ({} periods)\n", end - start + 1);

    let mut rotations = 0u64;
    let mut periods_synced = 0u64;
    let mut period = start;

    while period <= end {
        // Fetch updates in batches
        let count = std::cmp::min(config.batch_size, end - period + 1);
        let updates = match beacon.get_updates(period, count) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("[!] Failed to fetch updates for period {period}: {e}");
                period += count;
                continue;
            }
        };

        if updates.is_empty() {
            println!("[!] No updates available for period {period}, skipping");
            period += count;
            continue;
        }

        for update in &updates {
            let attested_slot: u64 = update.attested_header.beacon.slot
                .parse().unwrap_or(0);
            let finalized_slot: u64 = update.finalized_header.beacon.slot
                .parse().unwrap_or(0);
            let update_period = attested_slot / (32 * 256);

            // Parse the finalized header root
            let header_root = match parse_beacon_header_fields(&update.finalized_header.beacon) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[!] Period {update_period}: parse header error: {e}");
                    continue;
                }
            };

            let state_root = match parse_bytes32(&update.finalized_header.beacon.state_root) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[!] Period {update_period}: parse state root error: {e}");
                    continue;
                }
            };

            // Check for sync committee rotation
            let has_next_sc = update.next_sync_committee.is_some();
            let next_sc_hash = if has_next_sc {
                // Compute the next sync committee hash from the update
                if let Some(ref sc) = update.next_sync_committee {
                    match crate::beacon_api::convert_sync_committee_to_hash(sc) {
                        Ok(hash) => {
                            rotations += 1;
                            hash
                        }
                        Err(e) => {
                            eprintln!("[!] Period {update_period}: SC hash error: {e}");
                            [0u8; 32]
                        }
                    }
                } else {
                    [0u8; 32]
                }
            } else {
                [0u8; 32]
            };

            // Determine current SC hash
            let current_sc = if store.is_initialized() {
                // If next_sc_hash was set from previous period, it's now current
                if store.next_sync_committee_hash != [0u8; 32] {
                    store.next_sync_committee_hash
                } else {
                    store.current_sync_committee_hash
                }
            } else {
                // Bootstrap: use a period-derived placeholder
                let mut hash = [0u8; 32];
                hash[0..8].copy_from_slice(&update_period.to_le_bytes());
                hash
            };

            // Count participation
            let participation = count_sync_bits(&update.sync_aggregate.sync_committee_bits);

            // Apply the update
            // Allow slot regression during historical sync (we're catching up)
            let old_slot = store.finalized_slot;
            if finalized_slot > old_slot || !store.is_initialized() {
                match store.apply_finality_update(
                    finalized_slot,
                    header_root,
                    state_root,
                    current_sc,
                    next_sc_hash,
                    participation,
                ) {
                    Ok(()) => {
                        let sc_indicator = if has_next_sc { " [SC ROTATION]" } else { "" };
                        println!(
                            "  Period {update_period}: slot {old_slot} → {finalized_slot} \
                             (participation: {participation}/512){sc_indicator}"
                        );
                    }
                    Err(e) => {
                        eprintln!("[!] Period {update_period}: apply error: {e}");
                    }
                }
            } else {
                println!("  Period {update_period}: skipped (slot {finalized_slot} <= head {old_slot})");
            }

            periods_synced += 1;
        }

        period += count;

        // Save after each batch
        store.save(&config.store_path)?;
    }

    println!("\n=== Historical Sync Complete ===");
    println!("Periods synced:   {periods_synced}");
    println!("SC Rotations:     {rotations}");
    println!("Final slot:       {}", store.finalized_slot);
    println!("Final SC period:  {}", store.current_period());
    println!();
    println!("{}", store.summary());

    Ok(HistoricalSyncResult {
        periods_synced,
        start_period: start,
        end_period: end,
        rotations,
        final_slot: store.finalized_slot,
    })
}

// =============================================================================
// Helpers
// =============================================================================

/// Parse an API beacon block header into its hash_tree_root.
fn parse_beacon_header_fields(
    header: &crate::beacon_api::ApiBeaconBlockHeader,
) -> Result<Bytes32, String> {
    use crate::beacon_api::convert_header;
    use eth_lc_lib::merkle::beacon_header_root;

    let bh = convert_header(header)?;
    Ok(beacon_header_root(&bh))
}

/// Count set bits in a hex-encoded sync committee bitfield.
///
/// e.g., "0xffff..." → count of 1-bits.
fn count_sync_bits(hex_str: &str) -> u32 {
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = match hex::decode(hex) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    bytes.iter().map(|b| b.count_ones()).sum()
}
