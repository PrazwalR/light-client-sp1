//! Sync CLI — continuous light client syncing and historical period walking.
//!
//! Usage:
//!   cargo run --bin sync -- [--network mainnet] [--beacon-url URL] [--max-updates N]
//!   cargo run --bin sync -- --historical [--start-period 290] [--end-period 350]

use clap::Parser;
use eth_lc_script::sync::{run_sync_loop, run_historical_sync, SyncConfig, HistoricalSyncConfig};

#[derive(Parser)]
#[command(name = "sync", about = "Continuous light client sync loop and historical sync")]
struct Cli {
    /// Network (mainnet or sepolia).
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Beacon API URL.
    #[arg(long, env = "BEACON_URL")]
    beacon_url: Option<String>,

    /// Path to persist light client store.
    #[arg(long, default_value = "light_client_store.json")]
    store_path: String,

    /// Poll interval in seconds.
    #[arg(long, default_value = "384")]
    poll_interval: u64,

    /// Maximum number of updates to process (0 = unlimited).
    #[arg(long, default_value = "0")]
    max_updates: u64,

    /// Enable BLS signature verification.
    #[arg(long)]
    bls: bool,

    /// Fetch full updates (with sync committee rotation).
    #[arg(long)]
    full_update: bool,

    /// Run historical sync: walk through sync committee periods.
    #[arg(long)]
    historical: bool,

    /// Starting sync committee period for historical sync (0 = auto-detect).
    #[arg(long, default_value = "0")]
    start_period: u64,

    /// Ending sync committee period for historical sync (0 = current period).
    #[arg(long, default_value = "0")]
    end_period: u64,

    /// Number of updates to fetch per batch in historical sync.
    #[arg(long, default_value = "1")]
    batch_size: u64,
}

fn main() {
    dotenv::dotenv().ok();

    let cli = Cli::parse();

    let beacon_url = cli.beacon_url.unwrap_or_else(|| {
        match cli.network.as_str() {
            "mainnet" => "https://lodestar-mainnet.chainsafe.io".to_string(),
            "sepolia" => "https://lodestar-sepolia.chainsafe.io".to_string(),
            other => panic!("unknown network: {other}"),
        }
    });

    if cli.historical {
        // Historical sync mode: walk through sync committee periods
        let config = HistoricalSyncConfig {
            beacon_url,
            network: cli.network,
            store_path: cli.store_path,
            start_period: cli.start_period,
            end_period: cli.end_period,
            batch_size: cli.batch_size,
        };

        match run_historical_sync(config) {
            Ok(result) => {
                println!(
                    "\nSynced {} periods ({} → {}), {} rotations, final slot {}",
                    result.periods_synced,
                    result.start_period,
                    result.end_period,
                    result.rotations,
                    result.final_slot,
                );
            }
            Err(e) => {
                eprintln!("Historical sync error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        // Normal continuous sync mode
        let config = SyncConfig {
            beacon_url,
            network: cli.network,
            store_path: cli.store_path,
            poll_interval_secs: cli.poll_interval,
            verify_bls: cli.bls,
            full_updates: cli.full_update,
            max_updates: cli.max_updates,
        };

        match run_sync_loop(config) {
            Ok(store) => {
                println!("\n=== Final Store State ===");
                println!("{}", store.summary());
            }
            Err(e) => {
                eprintln!("Sync loop error: {e}");
                std::process::exit(1);
            }
        }
    }
}
