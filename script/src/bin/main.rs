//! Ethereum Light Client — SP1 proof generation script.
//!
//! This script generates ZK proofs of Ethereum light client state transitions.
//! Supports both real Beacon Chain data and mock data for testing.
//!
//! Usage:
//! ```shell
//! # Execute with real beacon chain data (mainnet)
//! RUST_LOG=info cargo run --release -- --execute --live
//!
//! # Execute with real data from Sepolia
//! RUST_LOG=info cargo run --release -- --execute --live --network sepolia
//!
//! # Execute with real data from custom beacon API
//! BEACON_API_URL=https://your-beacon-node.com RUST_LOG=info cargo run --release -- --execute --live
//!
//! # Execute with mock data (fast, for development)
//! RUST_LOG=info cargo run --release -- --execute
//!
//! # Generate and verify a core proof with real data
//! RUST_LOG=info cargo run --release -- --prove --live
//! ```

use alloy_sol_types::SolType;
use clap::{Parser, ValueEnum};
use eth_lc_lib::{
    config::{mainnet_config, sepolia_config},
    consensus::{compute_epoch, compute_sync_committee_period},
    merkle::{beacon_header_root, build_mock_merkle_branch},
    types::*,
    LightClientPublicValues,
};
use eth_lc_script::beacon_api::BeaconClient;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

/// The ELF file for the Ethereum Light Client zkVM program.
const LC_ELF: Elf = include_elf!("eth-lc-program");

/// Target network.
#[derive(Debug, Clone, ValueEnum)]
enum Network {
    Mainnet,
    Sepolia,
}

/// CLI arguments.
#[derive(Parser, Debug)]
#[command(
    name = "eth-light-client",
    about = "SP1 Ethereum Light Client — generate ZK proofs of consensus state"
)]
struct Args {
    /// Execute the program without generating a proof (fast, for development).
    #[arg(long)]
    execute: bool,

    /// Generate and verify a ZK proof.
    #[arg(long)]
    prove: bool,

    /// Use real Beacon Chain data instead of mock data.
    #[arg(long)]
    live: bool,

    /// Target network (mainnet or sepolia). Only used with --live.
    #[arg(long, value_enum, default_value = "mainnet")]
    network: Network,

    /// Custom Beacon API URL. Overrides --network default.
    /// Can also be set via BEACON_API_URL environment variable.
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: Option<String>,

    /// Enable BLS signature verification (fetches sync committee pubkeys).
    #[arg(long)]
    bls: bool,

    /// Fetch a full light client update (includes sync committee rotation).
    /// Without this flag, only a finality update is fetched.
    #[arg(long)]
    full_update: bool,
}

fn main() {
    // Setup logging and environment.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();
    eth_lc_script::normalize_sp1_prover_env();

    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the SP1 prover client.
    let client = ProverClient::from_env();

    // Get proof inputs — either live from Beacon API or mock data.
    let inputs = if args.live {
        if args.full_update {
            fetch_full_update_inputs(&args)
        } else {
            fetch_live_inputs(&args)
        }
    } else {
        println!("[*] Using mock data (pass --live for real Beacon Chain data)");
        create_mock_inputs()
    };

    println!();
    println!("=== Ethereum Light Client (SP1 V6 Hypercube) ===");
    println!(
        "Mode:           {}",
        if args.live { "LIVE (real data)" } else { "MOCK" }
    );
    println!(
        "Network:        {:?}",
        args.network
    );
    println!(
        "BLS verify:     {}",
        if args.bls && args.live { "ENABLED" } else { "DISABLED" }
    );
    println!(
        "Update type:    {}",
        if args.full_update && args.live { "FULL (with SC rotation)" } else { "FINALITY ONLY" }
    );
    println!("Attested slot:  {}", inputs.update.attested_header.slot);
    if let Some(ref fin) = inputs.update.finality_update {
        println!("Finalized slot: {}", fin.finalized_header.slot);
    }
    let participation = inputs
        .update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .filter(|&&b| b)
        .count();
    println!(
        "Participation:  {}/{}",
        participation, SYNC_COMMITTEE_SIZE,
    );
    if inputs.update.sync_committee_update.is_some() {
        println!("SC rotation:    YES");
    }
    println!();

    // Setup the SP1 stdin with the proof inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&inputs);

    if args.execute {
        // ----- Execute Mode (no proof, fast) -----
        println!("[*] Executing light client verification in zkVM...");
        let (output, report) = client.execute(LC_ELF, stdin).run().unwrap();
        println!("[+] Program executed successfully!\n");

        // Decode and display the public values.
        let decoded = LightClientPublicValues::abi_decode(output.as_slice()).unwrap();
        print_public_values(&decoded);

        println!(
            "\nTotal cycles:   {}",
            report.total_instruction_count()
        );
    } else {
        // ----- Prove Mode -----
        println!("[*] Setting up proving key...");
        let pk = client.setup(LC_ELF).expect("failed to setup ELF");

        println!("[*] Generating ZK proof of light client verification...");
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");
        println!("[+] Proof generated successfully!\n");

        // Decode the public values from the proof.
        let decoded =
            LightClientPublicValues::abi_decode(proof.public_values.as_slice()).unwrap();
        print_public_values(&decoded);

        // Verify the proof.
        // Note: SP1_PROVER=mock generates stub proofs that cannot be verified.
        println!("\n[*] Verifying proof...");
        match client.verify(&proof, pk.verifying_key(), None) {
            Ok(()) => println!("[+] Proof verified successfully!"),
            Err(e) => {
                let is_mock = std::env::var("SP1_PROVER")
                    .map(|v| v.eq_ignore_ascii_case("mock"))
                    .unwrap_or(false);
                if is_mock {
                    println!("[!] Proof verification skipped (SP1_PROVER=mock generates stub proofs)");
                    println!("    Use SP1_PROVER=cpu or SP1_PROVER=network for real verification.");
                } else {
                    panic!("proof verification failed: {e}");
                }
            }
        }
    }
}

/// Fetch live proof inputs from the Beacon Chain API.
fn fetch_live_inputs(args: &Args) -> ProofInputs {
    // Determine which beacon client and config to use
    let (beacon_client, config) = if let Some(ref url) = args.beacon_url {
        let network_config = match args.network {
            Network::Mainnet => mainnet_config(),
            Network::Sepolia => sepolia_config(),
        };
        (BeaconClient::new(url), network_config)
    } else {
        match args.network {
            Network::Mainnet => (BeaconClient::mainnet(), mainnet_config()),
            Network::Sepolia => (BeaconClient::sepolia(), sepolia_config()),
        }
    };

    println!("=== Fetching Live Beacon Chain Data ===\n");

    // Fetch the latest finality update
    let finality_update = beacon_client
        .get_finality_update()
        .expect("Failed to fetch finality update from Beacon API");

    println!(
        "[+] Got finality update: attested_slot={}, finalized_slot={}",
        finality_update.attested_header.beacon.slot,
        finality_update.finalized_header.beacon.slot,
    );

    let participation_count = eth_lc_script::beacon_api::parse_sync_committee_bits(
        &finality_update.sync_aggregate.sync_committee_bits,
    )
    .map(|bits| bits.iter().filter(|&&b| b).count())
    .unwrap_or(0);
    println!("[+] Sync committee participation: {participation_count}/{SYNC_COMMITTEE_SIZE}");

    // Optionally fetch sync committee for BLS verification
    let sync_committee = if args.bls {
        println!("[*] Fetching current sync committee for BLS verification...");
        let sc = beacon_client
            .fetch_current_sync_committee()
            .expect("Failed to fetch sync committee");
        println!("[+] Got sync committee, hash=0x{}", hex::encode(&sc.1[..8]));
        Some(sc)
    } else {
        None
    };

    // Convert to ProofInputs
    let inputs = beacon_client
        .finality_update_to_proof_inputs(&finality_update, &config, sync_committee)
        .expect("Failed to convert finality update to proof inputs");

    println!("[+] Successfully converted to ProofInputs");
    inputs
}

/// Fetch a full light client update (with sync committee rotation) from the Beacon API.
fn fetch_full_update_inputs(args: &Args) -> ProofInputs {
    let (beacon_client, config) = if let Some(ref url) = args.beacon_url {
        let network_config = match args.network {
            Network::Mainnet => mainnet_config(),
            Network::Sepolia => sepolia_config(),
        };
        (BeaconClient::new(url), network_config)
    } else {
        match args.network {
            Network::Mainnet => (BeaconClient::mainnet(), mainnet_config()),
            Network::Sepolia => (BeaconClient::sepolia(), sepolia_config()),
        }
    };

    println!("=== Fetching Full Light Client Update (with SC Rotation) ===\n");

    // Determine the current sync committee period from the latest finality update
    let finality_update = beacon_client
        .get_finality_update()
        .expect("Failed to fetch finality update");
    let current_slot: u64 = finality_update
        .attested_header
        .beacon
        .slot
        .parse()
        .expect("Failed to parse slot");
    let current_period = compute_sync_committee_period(current_slot);
    println!("[+] Current slot: {current_slot}, period: {current_period}");

    // Fetch a full update for the current period (includes next_sync_committee)
    let updates = beacon_client
        .get_updates(current_period, 1)
        .expect("Failed to fetch light client updates");

    if updates.is_empty() {
        eprintln!("Error: no updates available for period {current_period}");
        std::process::exit(1);
    }

    let update = &updates[0];
    let attested_slot: u64 = update.attested_header.beacon.slot.parse().unwrap_or(0);
    let finalized_slot: u64 = update.finalized_header.beacon.slot.parse().unwrap_or(0);
    println!(
        "[+] Got full update: attested_slot={}, finalized_slot={}",
        attested_slot, finalized_slot
    );

    let has_sc = update.next_sync_committee.is_some();
    let has_br = update.next_sync_committee_branch.is_some();
    println!("[+] Has next_sync_committee: {has_sc}, branch: {has_br}");

    let participation_count = eth_lc_script::beacon_api::parse_sync_committee_bits(
        &update.sync_aggregate.sync_committee_bits,
    )
    .map(|bits| bits.iter().filter(|&&b| b).count())
    .unwrap_or(0);
    println!("[+] Sync committee participation: {participation_count}/{SYNC_COMMITTEE_SIZE}");

    // Optionally fetch current sync committee for BLS verification
    let sync_committee = if args.bls {
        println!("[*] Fetching current sync committee for BLS verification...");
        let sc = beacon_client
            .fetch_current_sync_committee()
            .expect("Failed to fetch sync committee");
        println!("[+] Got sync committee, hash=0x{}", hex::encode(&sc.1[..8]));
        Some(sc)
    } else {
        None
    };

    // Convert to ProofInputs (includes SC rotation proof)
    let inputs = beacon_client
        .full_update_to_proof_inputs(update, &config, sync_committee)
        .expect("Failed to convert full update to proof inputs");

    println!("[+] Successfully converted to ProofInputs");
    if inputs.update.sync_committee_update.is_some() {
        println!(
            "[+] Next SC hash: 0x{}",
            hex::encode(
                inputs
                    .update
                    .sync_committee_update
                    .as_ref()
                    .unwrap()
                    .next_sync_committee_hash
            )
        );
    }
    inputs
}

/// Print decoded public values in a human-readable format.
fn print_public_values(pv: &LightClientPublicValues) {
    println!("--- Verified Public Values ---");
    println!("Finalized Slot:            {}", pv.finalizedSlot);
    println!(
        "Finalized Header Root:     0x{}",
        hex::encode(pv.finalizedHeaderRoot)
    );
    println!(
        "Finalized State Root:      0x{}",
        hex::encode(pv.finalizedStateRoot)
    );
    println!(
        "Current SC Hash:           0x{}",
        hex::encode(pv.currentSyncCommitteeHash)
    );
    println!(
        "Next SC Hash:              0x{}",
        hex::encode(pv.nextSyncCommitteeHash)
    );
    println!(
        "Participation:             {}/{}",
        pv.participation, SYNC_COMMITTEE_SIZE
    );
    if pv.numStorageSlots > 0 {
        println!("--- L1 Storage Proof Results ---");
        println!("Storage Slots Verified:    {}", pv.numStorageSlots);
        println!("Account Address:           0x{}", hex::encode(pv.storageProofAddress));
        println!("Storage Root:              0x{}", hex::encode(pv.storageProofStorageRoot));
    }
    if pv.numL2StorageSlots > 0 {
        println!("--- L2 Storage Proof Results ---");
        println!("L2 Slots Verified:         {}", pv.numL2StorageSlots);
        println!("L2 State Root:             0x{}", hex::encode(pv.l2StateRoot));
    }
}

/// Create mock proof inputs for testing the light client pipeline.
fn create_mock_inputs() -> ProofInputs {
    let config = sepolia_config();

    let finalized_header = BeaconBlockHeader {
        slot: 6_000_000,
        proposer_index: 42,
        parent_root: [0x11u8; 32],
        state_root: [0x22u8; 32],
        body_root: [0x33u8; 32],
    };

    let fin_header_root = beacon_header_root(&finalized_header);
    let (finality_branch, state_root) = build_mock_merkle_branch(
        &fin_header_root,
        FINALIZED_ROOT_DEPTH,
        FINALIZED_ROOT_SUBTREE_INDEX,
    );

    let attested_header = BeaconBlockHeader {
        slot: 6_000_032,
        proposer_index: 55,
        parent_root: [0x44u8; 32],
        state_root,
        body_root: [0x55u8; 32],
    };

    let sync_committee_bits = vec![true; SYNC_COMMITTEE_SIZE];
    let sync_committee_signature = vec![0u8; BYTES_PER_SIGNATURE];

    let epoch = compute_epoch(attested_header.slot);
    let fork_version = config.fork_version_for_epoch(epoch);

    ProofInputs {
        update: LightClientUpdate {
            attested_header,
            sync_aggregate: SyncAggregate {
                sync_committee_bits,
                sync_committee_signature,
            },
            signature_slot: 6_000_033,
            finality_update: Some(FinalityUpdate {
                finalized_header,
                finality_branch,
            }),
            sync_committee_update: None,
        },
        current_sync_committee_hash: [0x77u8; 32],
        sync_committee: None, // No BLS verification with mock data
        genesis_validators_root: config.genesis_validators_root,
        genesis_time: config.genesis_time,
        fork_version,
        storage_proof: None,
        l2_storage_proof: None,
    }
}
