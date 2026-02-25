//! Generate an EVM-compatible proof (Groth16/PLONK) for the Ethereum Light Client.
//!
//! This produces a fixture JSON file that can be used with the on-chain
//! `SP1EthereumLightClient` contract for testing and deployment.
//!
//! Usage:
//! ```shell
//! # Generate Groth16 proof with live mainnet data
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16 --live
//!
//! # Generate PLONK proof with mock data
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use alloy_sol_types::SolType;
use clap::{Parser, ValueEnum};
use eth_lc_lib::{
    config::{mainnet_config, sepolia_config},
    consensus::compute_epoch,
    merkle::{beacon_header_root, build_mock_merkle_branch},
    types::*,
    LightClientPublicValues,
};
use eth_lc_script::beacon_api::BeaconClient;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;

/// The ELF for the Ethereum Light Client zkVM program.
const LC_ELF: Elf = include_elf!("eth-lc-program");

/// Target network.
#[derive(Debug, Clone, ValueEnum)]
enum Network {
    Mainnet,
    Sepolia,
}

#[derive(Parser, Debug)]
#[command(
    name = "evm-proof",
    about = "Generate EVM-verifiable proofs for the Ethereum Light Client"
)]
struct EVMArgs {
    /// Proof system to use.
    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem,

    /// Use real Beacon Chain data instead of mock data.
    #[arg(long)]
    live: bool,

    /// Target network (used with --live).
    #[arg(long, value_enum, default_value = "mainnet")]
    network: Network,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}

/// Proof fixture for on-chain verification testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LightClientProofFixture {
    finalized_slot: u64,
    finalized_header_root: String,
    finalized_state_root: String,
    current_sync_committee_hash: String,
    next_sync_committee_hash: String,
    participation: u32,
    vkey: String,
    public_values: String,
    proof: String,
}

/// Create mock proof inputs.
fn create_mock_inputs() -> ProofInputs {
    let config = sepolia_config();

    let finalized_header = BeaconBlockHeader {
        slot: 6_000_000,
        proposer_index: 42,
        parent_root: [0x11u8; 32],
        state_root: [0x22u8; 32],
        body_root: [0x33u8; 32],
    };

    let finalized_header_root = beacon_header_root(&finalized_header);
    let (finality_branch, state_root) = build_mock_merkle_branch(
        &finalized_header_root,
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

/// Fetch live proof inputs from the Beacon Chain API.
fn fetch_live_inputs(args: &EVMArgs) -> ProofInputs {
    let (beacon_client, config) = match args.network {
        Network::Mainnet => (BeaconClient::mainnet(), mainnet_config()),
        Network::Sepolia => (BeaconClient::sepolia(), sepolia_config()),
    };

    println!("[*] Fetching live data from Beacon API...");
    let finality_update = beacon_client
        .get_finality_update()
        .expect("Failed to fetch finality update");

    println!(
        "[+] Got finality update: attested={}, finalized={}",
        finality_update.attested_header.beacon.slot,
        finality_update.finalized_header.beacon.slot,
    );

    beacon_client
        .finality_update_to_proof_inputs(&finality_update, &config, None)
        .expect("Failed to convert to ProofInputs")
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = EVMArgs::parse();

    let client = ProverClient::from_env();
    let pk = client.setup(LC_ELF).expect("failed to setup ELF");

    let inputs = if args.live {
        fetch_live_inputs(&args)
    } else {
        println!("[*] Using mock data");
        create_mock_inputs()
    };

    let mut stdin = SP1Stdin::new();
    stdin.write(&inputs);

    println!("[*] Generating {:?} proof...", args.system);

    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, stdin).groth16().run(),
    }
    .expect("failed to generate proof");

    println!("[+] Proof generated!");

    create_proof_fixture(&proof, pk.verifying_key(), args.system);
}

fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    system: ProofSystem,
) {
    let bytes = proof.public_values.as_slice();
    let pv = LightClientPublicValues::abi_decode(bytes).unwrap();

    let fixture = LightClientProofFixture {
        finalized_slot: pv.finalizedSlot,
        finalized_header_root: format!("0x{}", hex::encode(pv.finalizedHeaderRoot)),
        finalized_state_root: format!("0x{}", hex::encode(pv.finalizedStateRoot)),
        current_sync_committee_hash: format!("0x{}", hex::encode(pv.currentSyncCommitteeHash)),
        next_sync_committee_hash: format!("0x{}", hex::encode(pv.nextSyncCommitteeHash)),
        participation: pv.participation,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    println!("\n=== Proof Fixture ===");
    println!("Verification Key: {}", fixture.vkey);
    println!("Finalized Slot:   {}", fixture.finalized_slot);
    println!("Participation:    {}", fixture.participation);
    println!("Header Root:      {}", fixture.finalized_header_root);
    println!("State Root:       {}", fixture.finalized_state_root);

    // Save fixture for Solidity tests
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");

    let filename = format!("{:?}-fixture.json", system).to_lowercase();
    let filepath = fixture_path.join(&filename);
    std::fs::write(
        &filepath,
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    println!("\nFixture saved to: {}", filepath.display());
}
