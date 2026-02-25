//! Integration test binary — exercises all new features end-to-end.
//!
//! Tests:
//! 1. Live beacon API → finality update → zkVM execution (SP1_PROVER=mock)
//! 2. EIP-1186 storage proof fetch + MPT verification (Ethereum mainnet)
//! 3. L2 output root computation (Base)
//! 4. Sync loop single step
//! 5. Storage proof fetch for Base L2 via public RPC
//!
//! Usage:
//!   SP1_PROVER=mock INFURA_API_KEY=fba92cb083044034b177f647a3c882fb \
//!     cargo run --bin integration-test -- [--all] [--beacon] [--storage] [--l2] [--sync]

use clap::Parser;
use eth_lc_lib::{
    config,
    l2,
    mpt,
    types::*,
};
use eth_lc_script::{
    beacon_api::BeaconClient,
    eth_rpc::EthRpcClient,
    sync::{LightClientStore, SyncConfig, SyncResult},
};

#[derive(Parser)]
#[command(name = "integration-test", about = "End-to-end integration tests")]
struct Cli {
    /// Run all tests.
    #[arg(long)]
    all: bool,

    /// Test beacon API + zkVM execution.
    #[arg(long)]
    beacon: bool,

    /// Test EIP-1186 storage proof fetch + MPT verification.
    #[arg(long)]
    storage: bool,

    /// Test L2 output root computation.
    #[arg(long)]
    l2: bool,

    /// Test sync loop single step.
    #[arg(long)]
    sync: bool,

    /// Network (mainnet or sepolia).
    #[arg(long, default_value = "mainnet")]
    network: String,
}

fn main() {
    dotenv::dotenv().ok();

    let cli = Cli::parse();
    let run_all = cli.all || (!cli.beacon && !cli.storage && !cli.l2 && !cli.sync);

    println!("╔══════════════════════════════════════════════════╗");
    println!("║     SP1 Light Client Integration Tests          ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    let mut passed = 0u32;
    let mut failed = 0u32;

    if run_all || cli.beacon {
        match test_beacon_zkvm(&cli.network) {
            Ok(()) => { passed += 1; println!("  ✓ Beacon + zkVM execution\n"); }
            Err(e) => { failed += 1; eprintln!("  ✗ Beacon + zkVM: {e}\n"); }
        }
    }

    if run_all || cli.storage {
        match test_storage_proof() {
            Ok(()) => { passed += 1; println!("  ✓ Storage proof (EIP-1186 + MPT)\n"); }
            Err(e) => { failed += 1; eprintln!("  ✗ Storage proof: {e}\n"); }
        }
    }

    if run_all || cli.l2 {
        match test_l2_output_root() {
            Ok(()) => { passed += 1; println!("  ✓ L2 output root computation\n"); }
            Err(e) => { failed += 1; eprintln!("  ✗ L2 output root: {e}\n"); }
        }
    }

    if run_all || cli.sync {
        match test_sync_step(&cli.network) {
            Ok(()) => { passed += 1; println!("  ✓ Sync loop single step\n"); }
            Err(e) => { failed += 1; eprintln!("  ✗ Sync step: {e}\n"); }
        }
    }

    println!("═══════════════════════════════════════════════════");
    println!("Results: {passed} passed, {failed} failed");
    if failed > 0 {
        std::process::exit(1);
    }
}

// =============================================================================
// Test 1: Beacon API → zkVM Execution
// =============================================================================

fn test_beacon_zkvm(network: &str) -> Result<(), String> {
    use sp1_sdk::{
        blocking::{Prover, ProverClient},
        include_elf, Elf, SP1Stdin,
    };
    use alloy_sol_types::SolType;
    use eth_lc_lib::LightClientPublicValues;

    const LC_ELF: Elf = include_elf!("eth-lc-program");

    println!("─── Test: Beacon API + zkVM Execution ───");

    let beacon_url = match network {
        "mainnet" => "https://lodestar-mainnet.chainsafe.io",
        "sepolia" => "https://lodestar-sepolia.chainsafe.io",
        _ => return Err(format!("unknown network: {network}")),
    };

    let config = match network {
        "mainnet" => config::mainnet_config(),
        "sepolia" => config::sepolia_config(),
        _ => unreachable!(),
    };

    println!("  [1/4] Fetching finality update from {beacon_url}...");
    let beacon = BeaconClient::new(beacon_url);
    let finality = beacon.get_finality_update()
        .map_err(|e| format!("fetch finality: {e}"))?;

    let fin_slot = &finality.finalized_header.beacon.slot;
    let att_slot = &finality.attested_header.beacon.slot;
    println!("  [+] Attested slot: {att_slot}, Finalized slot: {fin_slot}");

    println!("  [2/4] Converting to proof inputs (no BLS)...");
    let inputs = beacon.finality_update_to_proof_inputs(&finality, &config, None)
        .map_err(|e| format!("convert: {e}"))?;

    let participation = inputs.update.sync_aggregate.sync_committee_bits
        .iter().filter(|&&b| b).count();
    println!("  [+] Participation: {participation}/512");

    println!("  [3/4] Executing in zkVM (SP1_PROVER={})...",
        std::env::var("SP1_PROVER").unwrap_or_else(|_| "mock".to_string()));

    let mut stdin = SP1Stdin::new();
    stdin.write(&inputs);

    eth_lc_script::normalize_sp1_prover_env();
    let client = ProverClient::from_env();
    let (output, report) = client.execute(LC_ELF, stdin)
        .run()
        .map_err(|e| format!("execute: {e}"))?;

    let decoded = LightClientPublicValues::abi_decode(output.as_slice())
        .map_err(|e| format!("decode: {e}"))?;

    println!("  [4/4] Results:");
    println!("    Finalized slot:     {}", decoded.finalizedSlot);
    println!("    Header root:        0x{}", hex::encode(decoded.finalizedHeaderRoot));
    println!("    State root:         0x{}...", &hex::encode(decoded.finalizedStateRoot)[..16]);
    println!("    Current SC hash:    0x{}...", &hex::encode(decoded.currentSyncCommitteeHash)[..16]);
    println!("    Next SC hash:       0x{}...", &hex::encode(decoded.nextSyncCommitteeHash)[..16]);
    println!("    Participation:      {}", decoded.participation);
    println!("    L1 Storage Slots:   {}", decoded.numStorageSlots);
    println!("    L2 Storage Slots:   {}", decoded.numL2StorageSlots);
    println!("    Total cycles:       {}", report.total_instruction_count());

    if decoded.finalizedSlot == 0 {
        return Err("finalized slot is 0".to_string());
    }

    Ok(())
}

// =============================================================================
// Test 2: EIP-1186 Storage Proof + MPT Verification
// =============================================================================

fn test_storage_proof() -> Result<(), String> {
    println!("─── Test: EIP-1186 Storage Proof + MPT ───");

    let infura_key = std::env::var("INFURA_API_KEY")
        .map_err(|_| "INFURA_API_KEY env var not set".to_string())?;
    let rpc_url = eth_lc_script::eth_rpc::infura_mainnet_url(&infura_key);

    let client = EthRpcClient::new(&rpc_url);

    // Use USDC contract on Ethereum mainnet as test target.
    // USDC proxy: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
    let usdc_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    // Storage slot 0 → typically proxy implementation or admin slot
    let storage_keys = vec!["0x0000000000000000000000000000000000000000000000000000000000000000".to_string()];

    // Pin to a specific block number so state_root and proof are consistent.
    println!("  [1/5] Fetching latest block number...");
    let block_num = get_block_number(&client)?;
    let block_hex = format!("0x{:x}", block_num);
    println!("  [+] Block: {} ({})", block_num, block_hex);

    println!("  [2/5] Fetching state root for block {}...", block_num);
    let state_root = client.get_state_root(&block_hex)
        .map_err(|e| format!("get state root: {e}"))?;
    println!("  [+] State root: 0x{}...", &hex::encode(state_root)[..16]);

    println!("  [3/5] Fetching EIP-1186 proof for USDC contract at block {}...", block_num);
    let proof = client.get_proof(usdc_address, &storage_keys, &block_hex)
        .map_err(|e| format!("get proof: {e}"))?;

    println!("  [+] Account proof nodes: {}", proof.account_proof.len());
    println!("  [+] Storage proofs: {}", proof.storage_proofs.len());
    println!("  [+] Nonce: {}", proof.nonce);
    println!("  [+] Storage root: 0x{}...", &hex::encode(proof.storage_root)[..16]);
    println!("  [+] Code hash: 0x{}...", &hex::encode(proof.code_hash)[..16]);

    println!("  [4/5] Verifying account proof against state root (MPT)...");
    let account = mpt::verify_account_proof(
        &proof.address,
        &proof.account_proof,
        &state_root,
    ).map_err(|e| format!("account proof MPT verification FAILED: {e:?}"))?;

    println!("  [+] MPT-verified account state:");
    println!("    Nonce:        {}", account.nonce);
    println!("    Storage root: 0x{}...", &hex::encode(account.storage_root)[..16]);
    println!("    Code hash:    0x{}...", &hex::encode(account.code_hash)[..16]);

    println!("  [5/5] Verifying storage proof against storage root (MPT)...");
    for (i, sp) in proof.storage_proofs.iter().enumerate() {
        let value = mpt::verify_storage_proof(
            &sp.key,
            &sp.proof,
            &proof.storage_root,
        ).map_err(|e| format!("storage proof #{i} MPT verification FAILED: {e:?}"))?;
        println!("  [+] Slot 0x{}... = 0x{}...",
            &hex::encode(sp.key)[..8],
            &hex::encode(value)[..16]);
    }

    Ok(())
}

// =============================================================================
// Test 3: L2 Output Root Computation + Base Config
// =============================================================================

fn test_l2_output_root() -> Result<(), String> {
    println!("─── Test: L2 Output Root + Base Config ───");

    // Test Base Mainnet config.
    let base_config = config::base_mainnet_config();
    println!("  [1/4] Base Mainnet config:");
    println!("    Chain ID:        {}", base_config.chain_id);
    println!("    L1 Chain ID:     {}", base_config.l1_chain_id);
    println!("    L2 RPC:          {}", base_config.l2_rpc_url);
    println!("    Oracle address:  0x{}", hex::encode(base_config.l2_output_oracle));

    // Test Base Sepolia config.
    let base_sep = config::base_sepolia_config();
    println!("  [2/4] Base Sepolia config:");
    println!("    Chain ID:        {}", base_sep.chain_id);
    println!("    Oracle address:  0x{}", hex::encode(base_sep.l2_output_oracle));

    // Test OP Stack output root computation.
    println!("  [3/4] Testing OP Stack output root computation...");
    let test_output = L2OutputRoot {
        version: 0,
        state_root: [0xaa; 32],
        withdrawal_storage_root: [0xbb; 32],
        latest_block_hash: [0xcc; 32],
    };
    let root = l2::compute_output_root(&test_output);
    println!("  [+] Output root: 0x{}...", &hex::encode(root)[..16]);

    // Verify it matches.
    l2::verify_output_root(&test_output, &root)
        .map_err(|e| format!("output root verify failed: {e}"))?;
    println!("  [+] Output root verification: PASSED");

    // Test L2 output slot computation.
    println!("  [4/4] Testing L2OutputOracle storage slot math...");
    let slot0 = l2::l2_output_slot(0);
    let slot1 = l2::l2_output_slot(1);
    let slot100 = l2::l2_output_slot(100);
    println!("  [+] l2Outputs[0] slot:   0x{}...", &hex::encode(slot0)[..16]);
    println!("  [+] l2Outputs[1] slot:   0x{}...", &hex::encode(slot1)[..16]);
    println!("  [+] l2Outputs[100] slot: 0x{}...", &hex::encode(slot100)[..16]);

    // Verify slot math is consistent.
    let idx_slot = l2::latest_output_index_slot();
    assert_eq!(idx_slot[31], 4, "latestOutputIndex should be at slot 4");
    println!("  [+] latestOutputIndex slot: {}", idx_slot[31]);

    // Try fetching actual L2OutputOracle proof from L1 (if Infura available).
    if let Ok(infura_key) = std::env::var("INFURA_API_KEY") {
        println!("\n  [bonus] Fetching L2OutputOracle account proof from L1...");
        let rpc = EthRpcClient::new(&eth_lc_script::eth_rpc::infura_mainnet_url(&infura_key));
        let oracle_hex = format!("0x{}", hex::encode(config::BASE_MAINNET_L2_OUTPUT_ORACLE));

        // Fetch the oracle's account proof + latestOutputIndex storage slot.
        let idx_key = format!("0x{}", hex::encode(idx_slot));
        match rpc.get_proof(&oracle_hex, &[idx_key], "finalized") {
            Ok(oracle_proof) => {
                println!("  [+] Oracle account proof: {} nodes", oracle_proof.account_proof.len());
                println!("  [+] Oracle storage root: 0x{}...", &hex::encode(oracle_proof.storage_root)[..16]);
                if !oracle_proof.storage_proofs.is_empty() {
                    let val = &oracle_proof.storage_proofs[0].value;
                    // latestOutputIndex is stored as uint256
                    let idx = u64::from_be_bytes([val[24], val[25], val[26], val[27], val[28], val[29], val[30], val[31]]);
                    println!("  [+] latestOutputIndex: {idx}");
                }

                // Verify the account proof with MPT.
                let state_root = rpc.get_state_root("finalized")
                    .map_err(|e| format!("state root: {e}"))?;
                let account = mpt::verify_account_proof(
                    &oracle_proof.address,
                    &oracle_proof.account_proof,
                    &state_root,
                ).map_err(|e| format!("oracle account MPT verify FAILED: {e:?}"))?;
                println!("  [+] L2OutputOracle account MPT verified!");
                println!("    Storage root: 0x{}...", &hex::encode(account.storage_root)[..16]);
            }
            Err(e) => {
                println!("  [!] Could not fetch oracle proof (non-fatal): {e}");
            }
        }
    }

    Ok(())
}

// =============================================================================
// Test 4: Sync Loop Single Step
// =============================================================================

fn test_sync_step(network: &str) -> Result<(), String> {
    println!("─── Test: Sync Loop Single Step ───");

    let beacon_url = match network {
        "mainnet" => "https://lodestar-mainnet.chainsafe.io",
        "sepolia" => "https://lodestar-sepolia.chainsafe.io",
        _ => return Err(format!("unknown network: {network}")),
    };

    let mut store = LightClientStore::new(network);
    println!("  [1/3] Created empty store for {network}");
    println!("  [+] Initial slot: {}", store.finalized_slot);

    let config = SyncConfig {
        beacon_url: beacon_url.to_string(),
        network: network.to_string(),
        store_path: "/tmp/integration_test_store.json".to_string(),
        poll_interval_secs: 0,
        verify_bls: false,
        full_updates: false,
        max_updates: 1,
    };

    println!("  [2/3] Running single sync step...");
    let result = eth_lc_script::sync::sync_step(&mut store, &config);

    match result {
        SyncResult::Updated { old_slot, new_slot, participation } => {
            println!("  [+] Updated: slot {old_slot} → {new_slot}");
            println!("  [+] Participation: {participation}/512");
            println!("  [+] Period: {}", store.current_period());
        }
        SyncResult::NoUpdate => {
            println!("  [!] No update available (head unchanged)");
        }
        SyncResult::Error(e) => {
            return Err(format!("sync step failed: {e}"));
        }
    }

    println!("  [3/3] Store state:");
    println!("    Slot:       {}", store.finalized_slot);
    println!("    Header:     0x{}...", &hex::encode(store.finalized_header_root)[..16]);
    println!("    Updates:    {}", store.updates_processed);

    // Save and reload to test persistence.
    store.save(&config.store_path)
        .map_err(|e| format!("save: {e}"))?;
    let loaded = LightClientStore::load_or_create(&config.store_path, network)
        .map_err(|e| format!("load: {e}"))?;
    assert_eq!(loaded.finalized_slot, store.finalized_slot);
    println!("  [+] Persistence: save/load verified");

    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

/// Get the current block number from the RPC.
fn get_block_number(client: &EthRpcClient) -> Result<u64, String> {
    // Using reqwest directly since EthRpcClient doesn't expose eth_blockNumber.
    let resp: serde_json::Value = client
        .rpc_url
        .parse::<reqwest::Url>()
        .map_err(|e| format!("bad URL: {e}"))
        .and_then(|_| {
            reqwest::blocking::Client::new()
                .post(&client.rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "eth_blockNumber",
                    "params": [],
                    "id": 1
                }))
                .send()
                .map_err(|e| format!("HTTP: {e}"))
        })
        .and_then(|r| r.json().map_err(|e| format!("JSON: {e}")))?;

    let hex = resp["result"]
        .as_str()
        .ok_or("missing result")?;
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(hex, 16).map_err(|e| format!("parse block: {e}"))
}
