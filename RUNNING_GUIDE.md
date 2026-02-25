# SP1 Ethereum Light Client — Complete Running Guide

> All commands are **macOS/Linux (zsh/bash)** compatible.
> Tested with SP1 zkVM v6.0.0-beta.1 (Hypercube).

---

## Table of Contents

1. [Prerequisites & Installation](#1-prerequisites--installation)
2. [Environment Setup](#2-environment-setup)
3. [Project Architecture](#3-project-architecture)
4. [Building the Project](#4-building-the-project)
5. [Running Library Tests](#5-running-library-tests)
6. [Execute Light Client (No Proof)](#6-execute-light-client-no-proof)
7. [Generate Core Proofs](#7-generate-core-proofs)
8. [Generate EVM Proofs (Groth16 & PLONK)](#8-generate-evm-proofs-groth16--plonk)
9. [Storage Proof Testing (L1 — EIP-1186)](#9-storage-proof-testing-l1--eip-1186)
10. [Multichain / L2 Testing (OP Stack / Base)](#10-multichain--l2-testing-op-stack--base)
11. [Integration Tests (All-in-One)](#11-integration-tests-all-in-one)
12. [Sync Loop & Historical Sync](#12-sync-loop--historical-sync)
13. [Proof Server (REST API)](#13-proof-server-rest-api)
14. [Solidity Contract Tests (Foundry)](#14-solidity-contract-tests-foundry)
15. [On-Chain Deployment](#15-on-chain-deployment)
16. [Verification Key](#16-verification-key)
17. [Prover Network (Remote Proving)](#17-prover-network-remote-proving)
18. [Troubleshooting](#18-troubleshooting)

---

## 1. Prerequisites & Installation

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable
```

### Install SP1 zkVM Toolchain

```bash
curl -L https://sp1up.dev | bash
source "$HOME/.cargo/env"
sp1up
```

Verify installation:

```bash
cargo prove --version
```

### Install Foundry (for Solidity contract tests)

```bash
curl -L https://foundry.paradigm.xyz | bash
source "$HOME/.cargo/env"
foundryup
```

Verify:

```bash
forge --version
```

### System Requirements

| Mode | RAM | Notes |
|------|-----|-------|
| Mock proofs | 4 GB | Fast, no real proving |
| Execute only | 8 GB | Runs in zkVM, no proof |
| Core proofs | 8 GB | Real SP1 core proof |
| Groth16/PLONK | **16+ GB** | EVM-compatible proofs |
| With BLS verification | 32+ GB | BLS12-381 inside zkVM |

---

## 2. Environment Setup

From the project root (`lcs/fibonacci`):

```bash
cd lcs/fibonacci
```

Create/edit the `.env` file:

```bash
cat > .env << 'EOF'
# SP1 Prover mode: mock | local | network
SP1_PROVER=mock

# Infura API Key (needed for storage proofs & L2 tests)
INFURA_API_KEY=YOUR_INFURA_KEY_HERE

# Beacon API URL (mainnet default)
BEACON_URL=https://lodestar-mainnet.chainsafe.io

# (Optional) For SP1 Prover Network
# NETWORK_PRIVATE_KEY=0x...
EOF
```

**Prover modes explained:**

| Mode | What it does | Speed |
|------|-------------|-------|
| `mock` | Generates stub proofs (no real crypto). Good for development. | ~seconds |
| `local` | Full local proving with real cryptography. | minutes–hours |
| `network` | Sends to Succinct's prover network. | depends on queue |

> **For testing storage proofs and multichain features, `SP1_PROVER=mock` is sufficient.**
> You only need `local` or `network` for production/real proofs.

---

## 3. Project Architecture

```
fibonacci/
├── lib/                    # Shared library (runs inside zkVM + host)
│   └── src/
│       ├── lib.rs          # Public values struct (LightClientPublicValues)
│       ├── types.rs        # All types: ProofInputs, StorageProofInputs, L2StorageProofInputs
│       ├── consensus.rs    # Light client verification logic
│       ├── merkle.rs       # SSZ Merkle proof verification
│       ├── mpt.rs          # MPT proof verification (EIP-1186 storage proofs)
│       ├── l2.rs           # OP Stack L2 output root & L2 state verification
│       ├── cross_chain.rs  # Cross-chain message verification (L1↔L2)
│       ├── bls.rs          # BLS12-381 aggregate signature verification
│       └── config.rs       # Network configs (Mainnet, Sepolia, Base)
│
├── program/                # zkVM guest program (runs inside SP1)
│   └── src/main.rs         # Verifies: consensus + L1 storage proofs + L2 state
│
├── script/                 # Host-side scripts (proof generation, APIs)
│   └── src/
│       ├── bin/
│       │   ├── main.rs           # CLI: --execute / --prove / --live
│       │   ├── evm.rs            # EVM proof generator (Groth16/PLONK)
│       │   ├── vkey.rs           # Print verification key
│       │   ├── server.rs         # REST API proof server
│       │   ├── sync_cli.rs       # Continuous sync loop
│       │   └── integration_test.rs  # All integration tests
│       ├── beacon_api.rs   # Beacon Chain API client
│       ├── eth_rpc.rs      # Ethereum JSON-RPC client (eth_getProof)
│       ├── sync.rs         # Sync loop logic & persistent store
│       ├── api.rs          # REST API handlers
│       └── lib.rs          # Script library exports
│
├── contracts/              # Solidity on-chain verifier
│   ├── src/
│   │   ├── SP1EthereumLightClient.sol   # Main contract
│   │   └── interfaces/ISP1Verifier.sol  # SP1 verifier interface
│   ├── test/SP1EthereumLightClient.t.sol
│   └── script/Deploy.s.sol
│
└── .env                    # Environment configuration
```

**Data flow for storage proofs:**

```
Beacon API → finality update → zkVM verifies consensus
                                    ↓
Infura RPC → eth_getProof → zkVM verifies MPT proofs against finalized state root
                                    ↓
                             Public values committed (storage root, address, slot count)
                                    ↓
                             On-chain contract stores verified storage roots
```

**Data flow for multichain (L2/Base):**

```
L1 finalized state root (from consensus verification)
        ↓
Verify L2OutputOracle account on L1 (MPT account proof)
        ↓
Read output root from oracle storage (MPT storage proof)
        ↓
Decompose output root → L2 state root
        ↓
Verify L2 account + storage proofs against L2 state root
        ↓
Public values: l2StateRoot, numL2StorageSlots committed to proof
```

---

## 4. Building the Project

```bash
cd lcs/fibonacci

# Build all crates (lib, program, script) in release mode
cargo build --release
```

> The zkVM program ELF is built automatically via `script/build.rs`.

Build only the zkVM program:

```bash
cd program
cargo prove build
cd ..
```

---

## 5. Running Library Tests

These test the core verification logic (MPT, L2, cross-chain, merkle, BLS, consensus) **without** needing any RPCs or proofs:

```bash
# Run ALL library unit tests
cd lcs/fibonacci
cargo test --release -p eth-lc-lib

# Run specific test modules
cargo test --release -p eth-lc-lib -- mpt          # MPT proof verification tests
cargo test --release -p eth-lc-lib -- l2            # L2 output root & verification tests
cargo test --release -p eth-lc-lib -- cross_chain   # Cross-chain message tests
cargo test --release -p eth-lc-lib -- consensus     # Consensus verification tests
cargo test --release -p eth-lc-lib -- merkle        # SSZ Merkle proof tests
cargo test --release -p eth-lc-lib -- config        # Network config tests

# Run with BLS feature enabled
cargo test --release -p eth-lc-lib --features bls   # Includes BLS12-381 tests

# Run with verbose output
cargo test --release -p eth-lc-lib -- --nocapture
```

---

## 6. Execute Light Client (No Proof)

Execute runs the zkVM program without generating a ZK proof — fast for development & testing.

### Mock Data (no internet needed)

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock RUST_LOG=info cargo run --release -- --execute
```

### Live Data from Mainnet Beacon Chain

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock RUST_LOG=info cargo run --release -- --execute --live
```

### Live Data from Sepolia

```bash
SP1_PROVER=mock RUST_LOG=info cargo run --release -- --execute --live --network sepolia
```

### Live Data with BLS Signature Verification

```bash
SP1_PROVER=mock RUST_LOG=info cargo run --release -- --execute --live --bls
```

### Full Update (with Sync Committee Rotation)

```bash
SP1_PROVER=mock RUST_LOG=info cargo run --release -- --execute --live --full-update
```

### Custom Beacon API URL

```bash
BEACON_API_URL=https://your-beacon-node.example.com \
  SP1_PROVER=mock RUST_LOG=info cargo run --release -- --execute --live
```

---

## 7. Generate Core Proofs

Core proofs are SP1 native proofs (not EVM-verifiable).

### Mock Proof (fast, for testing pipeline)

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock RUST_LOG=info cargo run --release -- --prove
```

### Real Core Proof (local, requires 8+ GB RAM)

```bash
SP1_PROVER=local RUST_LOG=info cargo run --release -- --prove --live
```

---

## 8. Generate EVM Proofs (Groth16 & PLONK)

> **Requires 16+ GB RAM for local proving.**
> Use `SP1_PROVER=mock` first to test the pipeline, then switch to `local` or `network`.

### Groth16 Proof (Mock — pipeline test)

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock RUST_LOG=info cargo run --release --bin evm -- --system groth16
```

### Groth16 Proof (Local — real proof)

```bash
SP1_PROVER=local RUST_LOG=info cargo run --release --bin evm -- --system groth16
```

### PLONK Proof (Mock — pipeline test)

```bash
SP1_PROVER=mock RUST_LOG=info cargo run --release --bin evm -- --system plonk
```

### PLONK Proof (Local — real proof)

```bash
SP1_PROVER=local RUST_LOG=info cargo run --release --bin evm -- --system plonk
```

### EVM Proofs with Live Beacon Data

```bash
# Groth16 with live mainnet data
SP1_PROVER=mock RUST_LOG=info cargo run --release --bin evm -- --system groth16 --live

# PLONK with live mainnet data
SP1_PROVER=mock RUST_LOG=info cargo run --release --bin evm -- --system plonk --live

# With Sepolia
SP1_PROVER=mock RUST_LOG=info cargo run --release --bin evm -- --system groth16 --live --network sepolia
```

### Output

Proof fixtures are saved to `contracts/src/fixtures/`:

- `groth16-fixture.json`
- `plonk-fixture.json`

These contain `vkey`, `publicValues`, `proof` (hex-encoded) for use in Solidity tests.

---

## 9. Storage Proof Testing (L1 — EIP-1186)

**This is the L1 storage proof feature.** It fetches an `eth_getProof` (EIP-1186) from Ethereum and verifies MPT proofs against the finalized state root — all inside the zkVM.

### Prerequisites

You need an Infura API key (or any Ethereum execution RPC):

```bash
export INFURA_API_KEY=YOUR_KEY_HERE
```

### Run Storage Proof Integration Test

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY_HERE \
  RUST_LOG=info cargo run --release --bin integration-test -- --storage
```

**What this does:**

1. Fetches the latest block number from Ethereum mainnet (via Infura)
2. Gets the state root for that block
3. Calls `eth_getProof` for the USDC contract (`0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`) at storage slot 0
4. Verifies the **account proof** (MPT) against the state root
5. Verifies each **storage slot proof** (MPT) against the account's storage root
6. Prints verified nonce, storage root, code hash, and slot values

### What You'll See

```
─── Test: EIP-1186 Storage Proof + MPT ───
  [1/5] Fetching latest block number...
  [+] Block: 19234567 (0x1258d97)
  [2/5] Fetching state root for block 19234567...
  [+] State root: 0x1a2b3c4d5e6f...
  [3/5] Fetching EIP-1186 proof for USDC contract at block 19234567...
  [+] Account proof nodes: 9
  [+] Storage proofs: 1
  [4/5] Verifying account proof against state root (MPT)...
  [+] MPT-verified account state:
    Nonce:        1
    Storage root: 0xabcdef...
  [5/5] Verifying storage proof against storage root (MPT)...
  [+] Slot 0x000000... = 0x...
  ✓ Storage proof (EIP-1186 + MPT)
```

### Run Storage Proof via the Proof Server API

Start the server:

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY_HERE \
  cargo run --release --bin server -- --port 3000 --network mainnet
```

In another terminal, request a storage proof:

```bash
curl -X POST http://localhost:3000/prove/storage \
  -H "Content-Type: application/json" \
  -d '{
    "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "storage_keys": ["0x0000000000000000000000000000000000000000000000000000000000000000"]
  }'
```

---

## 10. Multichain / L2 Testing (OP Stack / Base)

**This verifies L2 (Base) state via L1's L2OutputOracle contract.** The chain of trust:

```
Beacon consensus (L1) → L2OutputOracle on L1 → L2 state root → L2 storage proofs
```

### Run L2 / Multichain Integration Test

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY_HERE \
  RUST_LOG=info cargo run --release --bin integration-test -- --l2
```

**What this does:**

1. Loads **Base Mainnet** and **Base Sepolia** L2 chain configs
2. Verifies the `L2OutputOracle` contract addresses are correct
3. Tests **OP Stack output root computation**: `keccak256(version ++ state_root ++ withdrawal_root ++ block_hash)`
4. Tests **L2OutputOracle storage slot math** (`l2Outputs[i]` at `keccak256(3) + i*2`)
5. If Infura key is set: fetches the actual `L2OutputOracle` account proof from L1 and verifies it via MPT
6. Reads `latestOutputIndex` from the oracle's storage

### What You'll See

```
─── Test: L2 Output Root + Base Config ───
  [1/4] Base Mainnet config:
    Chain ID:        base-mainnet
    L1 Chain ID:     ethereum-mainnet
    L2 RPC:          https://mainnet.base.org
    Oracle address:  0x56315b90c40730925ec5485cf004d835058518a0
  [2/4] Base Sepolia config:
    Chain ID:        base-sepolia
    Oracle address:  0x84457ca9d0163fbc4bbfe4dfbb20ba46e48dd19f
  [3/4] Testing OP Stack output root computation...
    Output root verification: PASSED
  [4/4] Testing L2OutputOracle storage slot math...
    l2Outputs[0] slot:   0xc2575a0e...
    l2Outputs[1] slot:   0xc2575a0e...
    latestOutputIndex slot: 4
  [bonus] Fetching L2OutputOracle account proof from L1...
    Oracle account proof: 9 nodes
    L2OutputOracle account MPT verified!
  ✓ L2 output root computation
```

### Run L2 Unit Tests Only (no RPC needed)

```bash
cargo test --release -p eth-lc-lib -- l2
cargo test --release -p eth-lc-lib -- cross_chain
```

These test:

- `compute_output_root` — OP Stack output root hashing
- `verify_output_root` — output root verification
- `l2_output_slot` — storage slot computation for `l2Outputs[]` array
- `compute_mapping_slot` — Solidity mapping slot computation
- `l2_sent_messages_slot` — L2ToL1MessagePasser slot computation
- `compute_withdrawal_hash` — OP Stack withdrawal message hashing

---

## 11. Integration Tests (All-in-One)

Run **all** integration tests in a single command:

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY_HERE \
  RUST_LOG=info cargo run --release --bin integration-test -- --all
```

Or run individual suites:

```bash
# Beacon API + zkVM execution test
SP1_PROVER=mock cargo run --release --bin integration-test -- --beacon

# Storage proof (EIP-1186 + MPT) test
SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY cargo run --release --bin integration-test -- --storage

# L2 output root + Base config test
SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY cargo run --release --bin integration-test -- --l2

# Sync loop single step test
SP1_PROVER=mock cargo run --release --bin integration-test -- --sync

# Specify network
SP1_PROVER=mock cargo run --release --bin integration-test -- --all --network sepolia
```

### Expected Output (all passing)

```
╔══════════════════════════════════════════════════╗
║     SP1 Light Client Integration Tests          ║
╚══════════════════════════════════════════════════╝

  ✓ Beacon + zkVM execution
  ✓ Storage proof (EIP-1186 + MPT)
  ✓ L2 output root computation
  ✓ Sync loop single step

═══════════════════════════════════════════════════
Results: 4 passed, 0 failed
```

---

## 12. Sync Loop & Historical Sync

### Continuous Sync (polls beacon API for new finality updates)

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock cargo run --release --bin sync -- \
  --network mainnet \
  --poll-interval 384 \
  --max-updates 5
```

Options:

| Flag | Description | Default |
|------|-------------|---------|
| `--network` | `mainnet` or `sepolia` | `mainnet` |
| `--poll-interval` | Seconds between polls | `384` (1 epoch) |
| `--max-updates` | Stop after N updates (0 = unlimited) | `0` |
| `--bls` | Enable BLS signature verification | disabled |
| `--full-update` | Fetch full updates with SC rotation | disabled |
| `--store-path` | Path to persist light client state | `light_client_store.json` |
| `--beacon-url` | Custom beacon API URL | auto from network |

### Historical Sync (walk through sync committee periods)

```bash
SP1_PROVER=mock cargo run --release --bin sync -- \
  --historical \
  --network mainnet \
  --start-period 290 \
  --end-period 295 \
  --batch-size 1
```

---

## 13. Proof Server (REST API)

Start the proof server:

```bash
cd lcs/fibonacci/script

SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY_HERE \
  cargo run --release --bin server -- --port 3000 --network mainnet
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/head` | Current light client head |
| POST | `/prove/finality` | Request a finality proof |
| POST | `/prove/storage` | Request a storage proof |
| GET | `/proof/{id}` | Get proof result by job ID |
| GET | `/jobs` | List all proof jobs |
| GET | `/chains` | List supported chains |

### Example Requests

```bash
# Health check
curl http://localhost:3000/health

# Get current head
curl http://localhost:3000/head

# Request finality proof
curl -X POST http://localhost:3000/prove/finality

# Request storage proof for USDC
curl -X POST http://localhost:3000/prove/storage \
  -H "Content-Type: application/json" \
  -d '{
    "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "storage_keys": ["0x0000000000000000000000000000000000000000000000000000000000000000"]
  }'

# Check proof job status
curl http://localhost:3000/proof/JOB_ID_HERE

# List all jobs
curl http://localhost:3000/jobs

# List supported chains
curl http://localhost:3000/chains
```

---

## 14. Solidity Contract Tests (Foundry)

```bash
cd lcs/fibonacci/contracts

# Install forge-std (if not already)
forge install foundry-rs/forge-std --no-commit

# Run all Solidity tests
forge test -vvv

# Run specific test
forge test -vvv --match-test test_update_with_storage_proof
forge test -vvv --match-test test_update_with_l2_state_root

# Run with gas reporting
forge test -vvv --gas-report
```

### Key Solidity Tests

| Test | What it verifies |
|------|-----------------|
| `test_initialize` | Contract initialization with trusted checkpoint |
| `test_update_advances_head` | Light client head advancement via SP1 proof |
| `test_sync_committee_rotation` | Sync committee rotation across period boundaries |
| `test_update_with_storage_proof` | **L1 storage proof results stored on-chain** |
| `test_update_with_l2_state_root` | **L2 state root stored on-chain** |
| `test_no_storage_proof_leaves_zero` | No storage proof → zero values |
| `test_historical_roots` | Historical slot lookups |
| `test_update_reverts_if_insufficient_participation` | Participation threshold enforcement |
| `test_update_reverts_on_committee_mismatch` | Sync committee mismatch rejected |

---

## 15. On-Chain Deployment

### Get the Verification Key First

```bash
cd lcs/fibonacci/script
cargo run --release --bin vkey
```

This prints the `programVKey` (bytes32) needed for the contract constructor.

### Deploy with Foundry

```bash
cd lcs/fibonacci/contracts

export SP1_VERIFIER_ADDRESS=0x...   # SP1 verifier contract on target chain
export PROGRAM_VKEY=0x...           # From vkey binary above
export MIN_PARTICIPATION=342        # 2/3 of 512
export RPC_URL=https://...          # Target chain RPC
export PRIVATE_KEY=0x...            # Deployer private key

forge script script/Deploy.s.sol:DeployLightClient \
  --rpc-url "$RPC_URL" \
  --broadcast \
  --private-key "$PRIVATE_KEY"
```

---

## 16. Verification Key

```bash
cd lcs/fibonacci/script
cargo run --release --bin vkey
```

Output: a `bytes32` hex string — the verification key hash for the SP1 program ELF.

---

## 17. Prover Network (Remote Proving)

For real Groth16/PLONK proofs without needing 16+ GB locally:

```bash
export SP1_PROVER=network
export NETWORK_PRIVATE_KEY=0xYOUR_WHITELISTED_KEY

cd lcs/fibonacci/script

# Groth16 via prover network
cargo run --release --bin evm -- --system groth16 --live

# PLONK via prover network
cargo run --release --bin evm -- --system plonk --live
```

See [Succinct Prover Network docs](https://docs.succinct.xyz/docs/next/sp1/prover-network/quickstart) for key whitelisting.

---

## 18. Troubleshooting

### "failed to setup ELF" or build errors

```bash
# Rebuild the zkVM program
cd lcs/fibonacci/program
cargo prove build
cd ..
cargo build --release
```

### "INFURA_API_KEY env var not set"

```bash
export INFURA_API_KEY=your_key_here
# Or add to .env file
```

### "Failed to fetch finality update"

The Beacon API might be temporarily unavailable. Try:

```bash
# Use a different beacon API
BEACON_API_URL=https://lodestar-mainnet.chainsafe.io cargo run --release -- --execute --live
# Or
BEACON_API_URL=https://lodestar-sepolia.chainsafe.io cargo run --release -- --execute --live --network sepolia
```

### Mock proof verification "failed"

This is expected with `SP1_PROVER=mock`:

```
[!] Proof verification skipped (SP1_PROVER=mock generates stub proofs)
    Use SP1_PROVER=local or SP1_PROVER=network for real verification.
```

### Out of memory during Groth16/PLONK

- Ensure 16+ GB RAM
- Close other applications
- Use `SP1_PROVER=network` to offload to the prover network

### Line ending warnings on macOS (if cloned from Windows)

```bash
git config core.autocrlf input
git rm --cached -r .
git reset --hard
```

---

## Quick Reference — Copy-Paste Commands

```bash
# === SETUP (run once) ===
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
curl -L https://sp1up.dev | bash && sp1up
curl -L https://foundry.paradigm.xyz | bash && foundryup

# === BUILD ===
cd lcs/fibonacci
cargo build --release

# === LIB TESTS (no RPC needed) ===
cargo test --release -p eth-lc-lib
cargo test --release -p eth-lc-lib -- mpt
cargo test --release -p eth-lc-lib -- l2
cargo test --release -p eth-lc-lib -- cross_chain

# === EXECUTE (mock, no proof) ===
cd script
SP1_PROVER=mock cargo run --release -- --execute
SP1_PROVER=mock cargo run --release -- --execute --live

# === CORE PROOF ===
SP1_PROVER=mock cargo run --release -- --prove
SP1_PROVER=local cargo run --release -- --prove --live

# === EVM PROOFS ===
SP1_PROVER=mock cargo run --release --bin evm -- --system groth16
SP1_PROVER=mock cargo run --release --bin evm -- --system plonk
SP1_PROVER=mock cargo run --release --bin evm -- --system groth16 --live
SP1_PROVER=local cargo run --release --bin evm -- --system groth16 --live
SP1_PROVER=local cargo run --release --bin evm -- --system plonk --live

# === STORAGE PROOF TEST ===
SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY cargo run --release --bin integration-test -- --storage

# === L2 / MULTICHAIN TEST ===
SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY cargo run --release --bin integration-test -- --l2

# === ALL INTEGRATION TESTS ===
SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY cargo run --release --bin integration-test -- --all

# === SYNC LOOP ===
SP1_PROVER=mock cargo run --release --bin sync -- --network mainnet --max-updates 3

# === PROOF SERVER ===
SP1_PROVER=mock INFURA_API_KEY=YOUR_KEY cargo run --release --bin server -- --port 3000

# === SOLIDITY TESTS ===
cd ../contracts && forge test -vvv

# === VERIFICATION KEY ===
cd ../script && cargo run --release --bin vkey
```
