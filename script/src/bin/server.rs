//! Proof Server — axum REST API for light client proofs.
//!
//! Usage:
//!   cargo run --bin server -- [--port 3000] [--network mainnet] [--beacon-url URL]

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use eth_lc_script::api::{self, AppState};
use eth_lc_script::sync::LightClientStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

#[derive(Parser)]
#[command(name = "proof-server", about = "SP1 Light Client Proof Server")]
struct Cli {
    /// Port to listen on.
    #[arg(long, default_value = "3000")]
    port: u16,

    /// Network (mainnet or sepolia).
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Beacon API URL.
    #[arg(long, env = "BEACON_URL")]
    beacon_url: Option<String>,

    /// Path to light client store JSON file.
    #[arg(long, default_value = "light_client_store.json")]
    store_path: String,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let cli = Cli::parse();

    let beacon_url = cli.beacon_url.unwrap_or_else(|| {
        match cli.network.as_str() {
            "mainnet" => "https://lodestar-mainnet.chainsafe.io".to_string(),
            "sepolia" => "https://lodestar-sepolia.chainsafe.io".to_string(),
            other => panic!("unknown network: {other}"),
        }
    });

    // Load or create the light client store.
    let store = LightClientStore::load_or_create(&cli.store_path, &cli.network)
        .expect("failed to load store");

    println!("=== SP1 Light Client Proof Server ===");
    println!("Network:    {}", cli.network);
    println!("Beacon URL: {beacon_url}");
    println!("Port:       {}", cli.port);
    if store.is_initialized() {
        println!("Store:      slot {} (period {})", store.finalized_slot, store.current_period());
    } else {
        println!("Store:      empty (will initialize on first update)");
    }

    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        jobs: Arc::new(Mutex::new(HashMap::new())),
        beacon_url,
        network: cli.network,
    };

    let app = Router::new()
        .route("/health", get(api::health))
        .route("/head", get(api::head))
        .route("/prove/finality", post(api::prove_finality))
        .route("/prove/storage", post(api::prove_storage))
        .route("/proof/{id}", get(api::get_proof))
        .route("/jobs", get(api::list_jobs))
        .route("/chains", get(api::list_chains))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cli.port);
    println!("\nListening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}
