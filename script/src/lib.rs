//! Ethereum Light Client script library.
//!
//! Provides shared modules used by the CLI binaries.

pub mod api;
pub mod beacon_api;
pub mod eth_rpc;
pub mod sync;

/// Normalize the `SP1_PROVER` environment variable for SP1 v6 (Hypercube).
///
/// SP1 v6 renamed the local CPU prover from `"local"` to `"cpu"`.
/// This function remaps `"local"` → `"cpu"` so that existing scripts and
/// documentation that reference `SP1_PROVER=local` continue to work.
///
/// Call this **before** `ProverClient::from_env()`.
pub fn normalize_sp1_prover_env() {
    if let Ok(val) = std::env::var("SP1_PROVER") {
        match val.to_lowercase().as_str() {
            "local" => {
                eprintln!(
                    "[!] SP1_PROVER=local is deprecated in SP1 v6 Hypercube. \
                     Remapping to SP1_PROVER=cpu."
                );
                #[allow(deprecated)]
                std::env::set_var("SP1_PROVER", "cpu");
            }
            "mock" | "cpu" | "cuda" | "network" => { /* valid values */ }
            other => {
                eprintln!(
                    "[!] Unknown SP1_PROVER value '{}'. Valid values: mock, cpu, cuda, network",
                    other
                );
            }
        }
    }
}
