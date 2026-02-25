use sp1_sdk::{blocking::MockProver, blocking::Prover, include_elf, Elf, HashableKey, ProvingKey};

/// The ELF for the Ethereum Light Client zkVM program.
const LC_ELF: Elf = include_elf!("eth-lc-program");

fn main() {
    let prover = MockProver::new();
    let pk = prover.setup(LC_ELF).expect("failed to setup elf");
    println!("{}", pk.verifying_key().bytes32());
}
