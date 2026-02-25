//! Network configurations for Ethereum beacon chains.
//!
//! Provides genesis parameters and fork versions for Sepolia (testnet)
//! and Ethereum Mainnet.

use crate::types::{Address, Bytes32, ChainId, L2ChainConfig, NetworkConfig, SLOTS_PER_EPOCH};

// =============================================================================
// Sepolia Testnet
// =============================================================================

/// Sepolia genesis validators root.
pub const SEPOLIA_GENESIS_VALIDATORS_ROOT: Bytes32 = [
    0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05,
    0x2a, 0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b,
    0x80, 0x78,
];

/// Sepolia genesis time (Unix timestamp).
pub const SEPOLIA_GENESIS_TIME: u64 = 1655733600;

/// Get the Sepolia testnet configuration.
pub fn sepolia_config() -> NetworkConfig {
    NetworkConfig {
        genesis_validators_root: SEPOLIA_GENESIS_VALIDATORS_ROOT,
        genesis_time: SEPOLIA_GENESIS_TIME,
        altair_fork_version: [0x90, 0x00, 0x00, 0x70],
        altair_fork_epoch: 50,
        bellatrix_fork_version: [0x90, 0x00, 0x00, 0x71],
        bellatrix_fork_epoch: 100,
        capella_fork_version: [0x90, 0x00, 0x00, 0x73],
        capella_fork_epoch: 56832,
        deneb_fork_version: [0x90, 0x00, 0x00, 0x74],
        deneb_fork_epoch: 132608,
        electra_fork_version: [0x90, 0x00, 0x00, 0x75],
        electra_fork_epoch: 222464,  // Sepolia Electra epoch
        fulu_fork_version: [0x90, 0x00, 0x00, 0x76],
        fulu_fork_epoch: u64::MAX,  // Not yet scheduled on Sepolia
    }
}

// =============================================================================
// Ethereum Mainnet
// =============================================================================

/// Mainnet genesis validators root.
pub const MAINNET_GENESIS_VALIDATORS_ROOT: Bytes32 = [
    0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd,
    0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b,
    0xfe, 0x95,
];

/// Mainnet genesis time (Unix timestamp).
pub const MAINNET_GENESIS_TIME: u64 = 1606824023;

/// Get the Ethereum mainnet configuration.
pub fn mainnet_config() -> NetworkConfig {
    NetworkConfig {
        genesis_validators_root: MAINNET_GENESIS_VALIDATORS_ROOT,
        genesis_time: MAINNET_GENESIS_TIME,
        altair_fork_version: [0x01, 0x00, 0x00, 0x00],
        altair_fork_epoch: 74240,
        bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
        bellatrix_fork_epoch: 144896,
        capella_fork_version: [0x03, 0x00, 0x00, 0x00],
        capella_fork_epoch: 194048,
        deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
        deneb_fork_epoch: 269568,
        electra_fork_version: [0x05, 0x00, 0x00, 0x00],
        electra_fork_epoch: 364032,  // Mainnet Electra/Pectra epoch
        fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
        fulu_fork_epoch: 411392,  // Mainnet Fulu epoch
    }
}

// =============================================================================
// Fork Version Helpers
// =============================================================================

impl NetworkConfig {
    /// Get the fork version for a given epoch.
    ///
    /// Returns the latest applicable fork version at the given epoch.
    pub fn fork_version_for_epoch(&self, epoch: u64) -> [u8; 4] {
        if epoch >= self.fulu_fork_epoch {
            self.fulu_fork_version
        } else if epoch >= self.electra_fork_epoch {
            self.electra_fork_version
        } else if epoch >= self.deneb_fork_epoch {
            self.deneb_fork_version
        } else if epoch >= self.capella_fork_epoch {
            self.capella_fork_version
        } else if epoch >= self.bellatrix_fork_epoch {
            self.bellatrix_fork_version
        } else if epoch >= self.altair_fork_epoch {
            self.altair_fork_version
        } else {
            // Phase 0 genesis fork version — shouldn't be used for sync committee
            [0x00, 0x00, 0x00, 0x00]
        }
    }

    /// Get the fork version for a given slot.
    pub fn fork_version_for_slot(&self, slot: u64) -> [u8; 4] {
        let epoch = slot / SLOTS_PER_EPOCH;
        self.fork_version_for_epoch(epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sepolia_fork_versions() {
        let config = sepolia_config();
        // Before Altair
        assert_eq!(
            config.fork_version_for_epoch(0),
            [0x00, 0x00, 0x00, 0x00]
        );
        // At Altair
        assert_eq!(
            config.fork_version_for_epoch(50),
            [0x90, 0x00, 0x00, 0x70]
        );
        // At Deneb
        assert_eq!(
            config.fork_version_for_epoch(132608),
            [0x90, 0x00, 0x00, 0x74]
        );
        // After Deneb
        assert_eq!(
            config.fork_version_for_epoch(200000),
            [0x90, 0x00, 0x00, 0x74]
        );
    }

    #[test]
    fn test_mainnet_genesis_values() {
        let config = mainnet_config();
        assert_eq!(config.genesis_time, 1606824023);
        assert_eq!(config.genesis_validators_root[0], 0x4b);
    }
}

// =============================================================================
// Base L2 Chain Configurations (OP Stack)
// =============================================================================

/// L2OutputOracle contract address on Ethereum mainnet for Base.
pub const BASE_MAINNET_L2_OUTPUT_ORACLE: Address = [
    0x56, 0x31, 0x5b, 0x90, 0xc4, 0x07, 0x30, 0x92, 0x5e, 0xc5,
    0x48, 0x5c, 0xf0, 0x04, 0xd8, 0x35, 0x05, 0x85, 0x18, 0xA0,
];

/// L2OutputOracle contract address on Ethereum Sepolia for Base Sepolia.
pub const BASE_SEPOLIA_L2_OUTPUT_ORACLE: Address = [
    0x84, 0x45, 0x7c, 0xa9, 0xD0, 0x16, 0x3F, 0xbC, 0x4b, 0xbf,
    0xe4, 0xDf, 0xbb, 0x20, 0xba, 0x46, 0xe4, 0x8D, 0xD1, 0x9F,
];

/// Storage slot for `latestOutputIndex()` in L2OutputOracle.
/// `keccak256("latestOutputIndex") - 1` is not used; the actual slot is 4 for
/// the OP Stack L2OutputOracle contract.
pub const L2_OUTPUT_ORACLE_LATEST_INDEX_SLOT: u64 = 4;

/// Storage slot offset for `l2Outputs` mapping in L2OutputOracle.
/// Slot 3 stores the `l2Outputs` dynamic array length. Individual outputs
/// are at `keccak256(3) + index * 2`.
pub const L2_OUTPUT_ORACLE_OUTPUTS_SLOT: u64 = 3;

/// Get Base Mainnet L2 chain configuration.
pub fn base_mainnet_config() -> L2ChainConfig {
    L2ChainConfig {
        chain_id: ChainId::BaseMainnet,
        l2_output_oracle: BASE_MAINNET_L2_OUTPUT_ORACLE,
        l1_chain_id: ChainId::EthereumMainnet,
        l2_rpc_url: "https://mainnet.base.org".to_string(),
    }
}

/// Get Base Sepolia L2 chain configuration.
pub fn base_sepolia_config() -> L2ChainConfig {
    L2ChainConfig {
        chain_id: ChainId::BaseSepolia,
        l2_output_oracle: BASE_SEPOLIA_L2_OUTPUT_ORACLE,
        l1_chain_id: ChainId::EthereumSepolia,
        l2_rpc_url: "https://sepolia.base.org".to_string(),
    }
}

/// Get the L2 chain config by chain ID.
pub fn l2_config_for_chain(chain_id: ChainId) -> Option<L2ChainConfig> {
    match chain_id {
        ChainId::BaseMainnet => Some(base_mainnet_config()),
        ChainId::BaseSepolia => Some(base_sepolia_config()),
        _ => None,
    }
}
