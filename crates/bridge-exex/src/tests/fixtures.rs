//! Test fixtures for bridge e2e tests.
//!
//! Provides mock contracts, test accounts, and helper functions for
//! simulating the bridge environment with Anvil.

use alloy::{
    primitives::{address, keccak256, Address, B256},
    signers::local::PrivateKeySigner,
};

#[allow(dead_code)]
pub(super) const BRIDGE_ADDRESS: Address = address!("BBBB000000000000000000000000000000000000");

#[allow(dead_code)]
pub(super) const VALIDATOR_CONFIG_ADDRESS: Address =
    address!("CCCCCCCC00000000000000000000000000000000");

#[allow(dead_code)]
pub(super) const TEST_TIP20: Address = address!("20C0000000000000000000000001000000000000");

pub(super) const DEPOSIT_DOMAIN: &[u8] = b"TEMPO_BRIDGE_DEPOSIT_V1";

pub(super) const BURN_DOMAIN: &[u8] = b"TEMPO_BRIDGE_BURN_V1";

pub(super) const ANVIL_CHAIN_ID: u64 = 31337;

#[allow(dead_code)]
pub(super) const TEMPO_CHAIN_ID: u64 = 62049;

pub(super) fn anvil_accounts() -> Vec<(Address, PrivateKeySigner)> {
    let keys = [
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
        "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    ];

    keys.iter()
        .map(|k| {
            let signer: PrivateKeySigner = k.parse().unwrap();
            (signer.address(), signer)
        })
        .collect()
}

pub(super) fn compute_deposit_id(
    origin_chain_id: u64,
    origin_token: Address,
    origin_tx_hash: B256,
    origin_log_index: u32,
    tempo_recipient: Address,
    amount: u64,
    origin_block_number: u64,
) -> B256 {
    let mut buf = Vec::with_capacity(DEPOSIT_DOMAIN.len() + 8 + 20 + 32 + 4 + 20 + 8 + 8);
    buf.extend_from_slice(DEPOSIT_DOMAIN);
    buf.extend_from_slice(&origin_chain_id.to_be_bytes());
    buf.extend_from_slice(origin_token.as_slice());
    buf.extend_from_slice(origin_tx_hash.as_slice());
    buf.extend_from_slice(&origin_log_index.to_be_bytes());
    buf.extend_from_slice(tempo_recipient.as_slice());
    buf.extend_from_slice(&amount.to_be_bytes());
    buf.extend_from_slice(&origin_block_number.to_be_bytes());
    keccak256(&buf)
}

pub(super) fn compute_burn_id(
    origin_chain_id: u64,
    origin_token: Address,
    origin_recipient: Address,
    amount: u64,
    nonce: u64,
    sender: Address,
) -> B256 {
    let mut buf = Vec::with_capacity(BURN_DOMAIN.len() + 8 + 20 + 20 + 8 + 8 + 20);
    buf.extend_from_slice(BURN_DOMAIN);
    buf.extend_from_slice(&origin_chain_id.to_be_bytes());
    buf.extend_from_slice(origin_token.as_slice());
    buf.extend_from_slice(origin_recipient.as_slice());
    buf.extend_from_slice(&amount.to_be_bytes());
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf.extend_from_slice(sender.as_slice());
    keccak256(&buf)
}

pub(super) fn compute_threshold(validator_count: u64) -> u64 {
    (validator_count * 2).div_ceil(3)
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(super) struct TestDeposit {
    pub(super) deposit_id: B256,
    pub(super) origin_chain_id: u64,
    pub(super) origin_token: Address,
    pub(super) depositor: Address,
    pub(super) amount: u64,
    pub(super) tempo_recipient: Address,
    pub(super) nonce: u64,
    pub(super) tx_hash: B256,
    pub(super) log_index: u32,
    pub(super) block_number: u64,
}

impl TestDeposit {
    pub(super) fn new(
        origin_chain_id: u64,
        origin_token: Address,
        depositor: Address,
        amount: u64,
        tempo_recipient: Address,
        nonce: u64,
    ) -> Self {
        let tx_hash = B256::random();
        let log_index = 0;
        let block_number = 100;

        let deposit_id = compute_deposit_id(
            origin_chain_id,
            origin_token,
            tx_hash,
            log_index,
            tempo_recipient,
            amount,
            block_number,
        );

        Self {
            deposit_id,
            origin_chain_id,
            origin_token,
            depositor,
            amount,
            tempo_recipient,
            nonce,
            tx_hash,
            log_index,
            block_number,
        }
    }

    pub(super) fn usdc_deposit(amount: u64, recipient: Address) -> Self {
        let accounts = anvil_accounts();
        let (depositor, _) = &accounts[0];
        Self::new(
            ANVIL_CHAIN_ID,
            address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            *depositor,
            amount,
            recipient,
            0,
        )
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(super) struct TestBurn {
    pub(super) burn_id: B256,
    pub(super) origin_chain_id: u64,
    pub(super) origin_token: Address,
    pub(super) origin_recipient: Address,
    pub(super) amount: u64,
    pub(super) nonce: u64,
    pub(super) tempo_block_number: u64,
    pub(super) burner: Address,
}

impl TestBurn {
    pub(super) fn new(
        origin_chain_id: u64,
        origin_token: Address,
        origin_recipient: Address,
        amount: u64,
        nonce: u64,
        burner: Address,
        tempo_block_number: u64,
    ) -> Self {
        let burn_id = compute_burn_id(
            origin_chain_id,
            origin_token,
            origin_recipient,
            amount,
            nonce,
            burner,
        );

        Self {
            burn_id,
            origin_chain_id,
            origin_token,
            origin_recipient,
            amount,
            nonce,
            tempo_block_number,
            burner,
        }
    }

    pub(super) fn usdc_burn(amount: u64, recipient: Address, nonce: u64) -> Self {
        let accounts = anvil_accounts();
        let (burner, _) = &accounts[0];
        Self::new(
            ANVIL_CHAIN_ID,
            address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            recipient,
            amount,
            nonce,
            *burner,
            100,
        )
    }
}

#[derive(Debug, Clone)]
pub(super) struct MockValidatorSet {
    pub(super) validators: Vec<(Address, PrivateKeySigner)>,
    pub(super) threshold: u64,
}

impl MockValidatorSet {
    pub(super) fn new(count: usize) -> Self {
        let validators: Vec<_> = anvil_accounts().into_iter().take(count).collect();
        let threshold = compute_threshold(validators.len() as u64);
        Self {
            validators,
            threshold,
        }
    }

    pub(super) fn single() -> Self {
        Self::new(1)
    }

    pub(super) fn three_of_five() -> Self {
        Self::new(5)
    }

    pub(super) fn addresses(&self) -> Vec<Address> {
        self.validators.iter().map(|(addr, _)| *addr).collect()
    }

    pub(super) fn signers(&self) -> Vec<&PrivateKeySigner> {
        self.validators.iter().map(|(_, signer)| signer).collect()
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct MockBlockHeader {
    pub(super) block_number: u64,
    pub(super) block_hash: B256,
    #[allow(dead_code)]
    pub(super) state_root: B256,
    #[allow(dead_code)]
    pub(super) receipts_root: B256,
    #[allow(dead_code)]
    pub(super) parent_hash: B256,
}

impl MockBlockHeader {
    pub(super) fn at_height(height: u64) -> Self {
        Self {
            block_number: height,
            block_hash: B256::random(),
            state_root: B256::random(),
            receipts_root: B256::random(),
            parent_hash: if height > 0 {
                B256::random()
            } else {
                B256::ZERO
            },
        }
    }

    #[allow(dead_code)]
    pub(super) fn with_receipts_root(mut self, root: B256) -> Self {
        self.receipts_root = root;
        self
    }
}

#[derive(Debug, Clone)]
pub(super) struct MockReorg {
    pub(super) common_ancestor: u64,
    pub(super) old_chain: Vec<MockBlockHeader>,
    pub(super) new_chain: Vec<MockBlockHeader>,
}

impl MockReorg {
    pub(super) fn at_depth(ancestor: u64, reorg_depth: u64) -> Self {
        let old_chain: Vec<_> = (ancestor + 1..=ancestor + reorg_depth)
            .map(MockBlockHeader::at_height)
            .collect();

        let new_chain: Vec<_> = (ancestor + 1..=ancestor + reorg_depth)
            .map(MockBlockHeader::at_height)
            .collect();

        Self {
            common_ancestor: ancestor,
            old_chain,
            new_chain,
        }
    }

    pub(super) fn reorged_blocks(&self) -> Vec<u64> {
        self.old_chain.iter().map(|h| h.block_number).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anvil_accounts_valid() {
        let accounts = anvil_accounts();
        assert_eq!(accounts.len(), 5);

        for (address, signer) in &accounts {
            assert_eq!(*address, signer.address());
            assert!(!address.is_zero());
        }

        let addresses: Vec<_> = accounts.iter().map(|(a, _)| a).collect();
        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                assert_ne!(addresses[i], addresses[j], "Duplicate address found");
            }
        }
    }

    #[test]
    fn test_deposit_id_deterministic() {
        let id1 = compute_deposit_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            0,
            Address::repeat_byte(0x33),
            1_000_000,
            100,
        );

        let id2 = compute_deposit_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            0,
            Address::repeat_byte(0x33),
            1_000_000,
            100,
        );

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_burn_id_deterministic() {
        let id1 = compute_burn_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            1_000_000,
            0,
            Address::repeat_byte(0x33),
        );

        let id2 = compute_burn_id(
            ANVIL_CHAIN_ID,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            1_000_000,
            0,
            Address::repeat_byte(0x33),
        );

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_threshold_calculation() {
        assert_eq!(compute_threshold(1), 1);
        assert_eq!(compute_threshold(2), 2);
        assert_eq!(compute_threshold(3), 2);
        assert_eq!(compute_threshold(4), 3);
        assert_eq!(compute_threshold(5), 4);
        assert_eq!(compute_threshold(6), 4);
        assert_eq!(compute_threshold(10), 7);
        assert_eq!(compute_threshold(100), 67);
    }

    #[test]
    fn test_mock_validator_set() {
        let set = MockValidatorSet::three_of_five();
        assert_eq!(set.validators.len(), 5);
        assert_eq!(set.threshold, 4);
        assert_eq!(set.addresses().len(), 5);
        assert_eq!(set.signers().len(), 5);
    }

    #[test]
    fn test_test_deposit_creation() {
        let deposit = TestDeposit::usdc_deposit(1_000_000, Address::repeat_byte(0x42));
        assert!(!deposit.deposit_id.is_zero());
        assert_eq!(deposit.amount, 1_000_000);
        assert_eq!(deposit.tempo_recipient, Address::repeat_byte(0x42));
    }

    #[test]
    fn test_test_burn_creation() {
        let burn = TestBurn::usdc_burn(1_000_000, Address::repeat_byte(0x42), 0);
        assert!(!burn.burn_id.is_zero());
        assert_eq!(burn.amount, 1_000_000);
        assert_eq!(burn.origin_recipient, Address::repeat_byte(0x42));
    }

    #[test]
    fn test_mock_reorg() {
        let reorg = MockReorg::at_depth(100, 3);
        assert_eq!(reorg.common_ancestor, 100);
        assert_eq!(reorg.old_chain.len(), 3);
        assert_eq!(reorg.new_chain.len(), 3);
        assert_eq!(reorg.reorged_blocks(), vec![101, 102, 103]);
    }
}
