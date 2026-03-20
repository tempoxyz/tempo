use crate::input::*;

/// Normalized version of FuzzInput with all values clamped to valid ranges.
pub struct NormalizedInput {
    pub swarm: SwarmConfig,
    pub accounts: Vec<AccountSpec>,
    pub validators: Vec<ValidatorSpec>,
    pub blocks: Vec<BlockSpec>,
}

impl NormalizedInput {
    pub fn from_raw(raw: FuzzInput) -> Self {
        let mut input = raw;

        // Clamp accounts to 2..=16
        if input.accounts.is_empty() {
            input.accounts.push(AccountSpec {
                key_seed: 0,
                initial_balance: 1_000_000_000_000_000_000,
                initial_protocol_nonce: 0,
                user_nonce_seeds: vec![],
                hot: true,
            });
        }
        if input.accounts.len() < 2 {
            input.accounts.push(AccountSpec {
                key_seed: 1,
                initial_balance: 1_000_000_000_000_000_000,
                initial_protocol_nonce: 0,
                user_nonce_seeds: vec![],
                hot: false,
            });
        }
        input.accounts.truncate(16);

        // Clamp validators to 1..=8
        if input.validators.is_empty() {
            input.validators.push(ValidatorSpec {
                key_seed: 0,
                fee_recipient_seed: 0,
                active: true,
            });
        }
        input.validators.truncate(8);

        // Clamp blocks to 1..=3
        if input.blocks.is_empty() {
            input.blocks.push(BlockSpec {
                timestamp_delta_secs: 1,
                gas_limit: 30_000_000,
                shared_gas_limit: 10_000_000,
                general_gas_limit: 10_000_000,
                normal_txs: vec![],
                candidate_subblocks: vec![],
                system: SystemSpec {
                    include_metadata_tx: true,
                    duplicate_metadata_tx: false,
                    corrupt_rlp: false,
                    wrong_block_number: false,
                    metadata_order: MetadataOrderMode::AsSeen,
                },
            });
        }
        input.blocks.truncate(3);

        let num_accounts = input.accounts.len();
        let num_validators = input.validators.len();

        // Normalize each block
        for block in &mut input.blocks {
            // Clamp txs per block
            block.normal_txs.truncate(64);

            // Clamp subblocks per block
            block.candidate_subblocks.truncate(8);

            // Normalize gas limits
            block.gas_limit = block.gas_limit.max(1_000_000).min(100_000_000);
            block.shared_gas_limit = block.shared_gas_limit.min(block.gas_limit / 2);
            block.general_gas_limit = block.general_gas_limit.min(block.gas_limit);

            // Normalize tx indices
            for tx in &mut block.normal_txs {
                tx.sender_idx = tx.sender_idx % num_accounts as u8;
                if let Some(ref mut fp) = tx.fee_payer_idx {
                    *fp = *fp % num_accounts as u8;
                }
                if let Some(ref mut vi) = tx.subblock_validator_idx {
                    *vi = *vi % num_validators as u8;
                }
                // Normalize gas
                tx.gas_limit = tx.gas_limit.max(21_000).min(30_000_000);
                // Normalize nonce key for UserKey mode
                if matches!(tx.nonce_mode, NonceMode::UserKey) {
                    // Map to small hot pool
                    let hot_count = input.swarm.hot_nonce_key_count.max(1).min(8) as u128;
                    tx.nonce_key_raw = (tx.nonce_key_raw % hot_count) + 1; // keys 1..=8
                }
                // Normalize expiry delta based on swarm config
                if matches!(tx.nonce_mode, NonceMode::Expiring) {
                    tx.valid_before_delta = Some(match input.swarm.expiry_mode {
                        ExpirySkewMode::Past => 0, // will be adjusted to now-1
                        ExpirySkewMode::AtNow => 0,
                        ExpirySkewMode::AtNowPlus1 => 1,
                        ExpirySkewMode::AtMaxWindow => 30,
                        ExpirySkewMode::OverMaxWindow => 31,
                        ExpirySkewMode::WrapAroundBias => {
                            (tx.valid_before_delta.unwrap_or(15) % 31) + 1
                        }
                    });
                }
            }

            // Normalize subblock indices
            for subblock in &mut block.candidate_subblocks {
                subblock.validator_idx = subblock.validator_idx % num_validators as u8;
                let num_txs = block.normal_txs.len().max(1) as u16;
                subblock.tx_indexes.truncate(16);
                for idx in &mut subblock.tx_indexes {
                    *idx = *idx % num_txs;
                }
            }
        }

        // Normalize user nonce seeds per account
        for account in &mut input.accounts {
            account.user_nonce_seeds.truncate(4);
            for seed in &mut account.user_nonce_seeds {
                let hot_count = input.swarm.hot_nonce_key_count.max(1).min(8) as u128;
                seed.nonce_key_raw = (seed.nonce_key_raw % hot_count) + 1;
            }
        }

        NormalizedInput {
            swarm: input.swarm,
            accounts: input.accounts,
            validators: input.validators,
            blocks: input.blocks,
        }
    }

    /// Number of accounts
    pub fn num_accounts(&self) -> usize {
        self.accounts.len()
    }

    /// Number of validators
    pub fn num_validators(&self) -> usize {
        self.validators.len()
    }
}
