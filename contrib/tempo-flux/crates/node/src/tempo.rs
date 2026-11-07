//! Tempo protocol glue: genesis, load generation and the state view that
//! Tempo's block executor reads through.

use std::{
    convert::Infallible,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_consensus::transaction::Recovered;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, Cache, Database, InMemoryDB},
    interpreter::Word,
};
use reth_evm::BlockExecutorFactory;
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
    spec::TEMPO_T1_BASE_FEE,
};
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::{TempoBlockEnv, TempoEvmConfig, TempoEvmEnv, tempo_execution_config};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    error::TempoPrecompileError,
    nonce::NonceManager,
    storage::StorageCtx,
    tip_fee_manager::TipFeeManager,
    tip20::{ISSUER_ROLE, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::{TempoBlockExt, TempoTransaction, TempoTxEnvelope, transaction::Call};

pub const CHAIN_ID: u64 = 4217;
pub const BLOCK_GAS_LIMIT: u64 = 100_000_000_000;
const MINT: u128 = 1_000_000_000_000_000_000;
const FEE_PER_GAS: u128 = 100_000_000_000;
const TX_GAS_LIMIT: u64 = 300_000;

pub fn config() -> TempoEvmConfig {
    TempoEvmConfig::mainnet()
}

/// The hardfork mainnet runs today.
pub fn hardfork() -> TempoHardfork {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    TempoChainSpec::mainnet().tempo_hardfork_at(now)
}

pub fn env(hardfork: TempoHardfork, number: u64, timestamp_s: u64) -> TempoEvmEnv {
    let mut version = *tempo_execution_config(hardfork, CHAIN_ID).version();
    version.tx_gas_limit_cap = hardfork.tx_gas_limit_cap().unwrap_or(u64::MAX);
    TempoEvmEnv {
        spec: hardfork,
        version,
        block: TempoBlockEnv {
            number: U256::from(number),
            beneficiary: Address::repeat_byte(0x42),
            timestamp: U256::from(timestamp_s),
            basefee: U256::from(TEMPO_T1_BASE_FEE),
            gas_limit: U256::from(BLOCK_GAS_LIMIT),
            // Dev consensus runs no DKG, so no block may be an epoch boundary.
            ext: TempoBlockExt {
                epoch_length: std::num::NonZeroU64::new(1 << 62).unwrap(),
                ..Default::default()
            },
            ..Default::default()
        },
    }
}

/// Deploys the protocol precompiles' state (TIP-403 registry, TIP-20 factory,
/// pathUSD, fee manager, nonce manager) and mints pathUSD to `participants`.
pub fn genesis(participants: &[Address], hardfork: TempoHardfork) -> Cache {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut evm =
        BlockExecutorFactory::evm_with_env(&config(), InMemoryDB::default(), env(hardfork, 0, now));
    let admin = participants[0];
    StorageCtx::enter_evm(&mut evm, || {
        TIP403Registry::new().initialize()?;
        TIP20Factory::new().initialize()?;
        TIP20Factory::new().create_token_reserved_address(
            PATH_USD_ADDRESS,
            "pathUSD",
            "pathUSD",
            "USD",
            Address::ZERO,
            admin,
        )?;
        let mut token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
        token.grant_role_internal(admin, ISSUER_ROLE)?;
        for p in participants {
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: *p,
                    amount: U256::from(MINT),
                },
            )?;
        }
        TipFeeManager::new().initialize()?;
        NonceManager::new().initialize()?;
        Ok::<(), TempoPrecompileError>(())
    })
    .expect("seed genesis");
    evm.state_mut().commit_transaction();
    evm.state_mut().clear_transaction_state();
    evm.overlay_db().cache.clone()
}

/// Signs `count` 0x76 transactions, each a pathUSD transfer paying its fee in
/// pathUSD, spread over `accounts` senders with sequential protocol nonces.
pub fn presign(accounts: usize, count: usize, threads: usize) -> (Vec<Address>, Vec<Vec<u8>>) {
    let signers: Vec<_> = (0..accounts).map(|_| PrivateKeySigner::random()).collect();
    let addresses: Vec<Address> = signers.iter().map(|s| s.address()).collect();
    let per_thread = count.div_ceil(threads);
    let txs = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let (signers, addresses) = (&signers, &addresses);
                s.spawn(move || {
                    let end = ((t + 1) * per_thread).min(count);
                    (t * per_thread..end)
                        .map(|i| {
                            let to = addresses[(i.wrapping_mul(17) + 1) % accounts];
                            sign_transfer(&signers[i % accounts], to, (i / accounts) as u64)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    (addresses, txs)
}

fn sign_transfer(signer: &PrivateKeySigner, to: Address, nonce: u64) -> Vec<u8> {
    let input = ITIP20::transferCall {
        to,
        amount: U256::from(1),
    }
    .abi_encode();
    let tx = TempoTransaction {
        chain_id: CHAIN_ID,
        fee_token: Some(PATH_USD_ADDRESS),
        max_priority_fee_per_gas: FEE_PER_GAS,
        max_fee_per_gas: FEE_PER_GAS,
        gas_limit: TX_GAS_LIMIT,
        calls: vec![Call {
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: Bytes::from(input),
        }],
        access_list: Default::default(),
        nonce_key: Default::default(),
        nonce,
        fee_payer_signature: None,
        valid_before: None,
        valid_after: None,
        key_authorization: None,
        tempo_authorization_list: Vec::new(),
    };
    let sig = signer.sign_hash_sync(&tx.signature_hash()).expect("sign");
    TempoTxEnvelope::from(tx.into_signed(sig.into())).encoded_2718()
}

pub fn recovered(tx: TempoTxEnvelope, sender: Address) -> Recovered<TempoTxEnvelope> {
    Recovered::new_unchecked(tx, sender)
}

/// Read-only view of the node's state for one block's EVM.
pub struct StateView<'a>(pub &'a Cache);

impl Database for StateView<'_> {
    type Error = Infallible;

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Infallible> {
        Ok(self.0.accounts.get(address).cloned().flatten())
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Infallible> {
        Ok(self.0.contracts.get(code_hash).cloned().unwrap_or_default())
    }

    fn get_storage(&mut self, address: &Address, key: &Word) -> Result<Word, Infallible> {
        Ok(self
            .0
            .storage
            .get(address)
            .and_then(|s| s.slots.get(key).copied())
            .unwrap_or_default())
    }

    fn get_block_hash(&mut self, number: &Word) -> Result<B256, Infallible> {
        Ok(self.0.block_hashes.get(number).copied().unwrap_or_default())
    }
}
