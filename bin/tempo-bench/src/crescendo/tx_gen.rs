use std::{sync::LazyLock, time::Instant};

use alloy::{
    network::TxSignerSync,
    primitives::{Address, TxKind, U256},
    sol,
    sol_types::SolCall,
};
use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use dashmap::DashMap;
use rayon::prelude::*;
use tempo_precompiles::contracts::ITIP20;
use thousands::Separable;

use crate::crescendo::{config, tx_queue::TX_QUEUE};

static NONCE_MAP: LazyLock<DashMap<u32, u64>> = LazyLock::new(|| {
    let map = DashMap::with_capacity(config::get().tx_gen_worker.num_accounts as usize);
    for i in 0..config::get().tx_gen_worker.num_accounts {
        map.insert(i, 0);
    }
    map
});

static SIGNER_LIST: LazyLock<Vec<PrivateKeySigner>> = LazyLock::new(|| {
    let start = Instant::now();
    let config = &config::get().tx_gen_worker;
    let list: Vec<PrivateKeySigner> = (0..config.num_accounts)
        .into_par_iter()
        .map(|i| {
            MnemonicBuilder::<English>::default()
                .phrase(&config.mnemonic)
                .index(i)
                .unwrap()
                .build()
                .unwrap()
        })
        .collect();
    let duration = start.elapsed();
    println!(
        "[+] Initialized signer list of length {} in {:.1?}",
        config.num_accounts.separate_with_commas(),
        duration
    );
    list
});

sol! {
    interface ERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

//  TODO: pre generate `n` transactions from all of these accounts and then send them all
//  through the queue which will throttle tps accordingly.
pub fn tx_gen_worker(_worker_id: u32) {
    let config = &config::get().tx_gen_worker;

    let mut tx_batch = Vec::with_capacity(config.batch_size as usize);

    loop {
        // Account we'll be sending from.
        let sender_index = fastrand::u32(..config.num_accounts);
        // Send to 1/Nth of the accounts.
        let recipient_index =
            fastrand::u32(..(config.num_accounts / config.recipient_distribution_factor));

        // Get and increment nonce atomically.
        let nonce = {
            let mut entry = NONCE_MAP.get_mut(&sender_index).unwrap();
            let current_nonce = *entry;
            *entry = current_nonce + 1;
            current_nonce
        };

        let (signer, recipient_addr) = (
            &SIGNER_LIST[sender_index as usize],
            SIGNER_LIST[recipient_index as usize].address(),
        );

        let tx = sign_and_encode_tx(
            signer,
            TxLegacy {
                chain_id: Some(config.chain_id),
                nonce,
                gas_price: config.gas_price as u128,
                gas_limit: config.gas_limit,
                to: TxKind::Call(config.token_contract_address.parse::<Address>().unwrap()),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: recipient_addr,
                    amount: U256::from(fastrand::u64(1..=config.max_transfer_amount)),
                }
                .abi_encode()
                .into(),
            },
        );

        tx_batch.push(tx);

        // Once we've accumulated batch_size transactions, drain them all to the queue.
        if tx_batch.len() >= config.batch_size as usize {
            TX_QUEUE.push_txs(std::mem::take(&mut tx_batch));
        }
    }
}

pub fn sign_and_encode_tx(signer: &PrivateKeySigner, mut tx: TxLegacy) -> Vec<u8> {
    // TODO: Upstream to alloy the ability to use the secp256k1
    // crate instead of k256 for this which is like 5x+ faster.
    let signature = signer.sign_transaction_sync(&mut tx).unwrap();
    let mut payload = Vec::new();
    tx.into_signed(signature).eip2718_encode(&mut payload);
    payload
}
