use crate::crescendo::{config, tx_queue::TX_QUEUE};
use alloy::{
    network::TxSignerSync,
    primitives::{Address, TxKind, U128, U256},
    rpc::client::ClientBuilder,
    sol,
    sol_types::SolCall,
};
use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use dashmap::DashMap;
use futures::{StreamExt, stream::FuturesUnordered};
use rayon::prelude::*;
use std::{sync::Arc, time::Instant};
use tempo_precompiles::contracts::ITIP20;
use thousands::Separable;

type Nonces = DashMap<Address, u64>;
type Signers = Vec<PrivateKeySigner>;

sol! {
    interface ERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

pub struct TxGenerator {
    nonces: Arc<Nonces>,
    signers: Arc<Signers>,
}

impl TxGenerator {
    pub async fn new() -> eyre::Result<Arc<Self>> {
        let signers = Self::initialize_signers().await?;
        let nonces = Self::get_nonces(&signers).await?;

        Ok(Arc::new(Self {
            nonces: Arc::new(nonces),
            signers: Arc::new(signers),
        }))
    }

    async fn initialize_signers() -> eyre::Result<Signers> {
        let start = Instant::now();
        let config = &config::get().tx_gen_worker;

        let signers: Signers = (0..config.num_accounts)
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

        Ok(signers)
    }

    async fn get_nonces(addresses: &Signers) -> eyre::Result<Nonces> {
        let network_config = &config::get().network_worker;
        let client = ClientBuilder::default().http(
            network_config.target_urls[0]
                .parse()
                .map_err(|e| eyre::eyre!("Invalid RPC URL: {}", e))?,
        );

        let nonces: Nonces = DashMap::new();
        for chunk in addresses.chunks(network_config.max_concurrent_setup_requests) {
            let mut nonce_futures: FuturesUnordered<_> = chunk
                .iter()
                .map(|signer| {
                    let address = signer.address();
                    let client = &client;
                    async move {
                        let nonce = client
                            .request("eth_getTransactionCount", &(address, "latest"))
                            .map_resp(|resp: U128| resp.to::<u64>())
                            .await
                            .map_err(|e| {
                                eyre::eyre!(
                                    "Failed to get transaction count for address {}: {}",
                                    address,
                                    e
                                )
                            })?;
                        Ok::<(Address, u64), eyre::Error>((address, nonce))
                    }
                })
                .collect();

            while let Some(result) = nonce_futures.next().await {
                let (address, nonce) = result?;
                nonces.insert(address, nonce);
            }
        }

        Ok(nonces)
    }

    pub fn spawn_worker(self: Arc<Self>, worker_id: u32, worker_count: usize) {
        let config = &config::get().tx_gen_worker;

        let mut tx_batch = Vec::with_capacity(config.batch_size as usize);
        let worker_signers = self
            .signers
            .chunks(self.signers.len() / worker_count)
            .collect::<Vec<_>>()[worker_id as usize];

        loop {
            // Account we'll be sending from.
            let sender_index = fastrand::usize(..worker_signers.len());
            // Send to 1/Nth of the accounts.
            let recipient_index =
                fastrand::u32(..(config.num_accounts / config.recipient_distribution_factor));

            let (signer, recipient_addr) = (
                &worker_signers[sender_index],
                self.signers[recipient_index as usize].address(),
            );

            // Get and increment nonce atomically.
            let nonce = {
                let mut entry = self.nonces.get_mut(&signer.address()).unwrap();
                let current_nonce = *entry;
                *entry = current_nonce + 1;
                current_nonce
            };

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
}

pub fn sign_and_encode_tx(signer: &PrivateKeySigner, mut tx: TxLegacy) -> Vec<u8> {
    // TODO: Upstream to alloy the ability to use the secp256k1
    // crate instead of k256 for this which is like 5x+ faster.
    let signature = signer.sign_transaction_sync(&mut tx).unwrap();
    let mut payload = Vec::new();
    tx.into_signed(signature).eip2718_encode(&mut payload);
    payload
}
