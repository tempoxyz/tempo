//! Spam deposit transactions to a zone's L1 portal for throughput testing.
//!
//! Uses multiple funded signers and Tempo's `valid_after` field to queue
//! deposits in the mempool, making them all eligible for inclusion at the
//! same block.

use alloy::{
    network::primitives::ReceiptResponse,
    primitives::{Address, B256, Bytes, TxKind, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use eyre::{Context as _, eyre};
use std::{collections::BTreeMap, num::NonZeroU64, time::Instant};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::transaction::Call;
use tempo_zone_contracts::{DepositPayload, ZonePortal};
use zone_precompiles::ecies::encrypt_deposit;

use crate::zone_utils::parse_private_key;

#[derive(Debug, clap::Parser)]
pub(crate) struct SpamDeposits {
    /// Tempo L1 RPC URL.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,

    /// ZonePortal contract address on Tempo L1.
    #[arg(long, env = "L1_PORTAL_ADDRESS")]
    portal: Address,

    /// Private key (hex) of the funding/whale account.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// Total number of deposits to send.
    #[arg(long)]
    total: usize,

    /// Target deposits per block (= number of signers).
    #[arg(long)]
    per_block: usize,

    /// Amount per deposit (in smallest token units, includes fee).
    #[arg(long, default_value_t = 1_000_000)]
    amount: u128,

    /// TIP-20 token address to deposit.
    #[arg(long, default_value_t = PATH_USD_ADDRESS)]
    token: Address,

    /// Seconds into the future for the valid_after timestamp.
    #[arg(long, default_value_t = 3)]
    lead_time: u64,
}

impl SpamDeposits {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        if self.per_block == 0 {
            return Err(eyre!("--per-block must be at least 1"));
        }

        let start = Instant::now();

        // Parse whale key & create provider
        let whale = parse_private_key(&self.private_key)?;
        let whale_addr = whale.address();
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(whale)
            .connect(&self.l1_rpc_url)
            .await?;

        let chain_id = provider.get_chain_id().await?;
        let gas_price = provider.get_gas_price().await?;
        let portal = ZonePortal::new(self.portal, &provider);
        let deposit_fee = portal.calculateDepositFee().call().await?;

        println!("Chain ID: {chain_id}");
        println!("Gas price: {gas_price}");
        println!("Deposit fee: {deposit_fee}");

        if self.amount <= deposit_fee {
            return Err(eyre!(
                "amount ({}) must exceed deposit fee ({deposit_fee})",
                self.amount
            ));
        }

        // ── Phase 1: Setup signers ──────────────────────────────────────

        let num_signers = self.per_block;
        let deposits_per_signer = self.total.div_ceil(num_signers);

        println!("Generating {num_signers} signers ({deposits_per_signer} deposits each)...");
        let signers: Vec<PrivateKeySigner> = (0..num_signers)
            .map(|_| PrivateKeySigner::random())
            .collect();

        // Budget: tokens for deposits + 10% headroom for gas (Tempo L1 pays gas in TIP-20)
        let token_budget = U256::from(self.amount) * U256::from(deposits_per_signer);
        let funding_per_signer = token_budget * U256::from(150) / U256::from(100);

        println!("Funding {num_signers} signers with {funding_per_signer} each...");
        let token_contract = ITIP20::new(self.token, &provider);
        for (i, signer) in signers.iter().enumerate() {
            token_contract
                .transfer(signer.address(), funding_per_signer)
                .send_sync()
                .await
                .wrap_err_with(|| format!("failed to fund signer {i}"))?;
        }

        println!("Approving portal for all signers...");
        for (i, signer) in signers.iter().enumerate() {
            let p = ProviderBuilder::new_with_network::<TempoNetwork>()
                .wallet(signer.clone())
                .connect(&self.l1_rpc_url)
                .await?;
            let token = ITIP20::new(self.token, &p);
            token
                .approve(self.portal, U256::MAX)
                .send_sync()
                .await
                .wrap_err_with(|| format!("failed to approve for signer {i}"))?;
        }

        let (key, key_index) = portal
            .encryption_key()
            .await
            .wrap_err("failed to fetch encryption key — is one set?")?;
        let y_parity = key.normalized_y_parity().ok_or_else(|| {
            eyre!(
                "unexpected yParity {:#x}, expected 0/1 or 0x02/0x03",
                key.yParity
            )
        })?;
        println!(
            "Encryption key index: {key_index}, x: {}, parity: {y_parity:#x}",
            key.x
        );
        let enc_setup = (key.x, y_parity, key_index);

        let setup_elapsed = start.elapsed();
        println!("Setup complete in {:.1}s\n", setup_elapsed.as_secs_f64());

        // ── Phase 2: Spam waves ─────────────────────────────────────────

        let num_waves = deposits_per_signer;
        let mut total_sent = 0usize;
        let mut total_confirmed = 0usize;
        let mut block_counts: BTreeMap<u64, usize> = BTreeMap::new();
        let spam_start = Instant::now();

        for wave in 0..num_waves {
            let remaining = self.total - total_sent;
            let batch_size = remaining.min(num_signers);
            if batch_size == 0 {
                break;
            }

            // Target timestamp: current time + lead_time
            let target_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + self.lead_time;

            println!(
                "Wave {}/{num_waves}: sending {batch_size} deposits (valid_after: {target_ts})...",
                wave + 1
            );

            // Build and sign all deposits (pure computation, no IO)
            let mut encoded_txs = Vec::with_capacity(batch_size);
            for signer in signers.iter().take(batch_size) {
                let calldata =
                    self.build_deposit_calldata(whale_addr, signer.address(), &enc_setup)?;
                let nonce_key = U256::from(rand::random::<u128>());

                let tx = tempo_primitives::TempoTransaction {
                    chain_id,
                    max_fee_per_gas: gas_price * 3,
                    max_priority_fee_per_gas: gas_price,
                    gas_limit: 2_000_000,
                    calls: vec![Call {
                        to: TxKind::Call(self.portal),
                        value: U256::ZERO,
                        input: Bytes::from(calldata),
                    }],
                    nonce_key,
                    nonce: 0,
                    valid_after: Some(
                        NonZeroU64::new(target_ts).expect("target timestamp is always non-zero"),
                    ),
                    ..Default::default()
                };

                let sig_hash = tx.signature_hash();
                let sig = signer.sign_hash_sync(&sig_hash)?;
                encoded_txs.push(tx.into_signed(sig.into()).encoded_2718());
            }

            // Send all deposits concurrently (returns receipts directly)
            let receipts: Vec<_> =
                futures::future::join_all(encoded_txs.iter().enumerate().map(|(i, encoded)| {
                    let provider = &provider;
                    async move {
                        provider
                            .send_raw_transaction_sync(encoded)
                            .await
                            .map_err(|e| {
                                eprintln!("  deposit {i} failed: {e}");
                                e
                            })
                    }
                }))
                .await;

            for (i, result) in receipts.into_iter().enumerate() {
                match result {
                    Ok(receipt) => {
                        total_sent += 1;
                        if receipt.status() {
                            total_confirmed += 1;
                            if let Some(block_num) = receipt.block_number {
                                *block_counts.entry(block_num).or_default() += 1;
                            }
                        } else {
                            let signer = signers.get(i).map(|s| s.address()).unwrap_or_default();
                            eprintln!(
                                "  deposit reverted: tx={} signer={signer}",
                                receipt.transaction_hash,
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("  failed to send/confirm deposit {i}: {e}");
                    }
                }
            }
        }

        // ── Phase 3: Report ─────────────────────────────────────────────

        let spam_elapsed = spam_start.elapsed();
        let total_elapsed = start.elapsed();

        println!("\n== Results ==");
        println!("  Total sent:      {total_sent}");
        println!("  Total confirmed: {total_confirmed}");
        println!("  Spam duration:   {:.1}s", spam_elapsed.as_secs_f64());
        println!("  Total elapsed:   {:.1}s", total_elapsed.as_secs_f64());
        if spam_elapsed.as_millis() > 0 {
            println!(
                "  Throughput:      {:.2} deposits/s",
                total_confirmed as f64 / spam_elapsed.as_secs_f64()
            );
        }

        if !block_counts.is_empty() {
            println!("\n  Block Distribution:");
            for (block, count) in &block_counts {
                println!("    Block {block}: {count} deposits");
            }

            let counts: Vec<usize> = block_counts.values().copied().collect();
            let avg = counts.iter().sum::<usize>() as f64 / counts.len() as f64;
            let max = counts.iter().max().unwrap_or(&0);
            let min = counts.iter().min().unwrap_or(&0);
            println!("\n  Avg/Max/Min deposits per block: {avg:.1} / {max} / {min}");
        }

        Ok(())
    }

    /// Build the calldata for a single deposit.
    fn build_deposit_calldata(
        &self,
        recipient: Address,
        sender: Address,
        enc_setup: &(B256, u8, U256),
    ) -> eyre::Result<Vec<u8>> {
        let &(pub_x, y_parity, key_index) = enc_setup;
        let encrypted = encrypt_deposit(
            &pub_x,
            y_parity,
            recipient,
            B256::ZERO,
            sender,
            self.portal,
            key_index,
        )
        .ok_or_else(|| eyre!("ECIES encryption failed"))?;

        let payload = DepositPayload {
            ephemeralPubkeyX: encrypted.eph_pub_x,
            ephemeralPubkeyYParity: encrypted.eph_pub_y_parity,
            ciphertext: Bytes::from(encrypted.ciphertext),
            nonce: encrypted.nonce.into(),
            tag: encrypted.tag.into(),
        };

        Ok(ZonePortal::depositCall {
            token: self.token,
            amount: self.amount,
            keyIndex: key_index,
            encrypted: payload,
            tempoRefundRecipient: recipient,
        }
        .abi_encode())
    }
}
