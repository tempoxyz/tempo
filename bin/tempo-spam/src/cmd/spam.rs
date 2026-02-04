//! Spam command implementation for comprehensive testnet load generation.
//!
//! This generates transactions covering all major Tempo subsystems:
//! - TIP20: transfers, mints, burns, approvals, rewards
//! - StablecoinDEX: orders (bid/ask), swaps, flip orders, cancellations
//! - FeeAMM: mints, burns, rebalance swaps, fee distribution
//! - Nonce: 2D nonce increments
//! - AccountKeychain: key authorization, revocation, spending limits
//! - TIP20Factory: token creation
//! - TIP403Registry: policy creation and management

use std::{
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, Secp256k1Signer},
    transports::http::reqwest::Url,
};
use clap::Parser;
use eyre::{Context, OptionExt};
use futures::{StreamExt, TryStreamExt, stream};
use indicatif::{ProgressBar, ProgressStyle};
use rand::random_range;
use reth_tracing::{RethTracer, Tracer, tracing::info};
use tempo_alloy::{TempoNetwork, provider::ext::TempoProviderBuilderExt};
use tempo_contracts::precompiles::{
    IFeeManager::IFeeManagerInstance,
    IRolesAuth,
    IStablecoinDEX::IStablecoinDEXInstance,
    ITIP20::ITIP20Instance,
    ITIP20Factory::{self, ITIP20FactoryInstance},
    ITIP403Registry::{self, ITIP403RegistryInstance},
    ITIPFeeAMM::ITIPFeeAMMInstance,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::DEFAULT_FEE_TOKEN, tip20::ISSUER_ROLE,
};

use crate::actions::{ActionContext, ActionType, pick_random_action};

/// Run comprehensive transaction spam covering all Tempo codepaths
#[derive(Parser, Debug)]
pub struct SpamArgs {
    /// Target transactions per second
    #[arg(short, long, default_value_t = 100)]
    tps: u64,

    /// Test duration in seconds
    #[arg(short, long, default_value_t = 60)]
    duration: u64,

    /// Number of accounts for pre-generation
    #[arg(short, long, default_value_t = NonZeroU64::new(20).unwrap())]
    accounts: NonZeroU64,

    /// Mnemonic for generating accounts (use "random" for random mnemonic)
    #[arg(short, long, default_value = "random")]
    mnemonic: String,

    /// Starting index in the mnemonic derivation path
    #[arg(short, long, default_value_t = 0)]
    from_mnemonic_index: u32,

    /// Fee token address
    #[arg(long, default_value_t = DEFAULT_FEE_TOKEN)]
    fee_token: Address,

    /// Target URLs for network connections
    #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append, default_values_t = vec!["http://localhost:8545".parse::<Url>().unwrap()])]
    target_urls: Vec<Url>,

    /// Maximum concurrent requests
    #[arg(long, default_value_t = 100)]
    max_concurrent_requests: usize,

    /// Maximum pending transactions before waiting for receipts
    #[arg(long, default_value_t = 5000)]
    max_pending_txs: usize,

    /// Fund accounts from the faucet before running
    #[arg(long)]
    faucet: bool,

    /// Disable 2D nonces
    #[arg(long)]
    disable_2d_nonces: bool,

    /// Number of user tokens to create for testing
    #[arg(long, default_value_t = 4)]
    user_tokens: usize,

    /// Weight for TIP20 transfer transactions
    #[arg(long, default_value_t = 20)]
    weight_tip20_transfer: u32,

    /// Weight for TIP20 transferFrom transactions
    #[arg(long, default_value_t = 10)]
    weight_tip20_transfer_from: u32,

    /// Weight for TIP20 approve transactions
    #[arg(long, default_value_t = 5)]
    weight_tip20_approve: u32,

    /// Weight for TIP20 mint transactions
    #[arg(long, default_value_t = 5)]
    weight_tip20_mint: u32,

    /// Weight for TIP20 burn transactions
    #[arg(long, default_value_t = 3)]
    weight_tip20_burn: u32,

    /// Weight for TIP20 reward distribution
    #[arg(long, default_value_t = 2)]
    weight_tip20_reward: u32,

    /// Weight for DEX place order transactions
    #[arg(long, default_value_t = 15)]
    weight_dex_place: u32,

    /// Weight for DEX place flip order transactions
    #[arg(long, default_value_t = 5)]
    weight_dex_place_flip: u32,

    /// Weight for DEX cancel order transactions
    #[arg(long, default_value_t = 3)]
    weight_dex_cancel: u32,

    /// Weight for DEX swap transactions
    #[arg(long, default_value_t = 10)]
    weight_dex_swap: u32,

    /// Weight for DEX withdraw transactions
    #[arg(long, default_value_t = 2)]
    weight_dex_withdraw: u32,

    /// Weight for DEX deposit transactions
    #[arg(long, default_value_t = 2)]
    weight_dex_deposit: u32,

    /// Weight for FeeAMM mint transactions
    #[arg(long, default_value_t = 5)]
    weight_amm_mint: u32,

    /// Weight for FeeAMM burn transactions
    #[arg(long, default_value_t = 3)]
    weight_amm_burn: u32,

    /// Weight for FeeAMM rebalance swap transactions
    #[arg(long, default_value_t = 3)]
    weight_amm_rebalance: u32,

    /// Weight for FeeAMM distribute fees transactions
    #[arg(long, default_value_t = 2)]
    weight_amm_distribute_fees: u32,

    /// Weight for Nonce increment transactions
    #[arg(long, default_value_t = 5)]
    weight_nonce_increment: u32,

    /// Weight for token creation transactions
    #[arg(long, default_value_t = 1)]
    weight_token_create: u32,

    /// Weight for TIP403 policy transactions
    #[arg(long, default_value_t = 2)]
    weight_policy_modify: u32,
}

impl SpamArgs {
    pub async fn run(self) -> eyre::Result<()> {
        RethTracer::new().init()?;

        let mnemonic = if self.mnemonic == "random" {
            let mut rng = rand_08::thread_rng();
            use alloy::signers::local::coins_bip39::{English, Mnemonic};
            Mnemonic::<English>::new(&mut rng).to_phrase()
        } else {
            self.mnemonic.clone()
        };

        let accounts = self.accounts.get() as usize;
        info!(accounts, "Creating signers");

        // Create signer providers
        let signer_providers = create_signer_providers(
            &mnemonic,
            self.from_mnemonic_index,
            accounts,
            &self.target_urls,
            self.disable_2d_nonces,
        )?;

        let provider = signer_providers[0].1.clone();

        // Fund accounts if requested
        if self.faucet {
            info!("Funding accounts from faucet");
            fund_accounts(
                &provider,
                &signer_providers
                    .iter()
                    .map(|(s, _)| s.address())
                    .collect::<Vec<_>>(),
                self.max_concurrent_requests,
            )
            .await?;
        }

        // Set fee tokens for all signers
        info!(fee_token = %self.fee_token, "Setting default fee tokens");
        set_fee_tokens(
            &signer_providers,
            self.fee_token,
            self.max_concurrent_requests,
        )
        .await?;

        // Setup test infrastructure (tokens, DEX pairs, AMM pools)
        info!(
            user_tokens = self.user_tokens,
            "Setting up test infrastructure"
        );
        let ctx = setup_test_infrastructure(
            &signer_providers,
            self.user_tokens,
            self.max_concurrent_requests,
        )
        .await?;

        // Build action weights
        let weights = vec![
            (ActionType::Tip20Transfer, self.weight_tip20_transfer),
            (
                ActionType::Tip20TransferFrom,
                self.weight_tip20_transfer_from,
            ),
            (ActionType::Tip20Approve, self.weight_tip20_approve),
            (ActionType::Tip20Mint, self.weight_tip20_mint),
            (ActionType::Tip20Burn, self.weight_tip20_burn),
            (ActionType::Tip20DistributeReward, self.weight_tip20_reward),
            (ActionType::DexPlace, self.weight_dex_place),
            (ActionType::DexPlaceFlip, self.weight_dex_place_flip),
            (ActionType::DexCancel, self.weight_dex_cancel),
            (ActionType::DexSwap, self.weight_dex_swap),
            (ActionType::DexWithdraw, self.weight_dex_withdraw),
            (ActionType::DexDeposit, self.weight_dex_deposit),
            (ActionType::AmmMint, self.weight_amm_mint),
            (ActionType::AmmBurn, self.weight_amm_burn),
            (ActionType::AmmRebalance, self.weight_amm_rebalance),
            (
                ActionType::AmmDistributeFees,
                self.weight_amm_distribute_fees,
            ),
            (ActionType::NonceIncrement, self.weight_nonce_increment),
            (ActionType::TokenCreate, self.weight_token_create),
            (ActionType::PolicyModify, self.weight_policy_modify),
        ];

        let total_weight: u32 = weights.iter().map(|(_, w)| *w).sum();
        if total_weight == 0 {
            return Err(eyre::eyre!("All weights are zero, nothing to do"));
        }

        // Run the spam loop
        info!(
            tps = self.tps,
            duration = self.duration,
            total_txs = self.tps * self.duration,
            "Starting spam run"
        );

        run_spam_loop(
            ctx,
            signer_providers,
            weights,
            self.tps,
            self.duration,
            self.max_concurrent_requests,
            self.max_pending_txs,
        )
        .await?;

        info!("Spam run complete");
        Ok(())
    }
}

fn create_signer_providers(
    mnemonic: &str,
    from_index: u32,
    count: usize,
    target_urls: &[Url],
    disable_2d_nonces: bool,
) -> eyre::Result<Vec<(Secp256k1Signer, DynProvider<TempoNetwork>)>> {
    let mut signer_providers = Vec::with_capacity(count);

    for i in 0..count {
        let index = from_index + i as u32;
        let signer = MnemonicBuilder::from_phrase_nth(mnemonic, index).into_secp256k1();
        let target_url = target_urls[i % target_urls.len()].clone();

        let provider: DynProvider<TempoNetwork> = if disable_2d_nonces {
            ProviderBuilder::new_with_network::<TempoNetwork>()
                .fetch_chain_id()
                .with_gas_estimation()
                .wallet(EthereumWallet::from(signer.clone()))
                .connect_http(target_url)
                .erased()
        } else {
            ProviderBuilder::new_with_network::<TempoNetwork>()
                .with_random_2d_nonces()
                .with_gas_estimation()
                .wallet(EthereumWallet::from(signer.clone()))
                .connect_http(target_url)
                .erased()
        };

        signer_providers.push((signer, provider));
    }

    Ok(signer_providers)
}

async fn fund_accounts(
    provider: &DynProvider<TempoNetwork>,
    addresses: &[Address],
    max_concurrent: usize,
) -> eyre::Result<()> {
    let progress = ProgressBar::new(addresses.len() as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} Funding accounts")?
            .progress_chars("##-"),
    );

    stream::iter(addresses.iter().copied())
        .map(|address| {
            let provider = provider.clone();
            async move {
                provider
                    .raw_request::<_, Vec<B256>>("tempo_fundAddress".into(), (address,))
                    .await
                    .context("Failed to fund address")
            }
        })
        .buffer_unordered(max_concurrent)
        .try_for_each(|_| {
            progress.inc(1);
            futures::future::ok(())
        })
        .await?;

    progress.finish_with_message("Accounts funded");
    Ok(())
}

async fn set_fee_tokens(
    signer_providers: &[(Secp256k1Signer, DynProvider<TempoNetwork>)],
    fee_token: Address,
    max_concurrent: usize,
) -> eyre::Result<()> {
    stream::iter(signer_providers.iter())
        .map(|(_, provider)| {
            let provider = provider.clone();
            async move {
                let fee_manager = IFeeManagerInstance::new(TIP_FEE_MANAGER_ADDRESS, provider);
                fee_manager
                    .setUserToken(fee_token)
                    .send()
                    .await?
                    .get_receipt()
                    .await?;
                Ok::<_, eyre::Error>(())
            }
        })
        .buffer_unordered(max_concurrent)
        .try_collect::<Vec<_>>()
        .await?;

    Ok(())
}

async fn setup_test_infrastructure(
    signer_providers: &[(Secp256k1Signer, DynProvider<TempoNetwork>)],
    num_user_tokens: usize,
    max_concurrent: usize,
) -> eyre::Result<ActionContext> {
    let (admin_signer, admin_provider) = signer_providers.first().ok_or_eyre("No signers")?;
    let admin = admin_signer.address();

    let path_usd = tempo_contracts::precompiles::PATH_USD_ADDRESS;
    let factory = ITIP20FactoryInstance::new(
        tempo_contracts::precompiles::TIP20_FACTORY_ADDRESS,
        admin_provider.clone(),
    );
    let exchange = IStablecoinDEXInstance::new(
        tempo_contracts::precompiles::STABLECOIN_DEX_ADDRESS,
        admin_provider.clone(),
    );
    let amm = ITIPFeeAMMInstance::new(TIP_FEE_MANAGER_ADDRESS, admin_provider.clone());
    let registry = ITIP403RegistryInstance::new(
        tempo_contracts::precompiles::TIP403_REGISTRY_ADDRESS,
        admin_provider.clone(),
    );

    // Create user tokens
    info!(num_user_tokens, "Creating user tokens");
    let mut user_tokens = Vec::with_capacity(num_user_tokens);

    for i in 0..num_user_tokens {
        let salt = B256::random();
        let receipt = factory
            .createToken(
                format!("TestToken{}", i),
                format!("TT{}", i),
                "USD".to_string(),
                path_usd,
                admin,
                salt,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        let event = receipt
            .decoded_log::<ITIP20Factory::TokenCreated>()
            .ok_or_eyre("Token creation event not found")?;

        let token_addr = event.token;
        user_tokens.push(token_addr);

        // Grant issuer role to admin
        let roles = IRolesAuth::new(token_addr, admin_provider.clone());
        roles
            .grantRole(*ISSUER_ROLE, admin)
            .send()
            .await?
            .get_receipt()
            .await?;

        info!(token = %token_addr, index = i, "Created token");
    }

    // Create DEX pairs for each user token
    info!("Creating DEX pairs");
    for token in &user_tokens {
        exchange
            .createPair(*token)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    // Mint tokens to all signers
    let mint_amount = U256::from(1_000_000_000_000_000u128);
    info!(%mint_amount, "Minting tokens to all accounts");

    for (signer, _) in signer_providers.iter() {
        let recipient = signer.address();

        // Mint pathUSD
        let path_usd_token = ITIP20Instance::new(path_usd, admin_provider.clone());
        path_usd_token
            .mint(recipient, mint_amount)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Mint user tokens
        for token_addr in &user_tokens {
            let token = ITIP20Instance::new(*token_addr, admin_provider.clone());
            token
                .mint(recipient, mint_amount)
                .send()
                .await?
                .get_receipt()
                .await?;
        }
    }

    // Approve DEX for all signers and tokens
    info!("Approving DEX for all accounts");
    let dex_addr = tempo_contracts::precompiles::STABLECOIN_DEX_ADDRESS;
    let amm_addr = TIP_FEE_MANAGER_ADDRESS;

    stream::iter(signer_providers.iter())
        .map(|(_signer, provider)| {
            let user_tokens = user_tokens.clone();
            let provider = provider.clone();
            async move {
                // Approve pathUSD for DEX
                let path_usd_token = ITIP20Instance::new(path_usd, provider.clone());
                path_usd_token
                    .approve(dex_addr, U256::MAX)
                    .send()
                    .await?
                    .get_receipt()
                    .await?;
                path_usd_token
                    .approve(amm_addr, U256::MAX)
                    .send()
                    .await?
                    .get_receipt()
                    .await?;

                // Approve user tokens for DEX
                for token_addr in &user_tokens {
                    let token = ITIP20Instance::new(*token_addr, provider.clone());
                    token
                        .approve(dex_addr, U256::MAX)
                        .send()
                        .await?
                        .get_receipt()
                        .await?;
                    token
                        .approve(amm_addr, U256::MAX)
                        .send()
                        .await?
                        .get_receipt()
                        .await?;
                }
                Ok::<_, eyre::Error>(())
            }
        })
        .buffer_unordered(max_concurrent)
        .try_collect::<Vec<_>>()
        .await?;

    // Place initial flip orders to seed liquidity
    info!("Seeding DEX liquidity with flip orders");
    let order_amount = 100_000_000_000u128;
    let tick_under = exchange.priceToTick(99990).call().await?;
    let tick_over = exchange.priceToTick(100010).call().await?;

    for token_addr in &user_tokens {
        exchange
            .placeFlip(*token_addr, order_amount, true, tick_under, tick_over)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    // Initialize AMM pools
    info!("Initializing FeeAMM pools");
    let amm_deposit = U256::from(10_000_000_000u128);
    for i in 0..user_tokens.len().min(2) {
        for j in 0..user_tokens.len().min(2) {
            if i != j {
                amm.mint(user_tokens[i], user_tokens[j], amm_deposit, admin)
                    .send()
                    .await?
                    .get_receipt()
                    .await?;
            }
        }
    }

    // Create some TIP403 policies
    info!("Creating TIP403 policies");
    let mut policy_ids = Vec::new();
    for _ in 0..3 {
        let receipt = registry
            .createPolicy(admin, ITIP403Registry::PolicyType::BLACKLIST)
            .send()
            .await?
            .get_receipt()
            .await?;
        if let Some(event) = receipt.decoded_log::<ITIP403Registry::PolicyCreated>() {
            policy_ids.push(event.policyId);
        }
    }

    Ok(ActionContext {
        path_usd,
        user_tokens,
        policy_ids,
        orders: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        token_salt_counter: Arc::new(AtomicU64::new(1000)),
        admin,
    })
}

async fn run_spam_loop(
    ctx: ActionContext,
    signer_providers: Vec<(Secp256k1Signer, DynProvider<TempoNetwork>)>,
    weights: Vec<(ActionType, u32)>,
    tps: u64,
    duration: u64,
    max_concurrent: usize,
    _max_pending: usize,
) -> eyre::Result<()> {
    let total_txs = tps * duration;
    let ctx = Arc::new(ctx);

    let progress = ProgressBar::new(total_txs);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({per_sec}) {msg}")?
            .progress_chars("##-"),
    );

    let success_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));

    // Build cumulative weights for weighted random selection
    let total_weight: u32 = weights.iter().map(|(_, w)| *w).sum();
    let cumulative_weights: Vec<(ActionType, u32)> = {
        let mut acc = 0u32;
        weights
            .iter()
            .filter(|(_, w)| *w > 0)
            .map(|(action, w)| {
                acc += *w;
                (*action, acc)
            })
            .collect()
    };

    // Rate limiter for TPS control
    let rate_limiter = governor::RateLimiter::direct(governor::Quota::per_second(
        std::num::NonZeroU32::new(tps as u32).unwrap_or(std::num::NonZeroU32::MIN),
    ));

    let start = std::time::Instant::now();
    let deadline = start + Duration::from_secs(duration);

    let mut tx_futures = Vec::new();

    for _tx_idx in 0..total_txs {
        if std::time::Instant::now() >= deadline {
            break;
        }

        // Rate limit
        rate_limiter.until_ready().await;

        // Pick random signer
        let signer_idx = random_range(0..signer_providers.len());
        let (signer, provider) = signer_providers[signer_idx].clone();

        // Pick random action based on weights
        let action = pick_random_action(&cumulative_weights, total_weight);

        let ctx = ctx.clone();
        let progress = progress.clone();
        let success = success_count.clone();
        let errors = error_count.clone();
        let all_signers: Vec<Address> = signer_providers.iter().map(|(s, _)| s.address()).collect();

        let fut = tokio::spawn(async move {
            let result = crate::actions::execute_action(
                action,
                &ctx,
                signer.address(),
                &provider,
                &all_signers,
            )
            .await;

            match result {
                Ok(_) => {
                    success.fetch_add(1, Ordering::Relaxed);
                }
                Err(_e) => {
                    // Log but don't fail - some errors are expected (insufficient balance, etc.)
                    errors.fetch_add(1, Ordering::Relaxed);
                    // Uncomment for debugging:
                    // eprintln!("Action {:?} failed: {}", action, e);
                }
            }
            progress.inc(1);
        });

        tx_futures.push(fut);

        // Periodically drain completed futures to avoid unbounded growth
        if tx_futures.len() >= max_concurrent {
            let batch: Vec<_> = tx_futures.drain(..max_concurrent / 2).collect();
            futures::future::join_all(batch).await;
        }
    }

    // Wait for remaining futures
    futures::future::join_all(tx_futures).await;

    progress.finish();

    let elapsed = start.elapsed();
    let final_success = success_count.load(Ordering::Relaxed);
    let final_errors = error_count.load(Ordering::Relaxed);
    let actual_tps = final_success as f64 / elapsed.as_secs_f64();

    info!(
        success = final_success,
        errors = final_errors,
        elapsed_secs = elapsed.as_secs_f64(),
        actual_tps = format!("{:.2}", actual_tps),
        "Spam run complete"
    );

    Ok(())
}
