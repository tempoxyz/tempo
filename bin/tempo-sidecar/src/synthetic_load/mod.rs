use alloy::{
    network::EthereumWallet,
    primitives::{
        Address, U256,
        private::{
            rand,
            rand::{RngCore, SeedableRng, rngs::StdRng},
        },
    },
    providers::ProviderBuilder,
    signers::local::MnemonicBuilder,
};
use eyre::Context;
use rand_distr::{Distribution, Exp, Zipf};
use reqwest::Url;
use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::IFeeManager, tip20::ITIP20};
use tempo_telemetry_util::error_field;
use tracing::{debug, info, warn};

pub struct SyntheticLoadGenerator {
    mnemonic: String,
    rpc_url: Url,
    wallet_count: usize,
    average_tps: usize,
    fee_token_addresses: Vec<Address>,
    seed: Option<u64>,
}

impl SyntheticLoadGenerator {
    pub fn new(
        mnemonic: String,
        rpc_url: Url,
        wallet_count: usize,
        average_tps: usize,
        fee_token_addresses: Vec<Address>,
        seed: Option<u64>,
    ) -> Self {
        Self { rpc_url, wallet_count, average_tps, fee_token_addresses, mnemonic, seed }
    }

    pub async fn worker(&self) -> eyre::Result<()> {
        info!("starting synthetic load generator");

        let mut rng = match self.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::seed_from_u64(rand::rng().next_u64()),
        };

        let mut wallet = EthereumWallet::default();
        let mut addresses = Vec::new();
        for index in 0..self.wallet_count {
            let signer = MnemonicBuilder::from_phrase_nth(&self.mnemonic, index as u32);
            addresses.push(signer.address());
            wallet.register_signer(signer);
        }

        let provider =
            ProviderBuilder::new().wallet(wallet.clone()).connect_http(self.rpc_url.clone());

        let fee_token_zipf = Zipf::new(self.fee_token_addresses.len() as f64, 1.4)?;

        info!("setting fee tokens for load generating wallets");

        for address in &addresses {
            let fee_token_address =
                zipf_vec_sample(&mut rng, fee_token_zipf, &self.fee_token_addresses)?;
            let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
            _ = fee_manager
                .setUserToken(*fee_token_address)
                .from(*address)
                .send()
                .await
                .wrap_err_with(|| {
                    format!("failed to set fee token {address} for address {fee_token_address}",)
                })?;
        }

        let exp = Exp::new(self.average_tps as f64)?;
        let zipf = Zipf::new(self.wallet_count as f64, 1.4)?;

        loop {
            let sender = zipf_vec_sample(&mut rng, zipf, &addresses)?;
            let recipient = zipf_vec_sample(&mut rng, zipf, &addresses)?;
            let token = zipf_vec_sample(&mut rng, fee_token_zipf, &self.fee_token_addresses)?;

            info!(
                %sender,
                %recipient,
                "sending tip20 tokens"
            );

            let token = ITIP20::new(*token, provider.clone());
            if let Err(e) = token.transfer(*recipient, U256::from(10)).from(*sender).send().await {
                warn!(
                    %sender,
                    %recipient,
                    err = error_field(&e),
                    "failed to transfer tip20 token"
                );
            }

            let delay = exp.sample(&mut rng);

            debug!(%delay, "sleeping until next round");

            tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await;
        }
    }
}

fn zipf_vec_sample<'a, T>(
    rng: &mut StdRng,
    zipf: Zipf<f64>,
    items: &'a [T],
) -> eyre::Result<&'a T> {
    let index = zipf.sample(rng) as u32 - 1;
    items.get(index as usize).ok_or_else(|| eyre::eyre!("zipf out of bounds"))
}
