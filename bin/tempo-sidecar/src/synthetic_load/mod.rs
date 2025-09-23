use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256, private::rand},
    providers::ProviderBuilder,
    signers::local::MnemonicBuilder,
};
use rand_distr::{Distribution, Exp, Zipf};
use reqwest::Url;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{IFeeManager, ITIP20},
};
use tracing::{debug, error, info, trace};

pub struct SyntheticLoadGenerator {
    mnemonic: String,
    rpc_url: Url,
    wallet_count: usize,
    average_tps: usize,
    fee_token_addresses: Vec<Address>,
}

impl SyntheticLoadGenerator {
    pub fn new(
        mnemonic: String,
        rpc_url: Url,
        wallet_count: usize,
        average_tps: usize,
        fee_token_addresses: Vec<Address>,
    ) -> Self {
        Self {
            rpc_url,
            wallet_count,
            average_tps,
            fee_token_addresses,
            mnemonic,
        }
    }

    pub async fn worker(&self) -> eyre::Result<()> {
        info!("starting synthetic load generator");

        let mut wallet = EthereumWallet::default();
        let mut addresses = Vec::new();
        for index in 0..self.wallet_count {
            let signer = MnemonicBuilder::english()
                .phrase(&self.mnemonic)
                .index(index as u32)?
                .build()?;
            addresses.push(signer.address());
            wallet.register_signer(signer);
        }

        let provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .connect_http(self.rpc_url.clone());

        let fee_token_zipf = Zipf::new(self.fee_token_addresses.len() as f64, 1.4)?;

        info!("setting fee tokens for load generating wallets");

        for address in &addresses {
            let fee_token_address = zipf_vec_sample(fee_token_zipf, &self.fee_token_addresses)?;
            let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
            _ = fee_manager
                .setUserToken(*fee_token_address)
                .from(*address)
                .send()
                .await
                .map_err(|e| {
                    eyre::eyre!(
                        "failed to set fee token ({}) for address {}: {}",
                        address,
                        fee_token_address,
                        e
                    )
                })?;
        }

        let exp = Exp::new(self.average_tps as f64)?;
        let zipf = Zipf::new(self.wallet_count as f64, 1.4)?;

        loop {
            let sender = zipf_vec_sample(zipf, &addresses)?;
            let recipient = zipf_vec_sample(zipf, &addresses)?;
            let token = zipf_vec_sample(fee_token_zipf, &self.fee_token_addresses)?;

            trace!(
                sender = sender.to_string(),
                recipient = recipient.to_string(),
                "sending tip20 tokens"
            );

            let token = ITIP20::new(*token, provider.clone());
            if let Err(e) = token
                .transfer(*recipient, U256::from(10))
                .from(*sender)
                .send()
                .await
            {
                error!(
                    sender = sender.to_string(),
                    recipient = recipient.to_string(),
                    err = e.to_string(),
                    "failed to transfer tip20 token"
                );
            }

            let delay = exp.sample(&mut rand::rng());

            debug!(%delay, "sleeping until next round");

            tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await;
        }
    }
}

fn zipf_vec_sample<T>(zipf: Zipf<f64>, items: &[T]) -> eyre::Result<&T> {
    let index = zipf.sample(&mut rand::rng()) as u32 - 1;
    items
        .get(index as usize)
        .ok_or_else(|| eyre::eyre!("zipf out of bounds"))
}
