use std::collections::HashMap;

use alloy::{
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    transports::http::reqwest::Url,
};
use indicatif::ProgressIterator;
use rand::seq::IndexedRandom;
use tempo_alloy::TempoNetwork;

type SignerProviderFactory =
    Box<dyn Fn(PrivateKeySigner, Url) -> DynProvider<TempoNetwork> + Send + Sync>;

/// Manages signers and target URLs for creating providers.
pub(crate) struct SignerProviderManager {
    /// List of private key signers.
    signers: Vec<PrivateKeySigner>,
    /// List of target URLs.
    target_urls: Vec<Url>,
    /// Factory function for creating providers.
    provider_factory: SignerProviderFactory,
    /// List of providers (one per signer) with random target URLs.
    signer_providers: Vec<(PrivateKeySigner, DynProvider<TempoNetwork>)>,
    /// Cache of previously created signer providers.
    ///
    /// The mapping is `(signer_idx, target_url_idx) => provider`
    cached_signer_providers: HashMap<(usize, usize), DynProvider<TempoNetwork>>,
}

impl SignerProviderManager {
    /// Create a new instance of [`SignerProviderManager`].
    ///
    /// 1. Creates `accounts` signers from the `mnemonic` starting with `from_mnemonic_index` inde.
    /// 2. Creates `accounts` providers, one per signer, with random target URLs.
    pub fn new(
        mnemonic: String,
        from_mnemonic_index: u32,
        accounts: u64,
        target_urls: Vec<Url>,
        provider_factory: SignerProviderFactory,
    ) -> Self {
        let signers = (from_mnemonic_index..)
            .take(accounts as usize)
            .progress_count(accounts)
            .map(|i| MnemonicBuilder::from_phrase_nth(&mnemonic, i))
            .collect::<Vec<_>>();
        let signer_providers = signers
            .iter()
            .cloned()
            .map(|signer| {
                let target_url = target_urls.choose(&mut rand::rng()).unwrap().clone();
                let provider = (provider_factory)(signer.clone(), target_url);
                (signer, provider)
            })
            .collect();
        let cached_signer_providers = HashMap::with_capacity(signers.len() * target_urls.len());
        Self {
            signers,
            target_urls,
            provider_factory,
            signer_providers,
            cached_signer_providers,
        }
    }

    /// Returns a list of providers (one per target URL) with no signers and fillers set.
    pub fn target_url_providers(&self) -> Vec<(&Url, DynProvider<TempoNetwork>)> {
        self.target_urls
            .iter()
            .map(|target_url| {
                let provider = ProviderBuilder::default()
                    .connect_http(target_url.clone())
                    .erased();
                (target_url, provider)
            })
            .collect()
    }

    /// Returns a list of providers (one per signer) with random target URLs.
    pub fn signer_providers(&self) -> &[(PrivateKeySigner, DynProvider<TempoNetwork>)] {
        &self.signer_providers
    }

    /// Generates a single provider with random signer and random target URL.
    ///
    /// This method caches the generated provider to avoid redundant creation.
    pub fn random_provider(&mut self) -> DynProvider<TempoNetwork> {
        let signer_idx = rand::random_range(0..self.signers.len());
        let target_url_idx = rand::random_range(0..self.target_urls.len());
        self.cached_signer_providers
            .entry((signer_idx, target_url_idx))
            .or_insert_with(|| {
                let signer = self.signers[signer_idx].clone();
                let target_url = self.target_urls[target_url_idx].clone();
                (self.provider_factory)(signer, target_url)
            })
            .clone()
    }
}
