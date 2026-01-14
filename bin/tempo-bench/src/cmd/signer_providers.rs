use std::sync::Arc;

use alloy::{
    providers::{
        DynProvider, Provider, ProviderBuilder, RootProvider,
        fillers::{CachedNonceManager, FillProvider, TxFiller},
    },
    signers::local::{MnemonicBuilder, Secp256k1Signer},
    transports::http::reqwest::Url,
};
use indicatif::ProgressIterator;
use rand::seq::IndexedRandom;
use tempo_alloy::TempoNetwork;

type BenchProvider<F> = FillProvider<F, RootProvider<TempoNetwork>, TempoNetwork>;
type UnsignedProviderFactory<F> =
    Box<dyn Fn(Url, CachedNonceManager) -> BenchProvider<F> + Send + Sync>;
type SignedProviderFactory = Box<
    dyn Fn(Secp256k1Signer, Url, CachedNonceManager) -> DynProvider<TempoNetwork> + Send + Sync,
>;

/// Manages signers and target URLs for creating providers.
#[derive(Debug, Clone)]
pub(crate) struct SignerProviderManager<F: TxFiller<TempoNetwork>>(
    Arc<SignerProviderManagerInner<F>>,
);

#[derive(Debug)]
struct SignerProviderManagerInner<F: TxFiller<TempoNetwork>> {
    /// List of secp256k1 signers (faster than k256-based PrivateKeySigner).
    signers: Vec<Secp256k1Signer>,
    /// List of target URLs.
    target_urls: Vec<Url>,
    /// Providers without signing capabilities.
    unsigned_providers: Vec<BenchProvider<F>>,
    /// List of providers (one per signer) with random target URLs.
    signer_providers: Vec<(Secp256k1Signer, DynProvider<TempoNetwork>)>,
}

impl<F: TxFiller<TempoNetwork> + 'static> SignerProviderManager<F> {
    /// Create a new instance of [`SignerProviderManager`].
    ///
    /// 1. Creates `accounts` signers from the `mnemonic` starting with `from_mnemonic_index` index.
    /// 2. Creates `target_urls` providers without signing capabilities using `unsigned_provider_factory`.
    /// 3. Creates `accounts` providers with signing capabilities, one per signer,
    ///    with random target URLs using `signed_provider_factory`.
    pub fn new(
        mnemonic: String,
        from_mnemonic_index: u32,
        accounts: u64,
        target_urls: Vec<Url>,
        unsigned_provider_factory: UnsignedProviderFactory<F>,
        signed_provider_factory: SignedProviderFactory,
    ) -> Self {
        let cached_nonce_manager = CachedNonceManager::default();
        // Use Secp256k1Signer for better performance (libsecp256k1 bindings vs pure-Rust k256)
        let signers: Vec<Secp256k1Signer> = (from_mnemonic_index..)
            .take(accounts as usize)
            .progress_count(accounts)
            .map(|i| MnemonicBuilder::from_phrase_nth(&mnemonic, i).into_secp256k1())
            .collect();
        let unsigned_providers = target_urls
            .iter()
            .cloned()
            .map(|target_url| (unsigned_provider_factory)(target_url, cached_nonce_manager.clone()))
            .collect();
        let signer_providers = signers
            .iter()
            .progress()
            .cloned()
            .map(|signer| {
                let target_url = target_urls.choose(&mut rand::rng()).unwrap().clone();
                let provider = (signed_provider_factory)(
                    signer.clone(),
                    target_url,
                    cached_nonce_manager.clone(),
                );
                (signer, provider)
            })
            .collect();
        Self(Arc::new(SignerProviderManagerInner {
            signers,
            target_urls,
            unsigned_providers,
            signer_providers,
        }))
    }

    /// Returns a list of providers (one per target URL) with no signers and fillers set.
    pub fn target_url_providers(&self) -> Vec<(&Url, DynProvider<TempoNetwork>)> {
        self.0
            .target_urls
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
    pub fn signer_providers(&self) -> &[(Secp256k1Signer, DynProvider<TempoNetwork>)] {
        &self.0.signer_providers
    }

    /// Returns a random signer without signing capabilities.
    pub fn random_unsigned_provider(&self) -> BenchProvider<F> {
        self.0
            .unsigned_providers
            .choose(&mut rand::rng())
            .unwrap()
            .clone()
    }

    /// Returns a random signer.
    pub fn random_signer(&self) -> &Secp256k1Signer {
        self.0.signers.choose(&mut rand::rng()).unwrap()
    }
}
