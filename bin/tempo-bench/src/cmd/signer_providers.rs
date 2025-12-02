use std::sync::Arc;

use alloy::{
    providers::{
        DynProvider, Provider, ProviderBuilder, RootProvider, SendableTx,
        fillers::{CachedNonceManager, FillProvider, TxFiller},
    },
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    transports::{TransportResult, http::reqwest::Url},
};
use indicatif::ProgressIterator;
use rand::seq::IndexedRandom;
use tempo_alloy::{TempoNetwork, rpc::TempoTransactionRequest};

type UnsignedProviderFactory = Box<dyn Fn(Url, CachedNonceManager) -> Arc<dyn FillProviderExt>>;
type SignedProviderFactory =
    Box<dyn Fn(PrivateKeySigner, Url, CachedNonceManager) -> Arc<dyn FillProviderExt>>;

/// Manages signers and target URLs for creating providers.
#[derive(Clone)]
pub(crate) struct SignerProviderManager(Arc<SignerProviderManagerInner>);

struct SignerProviderManagerInner {
    /// List of private key signers.
    signers: Vec<PrivateKeySigner>,
    /// List of target URLs.
    target_urls: Vec<Url>,
    /// Providers without signing capabilities.
    unsigned_providers: Vec<BenchProvider>,
    /// List of providers (one per signer) with random target URLs.
    signer_providers: Vec<(PrivateKeySigner, BenchProvider)>,
}

impl SignerProviderManager {
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
        unsigned_provider_factory: UnsignedProviderFactory,
        signed_provider_factory: SignedProviderFactory,
    ) -> Self {
        let cached_nonce_manager = CachedNonceManager::default();
        let signers = (from_mnemonic_index..)
            .take(accounts as usize)
            .progress_count(accounts)
            .map(|i| MnemonicBuilder::from_phrase_nth(&mnemonic, i))
            .collect::<Vec<_>>();
        let unsigned_providers = target_urls
            .iter()
            .cloned()
            .map(|target_url| {
                BenchProvider((unsigned_provider_factory)(
                    target_url,
                    cached_nonce_manager.clone(),
                ))
            })
            .collect();
        let signer_providers = signers
            .iter()
            .progress()
            .cloned()
            .map(|signer| {
                let target_url = target_urls.choose(&mut rand::rng()).unwrap().clone();
                let provider = BenchProvider((signed_provider_factory)(
                    signer.clone(),
                    target_url,
                    cached_nonce_manager.clone(),
                ));
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
    pub fn signer_providers(&self) -> &[(PrivateKeySigner, BenchProvider)] {
        &self.0.signer_providers
    }

    /// Returns a random signer without signing capabilities.
    pub fn random_unsigned_provider(&self) -> BenchProvider {
        self.0
            .unsigned_providers
            .choose(&mut rand::rng())
            .unwrap()
            .clone()
    }

    /// Returns a random signer.
    pub fn random_signer(&self) -> &PrivateKeySigner {
        self.0.signers.choose(&mut rand::rng()).unwrap()
    }
}

#[async_trait::async_trait]
pub trait FillProviderExt: Provider<TempoNetwork> {
    async fn fill(&self, tx: TempoTransactionRequest) -> TransportResult<SendableTx<TempoNetwork>>;
}

#[async_trait::async_trait]
impl<P, F> FillProviderExt for FillProvider<F, P, TempoNetwork>
where
    P: Provider<TempoNetwork> + Send + Sync,
    F: TxFiller<TempoNetwork> + Send + Sync,
{
    async fn fill(&self, tx: TempoTransactionRequest) -> TransportResult<SendableTx<TempoNetwork>> {
        FillProvider::fill(self, tx).await
    }
}

#[derive(Clone, derive_more::Deref)]
pub(crate) struct BenchProvider(Arc<dyn FillProviderExt>);

impl Provider<TempoNetwork> for BenchProvider {
    fn root(&self) -> &RootProvider<TempoNetwork> {
        self.0.root()
    }
}
