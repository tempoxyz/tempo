use alloy_provider::{
    Identity, ProviderBuilder,
    fillers::{JoinFill, RecommendedFillers},
};

use crate::{
    TempoFillers, TempoNetwork,
    fillers::{ExpiringNonceFiller, NonceKeyFiller, Random2DNonceFiller},
};

/// Extension trait for [`ProviderBuilder`] with Tempo-specific functionality.
pub trait TempoProviderBuilderExt {
    /// Returns a provider builder with the recommended Tempo fillers and the random 2D nonce filler.
    ///
    /// See [`Random2DNonceFiller`] for more information on random 2D nonces.
    fn with_random_2d_nonces(
        self,
    ) -> ProviderBuilder<
        Identity,
        JoinFill<Identity, TempoFillers<Random2DNonceFiller>>,
        TempoNetwork,
    >;

    /// Returns a provider builder with the recommended Tempo fillers and the expiring nonce filler.
    ///
    /// See [`ExpiringNonceFiller`] for more information on expiring nonces ([TIP-1009]).
    ///
    /// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
    fn with_expiring_nonces(
        self,
    ) -> ProviderBuilder<
        Identity,
        JoinFill<Identity, TempoFillers<ExpiringNonceFiller>>,
        TempoNetwork,
    >;

    /// Returns a provider builder with the recommended Tempo fillers and the nonce key filler.
    ///
    /// The nonce key filler requires `nonce_key` to be set on the transaction request and
    /// fills the correct next nonce by querying the chain, with caching for batched sends.
    ///
    /// See [`NonceKeyFiller`] for more information.
    fn with_nonce_key_filler(
        self,
    ) -> ProviderBuilder<Identity, JoinFill<Identity, TempoFillers<NonceKeyFiller>>, TempoNetwork>;
}

impl TempoProviderBuilderExt
    for ProviderBuilder<
        Identity,
        JoinFill<Identity, <TempoNetwork as RecommendedFillers>::RecommendedFillers>,
        TempoNetwork,
    >
{
    fn with_random_2d_nonces(
        self,
    ) -> ProviderBuilder<
        Identity,
        JoinFill<Identity, TempoFillers<Random2DNonceFiller>>,
        TempoNetwork,
    > {
        ProviderBuilder::default().filler(TempoFillers::default())
    }

    fn with_expiring_nonces(
        self,
    ) -> ProviderBuilder<
        Identity,
        JoinFill<Identity, TempoFillers<ExpiringNonceFiller>>,
        TempoNetwork,
    > {
        ProviderBuilder::default().filler(TempoFillers::default())
    }

    fn with_nonce_key_filler(
        self,
    ) -> ProviderBuilder<Identity, JoinFill<Identity, TempoFillers<NonceKeyFiller>>, TempoNetwork>
    {
        ProviderBuilder::default().filler(TempoFillers::default())
    }
}

#[cfg(test)]
mod tests {
    use alloy_provider::{Identity, ProviderBuilder, fillers::JoinFill};

    use crate::{
        TempoFillers, TempoNetwork,
        fillers::{ExpiringNonceFiller, NonceKeyFiller, Random2DNonceFiller},
        provider::ext::TempoProviderBuilderExt,
    };

    #[test]
    fn test_with_random_nonces() {
        let _: ProviderBuilder<_, JoinFill<Identity, TempoFillers<Random2DNonceFiller>>, _> =
            ProviderBuilder::new_with_network::<TempoNetwork>().with_random_2d_nonces();
    }

    #[test]
    fn test_with_expiring_nonces() {
        let _: ProviderBuilder<_, JoinFill<Identity, TempoFillers<ExpiringNonceFiller>>, _> =
            ProviderBuilder::new_with_network::<TempoNetwork>().with_expiring_nonces();
    }

    #[test]
    fn test_with_nonce_key_filler() {
        let _: ProviderBuilder<_, JoinFill<Identity, TempoFillers<NonceKeyFiller>>, _> =
            ProviderBuilder::new_with_network::<TempoNetwork>().with_nonce_key_filler();
    }
}
