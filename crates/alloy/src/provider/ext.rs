use alloy_provider::{
    Identity, ProviderBuilder,
    fillers::{JoinFill, RecommendedFillers},
};

use crate::{TempoFillers, TempoNetwork, fillers::Random2DNonceFiller};

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
}

#[cfg(test)]
mod tests {
    use alloy_provider::{Identity, ProviderBuilder, fillers::JoinFill};

    use crate::{
        TempoFillers, TempoNetwork, fillers::Random2DNonceFiller,
        provider::ext::TempoProviderBuilderExt,
    };

    #[test]
    fn test_with_random_nonces() {
        let _: ProviderBuilder<_, JoinFill<Identity, TempoFillers<Random2DNonceFiller>>, _> =
            ProviderBuilder::new_with_network::<TempoNetwork>().with_random_2d_nonces();
    }
}
