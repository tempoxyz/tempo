/// Provider extension traits.
///
/// These traits extend existing [`Provider`](alloy_provider::Provider)s with new methods specific to Tempo.
pub mod ext;
pub mod keychain;
pub mod receive_policy;

#[doc(inline)]
pub use ext::{SponsoredProviderBuilder, TempoProviderBuilderExt, TempoProviderExt};
#[doc(inline)]
pub use keychain::{
    AccessKeyPolicyBuilder, AccessKeyPolicyTier, CallScopeBuilder, KeyRestrictions,
    KeychainBuildError, periodic_tip20_transfer_policy, tip20_transfer_policy,
    tip20_transfer_policy_tiers,
};
#[doc(inline)]
pub use receive_policy::BlockedTransfer;
