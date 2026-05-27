//! Conflict-domain policy classification.

/// Known high-conflict dependency domains for Tempo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockStmDependencyDomain {
    SenderNonce,
    ExpiringNonce,
    FeePayerBalance,
    FeeTokenLiquidity,
    ValidatorFeeCredit,
    KeychainAuthState,
    NativeBalanceTransfer,
    Tip20Balance,
    Tip20Allowance,
    TokenSupplyProtocolFee,
    AmmPoolLiquidity,
    LimitOrderBook,
    AccountCodeCreation,
    PrecompileSystemSideEffect,
    BuilderLimitsAndPoolFeedback,
    SystemTxSubblockFinalization,
    UnknownContractStorage,
}

/// Strategy selected for a dependency domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockStmStrategy {
    AlwaysReexecute,
    SerialConflictDomain,
    OrderedValidationOnly,
    SemanticActionReplay,
    CommutativeAccumulator,
    DirectSlotResolver,
    AdaptiveFallback,
}

/// Production conflict policy.
#[derive(Debug, Clone)]
pub struct BlockStmConflictPolicy {
    adaptive_threshold: usize,
}

impl Default for BlockStmConflictPolicy {
    fn default() -> Self {
        Self {
            adaptive_threshold: 64,
        }
    }
}

impl BlockStmConflictPolicy {
    /// Creates a policy with an adaptive fallback threshold.
    pub const fn new(adaptive_threshold: usize) -> Self {
        Self { adaptive_threshold }
    }

    /// Returns every known Tempo dependency domain.
    pub const fn known_domains() -> &'static [BlockStmDependencyDomain] {
        &[
            BlockStmDependencyDomain::SenderNonce,
            BlockStmDependencyDomain::ExpiringNonce,
            BlockStmDependencyDomain::FeePayerBalance,
            BlockStmDependencyDomain::FeeTokenLiquidity,
            BlockStmDependencyDomain::ValidatorFeeCredit,
            BlockStmDependencyDomain::KeychainAuthState,
            BlockStmDependencyDomain::NativeBalanceTransfer,
            BlockStmDependencyDomain::Tip20Balance,
            BlockStmDependencyDomain::Tip20Allowance,
            BlockStmDependencyDomain::TokenSupplyProtocolFee,
            BlockStmDependencyDomain::AmmPoolLiquidity,
            BlockStmDependencyDomain::LimitOrderBook,
            BlockStmDependencyDomain::AccountCodeCreation,
            BlockStmDependencyDomain::PrecompileSystemSideEffect,
            BlockStmDependencyDomain::BuilderLimitsAndPoolFeedback,
            BlockStmDependencyDomain::SystemTxSubblockFinalization,
            BlockStmDependencyDomain::UnknownContractStorage,
        ]
    }

    /// Selects the initial strategy for a domain.
    pub const fn strategy_for(&self, domain: BlockStmDependencyDomain) -> BlockStmStrategy {
        match domain {
            BlockStmDependencyDomain::SenderNonce
            | BlockStmDependencyDomain::Tip20Allowance
            | BlockStmDependencyDomain::AmmPoolLiquidity
            | BlockStmDependencyDomain::LimitOrderBook => BlockStmStrategy::SerialConflictDomain,
            BlockStmDependencyDomain::ExpiringNonce
            | BlockStmDependencyDomain::FeePayerBalance
            | BlockStmDependencyDomain::Tip20Balance => BlockStmStrategy::SemanticActionReplay,
            BlockStmDependencyDomain::KeychainAuthState => BlockStmStrategy::OrderedValidationOnly,
            BlockStmDependencyDomain::ValidatorFeeCredit => {
                BlockStmStrategy::CommutativeAccumulator
            }
            BlockStmDependencyDomain::BuilderLimitsAndPoolFeedback
            | BlockStmDependencyDomain::SystemTxSubblockFinalization => {
                BlockStmStrategy::SerialConflictDomain
            }
            BlockStmDependencyDomain::FeeTokenLiquidity
            | BlockStmDependencyDomain::TokenSupplyProtocolFee
            | BlockStmDependencyDomain::AccountCodeCreation
            | BlockStmDependencyDomain::PrecompileSystemSideEffect
            | BlockStmDependencyDomain::UnknownContractStorage => BlockStmStrategy::AlwaysReexecute,
            BlockStmDependencyDomain::NativeBalanceTransfer => {
                BlockStmStrategy::SerialConflictDomain
            }
        }
    }

    /// Selects adaptive fallback after repeated conflicts.
    pub const fn strategy_after_conflicts(
        &self,
        domain: BlockStmDependencyDomain,
        conflicts: usize,
    ) -> BlockStmStrategy {
        if conflicts >= self.adaptive_threshold {
            BlockStmStrategy::AdaptiveFallback
        } else {
            self.strategy_for(domain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blockstm_policy_covers_all_documented_domains() {
        assert_eq!(BlockStmConflictPolicy::known_domains().len(), 17);
    }

    #[test]
    fn blockstm_policy_selects_semantic_actions_for_pure_tip20_hotspots() {
        let policy = BlockStmConflictPolicy::default();

        assert_eq!(
            policy.strategy_for(BlockStmDependencyDomain::ExpiringNonce),
            BlockStmStrategy::SemanticActionReplay
        );
        assert_eq!(
            policy.strategy_for(BlockStmDependencyDomain::FeePayerBalance),
            BlockStmStrategy::SemanticActionReplay
        );
        assert_eq!(
            policy.strategy_for(BlockStmDependencyDomain::Tip20Balance),
            BlockStmStrategy::SemanticActionReplay
        );
        assert_eq!(
            policy.strategy_for(BlockStmDependencyDomain::ValidatorFeeCredit),
            BlockStmStrategy::CommutativeAccumulator
        );
    }

    #[test]
    fn blockstm_policy_keeps_unknown_and_amm_domains_conservative() {
        let policy = BlockStmConflictPolicy::default();

        assert_eq!(
            policy.strategy_for(BlockStmDependencyDomain::AmmPoolLiquidity),
            BlockStmStrategy::SerialConflictDomain
        );
        assert_eq!(
            policy.strategy_for(BlockStmDependencyDomain::UnknownContractStorage),
            BlockStmStrategy::AlwaysReexecute
        );
        assert_eq!(
            policy.strategy_for(BlockStmDependencyDomain::KeychainAuthState),
            BlockStmStrategy::OrderedValidationOnly
        );
    }

    #[test]
    fn blockstm_policy_uses_adaptive_fallback_after_threshold() {
        let policy = BlockStmConflictPolicy::new(2);

        assert_eq!(
            policy.strategy_after_conflicts(BlockStmDependencyDomain::Tip20Balance, 1),
            BlockStmStrategy::SemanticActionReplay
        );
        assert_eq!(
            policy.strategy_after_conflicts(BlockStmDependencyDomain::Tip20Balance, 2),
            BlockStmStrategy::AdaptiveFallback
        );
    }
}
