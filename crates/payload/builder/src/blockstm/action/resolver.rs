//! Ordered semantic action resolver.

use crate::blockstm::action::{
    BlockStmActionKind, BlockStmActionLog, BlockStmResource,
    fee_manager::{CollectedFeesDelta, CollectedFeesResolution, CollectedFeesResolver},
    nonce::{
        ExpiringNonceBaseState, ExpiringNonceResolution, ExpiringNonceResolutionError,
        ExpiringNonceResolver, ExpiringNonceUse,
    },
    tip20::{
        Tip20BalanceMap, Tip20BalanceResolution, Tip20BalanceResolver, Tip20FeeEscrowDelta,
        Tip20ResolutionError, Tip20TransferDelta,
    },
};

/// Resolves semantic actions in original transaction order.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockStmActionResolver;

impl BlockStmActionResolver {
    /// Counts actions for a resource. Concrete slot synthesis lives in the typed action modules.
    pub fn count(log: &BlockStmActionLog, resource: BlockStmResource) -> usize {
        log.count_resource(resource)
    }

    /// Resolves expiring nonce actions in original action order.
    pub fn resolve_expiring_nonces(
        log: &BlockStmActionLog,
        base: ExpiringNonceBaseState,
        block_timestamp: u64,
    ) -> Result<ExpiringNonceResolution, ExpiringNonceResolutionError> {
        let actions = log
            .actions()
            .iter()
            .filter_map(|action| match action.kind {
                BlockStmActionKind::ExpiringNonceUse(action) => Some(action),
                _ => None,
            })
            .collect::<Vec<ExpiringNonceUse>>();
        ExpiringNonceResolver::new(base, block_timestamp).resolve(&actions)
    }

    /// Resolves simple TIP20 transfer actions in original action order.
    pub fn resolve_tip20_transfers(
        log: &BlockStmActionLog,
        base: Tip20BalanceMap,
    ) -> Result<Tip20BalanceResolution, Tip20ResolutionError> {
        let actions = log
            .actions()
            .iter()
            .filter_map(|action| match action.kind {
                BlockStmActionKind::Tip20TransferDelta(action) => Some(action),
                _ => None,
            })
            .collect::<Vec<Tip20TransferDelta>>();
        Tip20BalanceResolver::new(base).resolve_transfers(&actions)
    }

    /// Resolves TIP20 fee escrow actions in original action order.
    pub fn resolve_tip20_fee_escrows(
        log: &BlockStmActionLog,
        base: Tip20BalanceMap,
    ) -> Result<Tip20BalanceResolution, Tip20ResolutionError> {
        let actions = log
            .actions()
            .iter()
            .filter_map(|action| match action.kind {
                BlockStmActionKind::Tip20FeeEscrowDelta(action) => Some(action),
                _ => None,
            })
            .collect::<Vec<Tip20FeeEscrowDelta>>();
        Tip20BalanceResolver::new(base).resolve_fee_escrows(&actions)
    }

    /// Resolves collected-fee accumulator actions in original action order.
    pub fn resolve_collected_fees(
        log: &BlockStmActionLog,
        base: crate::blockstm::action::fee_manager::CollectedFeesMap,
    ) -> Result<
        CollectedFeesResolution,
        crate::blockstm::action::fee_manager::CollectedFeesResolutionError,
    > {
        let actions = log
            .actions()
            .iter()
            .filter_map(|action| match action.kind {
                BlockStmActionKind::CollectedFeesDelta(action) => Some(action),
                _ => None,
            })
            .collect::<Vec<CollectedFeesDelta>>();
        CollectedFeesResolver::new(base).resolve(&actions)
    }
}
