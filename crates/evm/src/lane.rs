//! Block budgets a transaction counts toward.

use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoTxEnvelope;

/// The block budget a transaction counts toward.
///
/// Every transaction counts toward the block gas limit. General transactions also count toward
/// the general gas limit (TIP-1010), and from T17 registered payments (TIP-1180) toward the
/// registered payment gas limit. Payments of either kind are payment lane transactions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum TxLane {
    /// Not a payment: bounded by the general gas limit.
    #[default]
    General,
    /// A TIP-1045 payment: bounded by the block gas limit only.
    Payment,
    /// A TIP-1180 registered payment: bounded by the registered payment gas limit.
    RegisteredPayment,
}

impl TxLane {
    /// Returns [`Self::Payment`] for a payment and [`Self::General`] otherwise.
    pub const fn from_payment(is_payment: bool) -> Self {
        if is_payment {
            Self::Payment
        } else {
            Self::General
        }
    }

    /// Returns whether the transaction is in the payment lane, registered or not.
    pub const fn is_payment(self) -> bool {
        matches!(self, Self::Payment | Self::RegisteredPayment)
    }

    /// Returns whether the transaction is a registered payment.
    pub const fn is_registered_payment(self) -> bool {
        matches!(self, Self::RegisteredPayment)
    }
}

/// Returns whether `tx` is a TIP-1045 payment at `spec`, the classification that needs no state.
///
/// T15+: [`TempoTxEnvelope::is_payment_v3`]. T5+: [`TempoTxEnvelope::is_payment_v2`]. Earlier:
/// [`TempoTxEnvelope::is_payment_v1`]. From T17 a transaction that is not one may still be a
/// registered payment, which needs the payment call registry's state.
pub fn is_stateless_payment(spec: TempoHardfork, tx: &TempoTxEnvelope) -> bool {
    if spec.is_t15() {
        tx.is_payment_v3()
    } else if spec.is_t5() {
        tx.is_payment_v2()
    } else {
        tx.is_payment_v1()
    }
}
