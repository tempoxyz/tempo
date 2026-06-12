//! Channel-reserve invariants — a cross-precompile *entity scope* whose subject
//! is the channel-reserve precompile's accounting for one TIP-20 token, not the
//! token itself.
//!
//! Use this pattern when a check needs **more than one entity's scalars**: the
//! channels open against the reserve for a token aren't derivable from the token
//! or any single storage slot (channel state is keyed by channel id with no
//! per-token index). Enumerate them off-chain from `ChannelOpened` / `Settled`
//! / `Closed` events and supply them as the entity ([`ReserveView`]); `read`
//! then loads the one authoritative on-chain value the check needs (the
//! reserve's token balance) into [`ReserveSnapshot`].

use crate::{Check, EvalError, Scope, ScopeKind};
use alloy_primitives::{Address, U256};
use tempo_precompiles::{
    tip20::{ITIP20, TIP20Token},
    tip20_channel_reserve::TIP20_CHANNEL_RESERVE_ADDRESS,
};

mod solvency;

impl Scope for ReserveSnapshot {
    const KIND: ScopeKind = ScopeKind::Reserve;
}
crate::inventory::collect!(Check<ReserveSnapshot>);

/// Per-channel amounts the enumeration tier supplies for each open channel —
/// the precompile's own `ChannelState` (`{ settled, deposit, closeRequestedAt }`)
/// reused as the source of truth, so the shape stays in sync with the on-chain
/// layout. The unsettled balance `deposit - settled` is what the reserve still
/// owes the payee.
pub use tempo_precompiles::tip20_channel_reserve::ITIP20ChannelReserve::ChannelState;

/// Enumeration **entity**: a TIP-20 token plus every channel currently open
/// against the channel-reserve precompile for it (sourced off-chain).
#[derive(Debug, Clone)]
pub struct ReserveView {
    pub token: Address,
    pub channels: Vec<ChannelState>,
}

/// The read **snapshot**: the enumerated channels plus the one on-chain value
/// the check compares them against — the token balance the reserve holds.
#[derive(Debug, Clone)]
pub struct ReserveSnapshot {
    pub held: U256,
    pub channels: Vec<ChannelState>,
}

/// Read the reserve's authoritative balance of the token once. The channel set
/// is already in the entity (it came from enumeration); only the balance is a
/// state read. The balance is read via the real `TIP20Token` accessor.
pub(crate) fn read(view: &ReserveView) -> Result<ReserveSnapshot, EvalError> {
    let token = TIP20Token::from_address_unchecked(view.token);
    let held = token.balance_of(ITIP20::balanceOfCall {
        account: TIP20_CHANNEL_RESERVE_ADDRESS,
    })?;
    Ok(ReserveSnapshot {
        held,
        channels: view.channels.clone(),
    })
}
