//! Channel-reserve solvency.

use crate::{invariant, reserve::ReserveSnapshot};
use alloy_primitives::U256;

invariant! {
    id: "TEMPO-RESERVE-CHANNEL-SOLVENCY",
    severity: P0,
    description: "channel-reserve token balance must cover unsettled channel deposits",
    fn channel_solvency(s: &ReserveSnapshot, out: &mut Report<'_>) {
        let owed: U256 = s
            .channels
            .iter()
            .map(|c| U256::from(c.deposit).saturating_sub(U256::from(c.settled)))
            .fold(U256::ZERO, |acc, x| acc + x);

        if s.held < owed {
            out.fail(format!(
                "reserve holds {} of token but owes {owed} in unsettled channel deposits",
                s.held
            ));
        }
    }
}
