//! The roles that gate a token's privileged calls, read for the accounts that made them.

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{Address, B256, keccak256};
use alloy_sol_types::{SolCall, SolEvent};
use invariants_core::{Effects, Frame, check, ensure};

use tempo_contracts::precompiles::IRolesAuth::{self, RoleMembershipUpdated};

use super::ITIP20;
use crate::{
    Batch, Check, Checked, Observe, ObserveError, Ran, Step, StepChecked, TempoHardfork, Views,
    optional,
};

pub const ROLE_AUTHZ: &str = "TEMPO-TIP20-ROLE-AUTHZ";

/// Whether accounts held roles at a token, as `hasRole` reports them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roles {
    /// The token read.
    pub token: Address,
    /// Keyed `(account, role)`, leaving out reads nothing answered.
    pub held: BTreeMap<(Address, B256), bool>,
}

impl Observe for Roles {
    type At<'a> = At<'a>;

    fn observe<V: Views>(views: &mut V, at: At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let mut batch = Batch::default();
        let reads: Vec<_> = at
            .queries
            .iter()
            .map(|&(account, role)| {
                let call = IRolesAuth::hasRoleCall { account, role };
                ((account, role), batch.push(None, at.token, &call))
            })
            .collect();
        let answers = batch.run(views)?;
        let mut held = BTreeMap::new();
        for (query, read) in &reads {
            if let Some(has) = optional(views, answers.decode(read))? {
                held.insert(*query, has);
            }
        }
        Ok(Self {
            token: at.token,
            held,
        })
    }
}

impl fmt::Display for Roles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token={}", self.token)
    }
}

/// The token and the `(account, role)` pairs whose membership to read.
#[derive(Debug, Clone, Copy)]
pub struct At<'a> {
    /// The token to read.
    pub token: Address,
    /// The `(account, role)` pairs whose membership to read.
    pub queries: &'a [(Address, B256)],
}

/// A committed call that only a role holder may make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoleCall {
    caller: Address,
    function: &'static str,
    role: B256,
    /// How many of the step's logs came before the call.
    logs_before: usize,
}

impl fmt::Display for RoleCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} called {}", self.caller, self.function)
    }
}

/// The role a call to `frame` requires, from the TIP-20 spec, which names each role by the hash
/// of its name.
fn required_role(frame: &Frame) -> Option<(&'static str, B256)> {
    let selector: [u8; 4] = frame.input.get(..4)?.try_into().ok()?;
    Some(match selector {
        ITIP20::mintCall::SELECTOR => ("mint", keccak256("ISSUER_ROLE")),
        ITIP20::mintWithMemoCall::SELECTOR => ("mintWithMemo", keccak256("ISSUER_ROLE")),
        ITIP20::pauseCall::SELECTOR => ("pause", keccak256("PAUSE_ROLE")),
        ITIP20::unpauseCall::SELECTOR => ("unpause", keccak256("UNPAUSE_ROLE")),
        ITIP20::burnBlockedCall::SELECTOR => ("burnBlocked", keccak256("BURN_BLOCKED_ROLE")),
        ITIP20::burnAtCall::SELECTOR => ("burnAt", keccak256("BURN_AT_ROLE")),
        _ => return None,
    })
}

/// The committed role-gated calls into `token` in `effects`, in order.
fn role_calls<T>(effects: &Effects<T>, token: Address) -> impl Iterator<Item = RoleCall> + '_ {
    effects
        .calls_to(token)
        .filter(|frame| frame.committed)
        .filter_map(|frame| {
            let (function, role) = required_role(frame)?;
            Some(RoleCall {
                caller: frame.caller,
                function,
                role,
                logs_before: frame.logs.start,
            })
        })
}

/// The `(caller, role)` pairs the committed role-gated calls into `token` in `effects` need.
pub(crate) fn queries<T>(effects: &Effects<T>, token: Address) -> Vec<(Address, B256)> {
    let mut queries: Vec<_> = role_calls(effects, token)
        .map(|call| (call.caller, call.role))
        .collect();
    queries.sort_unstable();
    queries.dedup();
    queries
}

/// The step's effect on the roles that gate a token's calls.
pub const STEP_CHECKS: &[Check<Step<Roles, Ran>>] = &[check! {
    id: ROLE_AUTHZ,
    doc: "Only an account holding a token's role calls the token directly for what the role gates: mint, pause, unpause, burnBlocked and burnAt.",
    over: |s: &Step<Roles, Ran>| role_calls(&s.effects, s.post.token),
    judge: |s, call| {
        let mut held = *s.pre.held.get(&(call.caller, call.role))?;
        // The transaction may grant or revoke the role before the call.
        let before = s.logs.get(..call.logs_before).unwrap_or_default();
        for log in before.iter().filter(|log| log.address == s.post.token) {
            if let Ok(update) = RoleMembershipUpdated::decode_log_data(&log.data)
                && (update.account, update.role) == (call.caller, call.role)
            {
                held = update.hasRole;
            }
        }
        ensure!(held, "without the role {}", call.role)
    },
}];

impl Checked<TempoHardfork> for Roles {
    const CHECKS: &'static [Check<Self>] = &[];
}

impl StepChecked<Ran, TempoHardfork> for Roles {
    const STEP_CHECKS: &'static [Check<Step<Self, Ran>>] = STEP_CHECKS;
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::{Bytes, address};
    use invariants_core::{Outcome, Report};

    const TOKEN: Address = address!("0x20C0000000000000000000000000000000000001");
    const MINTER: Address = address!("0x0000000000000000000000000000000000000a11");

    fn issuer() -> B256 {
        keccak256("ISSUER_ROLE")
    }

    fn roles(held: bool) -> Roles {
        Roles {
            token: TOKEN,
            held: BTreeMap::from([((MINTER, issuer()), held)]),
        }
    }

    fn mint(effects: Effects<Ran>, outcome: Outcome) -> Effects<Ran> {
        let mint = ITIP20::mintCall {
            to: MINTER,
            amount: alloy_primitives::U256::from(1),
        };
        effects.call(MINTER, TOKEN, &mint, outcome)
    }

    fn judge(held: bool, effects: Effects<Ran>) -> (u64, u64, u64) {
        let mut report = Report::default();
        let step = Step::new(roles(held), roles(held), effects);
        report.run(STEP_CHECKS, &step, None);
        let counts = report.counts[ROLE_AUTHZ];
        (counts.evaluated, counts.armed, counts.fired)
    }

    #[test]
    fn a_committed_call_needs_the_role_it_gates_as_of_the_call() {
        let returned = || Outcome::Return(Bytes::new());
        let empty = || Effects {
            changes: Vec::new(),
            logs: Vec::new(),
            calls: None,
            ran: Ran::PreBlock,
        };
        assert_eq!(judge(true, mint(empty(), returned())), (1, 1, 0));
        assert_eq!(judge(false, mint(empty(), returned())), (1, 1, 1));
        assert_eq!(
            judge(false, mint(empty(), Outcome::Revert(Bytes::new()))),
            (0, 0, 0),
            "a reverted call is not judged"
        );

        let grant = RoleMembershipUpdated {
            role: issuer(),
            account: MINTER,
            sender: Address::ZERO,
            hasRole: true,
        };
        let granted = empty().event(TOKEN, &grant);
        assert_eq!(judge(false, mint(granted, returned())), (1, 1, 0));
        let revoked = empty().event(
            TOKEN,
            &RoleMembershipUpdated {
                hasRole: false,
                ..grant
            },
        );
        assert_eq!(judge(true, mint(revoked, returned())), (1, 1, 1));
    }
}
