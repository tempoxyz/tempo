//! Zone rules for the reservation core ([TIP-1153]).
//!
//! A zone runs the same core as Tempo L1 over its private TIP-20 balances, so private cards hold,
//! capture and refund as public ones do. Two zone rules sit in front of it:
//!
//! - Every state change moves or reserves funds inside the zone, so it needs T16 and the portal
//!   admin's transfer opt-in, as a zone-internal TIP-20 transfer does.
//! - Reads are private. A view about an owner answers only the owner and the counterparties that
//!   owner chose: a hold's placer and payee, a holder the owner approved, a creditor or payee the
//!   owner set terms for, and a lien's authority. Anyone else is refused, as `balanceOf` refuses
//!   anyone but the account.
//!   `releaseExpired`, which anyone may call, refuses a stranger to a live hold with the error a
//!   missing hold gives.
//!
//! [TIP-1153]: <https://docs.tempo.xyz/protocol/tips/tip-1153>

use alloy_primitives::{Address, B256};
use alloy_sol_types::{SolError, SolInterface};
use tempo_contracts::{
    precompiles::IReservationCore::{self, IReservationCoreCalls},
    zones::Unauthorized,
};
use tempo_precompiles::{
    dispatch::abi_decoder_config_for_spec,
    error::Result,
    reservations::{Reservations, empty_hold},
    storage::StorageCtx,
};

use crate::{
    L1State, L1StorageReader,
    execution::{CallCheck, CallRules},
    privacy::check_caller,
};

/// Zone-specific rules applied before forwarding to the upstream reservation core.
#[derive(Clone)]
pub(crate) struct ReservationRules<P> {
    /// Finalized Tempo state, used to read the portal's transfer opt-in.
    pub(crate) l1: L1State<P>,
}

impl<P: L1StorageReader> ReservationRules<P> {
    /// Admits a state change: T16 and the portal admin's transfer opt-in.
    fn admit_write(&self) -> Result<CallCheck> {
        if !StorageCtx::default().spec().is_t16()
            || !self.l1.read_portal(|portal| &portal.transfers_enabled)?
        {
            return Ok(unauthorized());
        }
        Ok(CallCheck::Continue)
    }

    /// Admits a read of `owner`'s position in `token`: the owner, or a holder it approved for the
    /// token that still has a budget or outstanding holds. Anyone else reads zero, all it could
    /// hold: a program asks about every token in an owner's funding order, approved or not.
    fn admit_position(caller: Address, owner: Address, token: Address) -> Result<CallCheck> {
        if caller == owner || Self::holds_for(caller, owner, token)? {
            return Ok(CallCheck::Continue);
        }
        Ok(CallCheck::Return(
            alloy_sol_types::SolValue::abi_encode(&0u128).into(),
        ))
    }

    /// Whether `owner` approved `caller` as a holder of `token`, or it still holds some.
    fn holds_for(caller: Address, owner: Address, token: Address) -> Result<bool> {
        let budget = Reservations::new().budget(owner, caller, token)?;
        Ok(budget.limit != 0 || budget.outstanding != 0)
    }

    /// Admits a read of the hold `id` that `placer` placed on `owner`'s balance: the owner, the
    /// placer or the payee. Anyone else reads an empty record, as for a hold that does not exist: a
    /// program checks for its leg's hold before placing it.
    fn admit_hold(caller: Address, owner: Address, placer: Address, id: B256) -> Result<CallCheck> {
        if caller == owner || caller == placer {
            return Ok(CallCheck::Continue);
        }
        if caller == Reservations::new().get_hold(owner, placer, id)?.payee {
            return Ok(CallCheck::Continue);
        }
        Ok(CallCheck::Return(
            alloy_sol_types::SolValue::abi_encode(&empty_hold()).into(),
        ))
    }

    /// Admits `releaseExpired` of the hold `id` that `placer` placed on `owner`'s balance. Anyone
    /// may release an expired hold, but a caller other than the owner, placer or payee is refused
    /// with `HoldNotFound` for a live hold as for a missing one, so it learns nothing about
    /// holds it cannot release.
    fn admit_release_expired(
        &self,
        caller: Address,
        owner: Address,
        placer: Address,
        id: B256,
    ) -> Result<CallCheck> {
        let check = self.admit_write()?;
        if !matches!(check, CallCheck::Continue) || caller == owner || caller == placer {
            return Ok(check);
        }
        let hold = Reservations::new().get_hold(owner, placer, id)?;
        let now: u64 = StorageCtx::default().timestamp().saturating_to();
        let expired = hold.kind != 0 && hold.expiresAt != 0 && now >= hold.expiresAt;
        if expired || caller == hold.payee {
            return Ok(check);
        }
        Ok(CallCheck::Revert(
            IReservationCore::HoldNotFound {}.abi_encode().into(),
        ))
    }

    /// Admits a read of `owner`'s debts in `token`: the owner, one of its creditors, or an
    /// approved holder.
    fn admit_debt(caller: Address, owner: Address, token: Address) -> Result<CallCheck> {
        if caller == owner {
            return Ok(CallCheck::Continue);
        }
        let debts = Reservations::new().debt_of(owner, token)?;
        if debts.iter().any(|debt| debt.creditor == caller)
            || Self::holds_for(caller, owner, token)?
        {
            return Ok(CallCheck::Continue);
        }
        Ok(unauthorized())
    }

    fn try_admit(&self, call: IReservationCoreCalls, caller: Address) -> Result<CallCheck> {
        use IReservationCoreCalls as C;
        // Intentionally exhaustive: an upstream ABI addition must be classified here.
        Ok(match call {
            C::approveHolder(_)
            | C::setPayeeTerms(_)
            | C::hold(_)
            | C::holdFrom(_)
            | C::pledge(_)
            | C::pledgeFrom(_)
            | C::lien(_)
            | C::adjust(_)
            | C::capture(_)
            | C::release(_)
            | C::charge(_)
            | C::refund(_)
            | C::clearLapsedDebt(_) => self.admit_write()?,
            C::releaseExpired(IReservationCore::releaseExpiredCall { owner, placer, id }) => {
                self.admit_release_expired(caller, owner, placer, id)?
            }
            C::getHold(IReservationCore::getHoldCall { owner, placer, id }) => {
                Self::admit_hold(caller, owner, placer, id)?
            }
            C::reserved(IReservationCore::reservedCall { owner, token })
            | C::available(IReservationCore::availableCall { owner, token }) => {
                Self::admit_position(caller, owner, token)?
            }
            C::debtOf(IReservationCore::debtOfCall { owner, token }) => {
                Self::admit_debt(caller, owner, token)?
            }
            C::budget(IReservationCore::budgetCall { owner, holder, .. }) => {
                check_caller(caller, &[owner, holder])
            }
            C::payeeTerms(IReservationCore::payeeTermsCall { owner, payee, .. }) => {
                check_caller(caller, &[owner, payee])
            }
        })
    }
}

impl<P: L1StorageReader> CallRules for ReservationRules<P> {
    fn admit(&self, data: &[u8], caller: Address) -> CallCheck {
        let config = abi_decoder_config_for_spec(StorageCtx::default().spec());
        let Ok(call) = IReservationCoreCalls::abi_decode_with_config(data, config) else {
            // Preserve the upstream error and gas behavior for malformed or unknown calldata.
            return CallCheck::Continue;
        };
        self.try_admit(call, caller)
            .unwrap_or_else(CallCheck::Error)
    }
}

fn unauthorized() -> CallCheck {
    CallCheck::Revert(Unauthorized {}.abi_encode().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, address};
    use alloy_sol_types::SolCall;
    use evm2::precompiles::PrecompileError;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::{
        PATH_USD_ADDRESS, Precompile, test_util::TIP20Setup, zone_factory::ZonePortalStorage,
    };
    use test_case::test_case;

    use crate::{
        TempoState,
        test_utils::{MockL1Reader, test_context, test_storage_provider},
    };
    use tempo_precompiles::storage::Handler as _;

    const TEMPO_BLOCK_NUMBER: u64 = 7;
    const PORTAL_ADDRESS: Address = address!("0x0000000000000000000000000000000000000b01");
    const OWNER: Address = Address::repeat_byte(0x11);
    const HOLDER: Address = Address::repeat_byte(0x22);
    const PAYEE: Address = Address::repeat_byte(0x33);
    const OUTSIDER: Address = Address::repeat_byte(0x44);

    fn rules(transfers_enabled: bool) -> ReservationRules<MockL1Reader> {
        let reader = MockL1Reader::default();
        reader
            .with_storage(TEMPO_BLOCK_NUMBER, || {
                ZonePortalStorage::new(PORTAL_ADDRESS)
                    .transfers_enabled
                    .write(transfers_enabled)
            })
            .unwrap();
        ReservationRules {
            l1: L1State::new(reader, PORTAL_ADDRESS),
        }
    }

    /// Admits each call at `spec` against a zone where OWNER approved HOLDER and HOLDER placed a hold
    /// for PAYEE.
    fn admit_all(
        rules: &ReservationRules<MockL1Reader>,
        spec: TempoHardfork,
        calls: &[(Vec<u8>, Address)],
    ) -> Vec<CallCheck> {
        in_zone(spec, || {
            calls
                .iter()
                .map(|(data, caller)| rules.admit(data, *caller))
                .collect()
        })
    }

    /// Runs `f` at `spec` in a zone where OWNER approved HOLDER and HOLDER placed a hold for
    /// PAYEE.
    fn in_zone<R>(spec: TempoHardfork, f: impl FnOnce() -> R) -> R {
        in_zone_after(spec, 0, f)
    }

    /// Like `in_zone`, with `f` run `seconds` after the hold was placed.
    fn in_zone_after<R>(spec: TempoHardfork, seconds: u64, f: impl FnOnce() -> R) -> R {
        let mut ctx = test_context();
        ctx.cfg.spec = spec;
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
        StorageCtx::enter(&mut storage, || {
            TempoState::new()
                .tempo_block_number
                .write(TEMPO_BLOCK_NUMBER)
                .unwrap();
            TIP20Setup::path_usd(OWNER)
                .with_issuer(OWNER)
                .with_mint(OWNER, U256::from(1_000u64))
                .apply()
                .unwrap();
            // Through the core's ABI, as a transaction would: OWNER approves HOLDER, which holds
            // part of OWNER's balance for PAYEE.
            let mut core = Reservations::new();
            core.initialize().unwrap();
            let approve = IReservationCore::approveHolderCall {
                holder: HOLDER,
                token: PATH_USD_ADDRESS,
                limit: 500,
                period: 0,
            };
            core.call(&approve.abi_encode(), OWNER)
                .expect("approve the holder");
            let expires_at = StorageCtx::default().timestamp().saturating_to::<u64>() + 3600;
            let hold = IReservationCore::holdFromCall {
                owner: OWNER,
                request: IReservationCore::HoldRequest {
                    token: PATH_USD_ADDRESS,
                    id: B256::repeat_byte(1),
                    amount: 100,
                    expiresAt: expires_at,
                    payee: PAYEE,
                    standIn: false,
                },
            };
            core.call(&hold.abi_encode(), HOLDER)
                .expect("place the hold");
        });
        ctx.block.timestamp += U256::from(seconds);
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
        StorageCtx::enter(&mut storage, f)
    }

    fn allowed(check: &CallCheck) -> bool {
        matches!(check, CallCheck::Continue)
    }

    #[test]
    fn reads_answer_only_the_owner_and_its_counterparties() {
        let token = PATH_USD_ADDRESS;
        let id = B256::repeat_byte(1);
        let hold = IReservationCore::getHoldCall {
            owner: OWNER,
            placer: HOLDER,
            id,
        }
        .abi_encode();
        let reserved = IReservationCore::reservedCall {
            owner: OWNER,
            token,
        }
        .abi_encode();
        let terms = IReservationCore::payeeTermsCall {
            owner: OWNER,
            payee: PAYEE,
            token,
        }
        .abi_encode();
        let calls = [
            (hold.clone(), OWNER),
            (hold.clone(), HOLDER),
            (hold.clone(), PAYEE),
            (hold, OUTSIDER),
            (reserved.clone(), OWNER),
            (reserved.clone(), HOLDER),
            (reserved.clone(), PAYEE),
            (reserved, OUTSIDER),
            (terms.clone(), PAYEE),
            (terms, OUTSIDER),
        ];
        let checks = admit_all(&rules(true), TempoHardfork::T16, &calls);
        let admitted: Vec<bool> = checks.iter().map(allowed).collect();
        assert_eq!(
            admitted,
            [
                true, true, true, false, true, true, false, false, true, false
            ]
        );
        // A stranger to the position reads zero rather than the owner's balance.
        let zero = alloy_sol_types::SolValue::abi_encode(&0u128);
        assert!(
            matches!(&checks[6], CallCheck::Return(output) if output.as_ref() == zero.as_slice())
        );
        // A stranger to a hold reads an empty record, the same as for a hold that does not exist.
        let empty = alloy_sol_types::SolValue::abi_encode(&empty_hold());
        assert!(
            matches!(&checks[3], CallCheck::Return(output) if output.as_ref() == empty.as_slice())
        );
        assert!(matches!(&checks[9], CallCheck::Revert(_)));
    }

    /// A caller OWNER never approved is refused the same way whether or not OWNER could afford
    /// the amount, so placing records tells it nothing about OWNER's balance.
    #[test]
    fn unapproved_placers_learn_nothing_about_the_owner_balance() {
        let rules = rules(true);
        let outcomes = in_zone(TempoHardfork::T16, || {
            let expires_at = StorageCtx::default().timestamp().saturating_to::<u64>() + 3600;
            [1u128, 900, 10_000]
                .into_iter()
                .flat_map(|amount| {
                    let hold = IReservationCore::holdFromCall {
                        owner: OWNER,
                        request: IReservationCore::HoldRequest {
                            token: PATH_USD_ADDRESS,
                            id: B256::repeat_byte(2),
                            amount,
                            expiresAt: expires_at,
                            payee: PAYEE,
                            standIn: false,
                        },
                    }
                    .abi_encode();
                    let pledge = IReservationCore::pledgeFromCall {
                        owner: OWNER,
                        token: PATH_USD_ADDRESS,
                        id: B256::repeat_byte(3),
                        amount,
                        expiresAt: expires_at,
                    }
                    .abi_encode();
                    [hold, pledge]
                })
                .map(|data| {
                    assert!(allowed(&rules.admit(&data, OUTSIDER)));
                    match Reservations::new().call(&data, OUTSIDER) {
                        Err(PrecompileError::Revert(bytes)) => bytes,
                        other => panic!("expected a revert, got {other:?}"),
                    }
                })
                .collect::<Vec<_>>()
        });
        let refused = IReservationCore::Unauthorized {}.abi_encode();
        assert!(
            outcomes
                .iter()
                .all(|bytes| bytes.as_ref() == refused.as_slice()),
            "{outcomes:?}"
        );
    }

    #[test_case(TempoHardfork::T16, true, true)]
    #[test_case(TempoHardfork::T16, false, false)]
    fn writes_require_the_portal_transfer_opt_in(
        spec: TempoHardfork,
        transfers_enabled: bool,
        expected: bool,
    ) {
        let release = IReservationCore::releaseCall {
            owner: OWNER,
            placer: HOLDER,
            id: B256::repeat_byte(1),
        }
        .abi_encode();
        let checks = admit_all(&rules(transfers_enabled), spec, &[(release, HOLDER)]);
        assert_eq!(allowed(&checks[0]), expected);
    }

    /// `releaseExpired` tells a stranger nothing about a live hold: it is refused as a missing
    /// hold is, while the owner, placer and payee get the core's own answer, and anyone may
    /// release the hold once it has expired.
    #[test]
    fn release_expired_hides_live_holds_from_strangers() {
        let release = |id: B256| {
            IReservationCore::releaseExpiredCall {
                owner: OWNER,
                placer: HOLDER,
                id,
            }
            .abi_encode()
        };
        let (live, missing) = (release(B256::repeat_byte(1)), release(B256::repeat_byte(2)));
        let not_found: Vec<u8> = IReservationCore::HoldNotFound {}.abi_encode();
        let refused = |check: &CallCheck| matches!(check, CallCheck::Revert(output) if output.as_ref() == not_found.as_slice());
        let rules = rules(true);

        let checks = admit_all(
            &rules,
            TempoHardfork::T16,
            &[
                (live.clone(), OUTSIDER),
                (missing.clone(), OUTSIDER),
                (live.clone(), OWNER),
                (live.clone(), HOLDER),
                (live.clone(), PAYEE),
            ],
        );
        assert!(refused(&checks[0]));
        assert!(refused(&checks[1]));
        assert!(checks[2..].iter().all(allowed));
        // The core answers a missing hold the same way, so a stranger reads one outcome.
        assert!(in_zone(TempoHardfork::T16, || {
            matches!(
                Reservations::new().call(&missing, OUTSIDER),
                Err(PrecompileError::Revert(output)) if output.as_ref() == not_found.as_slice()
            )
        }));

        let checks = in_zone_after(TempoHardfork::T16, 3_600, || {
            [(live.clone(), OUTSIDER), (missing.clone(), OUTSIDER)]
                .iter()
                .map(|(data, caller)| rules.admit(data, *caller))
                .collect::<Vec<_>>()
        });
        assert!(allowed(&checks[0]));
        assert!(refused(&checks[1]));
    }
}
