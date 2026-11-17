//! Zone rules for the reservation core ([TIP-1153]).
//!
//! A zone runs the same core as Tempo L1 over its private TIP-20 balances, so private cards hold,
//! capture and refund as public ones do. Two zone rules sit in front of it:
//!
//! - Every state change moves or reserves funds inside the zone, so it needs T15 and the portal
//!   admin's transfer opt-in, as a zone-internal TIP-20 transfer does.
//! - Reads are private. A view about an owner answers only the owner and the counterparties that
//!   owner chose: a hold's placer and payee, a holder the owner approved, a creditor or payee the
//!   owner set terms for, and a lien's authority. Anyone else is refused, as `balanceOf` refuses
//!   anyone but the account.
//!
//! [TIP-1153]: <https://docs.tempo.xyz/protocol/tips/tip-1153>

use alloy_primitives::{Address, B256};
use alloy_sol_types::{SolError, SolInterface};
use tempo_contracts::{
    precompiles::IReservationCore::{self, IReservationCoreCalls},
    zones::Unauthorized,
};
use tempo_precompiles::{
    dispatch::abi_decoder_config_for_spec, error::Result, reservations::Reservations,
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
    /// Admits a state change: T15 and the portal admin's transfer opt-in.
    fn admit_write(&self) -> Result<CallCheck> {
        if !StorageCtx::default().spec().is_t15()
            || !self.l1.read_portal(|portal| &portal.transfers_enabled)?
        {
            return Ok(unauthorized());
        }
        Ok(CallCheck::Continue)
    }

    /// Admits a read of `owner`'s position in `token`: the owner, or a holder it approved for the
    /// token that still has an allowance or outstanding holds. Anyone else reads zero, all it could
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
        let allowance = Reservations::new().allowance(owner, caller, token)?;
        Ok(allowance.allowance != 0 || allowance.outstanding != 0)
    }

    /// Admits a read of `owner`'s hold `id`: the owner, its placer or its payee. Anyone else reads
    /// an empty record, as for a hold that does not exist: a program checks for its leg's hold
    /// before placing it.
    fn admit_hold(caller: Address, owner: Address, id: B256) -> Result<CallCheck> {
        if caller == owner {
            return Ok(CallCheck::Continue);
        }
        let record = Reservations::new().get_hold(owner, id)?;
        if caller == record.placer || caller == record.payee {
            return Ok(CallCheck::Continue);
        }
        Ok(CallCheck::Return(
            alloy_sol_types::SolValue::abi_encode(&empty_hold()).into(),
        ))
    }

    /// Admits a read of lien `id` of `authority`: the authority or the owner it binds.
    fn admit_lien(caller: Address, authority: Address, id: B256) -> Result<CallCheck> {
        if caller == authority {
            return Ok(CallCheck::Continue);
        }
        let lien = Reservations::new().lien_of(authority, id)?;
        Ok(check_caller(caller, &[lien.owner]))
    }

    /// Admits a read of `owner`'s debt in `token`: the owner, its creditor, or an approved holder.
    fn admit_debt(caller: Address, owner: Address, token: Address) -> Result<CallCheck> {
        if caller == owner {
            return Ok(CallCheck::Continue);
        }
        let debt = Reservations::new().debt_of(owner, token)?;
        if (!debt.creditor.is_zero() && debt.creditor == caller)
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
            | C::setDebtCap(_)
            | C::setCaptureTolerance(_)
            | C::setOfflineCap(_)
            | C::hold(_)
            | C::holdFrom(_)
            | C::adjust(_)
            | C::capture(_)
            | C::release(_)
            | C::releaseExpired(_)
            | C::refund(_)
            | C::charge(_)
            | C::lien(_)
            | C::pledge(_)
            | C::releaseLien(_)
            | C::reduceLien(_)
            | C::seizeLien(_)
            | C::releaseExpiredLien(_) => self.admit_write()?,
            C::getHold(IReservationCore::getHoldCall { owner, id }) => {
                Self::admit_hold(caller, owner, id)?
            }
            C::reserved(IReservationCore::reservedCall { owner, token })
            | C::available(IReservationCore::availableCall { owner, token })
            | C::liened(IReservationCore::lienedCall { owner, token }) => {
                Self::admit_position(caller, owner, token)?
            }
            C::debtOf(IReservationCore::debtOfCall { owner, token }) => {
                Self::admit_debt(caller, owner, token)?
            }
            C::allowance(IReservationCore::allowanceCall { owner, holder, .. }) => {
                check_caller(caller, &[owner, holder])
            }
            C::debtCap(IReservationCore::debtCapCall {
                owner, creditor, ..
            }) => check_caller(caller, &[owner, creditor]),
            C::captureTolerance(IReservationCore::captureToleranceCall {
                owner, payee, ..
            })
            | C::offlineCap(IReservationCore::offlineCapCall { owner, payee, .. }) => {
                check_caller(caller, &[owner, payee])
            }
            C::lienOf(IReservationCore::lienOfCall { authority, id }) => {
                Self::admit_lien(caller, authority, id)?
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

/// The record of a hold that does not exist.
fn empty_hold() -> IReservationCore::HoldRecord {
    IReservationCore::HoldRecord {
        token: Address::ZERO,
        placer: Address::ZERO,
        payee: Address::ZERO,
        held: 0,
        approved: 0,
        captured: 0,
        refunded: 0,
        expiresAt: 0,
        standIn: false,
        settled: false,
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
                allowance: 500,
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
            calls
                .iter()
                .map(|(data, caller)| rules.admit(data, *caller))
                .collect()
        })
    }

    fn allowed(check: &CallCheck) -> bool {
        matches!(check, CallCheck::Continue)
    }

    #[test]
    fn reads_answer_only_the_owner_and_its_counterparties() {
        let token = PATH_USD_ADDRESS;
        let id = B256::repeat_byte(1);
        let hold = IReservationCore::getHoldCall { owner: OWNER, id }.abi_encode();
        let reserved = IReservationCore::reservedCall {
            owner: OWNER,
            token,
        }
        .abi_encode();
        let terms = IReservationCore::captureToleranceCall {
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
        let checks = admit_all(&rules(true), TempoHardfork::T15, &calls);
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

    #[test_case(TempoHardfork::T15, true, true)]
    #[test_case(TempoHardfork::T15, false, false)]
    fn writes_require_the_portal_transfer_opt_in(
        spec: TempoHardfork,
        transfers_enabled: bool,
        expected: bool,
    ) {
        let release = IReservationCore::releaseCall {
            owner: OWNER,
            id: B256::repeat_byte(1),
        }
        .abi_encode();
        let checks = admit_all(&rules(transfers_enabled), spec, &[(release, HOLDER)]);
        assert_eq!(allowed(&checks[0]), expected);
    }
}
