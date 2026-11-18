use super::*;
use crate::{
    account_keychain::{AccountKeychain, KeyRestrictions, SignatureType, TokenLimit},
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
    test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
    tip20::{BURN_BLOCKED_ROLE, IRolesAuth, ITIP20},
    tip403_registry::{ITIP403Registry, TIP403Registry},
};

use alloy::primitives::IntoLogData;
use proptest::prelude::*;
use std::collections::BTreeMap;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::IReservationCore::IReservationCoreCalls;

mod model;

const NOW: u64 = 1_000;
const EXPIRY: u64 = NOW + 600;
const DAY: u64 = 24 * 60 * 60;

struct Fixture {
    admin: Address,
    owner: Address,
    payee: Address,
    holder: Address,
    token: TIP20Token,
    reservations: Reservations,
}

impl Fixture {
    /// Mints the balance to a fresh owner of a fresh token.
    fn new(balance: u64) -> Result<Self> {
        let admin = Address::random();
        let owner = Address::random();
        let token = TIP20Setup::create("Core USD", "CUSD", admin)
            .with_issuer(admin)
            .with_mint(owner, U256::from(balance))
            .apply()?;
        let mut reservations = Reservations::new();
        reservations.initialize()?;
        Ok(Self {
            admin,
            owner,
            payee: Address::random(),
            holder: Address::random(),
            token,
            reservations,
        })
    }

    fn request(&self, id: B256, amount: u128, stand_in: bool) -> IReservationCore::HoldRequest {
        IReservationCore::HoldRequest {
            token: self.token.address(),
            id,
            amount,
            expiresAt: EXPIRY,
            payee: self.payee,
            standIn: stand_in,
        }
    }

    fn hold(&mut self, id: B256, amount: u128) -> Result<()> {
        let request = self.request(id, amount, false);
        self.reservations.place(self.owner, self.owner, request)
    }

    fn hold_stand_in(&mut self, id: B256, amount: u128) -> Result<()> {
        let request = self.request(id, amount, true);
        self.reservations.place(self.owner, self.owner, request)
    }

    fn hold_from(&mut self, id: B256, amount: u128) -> Result<()> {
        let request = self.request(id, amount, false);
        self.reservations.place(self.holder, self.owner, request)
    }

    fn approve(&mut self, limit: u128, period: u32) -> Result<()> {
        self.reservations.approve_holder(
            self.owner,
            IReservationCore::approveHolderCall {
                holder: self.holder,
                token: self.token.address(),
                limit,
                period,
            },
        )
    }

    fn adjust(&mut self, caller: Address, placer: Address, id: B256, amount: u128) -> Result<()> {
        self.reservations.adjust(
            caller,
            IReservationCore::adjustCall {
                owner: self.owner,
                placer,
                id,
                amount,
            },
        )
    }

    fn capture_of(
        &mut self,
        caller: Address,
        placer: Address,
        id: B256,
        amount: u128,
        is_final: bool,
    ) -> Result<()> {
        self.reservations.capture(
            caller,
            IReservationCore::captureCall {
                owner: self.owner,
                placer,
                id,
                amount,
                isFinal: is_final,
            },
        )
    }

    /// Captures a hold the owner placed.
    fn capture(&mut self, caller: Address, id: B256, amount: u128, is_final: bool) -> Result<()> {
        self.capture_of(caller, self.owner, id, amount, is_final)
    }

    fn release(&mut self, caller: Address, placer: Address, id: B256) -> Result<()> {
        self.reservations.release(
            caller,
            IReservationCore::releaseCall {
                owner: self.owner,
                placer,
                id,
            },
        )
    }

    fn release_expired(&mut self, placer: Address, id: B256) -> Result<()> {
        self.reservations
            .release_expired(IReservationCore::releaseExpiredCall {
                owner: self.owner,
                placer,
                id,
            })
    }

    fn refund(&mut self, caller: Address, id: B256, amount: u128) -> Result<()> {
        self.reservations.refund(
            caller,
            IReservationCore::refundCall {
                owner: self.owner,
                token: self.token.address(),
                placer: self.owner,
                id,
                amount,
            },
        )
    }

    fn charge(&mut self, caller: Address, amount: u128, stand_in: bool) -> Result<()> {
        self.charge_to(caller, self.payee, amount, stand_in)
    }

    fn charge_to(
        &mut self,
        caller: Address,
        payee: Address,
        amount: u128,
        stand_in: bool,
    ) -> Result<()> {
        self.reservations.charge(
            caller,
            IReservationCore::chargeCall {
                owner: self.owner,
                token: self.token.address(),
                id: B256::random(),
                amount,
                payee,
                standIn: stand_in,
            },
        )
    }

    fn set_terms_for(
        &mut self,
        payee: Address,
        debt_cap: u128,
        offline_cap: u128,
        tolerance_bps: u16,
        debt_term: u32,
    ) -> Result<()> {
        self.reservations.set_payee_terms(
            self.owner,
            IReservationCore::setPayeeTermsCall {
                payee,
                token: self.token.address(),
                terms: IReservationCore::PayeeTerms {
                    debtCap: debt_cap,
                    offlineCap: offline_cap,
                    toleranceBps: tolerance_bps,
                    debtTerm: debt_term,
                },
            },
        )
    }

    fn set_terms(&mut self, debt_cap: u128, offline_cap: u128, tolerance_bps: u16) -> Result<()> {
        self.set_terms_for(self.payee, debt_cap, offline_cap, tolerance_bps, 0)
    }

    fn lien_authority(&mut self) -> Result<Address> {
        let authority = Address::random();
        self.token.grant_role_internal(authority, LIEN_ROLE)?;
        Ok(authority)
    }

    fn lien(&mut self, authority: Address, id: B256, amount: u128, expires_at: u64) -> Result<()> {
        self.reservations.lien(
            authority,
            IReservationCore::lienCall {
                owner: self.owner,
                token: self.token.address(),
                id,
                amount,
                expiresAt: expires_at,
            },
        )
    }

    fn pledge(
        &mut self,
        authority: Address,
        id: B256,
        amount: u128,
        expires_at: u64,
    ) -> Result<()> {
        self.reservations.pledge(
            self.owner,
            IReservationCore::pledgeCall {
                authority,
                token: self.token.address(),
                id,
                amount,
                expiresAt: expires_at,
            },
        )
    }

    fn pledge_from(&mut self, id: B256, amount: u128, expires_at: u64) -> Result<()> {
        self.reservations.pledge_from(
            self.holder,
            IReservationCore::pledgeFromCall {
                owner: self.owner,
                token: self.token.address(),
                id,
                amount,
                expiresAt: expires_at,
            },
        )
    }

    fn mint(&mut self, to: Address, amount: u64) -> Result<()> {
        self.token.mint(
            self.admin,
            ITIP20::mintCall {
                to,
                amount: U256::from(amount),
            },
        )
    }

    fn transfer(&mut self, from: Address, to: Address, amount: u64) -> Result<bool> {
        self.token.transfer(
            from,
            ITIP20::transferCall {
                to,
                amount: U256::from(amount),
            },
        )
    }

    fn balance(&self, account: Address) -> Result<U256> {
        self.token.balance_of(ITIP20::balanceOfCall { account })
    }

    fn reserved(&self) -> Result<u128> {
        self.reservations
            .reserved_of(self.owner, self.token.address())
    }

    fn available(&self) -> Result<u128> {
        self.reservations
            .available_of(self.owner, self.token.address())
    }

    fn debts(&self) -> Result<Vec<(Address, u128)>> {
        Ok(self
            .reservations
            .debt_of(self.owner, self.token.address())?
            .into_iter()
            .map(|debt| (debt.creditor, debt.amount))
            .collect())
    }

    fn record(&self, placer: Address, id: B256) -> Result<IReservationCore::HoldRecord> {
        self.reservations.get_hold(self.owner, placer, id)
    }

    fn budget(&self) -> Result<IReservationCore::Budget> {
        self.reservations
            .budget(self.owner, self.holder, self.token.address())
    }

    /// Makes the token's transfer policy a blacklist of the accounts.
    fn blacklist(&mut self, accounts: Vec<Address>) -> Result<()> {
        let mut registry = TIP403Registry::new();
        registry.initialize()?;
        let policy = registry.create_policy_with_accounts(
            self.admin,
            ITIP403Registry::createPolicyWithAccountsCall {
                admin: self.admin,
                policyType: ITIP403Registry::PolicyType::BLACKLIST,
                accounts,
            },
        )?;
        self.token.change_transfer_policy_id(
            self.admin,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: policy,
            },
        )
    }
}

fn new_storage() -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T16);
    storage.set_timestamp(U256::from(NOW));
    storage
}

/// Runs the closure at T16 with the block timestamp at NOW.
fn at_fork(f: impl FnOnce() -> eyre::Result<()>) -> eyre::Result<()> {
    let mut storage = new_storage();
    StorageCtx::enter(&mut storage, f)
}

fn warp(seconds: u64) {
    let now = StorageCtx.timestamp().saturating_to::<u64>();
    StorageCtx.set_timestamp(U256::from(now + seconds));
}

/// Signs as the account with an access key that has no spending limits.
fn sign_with_access_key(account: Address) -> Result<()> {
    let mut keychain = AccountKeychain::new();
    keychain.set_tx_origin(account)?;
    keychain.set_transaction_key(Address::random())
}

/// Signs as the account with an access key that may spend at most the limit of the token.
fn sign_with_limited_key(account: Address, token: Address, limit: u64) -> Result<()> {
    let mut keychain = AccountKeychain::new();
    keychain.initialize()?;
    keychain.set_transaction_key(Address::ZERO)?;
    keychain.set_tx_origin(account)?;
    let key = Address::random();
    keychain.authorize_key(
        account,
        key,
        SignatureType::Secp256k1,
        KeyRestrictions {
            expiry: u64::MAX,
            enforceLimits: true,
            limits: vec![TokenLimit {
                token,
                amount: U256::from(limit),
                period: 0,
            }],
            allowAnyCalls: true,
            allowedCalls: vec![],
        },
        None,
    )?;
    keychain.set_transaction_key(key)
}

/// Evaluates a call that must fail and returns its error, reverting what it wrote as a failed
/// precompile call does.
macro_rules! err {
    ($call:expr) => {{
        let checkpoint = StorageCtx.checkpoint();
        let result = $call;
        drop(checkpoint);
        result.expect_err("call must fail")
    }};
}

/// Asserts the reservation core's latest event.
fn assert_last_event(reservations: &Reservations, event: ReservationsEvent) {
    assert_eq!(
        reservations.emitted_events().last(),
        Some(&event.into_log_data())
    );
}

fn e(error: IReservationCore::IReservationCoreErrors) -> TempoPrecompileError {
    error.into()
}

#[test]
fn test_selector_coverage() -> eyre::Result<()> {
    at_fork(|| {
        let mut reservations = Reservations::new();
        let unsupported = check_selector_coverage(
            &mut reservations,
            IReservationCoreCalls::SELECTORS,
            "IReservationCore",
            IReservationCoreCalls::name_by_selector,
        );
        assert_full_coverage([unsupported]);
        Ok(())
    })
}

#[test]
fn test_hold_reserves_in_place() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 300)?;
        assert_eq!((f.reserved()?, f.available()?), (300, 700));
        assert_eq!(f.balance(f.owner)?, U256::from(1_000));
        let record = f.record(f.owner, id)?;
        assert_eq!(
            (record.held, record.captureLimit, record.kind, record.payee),
            (300, 300, kind::HOLD, f.payee)
        );
        // Reserved funds cannot be transferred.
        let other = Address::random();
        assert!(
            err!(f.transfer(f.owner, other, 701))
                .to_string()
                .contains("nsufficient")
        );
        f.transfer(f.owner, other, 700)?;
        assert_eq!(f.balance(f.owner)?, U256::from(300));
        Ok(())
    })
}

#[test]
fn test_hold_rejects_invalid_requests() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(100)?;
        let id = B256::random();
        assert_eq!(err!(f.hold(id, 0)), e(ReservationsError::invalid_amount()));
        assert_eq!(
            err!(f.hold(id, 101)),
            e(ReservationsError::insufficient_available())
        );
        let mut late = f.request(id, 10, false);
        late.expiresAt = NOW + MAX_HOLD_DURATION + 1;
        assert_eq!(
            err!(f.reservations.place(f.owner, f.owner, late)),
            e(ReservationsError::invalid_expiry())
        );
        let mut past = f.request(id, 10, false);
        past.expiresAt = NOW;
        assert_eq!(
            err!(f.reservations.place(f.owner, f.owner, past)),
            e(ReservationsError::invalid_expiry())
        );
        let mut to_self = f.request(id, 10, false);
        to_self.payee = f.owner;
        assert_eq!(
            err!(f.reservations.place(f.owner, f.owner, to_self)),
            e(ReservationsError::policy_forbids())
        );
        f.hold(id, 10)?;
        assert_eq!(err!(f.hold(id, 10)), e(ReservationsError::hold_exists()));
        Ok(())
    })
}

/// Each placer's ids are its own: a stranger cannot take or touch the id another placer uses.
#[test]
fn test_hold_ids_are_namespaced_by_placer() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        f.approve(500, 0)?;
        let id = B256::repeat_byte(7);
        // The holder places first; the owner's own hold with the same id is a different record.
        f.hold_from(id, 100)?;
        f.hold(id, 200)?;
        assert_eq!(f.record(f.holder, id)?.held, 100);
        assert_eq!(f.record(f.owner, id)?.held, 200);
        assert_eq!(f.reserved()?, 300);
        // A stranger's charge with the id touches neither record.
        let stranger = Address::random();
        assert_eq!(
            err!(f.charge(stranger, 1, false)),
            e(ReservationsError::unauthorized())
        );
        // The payee names the placer to capture.
        f.capture_of(f.payee, f.holder, id, 100, true)?;
        assert_eq!(f.record(f.holder, id)?, empty_hold());
        assert_eq!(f.record(f.owner, id)?.held, 200);
        assert_eq!(
            err!(f.capture_of(f.payee, f.holder, id, 1, true)),
            e(ReservationsError::hold_not_found())
        );
        // A stranger cannot act on either record.
        assert_eq!(
            err!(f.release(stranger, f.owner, id)),
            e(ReservationsError::unauthorized())
        );
        assert_eq!(
            err!(f.adjust(stranger, f.owner, id, 1)),
            e(ReservationsError::unauthorized())
        );
        Ok(())
    })
}

#[test]
fn test_settled_holds_are_deleted_and_ids_reusable() -> eyre::Result<()> {
    let mut storage = new_storage();
    let count = |storage: &HashMapStorageProvider| storage.nonzero_slot_count(RESERVATIONS_ADDRESS);
    let mut f = StorageCtx::enter(&mut storage, || Fixture::new(1_000))?;
    let base = count(&storage);
    let id = B256::random();
    StorageCtx::enter(&mut storage, || f.hold(id, 100))?;
    // Two record slots and the owner's position.
    assert_eq!(count(&storage), base + 3);
    StorageCtx::enter(&mut storage, || f.capture(f.payee, id, 40, true))?;
    assert_eq!(count(&storage), base);
    StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
        assert_eq!(f.record(f.owner, id)?, empty_hold());
        f.hold(id, 50)?;
        f.release(f.payee, f.owner, id)?;
        Ok(())
    })?;
    assert_eq!(count(&storage), base);
    Ok(())
}

#[test]
fn test_part_captures_and_final_release_the_rest() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 500)?;
        f.capture(f.payee, id, 200, false)?;
        assert_eq!((f.reserved()?, f.balance(f.payee)?), (300, U256::from(200)));
        assert_eq!(f.record(f.owner, id)?.captureLimit, 300);
        f.capture(f.owner, id, 100, true)?;
        assert_eq!((f.reserved()?, f.available()?), (0, 700));
        assert_eq!(f.balance(f.payee)?, U256::from(300));
        assert_eq!(
            err!(f.capture(f.payee, id, 0, false)),
            e(ReservationsError::hold_not_found())
        );
        Ok(())
    })
}

#[test]
fn test_capture_tolerance_is_fixed_at_placement() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.set_terms(0, 0, 2_000)?;
        f.hold(id, 100)?;
        assert_eq!(f.record(f.owner, id)?.captureLimit, 120);
        // Raising the payee's tolerance later does not widen the hold.
        f.set_terms(0, 0, 5_000)?;
        assert_eq!(
            err!(f.capture(f.payee, id, 121, true)),
            e(ReservationsError::capture_limit_exceeded())
        );
        f.capture(f.payee, id, 120, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(120));
        Ok(())
    })
}

#[test]
fn test_adjust_by_placer_and_stand_in_limits() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 100)?;
        assert_eq!(
            err!(f.adjust(f.payee, f.owner, id, 50)),
            e(ReservationsError::unauthorized())
        );
        f.adjust(f.owner, f.owner, id, 300)?;
        assert_eq!(
            (f.reserved()?, f.record(f.owner, id)?.captureLimit),
            (300, 300)
        );
        f.adjust(f.owner, f.owner, id, 50)?;
        assert_eq!(
            (f.reserved()?, f.record(f.owner, id)?.captureLimit),
            (50, 300)
        );
        f.adjust(f.owner, f.owner, id, 200)?;
        assert_eq!(f.record(f.owner, id)?.captureLimit, 300);

        // A stand-in's approval was fixed offline.
        let stand_in = B256::random();
        f.hold_stand_in(stand_in, 100)?;
        f.adjust(f.owner, f.owner, stand_in, 60)?;
        f.adjust(f.owner, f.owner, stand_in, 100)?;
        assert_eq!(
            err!(f.adjust(f.owner, f.owner, stand_in, 101)),
            e(ReservationsError::invalid_amount())
        );
        Ok(())
    })
}

#[test]
fn test_hard_expiry() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 100)?;
        assert_eq!(
            err!(f.release_expired(f.owner, id)),
            e(ReservationsError::hold_not_expired())
        );
        warp(600);
        assert_eq!(
            err!(f.capture(f.payee, id, 100, true)),
            e(ReservationsError::hold_expired())
        );
        assert_eq!(
            err!(f.adjust(f.owner, f.owner, id, 10)),
            e(ReservationsError::hold_expired())
        );
        f.release_expired(f.owner, id)?;
        assert_eq!((f.reserved()?, f.record(f.owner, id)?), (0, empty_hold()));
        Ok(())
    })
}

#[test]
fn test_budget_spends_are_never_returned_and_reset_each_period() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(10_000)?;
        f.set_terms(0, 0, 5_000)?;
        f.approve(1_000, 3_600)?;
        let (a, b) = (B256::random(), B256::random());
        f.hold_from(a, 600)?;
        assert_eq!(
            err!(f.hold_from(b, 401)),
            e(ReservationsError::budget_exceeded())
        );
        // A capture moves what it pays from outstanding to spent, and returns the rest.
        f.capture_of(f.payee, f.holder, a, 200, true)?;
        let budget = f.budget()?;
        assert_eq!((budget.spent, budget.outstanding), (200, 0));
        // A release returns what the hold reserved; spending is not returned.
        let c = B256::random();
        f.hold_from(c, 100)?;
        f.release(f.payee, f.holder, c)?;
        assert_eq!((f.budget()?.spent, f.budget()?.outstanding), (200, 0));
        // A charge spends, and a capture beyond the hold spends its excess.
        f.charge(f.holder, 400, false)?;
        f.hold_from(b, 300)?;
        assert_eq!(
            err!(f.capture_of(f.payee, f.holder, b, 450, true)),
            e(ReservationsError::budget_exceeded())
        );
        f.capture_of(f.payee, f.holder, b, 400, true)?;
        let budget = f.budget()?;
        assert_eq!((budget.spent, budget.outstanding), (1_000, 0));
        assert_eq!(
            err!(f.charge(f.holder, 1, false)),
            e(ReservationsError::budget_exceeded())
        );
        // The next period starts afresh.
        warp(3_600);
        let budget = f.budget()?;
        assert_eq!(
            (budget.spent, budget.periodStart),
            (0, u64::from(NOW as u32) + 3_600)
        );
        f.charge(f.holder, 1_000, false)?;
        Ok(())
    })
}

#[test]
fn test_lifetime_budget_never_resets() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(10_000)?;
        f.approve(100, 0)?;
        f.charge(f.holder, 100, false)?;
        warp(400 * DAY);
        assert_eq!(
            err!(f.charge(f.holder, 1, false)),
            e(ReservationsError::budget_exceeded())
        );
        Ok(())
    })
}

#[test]
fn test_revoked_holder_places_nothing_but_settles() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(10_000)?;
        f.approve(1_000, 0)?;
        let (a, b, p) = (B256::random(), B256::random(), B256::random());
        f.hold_from(a, 100)?;
        f.hold_from(b, 100)?;
        f.pledge_from(p, 100, NOW + 90 * DAY)?;
        f.approve(0, 0)?;
        assert_eq!(
            err!(f.hold_from(B256::random(), 1)),
            e(ReservationsError::unauthorized())
        );
        assert_eq!(
            err!(f.charge(f.holder, 1, false)),
            e(ReservationsError::unauthorized())
        );
        assert_eq!(
            err!(f.pledge_from(B256::random(), 1, NOW + DAY)),
            e(ReservationsError::unauthorized())
        );
        assert_eq!(
            err!(f.adjust(f.holder, f.holder, a, 101)),
            e(ReservationsError::unauthorized())
        );
        // Existing holds still settle within what they reserved; nothing beyond them.
        assert_eq!(
            err!(f.capture_of(f.payee, f.holder, a, 101, true)),
            e(ReservationsError::capture_limit_exceeded())
        );
        f.capture_of(f.payee, f.holder, a, 100, true)?;
        f.release(f.holder, f.holder, b)?;
        f.capture_of(f.holder, f.holder, p, 100, true)?;
        let budget = f.budget()?;
        assert_eq!(
            (budget.limit, budget.spent, budget.outstanding),
            (0, 200, 0)
        );
        Ok(())
    })
}

#[test]
fn test_approve_and_terms_require_root_key() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        assert_eq!(
            err!(f.reservations.approve_holder(
                f.owner,
                IReservationCore::approveHolderCall {
                    holder: f.owner,
                    token: f.token.address(),
                    limit: 1,
                    period: 0,
                },
            )),
            e(ReservationsError::unauthorized())
        );
        f.approve(10, 60)?;
        assert_last_event(
            &f.reservations,
            ReservationsEvent::holder_approved(f.owner, f.holder, f.token.address(), 10, 60),
        );
        assert_eq!(
            err!(f.set_terms_for(f.payee, 0, 0, 0, (MAX_DEBT_TERM + 1) as u32)),
            e(ReservationsError::invalid_expiry())
        );
        sign_with_access_key(f.owner)?;
        assert_eq!(err!(f.approve(20, 0)), e(ReservationsError::unauthorized()));
        assert_eq!(
            err!(f.set_terms(1, 1, 1)),
            e(ReservationsError::unauthorized())
        );
        assert_eq!(
            err!(f.pledge(Address::random(), B256::random(), 1, EXPIRY)),
            e(ReservationsError::unauthorized())
        );
        assert_eq!(f.budget()?.limit, 10);
        Ok(())
    })
}

/// An access key answers for everything a hold lets captures pay, tolerance included.
#[test]
fn test_access_key_holds_charge_the_full_capture_limit() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(10_000)?;
        f.set_terms(0, 0, 5_000)?;
        sign_with_limited_key(f.owner, f.token.address(), 300)?;
        // 250 with 50% tolerance lets captures pay 375, more than the key may spend.
        assert!(
            err!(f.hold_stand_in(B256::random(), 250))
                .to_string()
                .contains("pending")
        );
        let id = B256::random();
        f.hold_stand_in(id, 200)?;
        // The key spent 300 on the hold, so even a capture of its full limit needs nothing more.
        f.capture(f.owner, id, 300, true)?;
        assert!(
            err!(f.charge(f.owner, 1, false))
                .to_string()
                .contains("pending")
        );
        Ok(())
    })
}

#[test]
fn test_stand_in_capture_is_capped_and_debt_reaches_the_offline_cap() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(100)?;
        f.set_terms(20, 80, 0)?;
        let id = B256::random();
        // A stand-in reserves what is available and records the full approval.
        f.hold_stand_in(id, 150)?;
        assert_eq!(
            (f.reserved()?, f.record(f.owner, id)?.captureLimit),
            (100, 150)
        );
        assert_eq!(
            err!(f.capture(f.payee, id, 190, true)),
            e(ReservationsError::capture_limit_exceeded())
        );
        f.capture(f.payee, id, 150, true)?;
        assert_eq!(f.debts()?, vec![(f.payee, 50)]);
        // A plain charge may not take the debt past the ordinary cap.
        assert_eq!(
            err!(f.charge(f.owner, 1, false)),
            e(ReservationsError::debt_cap_exceeded())
        );
        f.charge(f.owner, 30, true)?;
        assert_eq!(f.debts()?, vec![(f.payee, 80)]);
        Ok(())
    })
}

#[test]
fn test_debt_has_several_creditors_repaid_oldest_first() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(0)?;
        let creditors: Vec<Address> = (0..5).map(|_| Address::random()).collect();
        for creditor in &creditors {
            f.set_terms_for(*creditor, 100, 0, 0, 0)?;
        }
        for (index, creditor) in creditors.iter().take(4).enumerate() {
            f.charge_to(f.owner, *creditor, 10 * (index as u128 + 1), false)?;
        }
        assert_eq!(
            err!(f.charge_to(f.owner, creditors[4], 1, false)),
            e(ReservationsError::too_many_creditors())
        );
        // More debt to a standing creditor keeps its place.
        f.charge_to(f.owner, creditors[0], 5, false)?;
        assert_eq!(
            f.debts()?,
            vec![
                (creditors[0], 15),
                (creditors[1], 20),
                (creditors[2], 30),
                (creditors[3], 40)
            ]
        );
        // A credit repays oldest first; a blocked creditor is skipped and keeps its debt.
        f.blacklist(vec![creditors[1]])?;
        f.mint(f.owner, 50)?;
        assert_eq!(f.debts()?, vec![(creditors[1], 20), (creditors[3], 35)]);
        assert_eq!(f.balance(creditors[0])?, U256::from(15));
        assert_eq!(f.balance(creditors[2])?, U256::from(30));
        assert_eq!(f.balance(f.owner)?, U256::ZERO);
        f.blacklist(vec![])?;
        f.mint(f.owner, 100)?;
        assert_eq!(f.debts()?, vec![]);
        assert_eq!(f.balance(f.owner)?, U256::from(45));
        assert!(!f.reservations.owes_debt(f.owner)?);
        Ok(())
    })
}

#[test]
fn test_debt_lapses_after_its_term() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(0)?;
        let (short, long) = (Address::random(), Address::random());
        f.set_terms_for(short, 100, 0, 0, DAY as u32)?;
        f.set_terms_for(long, 100, 0, 0, 0)?;
        f.charge_to(f.owner, short, 40, false)?;
        f.charge_to(f.owner, long, 60, false)?;
        // More debt does not extend the term.
        warp(DAY - 1);
        f.charge_to(f.owner, short, 10, false)?;
        warp(1);
        assert_eq!(f.debts()?, vec![(long, 60)]);
        // The lapsed debt is not repaid; anyone may clear it.
        f.reservations
            .clear_lapsed_debt(f.owner, f.token.address())?;
        assert_last_event(
            &f.reservations,
            ReservationsEvent::debt_lapsed(f.owner, short, f.token.address(), 50),
        );
        f.mint(f.owner, 100)?;
        assert_eq!(
            (f.balance(short)?, f.balance(long)?),
            (U256::ZERO, U256::from(60))
        );
        warp(MAX_DEBT_TERM);
        f.charge_to(f.owner, long, 100, false)?;
        warp(MAX_DEBT_TERM);
        assert_eq!(f.debts()?, vec![]);
        Ok(())
    })
}

#[test]
fn test_refund_forgives_debt_then_pays() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(100)?;
        f.set_terms(200, 0, 0)?;
        let id = B256::random();
        f.hold(id, 100)?;
        f.capture(f.payee, id, 100, true)?;
        f.charge(f.owner, 80, false)?;
        assert_eq!(f.debts()?, vec![(f.payee, 80)]);
        assert_eq!(
            err!(f.refund(f.payee, id, 0)),
            e(ReservationsError::invalid_amount())
        );
        assert_eq!(
            err!(f.refund(f.payee, id, 181)),
            e(ReservationsError::insufficient_available())
        );
        f.refund(f.payee, id, 120)?;
        assert_eq!(f.debts()?, vec![]);
        assert_eq!(
            (f.balance(f.owner)?, f.balance(f.payee)?),
            (U256::from(40), U256::from(60))
        );
        assert_last_event(
            &f.reservations,
            ReservationsEvent::refunded(f.owner, f.payee, f.token.address(), f.owner, id, 120, 80),
        );
        // A refund is a payment, so the policy applies.
        f.blacklist(vec![f.payee])?;
        assert_eq!(
            err!(f.refund(f.payee, id, 1)),
            e(ReservationsError::policy_forbids())
        );
        Ok(())
    })
}

/// A hold's held part still pays its own payee after the owner is blocked; nothing else moves.
#[test]
fn test_policy_applies_to_every_movement() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        f.set_terms(500, 0, 5_000)?;
        f.approve(1_000, 0)?;
        let (part, whole, excess, pledged) = (
            B256::random(),
            B256::random(),
            B256::random(),
            B256::random(),
        );
        let authority = f.lien_authority()?;
        let lien = B256::random();
        f.hold(part, 100)?;
        f.hold(whole, 100)?;
        f.hold(excess, 100)?;
        f.pledge_from(pledged, 100, NOW + DAY)?;
        f.lien(authority, lien, 100, 0)?;
        f.blacklist(vec![f.owner])?;

        f.capture(f.payee, part, 40, false)?;
        f.capture(f.payee, whole, 100, true)?;
        assert_eq!(
            err!(f.capture(f.payee, excess, 101, true)),
            e(ReservationsError::policy_forbids())
        );
        assert_eq!(
            err!(f.charge(f.owner, 1, false)),
            e(ReservationsError::policy_forbids())
        );
        assert_eq!(
            err!(f.hold(B256::random(), 1)),
            e(ReservationsError::policy_forbids())
        );
        assert_eq!(
            err!(f.adjust(f.owner, f.owner, part, 61)),
            e(ReservationsError::policy_forbids())
        );
        // A pledge's seizure is a payment from the owner, so a blocked owner pays none.
        assert_eq!(
            err!(f.capture_of(f.holder, f.holder, pledged, 10, false)),
            e(ReservationsError::policy_forbids())
        );
        // A lien is a freeze: its authority seizes whatever the owner's status.
        f.capture_of(authority, authority, lien, 30, false)?;
        assert_eq!(f.balance(authority)?, U256::from(30));
        // Releases always work.
        f.release(f.payee, f.owner, excess)?;
        f.release(f.holder, f.holder, pledged)?;

        // A blocked payee receives nothing, not even from a hold.
        f.blacklist(vec![f.payee])?;
        assert_eq!(
            err!(f.capture(f.payee, part, 10, false)),
            e(ReservationsError::policy_forbids())
        );
        Ok(())
    })
}

#[test]
fn test_paused_token_moves_nothing() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        let authority = f.lien_authority()?;
        let lien = B256::random();
        f.hold(id, 100)?;
        f.lien(authority, lien, 100, 0)?;
        f.token
            .grant_role_internal(f.admin, crate::tip20::PAUSE_ROLE)?;
        f.token.pause(f.admin, ITIP20::pauseCall {})?;
        assert_eq!(
            err!(f.capture(f.payee, id, 1, true)),
            e(ReservationsError::policy_forbids())
        );
        assert_eq!(
            err!(f.capture_of(authority, authority, lien, 1, false)),
            e(ReservationsError::policy_forbids())
        );
        assert_eq!(
            err!(f.charge(f.owner, 1, false)),
            e(ReservationsError::policy_forbids())
        );
        f.release(f.owner, f.owner, id)?;
        Ok(())
    })
}

#[test]
fn test_liens_reserve_until_their_authority_acts() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let authority = f.lien_authority()?;
        let id = B256::random();
        assert_eq!(
            err!(f.lien(Address::random(), id, 100, 0)),
            e(ReservationsError::unauthorized())
        );
        f.lien(authority, id, 600, 0)?;
        assert_eq!((f.reserved()?, f.available()?), (600, 400));
        let record = f.record(authority, id)?;
        assert_eq!(
            (record.kind, record.payee, record.expiresAt),
            (kind::LIEN, authority, 0)
        );
        // Only the authority acts, and only downward.
        assert_eq!(
            err!(f.release(f.owner, authority, id)),
            e(ReservationsError::unauthorized())
        );
        assert_eq!(
            err!(f.adjust(authority, authority, id, 700)),
            e(ReservationsError::invalid_amount())
        );
        f.adjust(authority, authority, id, 500)?;
        assert_eq!(f.record(authority, id)?.captureLimit, 500);
        // Seizure needs the role at that time.
        f.token.revoke_role(
            f.admin,
            IRolesAuth::revokeRoleCall {
                role: LIEN_ROLE,
                account: authority,
            },
        )?;
        assert_eq!(
            err!(f.capture_of(authority, authority, id, 100, false)),
            e(ReservationsError::unauthorized())
        );
        f.token.grant_role_internal(authority, LIEN_ROLE)?;
        f.capture_of(authority, authority, id, 200, false)?;
        assert_eq!(f.record(authority, id)?.held, 300);
        // Seizing the rest settles it.
        f.capture_of(authority, authority, id, 300, false)?;
        assert_eq!(f.record(authority, id)?, empty_hold());
        assert_eq!((f.reserved()?, f.balance(authority)?), (0, U256::from(500)));
        Ok(())
    })
}

#[test]
fn test_pledges_expire_and_seize_to_the_authority() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let authority = Address::random();
        let id = B256::random();
        assert_eq!(
            err!(f.pledge(authority, id, 100, NOW + MAX_PLEDGE_DURATION + 1)),
            e(ReservationsError::invalid_expiry())
        );
        f.pledge(authority, id, 400, NOW + 90 * DAY)?;
        assert_eq!(f.record(f.owner, id)?.kind, kind::PLEDGE);
        assert_eq!(
            err!(f.capture(f.owner, id, 100, false)),
            e(ReservationsError::unauthorized())
        );
        assert_eq!(
            err!(f.release(f.owner, f.owner, id)),
            e(ReservationsError::unauthorized())
        );
        f.capture(authority, id, 100, false)?;
        assert_eq!(f.balance(authority)?, U256::from(100));
        warp(90 * DAY);
        assert_eq!(
            err!(f.capture(authority, id, 1, false)),
            e(ReservationsError::hold_expired())
        );
        f.release_expired(f.owner, id)?;
        assert_eq!((f.reserved()?, f.available()?), (0, 900));
        Ok(())
    })
}

#[test]
fn test_holder_pledges_draw_on_the_budget() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        assert_eq!(
            err!(f.pledge_from(B256::random(), 100, NOW + DAY)),
            e(ReservationsError::unauthorized())
        );
        f.approve(300, 0)?;
        let (a, b) = (B256::random(), B256::random());
        f.pledge_from(a, 200, NOW + 90 * DAY)?;
        assert_eq!(
            err!(f.pledge_from(b, 101, NOW + DAY)),
            e(ReservationsError::budget_exceeded())
        );
        assert_eq!(f.budget()?.outstanding, 200);
        f.adjust(f.holder, f.holder, a, 150)?;
        assert_eq!(f.budget()?.outstanding, 150);
        f.capture_of(f.holder, f.holder, a, 50, false)?;
        let budget = f.budget()?;
        assert_eq!((budget.spent, budget.outstanding), (50, 100));
        warp(90 * DAY);
        f.release_expired(f.holder, a)?;
        assert_eq!(f.budget()?.outstanding, 0);
        Ok(())
    })
}

#[test]
fn test_zone_holds_and_debt_repayment() -> eyre::Result<()> {
    let mut storage = new_storage().with_kind(TempoEvmKind::Zone);
    StorageCtx::enter(&mut storage, || {
        let mut f = Fixture::new(100)?;
        f.set_terms(0, 0, 5_000)?;
        let id = B256::random();
        f.hold(id, 60)?;
        assert_eq!((f.reserved()?, f.available()?), (60, 40));
        // The held part pays its payee after the owner is blocked on a zone too.
        f.blacklist(vec![f.owner])?;
        assert_eq!(
            err!(f.capture(f.payee, id, 61, true)),
            e(ReservationsError::policy_forbids())
        );
        f.capture(f.payee, id, 60, true)?;
        assert_eq!((f.reserved()?, f.balance(f.payee)?), (0, U256::from(60)));
        f.blacklist(vec![])?;

        f.set_terms(500, 0, 0)?;
        f.charge(f.owner, 140, false)?;
        assert_eq!(f.debts()?, vec![(f.payee, 100)]);
        assert!(f.reservations.owes_debt(f.owner)?);
        assert!(!TIP403Registry::new().has_reservation_debt(f.owner)?);

        let sender = Address::random();
        f.mint(sender, 1_000)?;
        f.transfer(sender, f.owner, 130)?;
        assert_eq!(f.debts()?, vec![]);
        assert_eq!(f.balance(f.owner)?, U256::from(30));
        assert!(!f.reservations.owes_debt(f.owner)?);
        Ok(())
    })
}

#[test]
fn test_compliance_burns_take_reserved_funds() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let (captured, released) = (B256::random(), B256::random());
        f.hold(captured, 600)?;
        f.hold(released, 300)?;
        f.token.grant_role_internal(f.admin, BURN_BLOCKED_ROLE)?;
        f.blacklist(vec![f.owner])?;
        f.token
            .burn_blocked(f.admin, f.owner, U256::from(800), true)?;
        assert_eq!(f.balance(f.owner)?, U256::from(200));
        assert_eq!((f.reserved()?, f.available()?), (200, 0));
        assert_eq!(f.record(f.owner, released)?.held, 300);

        // Ending a hold consumes the burned part first, so what remains still backs the others.
        f.blacklist(vec![])?;
        f.release(f.owner, f.owner, released)?;
        assert_eq!((f.reserved()?, f.available()?), (200, 0));
        assert_eq!(
            err!(f.capture(f.owner, captured, 600, true)),
            e(ReservationsError::insufficient_available())
        );
        f.set_terms(400, 0, 0)?;
        f.capture(f.owner, captured, 600, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(200));
        assert_eq!(f.debts()?, vec![(f.payee, 400)]);
        assert_eq!(f.reserved()?, 0);
        Ok(())
    })
}

/// Runs before T7, when TIP-20 rewards still accrue to opted-in holders; the reservation calls
/// themselves do not depend on the hardfork.
#[test]
fn test_reserved_funds_earn_no_rewards() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
    storage.set_timestamp(U256::from(NOW));
    StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
        let mut f = Fixture::new(1_000)?;
        let other = Address::random();
        let merchant = Address::random();
        f.mint(other, 1_000)?;
        f.mint(f.admin, 1_000)?;
        for account in [f.owner, other] {
            f.token.set_reward_recipient(
                account,
                ITIP20::setRewardRecipientCall { recipient: account },
            )?;
        }
        let owner = f.owner;
        let distribute = |f: &mut Fixture, amount: u64| {
            f.token.distribute_reward(
                f.admin,
                ITIP20::distributeRewardCall {
                    amount: U256::from(amount),
                },
            )
        };
        let rewards = |f: &mut Fixture, account: Address| -> Result<U256> {
            f.token.update_rewards(account)?;
            Ok(f.token.get_user_reward_info(account)?.reward_balance)
        };

        let id = B256::random();
        f.hold(id, 500)?;
        assert_eq!(f.token.get_opted_in_supply()?, 1_500);
        distribute(&mut f, 300)?;
        assert_eq!(rewards(&mut f, owner)?, U256::from(100));
        assert_eq!(rewards(&mut f, other)?, U256::from(200));

        f.transfer(f.owner, merchant, 100)?;
        assert_eq!(f.token.get_opted_in_supply()?, 1_400);

        f.release(f.owner, f.owner, id)?;
        assert_eq!(f.token.get_opted_in_supply()?, 1_900);
        distribute(&mut f, 190)?;
        assert_eq!(rewards(&mut f, owner)?, U256::from(190));
        assert_eq!(rewards(&mut f, other)?, U256::from(300));

        let id = B256::random();
        f.hold(id, 400)?;
        assert_eq!(f.token.get_opted_in_supply()?, 1_500);
        f.capture(f.payee, id, 400, true)?;
        assert_eq!(f.token.get_opted_in_supply()?, 1_500);
        distribute(&mut f, 150)?;
        assert_eq!(rewards(&mut f, owner)?, U256::from(240));
        assert_eq!(rewards(&mut f, other)?, U256::from(400));
        assert_eq!(f.balance(f.owner)?, U256::from(500));
        Ok(())
    })
}

/// New slots the reservation core holds after each operation, against its budget: a hold adds at
/// most its two record slots beyond the owner's position, and settling deletes them.
#[test]
fn test_slots_per_operation() -> eyre::Result<()> {
    let mut storage = new_storage();
    let count = |storage: &HashMapStorageProvider| storage.nonzero_slot_count(RESERVATIONS_ADDRESS);
    let mut f = StorageCtx::enter(&mut storage, || -> eyre::Result<_> {
        let mut f = Fixture::new(10_000)?;
        f.approve(5_000, 0)?;
        Ok(f)
    })?;
    let mut step = |op: &dyn Fn(&mut Fixture) -> Result<()>| -> eyre::Result<i64> {
        let before = count(&storage) as i64;
        StorageCtx::enter(&mut storage, || op(&mut f))?;
        Ok(count(&storage) as i64 - before)
    };
    let ids: Vec<B256> = (0..8).map(|_| B256::random()).collect();
    let (a, b, c, d) = (ids[0], ids[1], ids[2], ids[3]);
    // The first hold also writes the owner's position slot.
    assert_eq!(step(&|f| f.hold(a, 100))?, 3);
    assert_eq!(step(&|f| f.hold(b, 100))?, 2);
    // A holder's first hold also writes its budget's outstanding into the existing budget slot.
    assert_eq!(step(&|f| f.hold_from(c, 100))?, 2);
    assert_eq!(step(&|f| f.capture(f.payee, a, 40, false))?, 0);
    assert_eq!(step(&|f| f.capture(f.payee, a, 40, true))?, -2);
    assert_eq!(
        step(&|f| f.capture_of(f.payee, f.holder, c, 100, true))?,
        -2
    );
    // Releasing the last live hold clears the owner's position slot.
    assert_eq!(step(&|f| f.release(f.owner, f.owner, b))?, -3);
    assert_eq!(step(&|f| f.refund(f.payee, a, 30))?, 0);
    assert_eq!(step(&|f| f.charge(f.owner, 10, false))?, 0);
    assert_eq!(step(&|f| f.charge(f.holder, 10, false))?, 0);
    assert_eq!(step(&|f| f.hold(d, 10))?, 3);
    assert_eq!(step(&|f| f.pledge_from(ids[5], 100, NOW + 90 * DAY))?, 2);
    assert_eq!(step(&|f| f.pledge_from(ids[6], 100, NOW + 90 * DAY))?, 2);
    assert_eq!(
        step(&|f| f.capture_of(f.holder, f.holder, ids[6], 100, false))?,
        -2
    );
    // A debt is one slot per creditor.
    assert_eq!(step(&|f| f.set_terms(1_000_000, 0, 0))?, 1);
    assert_eq!(step(&|f| f.charge(f.owner, 20_000, false))?, 1);
    Ok(())
}

/// An owner with one hold at a time, as most cardholders are, pays three slots per hold: the
/// two record slots and the position slot, which empties and is deleted with the last record.
#[test]
fn test_slots_single_hold_cycle() -> eyre::Result<()> {
    let mut storage = new_storage();
    let count = |storage: &HashMapStorageProvider| storage.nonzero_slot_count(RESERVATIONS_ADDRESS);
    let mut f = StorageCtx::enter(&mut storage, || -> eyre::Result<_> {
        let mut f = Fixture::new(10_000)?;
        f.approve(5_000, 0)?;
        Ok(f)
    })?;
    let empty = count(&storage);
    for _ in 0..3 {
        let id = B256::random();
        let before = count(&storage);
        StorageCtx::enter(&mut storage, || f.hold_from(id, 100))?;
        assert_eq!(count(&storage) - before, 3);
        StorageCtx::enter(&mut storage, || {
            f.capture_of(f.payee, f.holder, id, 100, true)
        })?;
        assert_eq!(count(&storage), empty);
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Random sequences across owners, holders, payees, tokens and strangers: every call's result
    /// matches the model's, exact error included, and the invariants hold after every step.
    #[test]
    fn proptest_random_sequences_match_the_model(ops in prop::collection::vec(model::op_strategy(), 1..80)) {
        let mut storage = new_storage();
        let mut world = StorageCtx::enter(&mut storage, model::World::new)
            .map_err(|err| TestCaseError::fail(format!("setup: {err:?}")))?;
        for (step, op) in ops.iter().enumerate() {
            let outcome = StorageCtx::enter(&mut storage, || world.step(op));
            if let Err(err) = outcome {
                return Err(TestCaseError::fail(format!("step {step} {op:?}: {err}")));
            }
            let slots = storage.nonzero_slot_count(RESERVATIONS_ADDRESS);
            if let Err(err) = StorageCtx::enter(&mut storage, || world.check(slots)) {
                return Err(TestCaseError::fail(format!("after step {step} {op:?}: {err}")));
            }
        }
    }
}
