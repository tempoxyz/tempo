use super::*;
use crate::{
    STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    account_keychain::{AccountKeychain, KeyRestrictions, SignatureType, TokenLimit},
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
    test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
    tip20::{BURN_AT_ROLE, BURN_BLOCKED_ROLE, IRolesAuth, ITIP20, TIP20Error},
    tip403_registry::{ITIP403Registry, TIP403Registry},
    zone_factory::portal_address,
};

use alloy::primitives::IntoLogData;
use proptest::prelude::*;
use std::collections::BTreeMap;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::IReservationCore::IReservationCoreCalls;
use tempo_primitives::TempoEvmKind;

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

    fn request(&self, id: B256, amount: u128) -> IReservationCore::HoldRequest {
        IReservationCore::HoldRequest {
            token: self.token.address(),
            id,
            amount,
            expiresAt: EXPIRY,
            payee: self.payee,
        }
    }

    fn hold(&mut self, id: B256, amount: u128) -> Result<()> {
        let request = self.request(id, amount);
        self.reservations.place(self.owner, self.owner, request)
    }

    fn hold_from(&mut self, id: B256, amount: u128) -> Result<()> {
        let request = self.request(id, amount);
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

    fn charge(&mut self, caller: Address, amount: u128) -> Result<()> {
        self.reservations.charge(
            caller,
            IReservationCore::chargeCall {
                owner: self.owner,
                token: self.token.address(),
                id: B256::random(),
                amount,
                payee: self.payee,
            },
        )
    }

    fn set_tolerance(&mut self, tolerance_bps: u16) -> Result<()> {
        self.reservations.set_capture_tolerance(
            self.owner,
            IReservationCore::setCaptureToleranceCall {
                payee: self.payee,
                token: self.token.address(),
                toleranceBps: tolerance_bps,
            },
        )
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
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
    storage.set_timestamp(U256::from(NOW));
    storage
}

/// Runs the closure at T15 with the block timestamp at NOW.
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
        let mut late = f.request(id, 10);
        late.expiresAt = NOW + MAX_HOLD_DURATION + 1;
        assert_eq!(
            err!(f.reservations.place(f.owner, f.owner, late)),
            e(ReservationsError::invalid_expiry())
        );
        let mut past = f.request(id, 10);
        past.expiresAt = NOW;
        assert_eq!(
            err!(f.reservations.place(f.owner, f.owner, past)),
            e(ReservationsError::invalid_expiry())
        );
        let mut to_self = f.request(id, 10);
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
            err!(f.charge(stranger, 1)),
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
        f.set_tolerance(2_000)?;
        assert_last_event(
            &f.reservations,
            ReservationsEvent::capture_tolerance_set(f.owner, f.payee, f.token.address(), 2_000),
        );
        assert_eq!(
            f.reservations
                .capture_tolerance(f.owner, f.payee, f.token.address())?,
            2_000
        );
        f.hold(id, 100)?;
        assert_eq!(f.record(f.owner, id)?.captureLimit, 120);
        // Raising the payee's tolerance later does not widen the hold.
        f.set_tolerance(5_000)?;
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
fn test_adjust_by_placer() -> eyre::Result<()> {
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
        // Raising needs the increase available.
        assert_eq!(
            err!(f.adjust(f.owner, f.owner, id, 1_001)),
            e(ReservationsError::insufficient_available())
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
        f.set_tolerance(5_000)?;
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
        f.charge(f.holder, 400)?;
        f.hold_from(b, 300)?;
        assert_eq!(
            err!(f.capture_of(f.payee, f.holder, b, 450, true)),
            e(ReservationsError::budget_exceeded())
        );
        f.capture_of(f.payee, f.holder, b, 400, true)?;
        let budget = f.budget()?;
        assert_eq!((budget.spent, budget.outstanding), (1_000, 0));
        assert_eq!(
            err!(f.charge(f.holder, 1)),
            e(ReservationsError::budget_exceeded())
        );
        // The next period starts afresh.
        warp(3_600);
        let budget = f.budget()?;
        assert_eq!(
            (budget.spent, budget.periodStart),
            (0, u64::from(NOW as u32) + 3_600)
        );
        f.charge(f.holder, 1_000)?;
        Ok(())
    })
}

#[test]
fn test_lifetime_budget_never_resets() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(10_000)?;
        f.approve(100, 0)?;
        f.charge(f.holder, 100)?;
        warp(400 * DAY);
        assert_eq!(
            err!(f.charge(f.holder, 1)),
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
            err!(f.charge(f.holder, 1)),
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
fn test_approve_and_tolerance_require_root_key() -> eyre::Result<()> {
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
        let to_self = IReservationCore::setCaptureToleranceCall {
            payee: f.owner,
            token: f.token.address(),
            toleranceBps: 1,
        };
        assert_eq!(
            err!(f.reservations.set_capture_tolerance(f.owner, to_self)),
            e(ReservationsError::unauthorized())
        );
        sign_with_access_key(f.owner)?;
        assert_eq!(err!(f.approve(20, 0)), e(ReservationsError::unauthorized()));
        assert_eq!(
            err!(f.set_tolerance(1)),
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
        f.set_tolerance(5_000)?;
        sign_with_limited_key(f.owner, f.token.address(), 300)?;
        // 250 with 50% tolerance lets captures pay 375, more than the key may spend.
        assert!(
            err!(f.hold(B256::random(), 250))
                .to_string()
                .contains("pending")
        );
        let id = B256::random();
        f.hold(id, 200)?;
        // The key spent 300 on the hold, so even a capture of its full limit needs nothing more.
        f.capture(f.owner, id, 300, true)?;
        assert!(err!(f.charge(f.owner, 1)).to_string().contains("pending"));
        Ok(())
    })
}

/// A capture beyond its hold, within the tolerance, takes the excess from the owner's available
/// balance and reverts when that is short; nothing is ever owed.
#[test]
fn test_capture_beyond_the_hold_pays_only_from_the_available_balance() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(130)?;
        f.set_tolerance(5_000)?;
        let id = B256::random();
        f.hold(id, 100)?;
        assert_eq!(
            (f.reserved()?, f.record(f.owner, id)?.captureLimit),
            (100, 150)
        );
        assert_eq!(
            err!(f.capture(f.payee, id, 150, true)),
            e(ReservationsError::insufficient_available())
        );
        assert_eq!((f.reserved()?, f.available()?), (100, 30));
        f.capture(f.payee, id, 130, true)?;
        assert_last_event(
            &f.reservations,
            ReservationsEvent::hold_captured(
                f.owner,
                f.owner,
                f.token.address(),
                id,
                f.payee,
                130,
                true,
            ),
        );
        assert_eq!(
            (f.balance(f.owner)?, f.balance(f.payee)?),
            (U256::ZERO, U256::from(130))
        );
        Ok(())
    })
}

/// A charge pays only from the owner's available balance, and later credits to the owner move
/// nothing onward.
#[test]
fn test_charge_pays_only_from_the_available_balance() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(100)?;
        f.hold(B256::random(), 60)?;
        assert_eq!(
            err!(f.charge(f.owner, 41)),
            e(ReservationsError::insufficient_available())
        );
        f.charge(f.owner, 40)?;
        assert_eq!((f.available()?, f.balance(f.payee)?), (0, U256::from(40)));
        f.mint(f.owner, 50)?;
        assert_eq!((f.available()?, f.balance(f.payee)?), (50, U256::from(40)));
        Ok(())
    })
}

#[test]
fn test_refund_pays_from_the_caller() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(100)?;
        let id = B256::random();
        f.hold(id, 100)?;
        f.capture(f.payee, id, 100, true)?;
        assert_eq!(
            err!(f.refund(f.payee, id, 0)),
            e(ReservationsError::invalid_amount())
        );
        assert_eq!(
            err!(f.refund(f.payee, id, 101)),
            e(ReservationsError::insufficient_available())
        );
        f.refund(f.payee, id, 60)?;
        assert_eq!(
            (f.balance(f.owner)?, f.balance(f.payee)?),
            (U256::from(60), U256::from(40))
        );
        assert_last_event(
            &f.reservations,
            ReservationsEvent::refunded(f.owner, f.payee, f.token.address(), f.owner, id, 60),
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
        f.set_tolerance(5_000)?;
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
            err!(f.charge(f.owner, 1)),
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
            err!(f.charge(f.owner, 1)),
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

/// Pooled custody that compliance burns never take (the DEX, the fee manager, the channel
/// reserve, a zone portal) backs other users' claims, so no lien freezes or seizes it.
#[test]
fn test_liens_never_take_protected_custody() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let authority = f.lien_authority()?;
        let token = f.token.address();
        for account in [
            STABLECOIN_DEX_ADDRESS,
            TIP_FEE_MANAGER_ADDRESS,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            portal_address(1),
        ] {
            f.mint(account, 1_000)?;
            for expires_at in [0, EXPIRY] {
                let lien = IReservationCore::lienCall {
                    owner: account,
                    token,
                    id: B256::random(),
                    amount: 1_000,
                    expiresAt: expires_at,
                };
                assert_eq!(
                    err!(f.reservations.lien(authority, lien)),
                    e(ReservationsError::unauthorized())
                );
            }
            assert_eq!(f.reservations.available_of(account, token)?, 1_000);
            assert_eq!(f.balance(account)?, U256::from(1_000));
        }
        // Any other owner is liened as before.
        f.lien(authority, B256::random(), 1_000, 0)?;
        assert_eq!((f.reserved()?, f.available()?), (1_000, 0));
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
fn test_zone_holds() -> eyre::Result<()> {
    let mut storage = new_storage().with_kind(TempoEvmKind::Zone);
    StorageCtx::enter(&mut storage, || {
        let mut f = Fixture::new(100)?;
        f.set_tolerance(5_000)?;
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
        assert_eq!(
            err!(f.charge(f.owner, 41)),
            e(ReservationsError::insufficient_available())
        );
        f.charge(f.owner, 40)?;
        assert_eq!(f.balance(f.payee)?, U256::from(100));
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
        // What the hold still backs pays out.
        f.capture(f.owner, captured, 200, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(200));
        assert_eq!((f.reserved()?, f.available()?), (0, 0));
        Ok(())
    })
}

/// After a compliance burn takes part of a hold, a blocked owner's hold pays its payee only what
/// the hold still backs; funds the owner received later stay where they are.
#[test]
fn test_capture_after_compliance_burn_pays_only_what_the_hold_still_backs() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 600)?;
        f.token.grant_role_internal(f.admin, BURN_BLOCKED_ROLE)?;
        let owner = f.owner;
        block_sender_only(&mut f, owner)?;
        // Burning 500 takes 400 from the balance slot and 100 from the hold's reservation.
        f.token
            .burn_blocked(f.admin, f.owner, U256::from(500), true)?;
        assert_eq!((f.reserved()?, f.available()?), (500, 0));

        // The blocked owner receives 300 afterwards and cannot send them itself.
        f.mint(f.owner, 300)?;
        assert!(f.transfer(f.owner, Address::random(), 1).is_err());
        assert_eq!(f.available()?, 300);

        // Capturing the hold's full amount would draw 100 of the new funds.
        assert_eq!(
            err!(f.capture(f.owner, id, 600, true)),
            e(ReservationsError::policy_forbids())
        );
        // So would a partial capture, since the burned part is consumed first.
        assert_eq!(
            err!(f.capture(f.owner, id, 100, false)),
            e(ReservationsError::policy_forbids())
        );
        // What the hold still backs pays out.
        f.capture(f.owner, id, 500, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(500));
        assert_eq!(f.balance(f.owner)?, U256::from(300));
        assert_eq!((f.reserved()?, f.available()?), (0, 300));
        Ok(())
    })
}

/// A bridge's `burnAt` of an owner the policy does not block burns only its free balance, so the
/// owner's holds keep their funds and still pay their payees.
#[test]
fn test_burn_at_leaves_reserved_funds_of_an_unblocked_owner() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 600)?;
        // balanceOf still reports the reserved funds, which is what a bridge reads.
        assert_eq!(f.balance(f.owner)?, U256::from(1_000));
        let bridge = Address::random();
        f.token.grant_role_internal(bridge, BURN_AT_ROLE)?;
        let burn = |amount: u64| ITIP20::burnAtCall {
            from: f.owner,
            amount: U256::from(amount),
        };
        assert_eq!(
            err!(f.token.burn_at(bridge, burn(1_000))),
            TIP20Error::insufficient_balance(U256::from(400), U256::from(1_000), f.token.address())
                .into()
        );
        assert_eq!((f.reserved()?, f.available()?), (600, 400));

        f.token.burn_at(bridge, burn(400))?;
        assert_eq!((f.reserved()?, f.available()?), (600, 0));
        assert_eq!(f.token.total_supply()?, U256::from(600));
        f.capture(f.owner, id, 600, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(600));
        assert_eq!((f.reserved()?, f.available()?), (0, 0));
        Ok(())
    })
}

/// After a bridge burns all an unblocked owner's free balance, a pledge of fresh funds still pays
/// its lender in full, and the older hold returns only its own funds.
#[test]
fn test_pledge_after_burn_at_pays_its_lender_in_full() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let old = B256::random();
        f.hold(old, 500)?;
        let bridge = Address::random();
        f.token.grant_role_internal(bridge, BURN_AT_ROLE)?;
        f.token.burn_at(
            bridge,
            ITIP20::burnAtCall {
                from: f.owner,
                amount: U256::from(500),
            },
        )?;
        assert_eq!((f.reserved()?, f.available()?), (500, 0));

        f.mint(f.owner, 500)?;
        let lender = Address::random();
        let pledge = B256::random();
        f.pledge(lender, pledge, 500, NOW + DAY)?;
        f.capture_of(lender, f.owner, pledge, 500, false)?;
        assert_eq!(f.balance(lender)?, U256::from(500));

        f.release(f.owner, f.owner, old)?;
        assert_eq!((f.reserved()?, f.available()?), (0, 500));
        assert_eq!(f.balance(f.owner)?, U256::from(500));
        Ok(())
    })
}

/// A bridge's `burnAt` of an owner the policy blocks as a sender is a compliance burn: like
/// `burnBlocked`, it may take what holds reserve, but never what pledges and liens hold.
#[test]
fn test_burn_at_of_a_blocked_owner_takes_only_hold_reservations() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let (id, pledge) = (B256::random(), B256::random());
        f.hold(id, 400)?;
        let lender = Address::random();
        f.pledge(lender, pledge, 300, NOW + DAY)?;
        let bridge = Address::random();
        f.token.grant_role_internal(bridge, BURN_AT_ROLE)?;
        let owner = f.owner;
        block_sender_only(&mut f, owner)?;
        let burn = |amount: u64| ITIP20::burnAtCall {
            from: owner,
            amount: U256::from(amount),
        };
        // 300 free plus 400 held by the hold; the pledge's 300 are out of reach.
        assert_eq!(
            err!(f.token.burn_at(bridge, burn(701))),
            TIP20Error::insufficient_balance(U256::from(700), U256::from(701), f.token.address())
                .into()
        );
        f.token.burn_at(bridge, burn(700))?;
        assert_eq!((f.reserved()?, f.available()?), (300, 0));
        assert_eq!(f.record(f.owner, id)?.held, 400);

        // Once the block lifts, the lender's seizure is paid in full.
        f.token.change_transfer_policy_id(
            f.admin,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: crate::tip403_registry::ALLOW_ALL_POLICY_ID,
            },
        )?;
        f.capture_of(lender, f.owner, pledge, 300, false)?;
        assert_eq!(f.balance(lender)?, U256::from(300));
        // The burned hold pays nothing more and releases nothing.
        f.release(f.owner, f.owner, id)?;
        assert_eq!((f.reserved()?, f.available()?), (0, 0));
        Ok(())
    })
}

/// A lien the issuer places on a blocked owner's funds after a compliance burn is never absorbed
/// by an older hold's burned part: seizing it pays the authority, and the older hold pays its
/// payee only what it still backs itself.
#[test]
fn test_lien_after_compliance_burn_stays_backed() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 1_000)?;
        f.token.grant_role_internal(f.admin, BURN_BLOCKED_ROLE)?;
        let owner = f.owner;
        block_sender_only(&mut f, owner)?;
        f.token
            .burn_blocked(f.admin, f.owner, U256::from(500), true)?;
        assert_eq!((f.reserved()?, f.available()?), (500, 0));

        // The blocked owner receives 300, which the issuer liens.
        f.mint(f.owner, 300)?;
        let authority = f.lien_authority()?;
        let lien = B256::random();
        f.lien(authority, lien, 300, 0)?;
        assert_eq!((f.reserved()?, f.available()?), (800, 0));
        f.capture_of(authority, authority, lien, 300, false)?;
        assert_eq!(f.balance(authority)?, U256::from(300));
        assert_eq!((f.reserved()?, f.available()?), (500, 0));

        // The older hold backs 500 of its 1,000, and only that pays out under the exemption.
        assert_eq!(
            err!(f.capture(f.owner, id, 800, true)),
            e(ReservationsError::policy_forbids())
        );
        f.capture(f.owner, id, 500, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(500));
        assert_eq!((f.reserved()?, f.available()?), (0, 0));
        Ok(())
    })
}

/// Releasing a lien placed after a compliance burn returns its funds to the owner's balance,
/// where the block still holds them; they never back the older hold's capture.
#[test]
fn test_lien_release_after_compliance_burn_returns_its_funds() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 1_000)?;
        f.token.grant_role_internal(f.admin, BURN_BLOCKED_ROLE)?;
        let owner = f.owner;
        block_sender_only(&mut f, owner)?;
        f.token
            .burn_blocked(f.admin, f.owner, U256::from(500), true)?;
        f.mint(f.owner, 300)?;
        let authority = f.lien_authority()?;
        let lien = B256::random();
        f.lien(authority, lien, 300, 0)?;
        f.release(authority, authority, lien)?;
        assert_eq!((f.reserved()?, f.available()?), (500, 300));

        assert_eq!(
            err!(f.capture(f.owner, id, 800, true)),
            e(ReservationsError::policy_forbids())
        );
        f.capture(f.owner, id, 500, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(500));
        assert_eq!(f.balance(f.owner)?, U256::from(300));
        assert!(f.transfer(f.owner, Address::random(), 1).is_err());
        Ok(())
    })
}

/// While a compliance burn's shortfall stands, the owner places and raises no holds, so fresh
/// funds never back older burned holds; pledges, which the shortfall never reaches, still work.
#[test]
fn test_no_new_hold_reservations_while_a_burn_shortfall_stands() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let (old, kept) = (B256::random(), B256::random());
        f.hold(old, 800)?;
        f.hold(kept, 100)?;
        f.token.grant_role_internal(f.admin, BURN_BLOCKED_ROLE)?;
        f.blacklist(vec![f.owner])?;
        f.token
            .burn_blocked(f.admin, f.owner, U256::from(500), true)?;
        f.blacklist(vec![])?;
        f.mint(f.owner, 500)?;
        assert_eq!((f.reserved()?, f.available()?), (500, 500));

        assert_eq!(
            err!(f.hold(B256::random(), 1)),
            e(ReservationsError::insufficient_available())
        );
        assert_eq!(
            err!(f.adjust(f.owner, f.owner, kept, 101)),
            e(ReservationsError::insufficient_available())
        );
        let lender = Address::random();
        let pledge = B256::random();
        f.pledge(lender, pledge, 500, NOW + DAY)?;
        f.capture_of(lender, f.owner, pledge, 500, false)?;
        assert_eq!(f.balance(lender)?, U256::from(500));

        // The burn took the 100 free and 400 of the holds. Ending the burned hold settles the
        // shortfall: it gets back only its unburned 400, and holds may reserve again.
        f.release(f.owner, f.owner, old)?;
        assert_eq!((f.reserved()?, f.available()?), (100, 400));
        f.hold(B256::random(), 400)?;
        Ok(())
    })
}

/// A caller the owner never budgeted is refused before the owner's balance or policy is read, so
/// the error is the same whatever the owner holds.
#[test]
fn test_unbudgeted_hold_from_and_pledge_from_reveal_nothing_about_the_owner() -> eyre::Result<()> {
    at_fork(|| {
        let mut f = Fixture::new(1_000)?;
        let stranger = Address::random();
        for amount in [1, 1_000, 1_001] {
            let request = f.request(B256::random(), amount);
            assert_eq!(
                err!(f.reservations.place(stranger, f.owner, request)),
                e(ReservationsError::unauthorized())
            );
            let pledge = IReservationCore::pledgeFromCall {
                owner: f.owner,
                token: f.token.address(),
                id: B256::random(),
                amount,
                expiresAt: EXPIRY,
            };
            assert_eq!(
                err!(f.reservations.pledge_from(stranger, pledge)),
                e(ReservationsError::unauthorized())
            );
        }
        // The same holds when the owner is blocked.
        f.blacklist(vec![f.owner])?;
        let request = f.request(B256::random(), 1);
        assert_eq!(
            err!(f.reservations.place(stranger, f.owner, request)),
            e(ReservationsError::unauthorized())
        );
        // A budgeted holder past its limit learns nothing either.
        f.approve(100, 0)?;
        let request = f.request(B256::random(), 1_001);
        assert_eq!(
            err!(f.reservations.place(f.holder, f.owner, request)),
            e(ReservationsError::budget_exceeded())
        );
        Ok(())
    })
}

/// Makes the token's policy block `blocked` as a sender only, so it can still receive.
fn block_sender_only(f: &mut Fixture, blocked: Address) -> Result<()> {
    let mut registry = TIP403Registry::new();
    registry.initialize()?;
    let senders = registry.create_policy_with_accounts(
        f.admin,
        ITIP403Registry::createPolicyWithAccountsCall {
            admin: f.admin,
            policyType: ITIP403Registry::PolicyType::BLACKLIST,
            accounts: vec![blocked],
        },
    )?;
    let compound = registry.create_compound_policy(
        f.admin,
        ITIP403Registry::createCompoundPolicyCall {
            senderPolicyId: senders,
            recipientPolicyId: crate::tip403_registry::ALLOW_ALL_POLICY_ID,
            mintRecipientPolicyId: crate::tip403_registry::ALLOW_ALL_POLICY_ID,
        },
    )?;
    f.token.change_transfer_policy_id(
        f.admin,
        ITIP20::changeTransferPolicyIdCall {
            newPolicyId: compound,
        },
    )
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
    assert_eq!(step(&|f| f.charge(f.owner, 10))?, 0);
    assert_eq!(step(&|f| f.charge(f.holder, 10))?, 0);
    assert_eq!(step(&|f| f.hold(d, 10))?, 3);
    assert_eq!(step(&|f| f.pledge_from(ids[5], 100, NOW + 90 * DAY))?, 2);
    assert_eq!(step(&|f| f.pledge_from(ids[6], 100, NOW + 90 * DAY))?, 2);
    assert_eq!(
        step(&|f| f.capture_of(f.holder, f.holder, ids[6], 100, false))?,
        -2
    );
    // A tolerance is one slot per (owner, payee, token), and clearing it deletes the slot.
    assert_eq!(step(&|f| f.set_tolerance(500))?, 1);
    assert_eq!(step(&|f| f.set_tolerance(0))?, -1);
    Ok(())
}

/// An owner with one hold at a time, as most owners are, pays three slots per hold: the
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
