use super::*;
use crate::{
    account_keychain::AccountKeychain,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
    test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
    tip20::{BURN_BLOCKED_ROLE, IRolesAuth, ITIP20},
    tip403_registry::{ITIP403Registry, TIP403Registry},
};

use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::IReservationCore::IReservationCoreCalls;

const NOW: u64 = 1_000;
const EXPIRY: u64 = NOW + 600;

struct Fixture {
    admin: Address,
    owner: Address,
    payee: Address,
    holder: Address,
    token: TIP20Token,
    reservations: Reservations,
}

impl Fixture {
    /// Mints `balance` to a fresh owner of a fresh token.
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

    fn request(
        &self,
        id: B256,
        amount: u128,
        expires_at: u64,
        stand_in: bool,
    ) -> IReservationCore::HoldRequest {
        IReservationCore::HoldRequest {
            token: self.token.address(),
            id,
            amount,
            expiresAt: expires_at,
            payee: self.payee,
            standIn: stand_in,
        }
    }

    fn hold(&mut self, id: B256, amount: u128) -> Result<()> {
        let request = self.request(id, amount, EXPIRY, false);
        self.reservations.place(self.owner, self.owner, request)
    }

    fn hold_stand_in(&mut self, id: B256, amount: u128) -> Result<()> {
        let request = self.request(id, amount, EXPIRY, true);
        self.reservations.place(self.owner, self.owner, request)
    }

    fn hold_from(&mut self, id: B256, amount: u128) -> Result<()> {
        let request = self.request(id, amount, EXPIRY, false);
        self.reservations.place(self.holder, self.owner, request)
    }

    fn approve(&mut self, allowance: u128) -> Result<()> {
        self.reservations.approve_holder(
            self.owner,
            IReservationCore::approveHolderCall {
                holder: self.holder,
                token: self.token.address(),
                allowance,
            },
        )
    }

    fn adjust(&mut self, caller: Address, id: B256, amount: u128) -> Result<()> {
        self.reservations.adjust(
            caller,
            IReservationCore::adjustCall {
                owner: self.owner,
                id,
                amount,
            },
        )
    }

    fn capture(&mut self, caller: Address, id: B256, amount: u128, is_final: bool) -> Result<()> {
        self.reservations.capture(
            caller,
            IReservationCore::captureCall {
                owner: self.owner,
                id,
                amount,
                isFinal: is_final,
            },
        )
    }

    fn release(&mut self, caller: Address, id: B256) -> Result<()> {
        self.reservations.release(caller, self.owner, id)
    }

    fn refund(&mut self, id: B256, amount: u128) -> Result<()> {
        self.reservations.refund(
            self.payee,
            IReservationCore::refundCall {
                owner: self.owner,
                id,
                amount,
            },
        )
    }

    fn charge(&mut self, caller: Address, id: B256, amount: u128, stand_in: bool) -> Result<()> {
        self.reservations.charge(
            caller,
            IReservationCore::chargeCall {
                owner: self.owner,
                token: self.token.address(),
                id,
                amount,
                payee: self.payee,
                standIn: stand_in,
            },
        )
    }

    fn set_tolerance(&mut self, bps: u32) -> Result<()> {
        self.reservations.set_capture_tolerance(
            self.owner,
            IReservationCore::setCaptureToleranceCall {
                payee: self.payee,
                token: self.token.address(),
                toleranceBps: bps,
            },
        )
    }

    fn set_debt_cap(&mut self, cap: u128) -> Result<()> {
        self.reservations.set_debt_cap(
            self.owner,
            IReservationCore::setDebtCapCall {
                creditor: self.payee,
                token: self.token.address(),
                cap,
            },
        )
    }

    fn set_offline_cap(&mut self, cap: u128) -> Result<()> {
        self.reservations.set_offline_cap(
            self.owner,
            IReservationCore::setOfflineCapCall {
                payee: self.payee,
                token: self.token.address(),
                cap,
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

    fn seize(&mut self, authority: Address, id: B256, amount: u128) -> Result<()> {
        self.reservations
            .seize_lien(authority, IReservationCore::seizeLienCall { id, amount })
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

    fn debt(&self) -> Result<IReservationCore::debtOfReturn> {
        self.reservations.debt_of(self.owner, self.token.address())
    }

    fn record(&self, id: B256) -> Result<IReservationCore::HoldRecord> {
        self.reservations.get_hold(self.owner, id)
    }

    fn outstanding(&self) -> Result<u128> {
        Ok(self
            .reservations
            .allowance(self.owner, self.holder, self.token.address())?
            .outstanding)
    }

    /// Makes the token's transfer policy a blacklist of `accounts`.
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

/// Runs `f` at T15 with the block timestamp at [`NOW`].
fn at_t15(f: impl FnOnce() -> eyre::Result<()>) -> eyre::Result<()> {
    let mut storage = new_storage();
    StorageCtx::enter(&mut storage, f)
}

/// Signs as `account` with an access key for the rest of the transaction.
fn sign_with_access_key(account: Address) -> Result<()> {
    let mut keychain = AccountKeychain::new();
    keychain.set_tx_origin(account)?;
    keychain.set_transaction_key(Address::random())
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

#[test]
fn test_selector_coverage() -> eyre::Result<()> {
    at_t15(|| {
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
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 600)?;
        assert_eq!((f.reserved()?, f.available()?), (600, 400));
        assert_eq!(f.balance(f.owner)?, U256::from(1_000));
        let record = f.record(id)?;
        assert_eq!(
            (record.placer, record.payee, record.held, record.approved),
            (f.owner, f.payee, 600, 600)
        );
        assert_eq!(
            (record.expiresAt, record.standIn, record.settled),
            (EXPIRY, false, false)
        );
        assert!(f.transfer(f.owner, Address::random(), 401).is_err());
        assert!(f.transfer(f.owner, Address::random(), 400)?);
        assert_eq!(f.balance(f.owner)?, U256::from(600));
        f.reservations
            .assert_emitted_events(vec![ReservationsEvent::hold_placed(
                f.owner,
                id,
                f.token.address(),
                f.owner,
                f.payee,
                600,
                600,
                EXPIRY,
                false,
            )]);
        Ok(())
    })
}

#[test]
fn test_hold_rejects_invalid_requests() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        for amount in [0, u128::from(u64::MAX) + 1] {
            assert_eq!(
                err!(f.hold(id, amount)),
                ReservationsError::invalid_amount().into()
            );
        }
        for expires_at in [NOW, NOW - 1, NOW + MAX_HOLD_DURATION + 1] {
            let request = f.request(id, 1, expires_at, false);
            assert_eq!(
                err!(f.reservations.place(f.owner, f.owner, request)),
                ReservationsError::invalid_expiry().into()
            );
        }
        let request = f.request(id, 1, NOW + MAX_HOLD_DURATION, false);
        f.reservations.place(f.owner, f.owner, request)?;
        assert_eq!(err!(f.hold(id, 1)), ReservationsError::hold_exists().into());
        assert_eq!(
            err!(f.hold(B256::random(), 1_000)),
            ReservationsError::insufficient_available().into()
        );
        let mut request = f.request(B256::random(), 1, EXPIRY, false);
        request.payee = f.owner;
        assert_eq!(
            err!(f.reservations.place(f.owner, f.owner, request)),
            ReservationsError::policy_forbids().into()
        );
        f.blacklist(vec![f.payee])?;
        assert_eq!(
            err!(f.hold(B256::random(), 1)),
            ReservationsError::policy_forbids().into()
        );
        Ok(())
    })
}

#[test]
fn test_capture_tolerance_defaults_to_zero() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 100)?;
        assert_eq!(
            f.reservations
                .capture_tolerance(f.owner, f.payee, f.token.address())?,
            0
        );
        assert_eq!(
            err!(f.capture(f.owner, id, 101, true)),
            ReservationsError::tolerance_exceeded().into()
        );

        // 10% lets a capture reach 110, the excess coming from the available balance.
        f.set_tolerance(1_000)?;
        assert_eq!(
            err!(f.capture(f.owner, id, 111, true)),
            ReservationsError::tolerance_exceeded().into()
        );
        f.capture(f.owner, id, 110, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(110));
        assert_eq!(f.balance(f.owner)?, U256::from(890));
        assert_eq!((f.reserved()?, f.debt()?.amount), (0, 0));
        let record = f.record(id)?;
        assert_eq!(
            (record.held, record.captured, record.settled),
            (0, 110, true)
        );
        Ok(())
    })
}

#[test]
fn test_part_captures_and_final_release_the_rest() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 300)?;
        f.capture(f.payee, id, 100, false)?;
        assert_eq!((f.record(id)?.held, f.reserved()?), (200, 200));
        assert_eq!(
            err!(f.capture(f.payee, id, 0, false)),
            ReservationsError::invalid_amount().into()
        );
        // Part captures stay within the approval.
        assert_eq!(
            err!(f.capture(f.payee, id, 201, false)),
            ReservationsError::tolerance_exceeded().into()
        );
        f.capture(f.owner, id, 50, true)?;
        let record = f.record(id)?;
        assert_eq!(
            (record.held, record.captured, record.settled),
            (0, 150, true)
        );
        assert_eq!((f.reserved()?, f.available()?), (0, 850));
        assert_eq!(f.balance(f.payee)?, U256::from(150));

        // A stranger can neither capture nor release.
        let other = B256::random();
        f.hold(other, 10)?;
        let stranger = Address::random();
        assert_eq!(
            err!(f.capture(stranger, other, 1, true)),
            ReservationsError::unauthorized().into()
        );
        assert_eq!(
            err!(f.release(stranger, other)),
            ReservationsError::unauthorized().into()
        );
        f.release(f.payee, other)?;
        assert_eq!(f.reserved()?, 0);
        Ok(())
    })
}

#[test]
fn test_settled_id_is_terminal() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let (captured, released, charged) = (B256::random(), B256::random(), B256::random());
        f.hold(captured, 100)?;
        f.capture(f.owner, captured, 100, true)?;
        f.hold(released, 100)?;
        f.release(f.owner, released)?;
        f.charge(f.owner, charged, 10, false)?;
        for id in [captured, released, charged] {
            assert!(f.record(id)?.settled);
            assert_eq!(err!(f.hold(id, 1)), ReservationsError::hold_exists().into());
            assert_eq!(
                err!(f.charge(f.owner, id, 1, false)),
                ReservationsError::hold_exists().into()
            );
            assert_eq!(
                err!(f.capture(f.owner, id, 1, true)),
                ReservationsError::hold_settled().into()
            );
            assert_eq!(
                err!(f.adjust(f.owner, id, 1)),
                ReservationsError::hold_settled().into()
            );
            assert_eq!(
                err!(f.release(f.owner, id)),
                ReservationsError::hold_settled().into()
            );
            StorageCtx.set_timestamp(U256::from(EXPIRY));
            assert_eq!(
                err!(f.reservations.release_expired(f.owner, id)),
                ReservationsError::hold_settled().into()
            );
            StorageCtx.set_timestamp(U256::from(NOW));
        }
        assert_eq!(
            err!(f.capture(f.owner, B256::random(), 1, true)),
            ReservationsError::hold_not_found().into()
        );
        Ok(())
    })
}

#[test]
fn test_adjust_by_placer() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 300)?;
        assert_eq!(
            err!(f.adjust(f.payee, id, 100)),
            ReservationsError::unauthorized().into()
        );
        f.adjust(f.owner, id, 100)?;
        assert_eq!((f.reserved()?, f.record(id)?.approved), (100, 300));
        f.adjust(f.owner, id, 500)?;
        assert_eq!((f.reserved()?, f.record(id)?.approved), (500, 500));
        assert_eq!(
            err!(f.adjust(f.owner, id, 1_001)),
            ReservationsError::insufficient_available().into()
        );
        assert_eq!(
            err!(f.adjust(f.owner, id, 0)),
            ReservationsError::invalid_amount().into()
        );
        // After a part capture, adjusting sets what is left; the approval covers both.
        f.capture(f.payee, id, 200, false)?;
        f.adjust(f.owner, id, 400)?;
        let record = f.record(id)?;
        assert_eq!(
            (record.held, record.captured, record.approved),
            (400, 200, 600)
        );
        Ok(())
    })
}

#[test]
fn test_hard_expiry() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 300)?;
        let stranger = Address::random();
        assert_eq!(
            err!(f.reservations.release_expired(f.owner, id)),
            ReservationsError::hold_not_expired().into()
        );

        StorageCtx.set_timestamp(U256::from(EXPIRY));
        assert_eq!(
            err!(f.capture(f.payee, id, 1, false)),
            ReservationsError::hold_expired().into()
        );
        assert_eq!(
            err!(f.capture(f.owner, id, 0, true)),
            ReservationsError::hold_expired().into()
        );
        assert_eq!(
            err!(f.adjust(f.owner, id, 400)),
            ReservationsError::hold_expired().into()
        );
        assert_eq!(
            err!(f.adjust(f.owner, id, 100)),
            ReservationsError::hold_expired().into()
        );
        assert_eq!(
            err!(f.release(stranger, id)),
            ReservationsError::unauthorized().into()
        );

        // Anyone ends it; a late presentment is a charge.
        f.reservations.clear_emitted_events();
        f.reservations.release_expired(f.owner, id)?;
        f.reservations
            .assert_emitted_events(vec![ReservationsEvent::hold_released(
                f.owner,
                id,
                f.token.address(),
                300,
                true,
            )]);
        assert_eq!((f.reserved()?, f.available()?), (0, 1_000));
        assert!(f.record(id)?.settled);
        f.charge(f.owner, B256::random(), 300, false)?;
        assert_eq!(f.balance(f.payee)?, U256::from(300));

        // The placer or payee may also release after expiry.
        StorageCtx.set_timestamp(U256::from(NOW));
        let other = B256::random();
        f.hold(other, 10)?;
        StorageCtx.set_timestamp(U256::from(EXPIRY + 1));
        f.release(f.payee, other)?;
        Ok(())
    })
}

#[test]
fn test_holder_allowance_bounds_outstanding() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let (first, second) = (B256::random(), B256::random());
        assert_eq!(
            err!(f.hold_from(first, 100)),
            ReservationsError::unauthorized().into()
        );
        f.approve(300)?;
        f.hold_from(first, 200)?;
        let record = f.record(first)?;
        assert_eq!((record.placer, record.held), (f.holder, 200));
        assert_eq!(f.outstanding()?, 200);
        assert_eq!(
            err!(f.hold_from(second, 101)),
            ReservationsError::allowance_exceeded().into()
        );
        f.hold_from(second, 100)?;
        assert_eq!(f.outstanding()?, 300);

        // Only the placer adjusts, within the allowance.
        assert_eq!(
            err!(f.adjust(f.owner, first, 100)),
            ReservationsError::unauthorized().into()
        );
        assert_eq!(
            err!(f.adjust(f.holder, first, 201)),
            ReservationsError::allowance_exceeded().into()
        );
        f.adjust(f.holder, first, 150)?;
        assert_eq!(f.outstanding()?, 250);

        // Captures free the allowance.
        f.capture(f.payee, first, 100, false)?;
        assert_eq!(f.outstanding()?, 150);
        f.capture(f.holder, first, 20, true)?;
        assert_eq!(f.outstanding()?, 100);

        // Revoking stops new holds; existing ones still capture, release and refund.
        f.approve(0)?;
        assert_eq!(
            err!(f.hold_from(B256::random(), 1)),
            ReservationsError::unauthorized().into()
        );
        assert_eq!(
            err!(f.charge(f.holder, B256::random(), 1, false)),
            ReservationsError::unauthorized().into()
        );
        f.capture(f.payee, second, 60, false)?;
        f.release(f.holder, second)?;
        assert_eq!((f.outstanding()?, f.reserved()?), (0, 0));
        f.refund(first, 120)?;
        f.refund(second, 60)?;
        assert_eq!(f.balance(f.owner)?, U256::from(1_000));
        Ok(())
    })
}

#[test]
fn test_holder_charges_and_captures_beyond_the_hold_within_its_allowance() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        f.approve(100)?;
        assert_eq!(
            err!(f.charge(f.holder, B256::random(), 101, false)),
            ReservationsError::allowance_exceeded().into()
        );
        f.charge(f.holder, B256::random(), 100, false)?;
        // A charge leaves nothing outstanding.
        assert_eq!(f.outstanding()?, 0);

        let (id, other) = (B256::random(), B256::random());
        f.hold_from(id, 40)?;
        f.hold_from(other, 60)?;
        f.set_tolerance(20_000)?;
        // Past the hold, the excess counts against the allowance once the hold is freed.
        assert_eq!(
            err!(f.capture(f.holder, id, 100, true)),
            ReservationsError::allowance_exceeded().into()
        );
        f.capture(f.holder, id, 80, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(180));
        f.capture(f.payee, other, 20, true)?;
        assert_eq!(
            (f.balance(f.payee)?, f.outstanding()?),
            (U256::from(200), 0)
        );
        Ok(())
    })
}

#[test]
fn test_approve_holder_requires_root_key() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        assert_eq!(
            err!(f.reservations.approve_holder(
                f.owner,
                IReservationCore::approveHolderCall {
                    holder: f.owner,
                    token: f.token.address(),
                    allowance: 1,
                },
            )),
            ReservationsError::unauthorized().into()
        );
        f.approve(10)?;
        f.reservations
            .assert_emitted_events(vec![ReservationsEvent::holder_approved(
                f.owner,
                f.holder,
                f.token.address(),
                10,
            )]);
        sign_with_access_key(f.owner)?;
        assert_eq!(
            err!(f.approve(20)),
            ReservationsError::unauthorized().into()
        );
        assert_eq!(
            err!(f.set_tolerance(1)),
            ReservationsError::unauthorized().into()
        );
        assert_eq!(
            err!(f.set_debt_cap(1)),
            ReservationsError::unauthorized().into()
        );
        assert_eq!(
            err!(f.set_offline_cap(1)),
            ReservationsError::unauthorized().into()
        );
        assert_eq!(
            err!(f.pledge(Address::random(), B256::random(), 1, EXPIRY)),
            ReservationsError::unauthorized().into()
        );
        assert_eq!(
            f.reservations
                .allowance(f.owner, f.holder, f.token.address())?
                .allowance,
            10
        );
        Ok(())
    })
}

#[test]
fn test_stand_in_capture_is_capped_at_the_approval() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(100)?;
        let id = B256::random();
        f.hold_stand_in(id, 200)?;
        let record = f.record(id)?;
        assert_eq!(
            (record.held, record.approved, record.standIn),
            (100, 200, true)
        );
        assert_eq!(f.available()?, 0);

        // A capture above the offline approval is refused, however much debt room there is.
        f.set_offline_cap(1_000)?;
        assert_eq!(
            err!(f.capture(f.payee, id, 450, true)),
            ReservationsError::tolerance_exceeded().into()
        );
        // Raising a stand-in past its approval is refused too.
        assert_eq!(
            err!(f.adjust(f.owner, id, 201)),
            ReservationsError::invalid_amount().into()
        );
        f.set_tolerance(1_000)?;
        assert_eq!(
            err!(f.capture(f.payee, id, 221, true)),
            ReservationsError::tolerance_exceeded().into()
        );
        f.capture(f.payee, id, 220, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(100));
        assert_eq!(f.debt()?.amount, 120);
        assert_eq!(f.debt()?.creditor, f.payee);
        Ok(())
    })
}

#[test]
fn test_stand_in_debt_reaches_the_offline_cap_only() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(100)?;
        f.set_debt_cap(50)?;
        f.set_offline_cap(150)?;
        // Ordinary payments stay within the debt cap.
        assert_eq!(
            err!(f.charge(f.owner, B256::random(), 151, false)),
            ReservationsError::debt_cap_exceeded().into()
        );
        let id = B256::random();
        f.hold_stand_in(id, 300)?;
        assert_eq!(
            err!(f.capture(f.payee, id, 251, true)),
            ReservationsError::debt_cap_exceeded().into()
        );
        f.capture(f.payee, id, 250, true)?;
        assert_eq!(f.debt()?.amount, 150);
        assert_eq!(
            err!(f.charge(f.owner, B256::random(), 1, true)),
            ReservationsError::debt_cap_exceeded().into()
        );
        Ok(())
    })
}

#[test]
fn test_charge_shortfall_is_capped_debt_repaid_on_receive() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(100)?;
        assert_eq!(
            err!(f.charge(f.owner, B256::random(), 101, false)),
            ReservationsError::insufficient_available().into()
        );
        f.set_debt_cap(500)?;
        let id = B256::random();
        f.charge(f.owner, id, 300, false)?;
        f.reservations
            .assert_emitted_events(vec![ReservationsEvent::charged(
                f.owner,
                id,
                f.token.address(),
                f.payee,
                300,
                200,
            )]);
        let record = f.record(id)?;
        assert_eq!(
            (record.captured, record.held, record.settled),
            (300, 0, true)
        );
        assert_eq!(f.debt()?.amount, 200);

        // A second creditor waits until the first is repaid.
        let other = Address::random();
        f.reservations.set_debt_cap(
            f.owner,
            IReservationCore::setDebtCapCall {
                creditor: other,
                token: f.token.address(),
                cap: 100,
            },
        )?;
        assert_eq!(
            err!(f.reservations.charge(
                f.owner,
                IReservationCore::chargeCall {
                    owner: f.owner,
                    token: f.token.address(),
                    id: B256::random(),
                    amount: 1,
                    payee: other,
                    standIn: false,
                },
            )),
            ReservationsError::debt_cap_exceeded().into()
        );

        let sender = Address::random();
        f.mint(sender, 1_000)?;
        f.transfer(sender, f.owner, 150)?;
        assert_eq!(f.balance(f.owner)?, U256::ZERO);
        assert_eq!(f.balance(f.payee)?, U256::from(250));
        assert_eq!(f.debt()?.amount, 50);
        f.mint(f.owner, 80)?;
        assert_eq!(f.balance(f.owner)?, U256::from(30));
        assert_eq!(
            f.debt()?,
            IReservationCore::debtOfReturn {
                creditor: Address::ZERO,
                amount: 0
            }
        );
        Ok(())
    })
}

#[test]
fn test_refund_bounds() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        f.hold(id, 300)?;
        assert_eq!(
            err!(f.refund(id, 1)),
            ReservationsError::refund_exceeds_capture().into()
        );
        f.capture(f.payee, id, 100, false)?;
        assert_eq!(
            err!(f.reservations.refund(
                f.owner,
                IReservationCore::refundCall {
                    owner: f.owner,
                    id,
                    amount: 1
                },
            )),
            ReservationsError::unauthorized().into()
        );
        assert_eq!(
            err!(f.refund(id, 0)),
            ReservationsError::invalid_amount().into()
        );
        assert_eq!(
            err!(f.refund(id, 101)),
            ReservationsError::refund_exceeds_capture().into()
        );
        f.refund(id, 60)?;
        f.capture(f.payee, id, 50, true)?;
        f.refund(id, 90)?;
        assert_eq!(
            err!(f.refund(id, 1)),
            ReservationsError::refund_exceeds_capture().into()
        );
        let record = f.record(id)?;
        assert_eq!((record.captured, record.refunded), (150, 150));
        assert_eq!(f.balance(f.owner)?, U256::from(1_000));
        assert_eq!(
            err!(f.refund(B256::random(), 1)),
            ReservationsError::hold_not_found().into()
        );
        Ok(())
    })
}

#[test]
fn test_liens_reserve_until_their_authority_acts() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let id = B256::random();
        let stranger = Address::random();
        assert_eq!(
            err!(f.lien(stranger, id, 10, 0)),
            ReservationsError::unauthorized().into()
        );
        let authority = f.lien_authority()?;
        assert_eq!(
            err!(f.lien(authority, id, 0, 0)),
            ReservationsError::invalid_amount().into()
        );
        assert_eq!(
            err!(f.lien(authority, id, 10, NOW)),
            ReservationsError::invalid_expiry().into()
        );
        f.lien(authority, id, 400, 0)?;
        assert_eq!(
            err!(f.lien(authority, id, 1, 0)),
            ReservationsError::lien_exists().into()
        );
        assert_eq!((f.reserved()?, f.available()?), (400, 600));
        assert_eq!(f.reservations.liened_of(f.owner, f.token.address())?, 400);
        assert_eq!(
            err!(f.hold(B256::random(), 601)),
            ReservationsError::insufficient_available().into()
        );

        // Only the authority acts on it, and a lien without expiry never expires.
        assert_eq!(
            err!(f.reservations.release_lien(stranger, id)),
            ReservationsError::lien_not_found().into()
        );
        StorageCtx.set_timestamp(U256::from(u64::from(u32::MAX)));
        assert_eq!(
            err!(f.reservations.release_expired_lien(authority, id)),
            ReservationsError::lien_not_expired().into()
        );
        StorageCtx.set_timestamp(U256::from(NOW));
        f.reservations.reduce_lien(
            authority,
            IReservationCore::reduceLienCall { id, amount: 100 },
        )?;
        assert_eq!(f.reservations.lien_of(authority, id)?.amount, 300);

        // Seizure pays the authority only.
        f.seize(authority, id, 120)?;
        assert_eq!(f.balance(authority)?, U256::from(120));
        assert_eq!(f.balance(f.owner)?, U256::from(880));
        assert_eq!(f.reserved()?, 180);
        assert_eq!(
            err!(f.seize(authority, id, 181)),
            ReservationsError::invalid_amount().into()
        );

        // A role lien's seizure still needs the role.
        f.token.revoke_role(
            f.admin,
            IRolesAuth::revokeRoleCall {
                role: LIEN_ROLE,
                account: authority,
            },
        )?;
        assert_eq!(
            err!(f.seize(authority, id, 1)),
            ReservationsError::unauthorized().into()
        );
        f.reservations.release_lien(authority, id)?;
        assert_eq!((f.reserved()?, f.available()?), (0, 880));
        assert_eq!(
            err!(f.reservations.release_lien(authority, id)),
            ReservationsError::lien_not_found().into()
        );
        Ok(())
    })
}

#[test]
fn test_pledges_expire_and_seize_to_the_authority() -> eyre::Result<()> {
    at_t15(|| {
        let mut f = Fixture::new(1_000)?;
        let lender = Address::random();
        let id = B256::random();
        assert_eq!(
            err!(f.pledge(lender, id, 100, 0)),
            ReservationsError::invalid_expiry().into()
        );
        assert_eq!(
            err!(f.pledge(f.owner, id, 100, EXPIRY)),
            ReservationsError::unauthorized().into()
        );
        f.pledge(lender, id, 500, EXPIRY)?;
        let lien = f.reservations.lien_of(lender, id)?;
        assert_eq!(
            (lien.owner, lien.amount, lien.expiresAt, lien.pledged),
            (f.owner, 500, EXPIRY, true)
        );

        // The pledge's authority seizes without the role.
        f.seize(lender, id, 200)?;
        assert_eq!(f.balance(lender)?, U256::from(200));

        let anyone = Address::random();
        assert_eq!(
            err!(f.reservations.release_expired_lien(lender, id)),
            ReservationsError::lien_not_expired().into()
        );
        let _ = anyone;
        StorageCtx.set_timestamp(U256::from(EXPIRY));
        assert_eq!(
            err!(f.seize(lender, id, 1)),
            ReservationsError::invalid_expiry().into()
        );
        f.reservations.clear_emitted_events();
        f.reservations.release_expired_lien(lender, id)?;
        f.reservations
            .assert_emitted_events(vec![ReservationsEvent::lien_released(
                f.owner,
                lender,
                f.token.address(),
                id,
                300,
                true,
            )]);
        assert_eq!((f.reserved()?, f.available()?), (0, 800));
        Ok(())
    })
}

#[test]
fn test_compliance_burns_take_reserved_funds() -> eyre::Result<()> {
    at_t15(|| {
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
        assert_eq!(f.record(released)?.held, 300);

        // Ending a hold consumes the burned part first, so what remains still backs the others.
        f.blacklist(vec![])?;
        f.release(f.owner, released)?;
        assert_eq!((f.reserved()?, f.available()?), (200, 0));
        assert_eq!(
            err!(f.capture(f.owner, captured, 600, true)),
            ReservationsError::insufficient_available().into()
        );
        f.set_debt_cap(400)?;
        f.capture(f.owner, captured, 600, true)?;
        assert_eq!(f.balance(f.payee)?, U256::from(200));
        assert_eq!(f.debt()?.amount, 400);
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

        // A hold takes its funds out of the opted-in supply.
        let id = B256::random();
        f.hold(id, 500)?;
        assert_eq!(f.token.get_opted_in_supply()?, 1_500);
        distribute(&mut f, 300)?;
        assert_eq!(rewards(&mut f, owner)?, U256::from(100));
        assert_eq!(rewards(&mut f, other)?, U256::from(200));

        // A transfer of available funds moves them as usual.
        f.transfer(f.owner, merchant, 100)?;
        assert_eq!(f.token.get_opted_in_supply()?, 1_400);

        // Releasing brings them back.
        f.release(f.owner, id)?;
        assert_eq!(f.token.get_opted_in_supply()?, 1_900);
        distribute(&mut f, 190)?;
        assert_eq!(rewards(&mut f, owner)?, U256::from(190));
        assert_eq!(rewards(&mut f, other)?, U256::from(300));

        // Capturing to a payee that is not opted in leaves the supply.
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

/// New slots the reservation core holds after each operation, against the slot budget.
#[test]
fn test_slots_per_operation() -> eyre::Result<()> {
    let mut storage = new_storage();
    let count = |storage: &HashMapStorageProvider| storage.nonzero_slot_count(RESERVATIONS_ADDRESS);
    let mut f = StorageCtx::enter(&mut storage, || -> eyre::Result<_> {
        let mut f = Fixture::new(10_000)?;
        f.approve(5_000)?;
        Ok(f)
    })?;
    let step = |storage: &mut HashMapStorageProvider,
                f: &mut Fixture,
                op: &dyn Fn(&mut Fixture) -> Result<()>|
     -> eyre::Result<i64> {
        let before = count(storage) as i64;
        StorageCtx::enter(storage, || op(f))?;
        Ok(count(storage) as i64 - before)
    };
    let ids: Vec<B256> = (0..8).map(|_| B256::random()).collect();
    let (a, b, c, d, e) = (ids[0], ids[1], ids[2], ids[3], ids[4]);
    // The first hold also writes the owner's position slot.
    assert_eq!(step(&mut storage, &mut f, &|f| f.hold(a, 100))?, 3);
    assert_eq!(step(&mut storage, &mut f, &|f| f.hold(b, 100))?, 2);
    assert_eq!(step(&mut storage, &mut f, &|f| f.hold_from(c, 100))?, 3);
    // The payee's balance is a TIP-20 slot; the core adds the totals slot on the first capture.
    assert_eq!(
        step(&mut storage, &mut f, &|f| f.capture(f.payee, a, 40, false))?,
        1
    );
    assert_eq!(
        step(&mut storage, &mut f, &|f| f.capture(f.payee, a, 40, true))?,
        0
    );
    assert_eq!(
        step(&mut storage, &mut f, &|f| f.capture(f.payee, c, 100, true))?,
        1
    );
    // Releasing the last live hold clears the owner's position slot.
    assert_eq!(step(&mut storage, &mut f, &|f| f.release(f.owner, b))?, -1);
    assert_eq!(step(&mut storage, &mut f, &|f| f.refund(a, 30))?, 0);
    assert_eq!(
        step(&mut storage, &mut f, &|f| f.charge(f.owner, d, 10, false))?,
        3
    );
    assert_eq!(step(&mut storage, &mut f, &|f| f.hold(e, 10))?, 3);
    Ok(())
}

/// One operation of the random sequences.
#[derive(Debug, Clone)]
enum Op {
    Hold {
        owner: usize,
        id: usize,
        amount: u128,
        ttl: u64,
        stand_in: bool,
        by_holder: bool,
    },
    Adjust {
        owner: usize,
        id: usize,
        amount: u128,
    },
    Capture {
        owner: usize,
        id: usize,
        amount: u128,
        is_final: bool,
        by_payee: bool,
    },
    Release {
        owner: usize,
        id: usize,
        by_payee: bool,
    },
    ReleaseExpired {
        owner: usize,
        id: usize,
    },
    Refund {
        owner: usize,
        id: usize,
        amount: u128,
    },
    Charge {
        owner: usize,
        id: usize,
        amount: u128,
        stand_in: bool,
        by_holder: bool,
    },
    Transfer {
        from: usize,
        to: usize,
        amount: u64,
    },
    Lien {
        owner: usize,
        id: usize,
        amount: u128,
        ttl: u64,
    },
    ReleaseLien {
        id: usize,
    },
    Warp {
        seconds: u64,
    },
}

const OWNERS: usize = 2;
const IDS: usize = 6;

fn op_strategy() -> impl Strategy<Value = Op> {
    let owner = 0..OWNERS;
    let id = 0..IDS;
    prop_oneof![
        4 => (owner.clone(), id.clone(), 1..400u128, 1..900u64, any::<bool>(), any::<bool>()).prop_map(
            |(owner, id, amount, ttl, stand_in, by_holder)| Op::Hold { owner, id, amount, ttl, stand_in, by_holder }
        ),
        2 => (owner.clone(), id.clone(), 1..400u128).prop_map(|(owner, id, amount)| Op::Adjust { owner, id, amount }),
        4 => (owner.clone(), id.clone(), 0..500u128, any::<bool>(), any::<bool>()).prop_map(
            |(owner, id, amount, is_final, by_payee)| Op::Capture { owner, id, amount, is_final, by_payee }
        ),
        2 => (owner.clone(), id.clone(), any::<bool>()).prop_map(|(owner, id, by_payee)| Op::Release { owner, id, by_payee }),
        1 => (owner.clone(), id.clone()).prop_map(|(owner, id)| Op::ReleaseExpired { owner, id }),
        2 => (owner.clone(), id.clone(), 1..300u128).prop_map(|(owner, id, amount)| Op::Refund { owner, id, amount }),
        2 => (owner.clone(), id, 1..300u128, any::<bool>(), any::<bool>()).prop_map(
            |(owner, id, amount, stand_in, by_holder)| Op::Charge { owner, id, amount, stand_in, by_holder }
        ),
        2 => (0..4usize, 0..4usize, 1..300u64).prop_map(|(from, to, amount)| Op::Transfer { from, to, amount }),
        1 => (owner, 0..2usize, 1..200u128, 0..900u64).prop_map(|(owner, id, amount, ttl)| Op::Lien { owner, id, amount, ttl }),
        1 => (0..2usize).prop_map(|id| Op::ReleaseLien { id }),
        2 => (0..400u64).prop_map(|seconds| Op::Warp { seconds }),
    ]
}

/// Accounts and terms of a random sequence.
struct World {
    token: TIP20Token,
    reservations: Reservations,
    owners: [Address; OWNERS],
    holder: Address,
    payee: Address,
    authority: Address,
    stranger: Address,
    ids: Vec<B256>,
    lien_ids: Vec<B256>,
    /// Hold records seen settled.
    settled: BTreeSet<(usize, usize)>,
    /// Captured and held amounts first seen past expiry.
    expired: BTreeMap<(usize, usize), (u128, u128)>,
}

const ALLOWANCE: u128 = 500;
const TOLERANCE: u32 = 2_000;
const DEBT_CAP: u128 = 100;
const OFFLINE_CAP: u128 = 250;

impl World {
    fn new() -> Result<Self> {
        let admin = Address::random();
        let owners = [Address::random(), Address::random()];
        let (holder, payee, authority, stranger) = (
            Address::random(),
            Address::random(),
            Address::random(),
            Address::random(),
        );
        let mut token = TIP20Setup::create("Core USD", "CUSD", admin)
            .with_issuer(admin)
            .with_mint(owners[0], U256::from(1_000))
            .with_mint(owners[1], U256::from(500))
            .with_mint(stranger, U256::from(500))
            .apply()?;
        token.grant_role_internal(authority, LIEN_ROLE)?;
        let mut reservations = Reservations::new();
        reservations.initialize()?;
        let token_address = token.address();
        for owner in owners {
            reservations.approve_holder(
                owner,
                IReservationCore::approveHolderCall {
                    holder,
                    token: token_address,
                    allowance: ALLOWANCE,
                },
            )?;
            reservations.set_capture_tolerance(
                owner,
                IReservationCore::setCaptureToleranceCall {
                    payee,
                    token: token_address,
                    toleranceBps: TOLERANCE,
                },
            )?;
            reservations.set_debt_cap(
                owner,
                IReservationCore::setDebtCapCall {
                    creditor: payee,
                    token: token_address,
                    cap: DEBT_CAP,
                },
            )?;
            reservations.set_offline_cap(
                owner,
                IReservationCore::setOfflineCapCall {
                    payee,
                    token: token_address,
                    cap: OFFLINE_CAP,
                },
            )?;
        }
        Ok(Self {
            token,
            reservations,
            owners,
            holder,
            payee,
            authority,
            stranger,
            ids: (0..IDS).map(|_| B256::random()).collect(),
            lien_ids: (0..2).map(|_| B256::random()).collect(),
            settled: BTreeSet::new(),
            expired: BTreeMap::new(),
        })
    }

    fn accounts(&self) -> [Address; 5] {
        [
            self.owners[0],
            self.owners[1],
            self.payee,
            self.stranger,
            self.authority,
        ]
    }

    fn apply(&mut self, op: &Op) -> Result<()> {
        let token = self.token.address();
        let now = StorageCtx.timestamp().saturating_to::<u64>();
        match *op {
            Op::Hold {
                owner,
                id,
                amount,
                ttl,
                stand_in,
                by_holder,
            } => {
                let request = IReservationCore::HoldRequest {
                    token,
                    id: self.ids[id],
                    amount,
                    expiresAt: now + ttl,
                    payee: self.payee,
                    standIn: stand_in,
                };
                let owner = self.owners[owner];
                let placer = if by_holder { self.holder } else { owner };
                self.reservations.place(placer, owner, request)
            }
            Op::Adjust { owner, id, amount } => {
                let (owner, id) = (self.owners[owner], self.ids[id]);
                let placer = self.reservations.get_hold(owner, id)?.placer;
                self.reservations
                    .adjust(placer, IReservationCore::adjustCall { owner, id, amount })
            }
            Op::Capture {
                owner,
                id,
                amount,
                is_final,
                by_payee,
            } => {
                let (owner, id) = (self.owners[owner], self.ids[id]);
                let caller = if by_payee {
                    self.payee
                } else {
                    self.reservations.get_hold(owner, id)?.placer
                };
                self.reservations.capture(
                    caller,
                    IReservationCore::captureCall {
                        owner,
                        id,
                        amount,
                        isFinal: is_final,
                    },
                )
            }
            Op::Release {
                owner,
                id,
                by_payee,
            } => {
                let (owner, id) = (self.owners[owner], self.ids[id]);
                let caller = if by_payee {
                    self.payee
                } else {
                    self.reservations.get_hold(owner, id)?.placer
                };
                self.reservations.release(caller, owner, id)
            }
            Op::ReleaseExpired { owner, id } => self
                .reservations
                .release_expired(self.owners[owner], self.ids[id]),
            Op::Refund { owner, id, amount } => self.reservations.refund(
                self.payee,
                IReservationCore::refundCall {
                    owner: self.owners[owner],
                    id: self.ids[id],
                    amount,
                },
            ),
            Op::Charge {
                owner,
                id,
                amount,
                stand_in,
                by_holder,
            } => {
                let owner = self.owners[owner];
                let caller = if by_holder { self.holder } else { owner };
                self.reservations.charge(
                    caller,
                    IReservationCore::chargeCall {
                        owner,
                        token,
                        id: self.ids[id],
                        amount,
                        payee: self.payee,
                        standIn: stand_in,
                    },
                )
            }
            Op::Transfer { from, to, amount } => {
                let accounts = self.accounts();
                let (from, to) = (accounts[from], accounts[to]);
                let spendable = self.token.balances[from].read()?;
                let result = self.token.transfer(
                    from,
                    ITIP20::transferCall {
                        to,
                        amount: U256::from(amount),
                    },
                );
                // Transfers never spend reserved funds.
                if U256::from(amount) > spendable {
                    assert!(result.is_err(), "transfer above the balance slot must fail");
                }
                result.map(|_| ())
            }
            Op::Lien {
                owner,
                id,
                amount,
                ttl,
            } => self.reservations.lien(
                self.authority,
                IReservationCore::lienCall {
                    owner: self.owners[owner],
                    token,
                    id: self.lien_ids[id],
                    amount,
                    expiresAt: if ttl == 0 { 0 } else { now + ttl },
                },
            ),
            Op::ReleaseLien { id } => self
                .reservations
                .release_lien(self.authority, self.lien_ids[id]),
            Op::Warp { seconds } => {
                StorageCtx.set_timestamp(U256::from(now + seconds));
                Ok(())
            }
        }
    }

    /// Checks the TIP-1153 invariants.
    fn check(&mut self) -> Result<()> {
        let token = self.token.address();
        let now = StorageCtx.timestamp().saturating_to::<u64>();
        let mut slots = U256::ZERO;
        let mut reserved_total = 0u128;
        for account in self.accounts() {
            let slot = self.token.balances[account].read()?;
            let reserved = self.reservations.reserved_of(account, token)?;
            // 1. The balance slot plus what is reserved is what the owner holds.
            assert_eq!(
                self.token.balance_of(ITIP20::balanceOfCall { account })?,
                slot + U256::from(reserved)
            );
            slots += slot;
            reserved_total += reserved;
        }
        slots += self.token.balances[self.holder].read()?;
        slots += self.token.balances[token].read()?;
        assert_eq!(
            self.token.total_supply()?,
            slots + U256::from(reserved_total)
        );

        for (o, owner) in self.owners.into_iter().enumerate() {
            let mut held = 0u128;
            let mut delegated = 0u128;
            for (i, id) in self.ids.clone().into_iter().enumerate() {
                let record = self.reservations.get_hold(owner, id)?;
                if record.token.is_zero() {
                    continue;
                }
                // 3. Captures stay within the approval and its tolerance, refunds within captures.
                let cap = record.approved * (BPS + u128::from(TOLERANCE)) / BPS;
                assert!(
                    record.captured <= cap,
                    "captured {} over cap {cap}",
                    record.captured
                );
                assert!(record.refunded <= record.captured);
                if record.settled {
                    assert_eq!(record.held, 0);
                    self.settled.insert((o, i));
                } else {
                    assert!(!self.settled.contains(&(o, i)), "a settled id reopened");
                    held += record.held;
                    if record.placer == self.holder {
                        delegated += record.held;
                    }
                }
                // 6. After expiry, a hold can only be released.
                if now >= record.expiresAt && !record.settled || self.expired.contains_key(&(o, i))
                {
                    let seen = *self
                        .expired
                        .entry((o, i))
                        .or_insert((record.captured, record.held));
                    assert_eq!(record.captured, seen.0, "captured after expiry");
                    assert!(record.held == seen.1 || (record.held == 0 && record.settled));
                }
            }
            let mut liened = 0u128;
            for id in self.lien_ids.clone() {
                let lien = self.reservations.lien_of(self.authority, id)?;
                if lien.owner == owner {
                    liened += lien.amount;
                }
            }
            // 2. Reserved is what live holds and liens hold.
            assert_eq!(self.reservations.reserved_of(owner, token)?, held + liened);
            assert_eq!(self.reservations.liened_of(owner, token)?, liened);
            // 4. Outstanding is what the holder's live holds hold, within its allowance.
            let allowance = self.reservations.allowance(owner, self.holder, token)?;
            assert_eq!(allowance.outstanding, delegated);
            assert!(allowance.outstanding <= ALLOWANCE);
            // 5. Debt stays within the larger of its caps.
            let debt = self.reservations.debt_of(owner, token)?;
            assert!(debt.amount <= DEBT_CAP.max(OFFLINE_CAP));
            if debt.amount != 0 {
                assert_eq!(debt.creditor, self.payee);
            }
        }
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn proptest_random_sequences_keep_the_invariants(ops in prop::collection::vec(op_strategy(), 1..60)) {
        let mut storage = new_storage();
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut world = World::new()?;
            for op in &ops {
                // A failed call reverts, as it does in a transaction.
                let checkpoint = StorageCtx.checkpoint();
                if world.apply(op).is_ok() {
                    checkpoint.commit();
                } else {
                    drop(checkpoint);
                }
                world.check()?;
            }
            Ok(())
        }).unwrap();
    }
}
