//! Execution time of the reservations precompile's core operations, beside TIP-20 transfers on the
//! same hardfork as pricing baselines.
//!
//! Every operation runs through its precompile's `call` entry with ABI-encoded calldata, so
//! decoding counts. Operations that consume state (a record, a debt) get their own fresh state,
//! prepared outside the timed section.

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    sol_types::SolCall,
};
use criterion::{Criterion, criterion_group, criterion_main};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::IReservationCore;
use tempo_precompiles::{
    Precompile, RESERVATIONS_ADDRESS,
    reservations::{LIEN_ROLE, MAX_CREDITORS, Reservations},
    storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
    test_util::{TIP20Setup, set_empty_compound_transfer_policy, set_empty_receive_policies},
    tip20::{ITIP20, TIP20Token},
};

const NOW: u64 = 1_000;
const EXPIRY: u64 = NOW + 600;
const HOLD: u128 = 1_000;
const DEBT: u128 = 10;
/// Timed calls share one world before it is rebuilt, which keeps its maps small.
const CHUNK: u64 = 256;
const CREDITORS: usize = MAX_CREDITORS as usize;

const ADMIN: Address = Address::repeat_byte(0x11);
const OWNER: Address = Address::repeat_byte(0x12);
const PAYEE: Address = Address::repeat_byte(0x13);
const HOLDER: Address = Address::repeat_byte(0x14);
const AUTHORITY: Address = Address::repeat_byte(0x15);
const CREDITOR_ACCOUNTS: [Address; CREDITORS] = [
    Address::repeat_byte(0x21),
    Address::repeat_byte(0x22),
    Address::repeat_byte(0x23),
    Address::repeat_byte(0x24),
];

/// One call: the precompile, its sender and its calldata.
struct Call {
    target: Address,
    sender: Address,
    calldata: Bytes,
}

impl Call {
    fn reservations(sender: Address, call: impl SolCall) -> Self {
        Self {
            target: RESERVATIONS_ADDRESS,
            sender,
            calldata: call.abi_encode().into(),
        }
    }

    fn token(token: Address, sender: Address, call: impl SolCall) -> Self {
        Self {
            target: token,
            sender,
            calldata: call.abi_encode().into(),
        }
    }
}

/// T16 state with a funded TIP-20 token, an initialized reservations precompile, and a holder
/// the owner approved without limit.
struct World {
    storage: HashMapStorageProvider,
    token: Address,
}

impl World {
    fn new(policies: bool) -> Self {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T16);
        storage.set_timestamp(U256::from(NOW));
        let token = StorageCtx::enter(&mut storage, || {
            let mut setup = TIP20Setup::create("Core USD", "CUSD", ADMIN).with_issuer(ADMIN);
            for account in [OWNER, PAYEE, HOLDER].into_iter().chain(CREDITOR_ACCOUNTS) {
                setup = setup.with_mint(account, U256::from(u64::MAX));
            }
            let mut token = setup.apply().unwrap();
            token.grant_role_internal(AUTHORITY, LIEN_ROLE).unwrap();
            if policies {
                set_empty_compound_transfer_policy(ADMIN, token.address()).unwrap();
                let mut receivers = vec![OWNER, PAYEE, HOLDER, AUTHORITY];
                receivers.extend(CREDITOR_ACCOUNTS);
                set_empty_receive_policies(ADMIN, &receivers).unwrap();
            }
            Reservations::new().initialize().unwrap();
            token.address()
        });
        let mut world = Self { storage, token };
        world.run(&Call::reservations(
            OWNER,
            IReservationCore::approveHolderCall {
                holder: HOLDER,
                token,
                limit: u128::MAX,
                period: 0,
            },
        ));
        world
    }

    /// Runs a setup call, which must succeed.
    fn run(&mut self, call: &Call) {
        self.execute(call).expect("setup call succeeds");
    }

    fn execute(&mut self, call: &Call) -> evm2::precompiles::PrecompileResult {
        StorageCtx::enter(&mut self.storage, || {
            if call.target == RESERVATIONS_ADDRESS {
                Reservations::new().call(&call.calldata, call.sender)
            } else {
                TIP20Token::from_address(call.target)
                    .expect("TIP-20 token")
                    .call(&call.calldata, call.sender)
            }
        })
    }

    fn set_timestamp(&mut self, timestamp: u64) {
        self.storage.set_timestamp(U256::from(timestamp));
    }

    fn request(&self, id: B256, stand_in: bool) -> IReservationCore::HoldRequest {
        IReservationCore::HoldRequest {
            token: self.token,
            id,
            amount: HOLD,
            expiresAt: EXPIRY,
            payee: PAYEE,
            standIn: stand_in,
        }
    }

    fn hold(&mut self, id: B256) {
        let request = self.request(id, false);
        self.run(&Call::reservations(
            OWNER,
            IReservationCore::holdCall { request },
        ));
    }

    fn hold_from(&mut self, id: B256) {
        let request = self.request(id, false);
        self.run(&Call::reservations(
            HOLDER,
            IReservationCore::holdFromCall {
                owner: OWNER,
                request,
            },
        ));
    }

    /// Leaves `debtor`, which holds none of the token, owing `DEBT` to each of the first `count`
    /// creditors, in debts that lapse after `debt_term` seconds (zero for the longest term).
    fn owe(&mut self, debtor: Address, count: usize, debt_term: u32) {
        for creditor in &CREDITOR_ACCOUNTS[..count] {
            self.run(&Call::reservations(
                debtor,
                IReservationCore::setPayeeTermsCall {
                    payee: *creditor,
                    token: self.token,
                    terms: IReservationCore::PayeeTerms {
                        debtCap: 1_000_000,
                        offlineCap: 0,
                        toleranceBps: 0,
                        debtTerm: debt_term,
                    },
                },
            ));
            let charge = charge(self.token, debtor, *creditor, DEBT);
            self.run(&Call::reservations(debtor, charge));
        }
    }
}

fn charge(
    token: Address,
    owner: Address,
    payee: Address,
    amount: u128,
) -> IReservationCore::chargeCall {
    IReservationCore::chargeCall {
        owner,
        token,
        id: B256::repeat_byte(0xc1),
        amount,
        payee,
        standIn: false,
    }
}

fn capture(
    placer: Address,
    id: B256,
    amount: u128,
    is_final: bool,
) -> IReservationCore::captureCall {
    IReservationCore::captureCall {
        owner: OWNER,
        placer,
        id,
        amount,
        isFinal: is_final,
    }
}

/// A distinct record id for each iteration.
fn id(index: u64) -> B256 {
    B256::from(U256::from(index + 1))
}

/// A distinct account for each iteration, holding none of the token.
fn account(index: u64) -> Address {
    let mut bytes = [0xaa; 20];
    bytes[12..].copy_from_slice(&index.to_be_bytes());
    Address::from(bytes)
}

/// Times the call `prepare` returns for each iteration, after `prepare` sets up its state.
fn bench(
    c: &mut Criterion,
    name: &str,
    policies: bool,
    mut prepare: impl FnMut(&mut World, u64) -> Call,
) {
    c.bench_function(name, |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            let mut world = World::new(policies);
            for index in 0..iters {
                if index != 0 && index % CHUNK == 0 {
                    world = World::new(policies);
                }
                let call = prepare(&mut world, index);
                // Wall time measures the bench itself; precompiles never read it.
                #[expect(clippy::disallowed_methods)]
                let start = Instant::now();
                let result = world.execute(black_box(&call));
                total += start.elapsed();
                black_box(result).expect("timed call succeeds");
            }
            total
        })
    });
}

fn baselines(c: &mut Criterion) {
    for (name, policies) in [
        ("tip20_transfer", false),
        ("tip20_transfer_with_policies", true),
    ] {
        bench(c, name, policies, |world, _| {
            Call::token(
                world.token,
                OWNER,
                ITIP20::transferCall {
                    to: PAYEE,
                    amount: U256::ONE,
                },
            )
        });
    }
}

fn place(c: &mut Criterion) {
    for (name, policies) in [("hold", false), ("hold_with_policies", true)] {
        bench(c, name, policies, |world, index| {
            let request = world.request(id(index), false);
            Call::reservations(OWNER, IReservationCore::holdCall { request })
        });
    }
    bench(c, "hold_from", false, |world, index| {
        let request = world.request(id(index), false);
        Call::reservations(
            HOLDER,
            IReservationCore::holdFromCall {
                owner: OWNER,
                request,
            },
        )
    });
    bench(c, "pledge_from", false, |world, index| {
        Call::reservations(
            HOLDER,
            IReservationCore::pledgeFromCall {
                owner: OWNER,
                token: world.token,
                id: id(index),
                amount: HOLD,
                expiresAt: NOW + 90 * 24 * 60 * 60,
            },
        )
    });
    bench(c, "lien", false, |world, index| {
        Call::reservations(
            AUTHORITY,
            IReservationCore::lienCall {
                owner: OWNER,
                token: world.token,
                id: id(index),
                amount: HOLD,
                expiresAt: EXPIRY,
            },
        )
    });
    // A hold reads neither the owner's debts nor its other records: only a stand-in places one on
    // an owner that owes, reserving nothing.
    bench(
        c,
        "hold_stand_in_owing_4_creditors",
        false,
        |world, index| {
            let debtor = account(index);
            world.owe(debtor, CREDITORS, 0);
            let request = world.request(id(index), true);
            Call::reservations(debtor, IReservationCore::holdCall { request })
        },
    );
}

fn settle(c: &mut Criterion) {
    for (name, policies) in [
        ("capture_final", false),
        ("capture_final_with_policies", true),
    ] {
        bench(c, name, policies, |world, index| {
            world.hold(id(index));
            Call::reservations(PAYEE, capture(OWNER, id(index), HOLD, true))
        });
    }
    bench(c, "capture_final_holder_hold", false, |world, index| {
        world.hold_from(id(index));
        Call::reservations(PAYEE, capture(HOLDER, id(index), HOLD, true))
    });
    bench(c, "capture_partial", false, |world, index| {
        world.hold(id(index));
        Call::reservations(PAYEE, capture(OWNER, id(index), 400, false))
    });
    bench(c, "release", false, |world, index| {
        world.hold(id(index));
        Call::reservations(
            OWNER,
            IReservationCore::releaseCall {
                owner: OWNER,
                placer: OWNER,
                id: id(index),
            },
        )
    });
    bench(c, "release_expired", false, |world, index| {
        world.set_timestamp(NOW);
        world.hold(id(index));
        world.set_timestamp(EXPIRY + 1);
        Call::reservations(
            PAYEE,
            IReservationCore::releaseExpiredCall {
                owner: OWNER,
                placer: OWNER,
                id: id(index),
            },
        )
    });
    bench(c, "refund", false, |world, _| {
        Call::reservations(
            PAYEE,
            IReservationCore::refundCall {
                owner: OWNER,
                token: world.token,
                placer: OWNER,
                id: id(0),
                amount: 100,
            },
        )
    });
    for (name, policies) in [("charge", false), ("charge_with_policies", true)] {
        bench(c, name, policies, |world, _| {
            Call::reservations(OWNER, charge(world.token, OWNER, PAYEE, 100))
        });
    }
}

/// Operations that loop over an owner's debts, at one creditor and at the most creditors.
fn debts(c: &mut Criterion) {
    for (name, count) in [
        ("charge_into_debt_1_creditor", 1),
        ("charge_into_debt_4_creditors", CREDITORS),
    ] {
        // Adds to the debt of the last creditor, so every entry is read and compared.
        bench(c, name, false, move |world, index| {
            let debtor = account(index);
            world.owe(debtor, count, 0);
            let creditor = CREDITOR_ACCOUNTS[count - 1];
            Call::reservations(debtor, charge(world.token, debtor, creditor, DEBT))
        });
    }
    // The last creditor forgives its debt and pays the rest, which repays the other three.
    bench(c, "refund_owing_4_creditors", false, |world, index| {
        let debtor = account(index);
        world.owe(debtor, CREDITORS, 0);
        Call::reservations(
            CREDITOR_ACCOUNTS[CREDITORS - 1],
            IReservationCore::refundCall {
                owner: debtor,
                token: world.token,
                placer: debtor,
                id: id(index),
                amount: DEBT * CREDITORS as u128,
            },
        )
    });
    // A plain transfer to an owner that owes repays its creditors oldest first.
    for (name, count) in [
        ("tip20_transfer_repaying_1_creditor", 1),
        ("tip20_transfer_repaying_4_creditors", CREDITORS),
    ] {
        bench(c, name, false, move |world, index| {
            let debtor = account(index);
            world.owe(debtor, count, 0);
            Call::token(
                world.token,
                OWNER,
                ITIP20::transferCall {
                    to: debtor,
                    amount: U256::from(DEBT * count as u128),
                },
            )
        });
    }
    for (name, count) in [
        ("clear_lapsed_debt_1_creditor", 1),
        ("clear_lapsed_debt_4_creditors", CREDITORS),
    ] {
        bench(c, name, false, move |world, index| {
            let debtor = account(index);
            world.set_timestamp(NOW);
            world.owe(debtor, count, 1);
            world.set_timestamp(NOW + 2);
            Call::reservations(
                PAYEE,
                IReservationCore::clearLapsedDebtCall {
                    owner: debtor,
                    token: world.token,
                },
            )
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = baselines, place, settle, debts
}
criterion_main!(benches);
