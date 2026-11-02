//! Permits and channel vouchers signed by a root key whose account has a configuration commitment.

use alloy::{
    primitives::{Address, B256, Bytes, U256, aliases::U96, keccak256},
    sol,
    sol_types::SolStruct,
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use tempo_chainspec::hardfork::TempoHardfork::{self, T13, T14};
use tempo_contracts::precompiles::{
    ITIP20, ITIP20ChannelReserve, TIP20ChannelReserveError, TIP20Error,
};
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{
        ConfigCommitmentWriteGas, ContractStorage, StorageCtx, hashmap::HashMapStorageProvider,
    },
    test_util::TIP20Setup,
    tip20::PERMIT_TYPEHASH,
    tip20_channel_reserve::TIP20ChannelReserve,
};

use Party::{Delegate, Payer};

const COMMITMENT: B256 = B256::repeat_byte(0x11);

sol! {
    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }
}

/// The payer of a channel, or the separate signer it authorizes to sign vouchers.
#[derive(Clone, Copy)]
enum Party {
    Payer,
    Delegate,
}

/// What submitting a permit did.
struct PermitOutcome {
    owner: Address,
    result: Result<(), TempoPrecompileError>,
    /// The owner's permit nonce afterwards.
    nonce: U256,
}

/// Storage at T14, with a commitment on each of `committed`, running at `spec`.
fn storage_at(spec: TempoHardfork, committed: &[Address]) -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new_with_spec(1, T14);
    StorageCtx::enter(&mut storage, || {
        for account in committed {
            StorageCtx
                .set_config_commitment(*account, COMMITMENT, ConfigCommitmentWriteGas::Intrinsic)
                .unwrap();
        }
    });
    storage.set_spec(spec);
    storage
}

/// Submits a permit signed by a fresh owner, with a commitment on the owner when `committed`.
fn permit(spec: TempoHardfork, committed: bool) -> PermitOutcome {
    let signer = PrivateKeySigner::random();
    let owner = signer.address();
    let spender = Address::repeat_byte(0x22);
    let committed_accounts: &[Address] = if committed { &[owner] } else { &[] };
    let mut storage = storage_at(spec, committed_accounts);
    StorageCtx::enter(&mut storage, || {
        let admin = Address::repeat_byte(0x33);
        let mut token = TIP20Setup::create("Test", "TST", admin).apply().unwrap();
        let (value, nonce, deadline) = (U256::from(1_000), U256::ZERO, U256::MAX);
        let permit = Permit {
            owner,
            spender,
            value,
            nonce,
            deadline,
        };
        assert_eq!(permit.eip712_type_hash(), PERMIT_TYPEHASH);
        let struct_hash = permit.eip712_hash_struct();
        let digest = keccak256(
            [
                &[0x19, 0x01],
                token.domain_separator().unwrap().as_slice(),
                struct_hash.as_slice(),
            ]
            .concat(),
        );
        let signature = signer.sign_hash_sync(&digest).unwrap();
        let result = token.permit(ITIP20::permitCall {
            owner,
            spender,
            value,
            deadline,
            v: signature.v_byte(),
            r: signature.r().into(),
            s: signature.s().into(),
        });
        let nonce = token.nonces(ITIP20::noncesCall { owner }).unwrap();
        PermitOutcome {
            owner,
            result,
            nonce,
        }
    })
}

#[test]
fn permit_by_a_root_with_a_commitment_is_rejected_from_t14() {
    struct Case {
        name: &'static str,
        spec: TempoHardfork,
        committed: bool,
        rejected: bool,
    }
    for Case {
        name,
        spec,
        committed,
        rejected,
    } in [
        Case {
            name: "committed root",
            spec: T14,
            committed: true,
            rejected: true,
        },
        Case {
            name: "uncommitted root",
            spec: T14,
            committed: false,
            rejected: false,
        },
        Case {
            name: "committed root before T14",
            spec: T13,
            committed: true,
            rejected: false,
        },
    ] {
        let PermitOutcome {
            owner,
            result,
            nonce,
        } = permit(spec, committed);
        if rejected {
            assert_eq!(
                result.expect_err(name),
                TIP20Error::root_key_retired(owner).into(),
                "{name}"
            );
            // The rejected permit consumes no nonce.
            assert_eq!(nonce, U256::ZERO, "{name}");
        } else {
            result.expect(name);
            assert_eq!(nonce, U256::ONE, "{name}");
        }
    }
}

/// The payer's key and the separate key it can authorize to sign vouchers.
struct Parties {
    payer: PrivateKeySigner,
    delegate: PrivateKeySigner,
}

impl Parties {
    fn new() -> Self {
        Self {
            payer: PrivateKeySigner::random(),
            delegate: PrivateKeySigner::random(),
        }
    }

    fn key(&self, party: Party) -> &PrivateKeySigner {
        match party {
            Payer => &self.payer,
            Delegate => &self.delegate,
        }
    }

    fn address(&self, party: Party) -> Address {
        self.key(party).address()
    }
}

const PAYEE: Address = Address::repeat_byte(0x44);

/// A funded channel from the payer to `PAYEE`. Its methods run inside a storage context.
struct Channel {
    descriptor: ITIP20ChannelReserve::ChannelDescriptor,
    channel_id: B256,
}

impl Channel {
    /// Funds the payer and opens a 100-unit channel whose vouchers `signer` signs.
    fn open(parties: &Parties, signer: Party) -> Result<Self, TempoPrecompileError> {
        let payer = parties.payer.address();
        let token = TIP20Setup::path_usd(payer)
            .with_issuer(payer)
            .with_mint(payer, U256::from(200))
            .apply()
            .unwrap();
        let authorized_signer = match signer {
            Payer => Address::ZERO,
            Delegate => parties.delegate.address(),
        };
        let salt = B256::repeat_byte(0x55);
        let expiring_nonce_hash = B256::repeat_byte(0x66);
        let mut reserve = TIP20ChannelReserve::new();
        reserve.initialize().unwrap();
        reserve
            .set_channel_open_context_hash(expiring_nonce_hash)
            .unwrap();
        let channel_id = reserve.open(
            payer,
            ITIP20ChannelReserve::openCall {
                payee: PAYEE,
                operator: Address::ZERO,
                token: token.address(),
                deposit: U96::from(100),
                salt,
                authorizedSigner: authorized_signer,
            },
        )?;
        Ok(Self {
            descriptor: ITIP20ChannelReserve::ChannelDescriptor {
                payer,
                payee: PAYEE,
                operator: Address::ZERO,
                token: token.address(),
                salt,
                authorizedSigner: authorized_signer,
                expiringNonceHash: expiring_nonce_hash,
            },
            channel_id,
        })
    }

    fn voucher(&self, key: &PrivateKeySigner, cumulative_amount: U96) -> Bytes {
        let digest = TIP20ChannelReserve::new()
            .get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                channelId: self.channel_id,
                cumulativeAmount: cumulative_amount,
            })
            .unwrap();
        Bytes::from(key.sign_hash_sync(&digest).unwrap().as_bytes())
    }

    fn settle(&self, cumulative_amount: U96, signature: Bytes) -> Result<(), TempoPrecompileError> {
        TIP20ChannelReserve::new().settle(
            PAYEE,
            ITIP20ChannelReserve::settleCall {
                descriptor: self.descriptor.clone(),
                cumulativeAmount: cumulative_amount,
                signature,
            },
        )
    }

    fn top_up(&self, amount: u64) -> Result<(), TempoPrecompileError> {
        TIP20ChannelReserve::new().top_up(
            self.descriptor.payer,
            ITIP20ChannelReserve::topUpCall {
                descriptor: self.descriptor.clone(),
                additionalDeposit: U96::from(amount),
            },
        )
    }

    fn request_close(&self) {
        TIP20ChannelReserve::new()
            .request_close(
                self.descriptor.payer,
                ITIP20ChannelReserve::requestCloseCall {
                    descriptor: self.descriptor.clone(),
                },
            )
            .unwrap();
    }

    fn state(&self) -> ITIP20ChannelReserve::ChannelState {
        TIP20ChannelReserve::new()
            .get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                channelId: self.channel_id,
            })
            .unwrap()
    }
}

/// Gives `account` a configuration commitment, as migration does, then runs at `spec`.
fn migrate(storage: &mut HashMapStorageProvider, account: Address, spec: TempoHardfork) {
    storage.set_spec(T14);
    StorageCtx::enter(storage, || {
        StorageCtx
            .set_config_commitment(account, COMMITMENT, ConfigCommitmentWriteGas::Intrinsic)
            .unwrap();
    });
    storage.set_spec(spec);
}

/// Migrating must not let the payer void a voucher the payee holds and reclaim the deposit.
#[test]
fn voucher_signed_before_its_signer_migrates_stays_redeemable() {
    for (name, signer) in [("payer", Payer), ("separate signer", Delegate)] {
        let parties = Parties::new();
        let mut storage = HashMapStorageProvider::new_with_spec(1, T14);
        let cumulative_amount = U96::from(40);
        let (channel, voucher) = StorageCtx::enter(&mut storage, || {
            let channel = Channel::open(&parties, signer).unwrap();
            let voucher = channel.voucher(parties.key(signer), cumulative_amount);
            (channel, voucher)
        });
        migrate(&mut storage, parties.address(signer), T14);
        StorageCtx::enter(&mut storage, || {
            channel.request_close();
            channel.settle(cumulative_amount, voucher).expect(name);
            assert_eq!(channel.state().settled, cumulative_amount, "{name}");
        });
    }
}

#[test]
fn open_with_a_retired_voucher_signer_is_rejected_from_t14() {
    struct Case {
        name: &'static str,
        spec: TempoHardfork,
        signer: Party,
        committed: Party,
        rejected: bool,
    }
    for Case {
        name,
        spec,
        signer,
        committed,
        rejected,
    } in [
        Case {
            name: "committed payer",
            spec: T14,
            signer: Payer,
            committed: Payer,
            rejected: true,
        },
        Case {
            name: "committed separate signer",
            spec: T14,
            signer: Delegate,
            committed: Delegate,
            rejected: true,
        },
        // A configurable payer opens channels through an active separate signer.
        Case {
            name: "committed payer, separate signer",
            spec: T14,
            signer: Delegate,
            committed: Payer,
            rejected: false,
        },
        Case {
            name: "committed payer before T14",
            spec: T13,
            signer: Payer,
            committed: Payer,
            rejected: false,
        },
    ] {
        let parties = Parties::new();
        let mut storage = storage_at(spec, &[parties.address(committed)]);
        let result =
            StorageCtx::enter(&mut storage, || Channel::open(&parties, signer).map(|_| ()));
        if rejected {
            assert_eq!(
                result.expect_err(name),
                TIP20ChannelReserveError::root_key_retired(parties.address(signer)).into(),
                "{name}"
            );
        } else {
            result.expect(name);
        }
    }
}

/// A retired signer keeps authority over its channel's deposit, so the deposit cannot grow.
#[test]
fn top_up_with_a_retired_voucher_signer_is_rejected_from_t14() {
    for (name, signer, committed, rejected) in [
        ("committed payer", Payer, Payer, true),
        ("committed separate signer", Delegate, Delegate, true),
        ("committed payer, separate signer", Delegate, Payer, false),
    ] {
        let parties = Parties::new();
        let mut storage = HashMapStorageProvider::new_with_spec(1, T14);
        let channel = StorageCtx::enter(&mut storage, || {
            let channel = Channel::open(&parties, signer).unwrap();
            channel.request_close();
            channel
        });
        migrate(&mut storage, parties.address(committed), T14);
        StorageCtx::enter(&mut storage, || {
            if rejected {
                assert_eq!(
                    channel.top_up(50).expect_err(name),
                    TIP20ChannelReserveError::root_key_retired(parties.address(signer)).into(),
                    "{name}"
                );
                // A zero top-up adds no deposit, so it still cancels the close request.
                channel.top_up(0).expect(name);
            } else {
                channel.top_up(50).expect(name);
            }
            let state = channel.state();
            assert_eq!(state.closeRequestedAt, 0, "{name}");
            assert_eq!(
                state.deposit,
                U96::from(if rejected { 100 } else { 150 }),
                "{name}"
            );
        });
    }
}
