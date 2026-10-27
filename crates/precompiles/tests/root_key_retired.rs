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

/// Opens a channel from a fresh payer, authorizing a separate signer when `signer` is the
/// delegate, and settles a voucher signed by `signer`, with a commitment on `committed`.
/// Returns the signer's address and the settle result.
fn settle(
    spec: TempoHardfork,
    signer: Party,
    committed: Party,
) -> (Address, Result<(), TempoPrecompileError>) {
    let payer_signer = PrivateKeySigner::random();
    let payer = payer_signer.address();
    let delegate_signer = PrivateKeySigner::random();
    let delegate = delegate_signer.address();
    let committed_account = match committed {
        Payer => payer,
        Delegate => delegate,
    };
    let (authorized_signer, voucher_signer) = match signer {
        Payer => (Address::ZERO, payer_signer),
        Delegate => (delegate, delegate_signer),
    };
    let payee = Address::repeat_byte(0x44);
    let mut storage = storage_at(spec, &[committed_account]);
    let result = StorageCtx::enter(&mut storage, || {
        let token = TIP20Setup::path_usd(payer)
            .with_issuer(payer)
            .with_mint(payer, U256::from(200))
            .apply()
            .unwrap();
        let mut reserve = TIP20ChannelReserve::new();
        reserve.initialize().unwrap();
        let salt = B256::repeat_byte(0x55);
        let expiring_nonce_hash = B256::repeat_byte(0x66);
        reserve
            .set_channel_open_context_hash(expiring_nonce_hash)
            .unwrap();
        let channel_id = reserve
            .open(
                payer,
                ITIP20ChannelReserve::openCall {
                    payee,
                    operator: Address::ZERO,
                    token: token.address(),
                    deposit: U96::from(100),
                    salt,
                    authorizedSigner: authorized_signer,
                },
            )
            .unwrap();
        let cumulative_amount = U96::from(40);
        let digest = reserve
            .get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                channelId: channel_id,
                cumulativeAmount: cumulative_amount,
            })
            .unwrap();
        let signature = Bytes::from(voucher_signer.sign_hash_sync(&digest).unwrap().as_bytes());
        reserve.settle(
            payee,
            ITIP20ChannelReserve::settleCall {
                descriptor: ITIP20ChannelReserve::ChannelDescriptor {
                    payer,
                    payee,
                    operator: Address::ZERO,
                    token: token.address(),
                    salt,
                    authorizedSigner: authorized_signer,
                    expiringNonceHash: expiring_nonce_hash,
                },
                cumulativeAmount: cumulative_amount,
                signature,
            },
        )
    });
    (voucher_signer.address(), result)
}

#[test]
fn voucher_by_a_signer_with_a_commitment_is_rejected_from_t14() {
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
            name: "committed delegate",
            spec: T14,
            signer: Delegate,
            committed: Delegate,
            rejected: true,
        },
        // Only the channel's expected signer is checked.
        Case {
            name: "committed payer, delegated",
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
        let (signer, result) = settle(spec, signer, committed);
        if rejected {
            assert_eq!(
                result.expect_err(name),
                TIP20ChannelReserveError::root_key_retired(signer).into(),
                "{name}"
            );
        } else {
            result.expect(name);
        }
    }
}
