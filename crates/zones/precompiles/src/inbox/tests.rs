use super::*;

use alloy_primitives::{B256, Bytes, U256, address, keccak256};
use alloy_sol_types::{SolCall, SolError, SolInterface, SolValue};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::{
    precompiles::UnknownFunctionSelector,
    zones::{MAX_UNPROCESSED_DEPOSITS, MAX_UNPROCESSED_TOKEN_ENABLEMENTS},
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS, TIP403_REGISTRY_ADDRESS,
    storage::{ContractStorage, Handler, StorageCtx},
    test_util::{TIP20Setup, TIP403Setup},
    tip20::{self, ITIP20, TIP20Token},
    tip403_registry::{ALLOW_ALL_POLICY_ID, ITIP403Registry, REJECT_ALL_POLICY_ID, TIP403Registry},
    zone_factory::portal::{self, ZonePortalStorage},
};
use zone_primitives::constants::ZONE_OUTBOX_ADDRESS;

use crate::test_utils::{
    EncryptedDepositFixture, MockL1Reader, ZoneEnv, ZoneSpec, build_plaintext, call_precompile,
    compressed_x_and_parity, encrypt_plaintext,
};

const PORTAL: Address = Address::repeat_byte(0x42);
const SEQUENCER: Address = Address::with_last_byte(0xa1);
const ALICE: Address = Address::with_last_byte(0xa2);
const BOB: Address = Address::with_last_byte(0xb0);
/// Decryption data whose shared secret is not a curve point, so its proof never verifies.
const INVALID_DECRYPTION: DecryptionData = DecryptionData {
    sharedSecret: B256::ZERO,
    sharedSecretYParity: 2,
    cpProof: tempo_contracts::zones::ChaumPedersenProof {
        s: B256::ZERO,
        c: B256::ZERO,
    },
};

fn spec() -> ZoneSpec {
    ZoneSpec {
        portal: PORTAL,
        sequencer: SEQUENCER,
        tokens: vec![path_usd()],
        ..Default::default()
    }
}

fn path_usd() -> TIP20Setup {
    TIP20Setup::path_usd(ALICE)
        .with_issuer(ALICE)
        .with_issuer(ZONE_INBOX_ADDRESS)
        .with_issuer(ZONE_OUTBOX_ADDRESS)
}

/// `advanceTempo` calldata without deposits, decryptions or token enablements.
fn empty_advance(env: &ZoneEnv) -> Vec<u8> {
    IZoneInbox::advanceTempoCall {
        header: alloy_rlp::encode(&env.child_header).into(),
        deposits: Vec::new(),
        decryptions: Vec::new(),
        enabledTokens: Vec::new(),
    }
    .abi_encode()
}

fn assert_single_bounce_back(env: &mut ZoneEnv, amount: u128, recipient: Address) {
    let pending = env.pending_withdrawals();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].token, PATH_USD_ADDRESS);
    assert_eq!(pending[0].amount, amount);
    assert_eq!(pending[0].to, recipient);
}

fn maximum_metadata_token(index: u16) -> EnabledToken {
    let mut token = [0u8; 20];
    token[0] = 0x20;
    token[1] = 0xc0;
    token[18..].copy_from_slice(&index.to_be_bytes());
    EnabledToken {
        token: Address::from(token),
        name: "n".repeat(31),
        symbol: "s".repeat(31),
        currency: "c".repeat(31),
    }
}

fn failed_deposit_gas(deposits: usize, token_enablements: usize) -> eyre::Result<u64> {
    failed_deposit_gas_at(TempoHardfork::T13, deposits, token_enablements)
}

/// Gas for one `advanceTempo` of `deposits` failed mints and `token_enablements` initializations
/// under `hardfork`'s rules and gas schedule.
fn failed_deposit_gas_at(
    hardfork: TempoHardfork,
    deposits: usize,
    token_enablements: usize,
) -> eyre::Result<u64> {
    let mut env = ZoneSpec { hardfork, ..spec() }.apply()?;
    let enabled_tokens = (1..=token_enablements)
        .map(|index| maximum_metadata_token(index as u16))
        .collect::<Vec<_>>();
    for enabled in &enabled_tokens {
        env.queue_token_enablement(enabled);
    }
    env.with_storage(|| -> eyre::Result<()> {
        TIP20Token::from_address(PATH_USD_ADDRESS)?.change_transfer_policy_id(
            ALICE,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: REJECT_ALL_POLICY_ID,
            },
        )?;
        let anchored_policy = U256::from(7) | (U256::ONE << 64);
        for enabled in &enabled_tokens {
            let binding_slot =
                TIP403Registry::new().token_transfer_policies[enabled.token].base_slot();
            StorageCtx.sstore(TIP403_REGISTRY_ADDRESS, binding_slot, anchored_policy)?;
        }
        Ok(())
    })?;

    let fixture = EncryptedDepositFixture::new();
    seed_encryption_key(&env, &fixture);
    let (deposit, decryption) = encrypted_deposit(&fixture, BOB, 1);
    let queued_deposits = (0..deposits)
        .map(|_| env.queue_deposit(DepositType::Deposit, deposit.clone()))
        .collect();

    let output = env.advance_tempo(queued_deposits, vec![decryption; deposits], enabled_tokens)?;
    assert!(output.is_success(), "deposit block failed: {output:?}");
    Ok(output.gas_used)
}

/// Seeds the fixture's sequencer key on the portal at the child block and returns its `x` slot.
fn seed_encryption_key(env: &ZoneEnv, fixture: &EncryptedDepositFixture) -> U256 {
    let (sequencer_x, sequencer_y_parity) = compressed_x_and_parity(&fixture.seq_pub);
    let base: U256 = keccak256(B256::from(portal::slots::ENCRYPTION_KEYS)).into();
    let slot_x = base + fixture.key_index * U256::from(2);
    let block = env.child_header.inner.number;
    env.l1.insert(PORTAL, slot_x, block, sequencer_x.into());
    env.l1.insert(
        PORTAL,
        slot_x + U256::ONE,
        block,
        U256::from(sequencer_y_parity),
    );
    slot_x
}

/// A pathUSD deposit of `amount` from ALICE to `to`, encrypted to the fixture's sequencer key,
/// with the decryption data that proves it.
fn encrypted_deposit(
    fixture: &EncryptedDepositFixture,
    to: Address,
    amount: u128,
) -> (Deposit, DecryptionData) {
    let decrypted = fixture.decrypt().expect("fixture decrypts");
    let info = crate::ecies::hkdf_info(
        &PORTAL,
        &fixture.key_index,
        &fixture.eph_pub_x,
        &ALICE,
        None,
    );
    let key = crate::ecies::hkdf_sha256(&decrypted.proof.shared_secret.0, b"ecies-aes-key", &info);
    let plaintext = build_plaintext(&to, &fixture.memo);
    let (ciphertext, nonce, tag) = encrypt_plaintext(&key, &plaintext);
    let deposit = Deposit {
        token: PATH_USD_ADDRESS,
        sender: ALICE,
        amount,
        tempoRefundRecipient: ALICE,
        keyIndex: fixture.key_index,
        encrypted: tempo_contracts::zones::DepositPayload {
            ephemeralPubkeyX: fixture.eph_pub_x,
            ephemeralPubkeyYParity: fixture.eph_pub_y_parity,
            ciphertext: ciphertext.into(),
            nonce: nonce.into(),
            tag: tag.into(),
        },
    };
    let decryption = DecryptionData {
        sharedSecret: decrypted.proof.shared_secret,
        sharedSecretYParity: decrypted.proof.shared_secret_y_parity,
        cpProof: decrypted.proof.cp_proof,
    };
    (deposit, decryption)
}

#[test]
fn max_portal_deposit_block_fits_system_gas_budget() -> eyre::Result<()> {
    const BUFFERED_GAS_LIMIT: u64 = 200_000_000;

    for deposits in [640, MAX_UNPROCESSED_DEPOSITS] {
        let should_fit = deposits <= MAX_UNPROCESSED_DEPOSITS;
        let gas_used = failed_deposit_gas(deposits, 0)?;
        eprintln!("{deposits} portal deposit block: {gas_used} gas");
        assert_eq!(
            gas_used <= BUFFERED_GAS_LIMIT,
            should_fit,
            "{deposits} deposit block used {gas_used} gas"
        );
    }
    Ok(())
}

#[test]
fn max_portal_deposit_and_token_block_fits_system_gas_budget() -> eyre::Result<()> {
    const COMBINED_BUFFERED_GAS_LIMIT: u64 = 225_000_000;

    let gas_used = failed_deposit_gas(MAX_UNPROCESSED_DEPOSITS, MAX_UNPROCESSED_TOKEN_ENABLEMENTS)?;
    eprintln!("max portal deposit and token block: {gas_used} gas");
    assert!(
        gas_used <= COMBINED_BUFFERED_GAS_LIMIT,
        "max portal deposit and token block used {gas_used} gas"
    );
    Ok(())
}

#[test]
fn system_advance_selects_child_anchor_and_reads_queue() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    env.advance_tempo(Vec::new(), Vec::new(), Vec::new())?;

    assert_eq!(env.l1_state.get_anchor(), Some(1));
    assert!(env.l1.requested(
        1,
        &ZonePortalStorage::new(PORTAL).current_deposit_queue_hash,
    ));
    Ok(())
}

#[test]
fn non_system_advance_reverts_before_selecting_or_reading_l1() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let output = env.call(SEQUENCER, ZONE_INBOX_ADDRESS, empty_advance(&env))?;

    assert!(output.is_revert());
    assert_eq!(output.bytes, IZoneInbox::OnlySequencer {}.abi_encode());
    assert_eq!(env.l1_state.get_anchor(), None);
    assert!(env.l1.storage_requests().is_empty());
    Ok(())
}

#[test]
fn advance_tempo_headers_activates_at_t13() -> eyre::Result<()> {
    for hardfork in [TempoHardfork::T12, TempoHardfork::T13] {
        let mut env = ZoneSpec { hardfork, ..spec() }.apply()?;
        let calldata = IZoneInbox::advanceTempoHeadersCall {
            headers: vec![alloy_rlp::encode(&env.child_header).into()],
        }
        .abi_encode();
        let output = env.call(Address::ZERO, ZONE_INBOX_ADDRESS, calldata)?;
        if hardfork == TempoHardfork::T12 {
            assert!(output.is_revert());
            let error = UnknownFunctionSelector::abi_decode(&output.bytes)?;
            assert_eq!(
                error.selector.as_slice(),
                &IZoneInbox::advanceTempoHeadersCall::SELECTOR
            );
        } else {
            assert!(output.is_success());
        }
        assert!(env.l1.storage_requests().is_empty());
    }
    Ok(())
}

#[test]
fn processed_enabled_token_count_activates_at_t13() -> eyre::Result<()> {
    let mut env = ZoneSpec {
        hardfork: TempoHardfork::T12,
        ..spec()
    }
    .apply()?;
    let calldata = IZoneInbox::processedEnabledTokenCountCall {}.abi_encode();

    let pre_t13 = env.call(ALICE, ZONE_INBOX_ADDRESS, &calldata)?;
    assert!(pre_t13.is_revert());
    let error = UnknownFunctionSelector::abi_decode(&pre_t13.bytes)?;
    assert_eq!(
        error.selector.as_slice(),
        &IZoneInbox::processedEnabledTokenCountCall::SELECTOR
    );

    let post_t13 = spec()
        .apply()?
        .static_call(ALICE, ZONE_INBOX_ADDRESS, &calldata)?;
    assert!(post_t13.is_success());
    assert_eq!(
        IZoneInbox::processedEnabledTokenCountCall::abi_decode_returns(&post_t13.bytes)?,
        0
    );
    Ok(())
}

#[test]
fn static_advance_and_delegate_call_revert_before_l1_reads() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let calldata = empty_advance(&env);
    let output = env.static_call(Address::ZERO, ZONE_INBOX_ADDRESS, &calldata)?;
    assert!(output.is_revert());
    assert!(output.bytes.is_empty());
    assert!(env.l1.storage_requests().is_empty());

    let output = call_precompile(
        &mut env.ctx,
        &mut env.precompiles,
        Address::ZERO,
        &calldata,
        u64::MAX,
        false,
        Address::repeat_byte(0x44),
        ZONE_INBOX_ADDRESS,
    )?;
    assert!(output.is_revert());
    assert_eq!(
        output.bytes,
        tempo_precompiles::DelegateCallNotAllowed {}.abi_encode()
    );
    assert!(env.l1.storage_requests().is_empty());
    Ok(())
}

#[test]
fn advance_rejects_a_preselected_anchor_before_child_selection() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    env.l1_state
        .read_l1_storage_unmetered(Address::ZERO, B256::ZERO, 0)?;
    let request_count = env.l1.storage_requests().len();

    let result = env.advance_tempo(Vec::new(), Vec::new(), Vec::new());

    assert!(result.is_err());
    assert_eq!(env.l1.storage_requests().len(), request_count);
    Ok(())
}

#[test]
fn child_anchor_storage_failure_is_fatal_and_rolls_back_checkpoint() -> eyre::Result<()> {
    let mut env = ZoneSpec {
        l1: MockL1Reader::failing_storage(),
        ..spec()
    }
    .apply()?;
    let result = env.advance_tempo(Vec::new(), Vec::new(), Vec::new());
    assert!(result.is_err(), "L1 storage failure must remain fatal");

    env.with_storage(|| -> eyre::Result<()> {
        assert_eq!(TempoState::new().tempo_block_number()?, 0);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn queue_head_mismatch_reverts_and_rolls_back() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let nonce = 1u64;
    env.with_storage(|| ZoneOutbox::new().seed_fallback_recipient(nonce, BOB))?;
    let first = WithdrawalBounceBackDeposit {
        token: PATH_USD_ADDRESS,
        to: Address::left_padding_from(&nonce.to_be_bytes()),
        amount: 100,
    };
    let queued = env.queue_deposit(DepositType::WithdrawalBounceBack, first.clone());
    let second = WithdrawalBounceBackDeposit {
        amount: 200,
        ..first
    };
    env.queue_deposit(DepositType::WithdrawalBounceBack, second);

    let output = env.advance_tempo(vec![queued], Vec::new(), Vec::new())?;
    assert!(output.is_revert());
    assert_eq!(
        output.bytes,
        IZoneInbox::InvalidDepositQueueHash {}.abi_encode()
    );

    assert_eq!(env.balance(PATH_USD_ADDRESS, BOB), U256::ZERO);
    env.with_storage(|| -> eyre::Result<()> {
        assert_eq!(TempoState::new().tempo_block_number()?, 0);
        assert_eq!(
            ZoneInbox::new().processed_deposit_queue_hash.read()?,
            B256::ZERO
        );
        assert_eq!(ZoneInbox::new().processed_deposit_number.read()?, 0);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn enabled_token_is_initialized_before_deposit_processing() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let token = address!("0x20c00000000000000000000000000000000000aa");
    let anchored_policy = U256::from(7) | (U256::ONE << 64);
    let binding_slot = TIP403Registry::new().token_transfer_policies[token].base_slot();
    env.with_storage(|| StorageCtx.sstore(TIP403_REGISTRY_ADDRESS, binding_slot, anchored_policy))?;
    let enabled = EnabledToken {
        token,
        name: "Example Dollar".into(),
        symbol: "EXD".into(),
        currency: "USD".into(),
    };
    env.queue_token_enablement(&enabled);

    env.advance_tempo(Vec::new(), Vec::new(), vec![enabled])?;

    env.with_storage(|| -> eyre::Result<()> {
        let token = TIP20Token::from_address(token)?;
        assert!(token.is_initialized()?);
        assert_eq!(token.name()?, "Example Dollar");
        assert_eq!(token.next_quote_token()?, PATH_USD_ADDRESS);
        assert!(token.has_role_internal(ZONE_INBOX_ADDRESS, ISSUER_ROLE)?);
        assert!(token.has_role_internal(ZONE_OUTBOX_ADDRESS, ISSUER_ROLE)?);
        assert_eq!(
            StorageCtx.sload(TIP403_REGISTRY_ADDRESS, binding_slot)?,
            anchored_policy
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn omitted_token_enablement_reverts() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    env.queue_token_enablement(&EnabledToken {
        token: address!("0x20c00000000000000000000000000000000000ab"),
        name: "Example Dollar".into(),
        symbol: "EXD".into(),
        currency: "USD".into(),
    });

    let output = env.advance_tempo(Vec::new(), Vec::new(), Vec::new())?;
    assert_eq!(
        output.bytes,
        IZoneInbox::InvalidTokenEnablementHash {}.abi_encode()
    );
    Ok(())
}

#[test]
fn malformed_nested_deposit_reverts_before_l1_reads() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let output = env.advance_tempo(
        vec![QueuedDeposit {
            depositType: DepositType::WithdrawalBounceBack,
            rejected: false,
            depositData: Bytes::from_static(b"malformed"),
        }],
        Vec::new(),
        Vec::new(),
    )?;

    assert!(output.is_revert());
    assert!(output.bytes.is_empty());
    assert!(env.l1.storage_requests().is_empty());
    Ok(())
}

#[test]
fn non_canonical_deposits_are_rejected() {
    let deposit = Deposit {
        token: Address::ZERO,
        sender: Address::ZERO,
        amount: 0,
        tempoRefundRecipient: Address::ZERO,
        keyIndex: U256::ZERO,
        encrypted: tempo_contracts::zones::DepositPayload {
            ephemeralPubkeyX: B256::ZERO,
            ephemeralPubkeyYParity: 0,
            ciphertext: Bytes::new(),
            nonce: [0; 12].into(),
            tag: [0; 16].into(),
        },
    };
    let bounce_back = WithdrawalBounceBackDeposit {
        token: Address::ZERO,
        to: Address::ZERO,
        amount: 0,
    };
    for (deposit_type, canonical) in [
        (DepositType::Deposit, deposit.abi_encode()),
        (DepositType::WithdrawalBounceBack, bounce_back.abi_encode()),
    ] {
        let mut non_canonical = canonical.clone();
        non_canonical.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        assert!(
            decode_deposits(vec![QueuedDeposit {
                depositType: deposit_type,
                rejected: false,
                depositData: canonical.into(),
            }])
            .is_ok()
        );
        assert!(
            decode_deposits(vec![QueuedDeposit {
                depositType: deposit_type,
                rejected: false,
                depositData: non_canonical.into(),
            }])
            .is_err()
        );
    }
}

#[test]
fn deposit_uses_child_anchor_key_and_mints_plaintext_recipient() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let fixture = EncryptedDepositFixture::new();
    let slot_x = seed_encryption_key(&env, &fixture);
    let (deposit, decryption) = encrypted_deposit(&fixture, fixture.to, 900);
    let queued = env.queue_deposit(DepositType::Deposit, deposit);

    env.advance_tempo(vec![queued], vec![decryption], Vec::new())?;

    assert_eq!(env.balance(PATH_USD_ADDRESS, fixture.to), U256::from(900));
    assert!(env.pending_withdrawals().is_empty());
    assert!(
        env.l1
            .storage_requests()
            .contains(&(PORTAL, B256::from(slot_x), 1))
    );
    Ok(())
}

#[test]
fn receive_policy_blocked_deposit_enqueues_bounce_back() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let fixture = EncryptedDepositFixture::new();
    seed_encryption_key(&env, &fixture);
    let (deposit, decryption) = encrypted_deposit(&fixture, fixture.to, 500);
    env.with_storage(|| {
        TIP403Registry::new().set_receive_policy(
            fixture.to,
            ITIP403Registry::setReceivePolicyCall {
                senderPolicyId: REJECT_ALL_POLICY_ID,
                tokenFilterId: ALLOW_ALL_POLICY_ID,
                recoveryAuthority: Address::ZERO,
            },
        )
    })?;
    let queued = env.queue_deposit(DepositType::Deposit, deposit);

    env.advance_tempo(vec![queued], vec![decryption], Vec::new())?;

    assert_eq!(env.balance(PATH_USD_ADDRESS, fixture.to), U256::ZERO);
    assert_eq!(
        env.balance(PATH_USD_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS),
        U256::ZERO
    );
    assert_single_bounce_back(&mut env, 500, ALICE);
    Ok(())
}

#[test]
fn invalid_encrypted_proof_bounces_without_mint() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let fixture = EncryptedDepositFixture::new();
    seed_encryption_key(&env, &fixture);
    let deposit = Deposit {
        tempoRefundRecipient: BOB,
        ..encrypted_deposit(&fixture, fixture.to, 333).0
    };
    let queued = env.queue_deposit(DepositType::Deposit, deposit);

    env.advance_tempo(vec![queued], vec![INVALID_DECRYPTION], Vec::new())?;

    assert_eq!(env.balance(PATH_USD_ADDRESS, fixture.to), U256::ZERO);
    assert_single_bounce_back(&mut env, 333, BOB);
    Ok(())
}

#[test]
fn missing_and_extra_decryption_data_revert() -> eyre::Result<()> {
    let fixture = EncryptedDepositFixture::new();
    let (deposit, _) = encrypted_deposit(&fixture, BOB, 1);
    let mut missing = spec().apply()?;
    let queued = missing.queue_deposit(DepositType::Deposit, deposit);
    let output = missing.advance_tempo(vec![queued], Vec::new(), Vec::new())?;
    assert!(output.is_revert());
    assert_eq!(
        output.bytes,
        IZoneInbox::MissingDecryptionData {}.abi_encode()
    );

    let mut extra = spec().apply()?;
    let output = extra.advance_tempo(Vec::new(), vec![INVALID_DECRYPTION], Vec::new())?;
    assert!(output.is_revert());
    assert_eq!(
        output.bytes,
        IZoneInbox::ExtraDecryptionData {}.abi_encode()
    );
    Ok(())
}

#[test]
fn refund_is_readable_by_owner_and_sequencer_and_claimable_once() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    env.with_storage(|| {
        ZoneInbox::new().withdrawal_bounce_backs[PATH_USD_ADDRESS][BOB].write(444)
    })?;

    let calldata = IZoneInbox::refundsCall {
        token: PATH_USD_ADDRESS,
        owner: BOB,
    }
    .abi_encode();
    for reader in [BOB, SEQUENCER] {
        let output = env.call(reader, ZONE_INBOX_ADDRESS, &calldata)?;
        assert_eq!(
            IZoneInbox::refundsCall::abi_decode_returns(&output.bytes)?,
            444
        );
    }
    let outsider_output = env.call(ALICE, ZONE_INBOX_ADDRESS, &calldata)?;
    assert!(outsider_output.is_revert());
    assert_eq!(
        outsider_output.bytes,
        IZoneInbox::Unauthorized {}.abi_encode()
    );

    let calldata = IZoneInbox::claimRefundCall {
        token: PATH_USD_ADDRESS,
    }
    .abi_encode();

    let output = env.call(BOB, ZONE_INBOX_ADDRESS, &calldata)?;
    assert_eq!(
        IZoneInbox::claimRefundCall::abi_decode_returns(&output.bytes)?,
        444
    );
    assert_eq!(env.balance(PATH_USD_ADDRESS, BOB), U256::from(444));
    let repeated = env.call(BOB, ZONE_INBOX_ADDRESS, calldata)?;
    assert!(repeated.is_revert());
    assert_eq!(repeated.bytes, IZoneInbox::NoRefund {}.abi_encode());
    assert_eq!(
        env.with_storage(
            || ZoneInbox::new().withdrawal_bounce_backs[PATH_USD_ADDRESS][BOB].read()
        )?,
        0
    );
    Ok(())
}

#[test]
fn claim_refund_zero_amount_is_gated_by_t13() -> eyre::Result<()> {
    for (hardfork, expected) in [
        (TempoHardfork::T12, 0u128.abi_encode()),
        (TempoHardfork::T13, IZoneInbox::NoRefund {}.abi_encode()),
    ] {
        let output = ZoneSpec { hardfork, ..spec() }.apply()?.call(
            BOB,
            ZONE_INBOX_ADDRESS,
            IZoneInbox::claimRefundCall {
                token: PATH_USD_ADDRESS,
            }
            .abi_encode(),
        )?;
        assert_eq!(output.is_revert(), hardfork.is_t13());
        assert_eq!(output.bytes, expected);
    }
    Ok(())
}

#[test]
fn claim_refund_reverts_with_the_mint_error_from_t15() -> eyre::Result<()> {
    for (hardfork, expected) in [
        (TempoHardfork::T14, TIP20Error::policy_forbids()),
        (TempoHardfork::T15, TIP20Error::contract_paused()),
    ] {
        let mut env = ZoneSpec { hardfork, ..spec() }.apply()?;
        env.with_storage(|| {
            ZoneInbox::new().withdrawal_bounce_backs[PATH_USD_ADDRESS][BOB].write(444)?;
            StorageCtx.sstore(PATH_USD_ADDRESS, tip20::slots::PAUSED, U256::ONE)
        })?;

        let output = env.call(
            BOB,
            ZONE_INBOX_ADDRESS,
            IZoneInbox::claimRefundCall {
                token: PATH_USD_ADDRESS,
            }
            .abi_encode(),
        )?;
        assert!(output.is_revert(), "{hardfork:?}");
        assert_eq!(output.bytes, expected.abi_encode(), "{hardfork:?}");
        assert_eq!(env.balance(PATH_USD_ADDRESS, BOB), U256::ZERO);
    }
    Ok(())
}

#[test]
fn failed_withdrawal_bounce_back_parks_refund() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let nonce = 8u64;
    env.with_storage(|| ZoneOutbox::new().seed_fallback_recipient(nonce, BOB))?;
    let token = address!("0x20c00000000000000000000000000000000000cc");
    let deposit = WithdrawalBounceBackDeposit {
        token,
        to: Address::left_padding_from(&nonce.to_be_bytes()),
        amount: 555,
    };
    let queued = env.queue_deposit(DepositType::WithdrawalBounceBack, deposit);

    env.advance_tempo(vec![queued], Vec::new(), Vec::new())?;

    assert_eq!(
        env.with_storage(|| ZoneInbox::new().withdrawal_bounce_backs[token][BOB].read())?,
        555
    );
    assert!(env.pending_withdrawals().is_empty());
    Ok(())
}

#[test]
fn withdrawal_bounce_back_consumes_fallback_nonce() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let nonce = 7u64;
    env.with_storage(|| ZoneOutbox::new().seed_fallback_recipient(nonce, BOB))?;
    let deposit = WithdrawalBounceBackDeposit {
        token: PATH_USD_ADDRESS,
        to: Address::left_padding_from(&nonce.to_be_bytes()),
        amount: 321,
    };
    let queued = env.queue_deposit(DepositType::WithdrawalBounceBack, deposit);

    env.advance_tempo(vec![queued], Vec::new(), Vec::new())?;

    assert_eq!(env.balance(PATH_USD_ADDRESS, BOB), U256::from(321));
    assert!(env.pending_withdrawals().is_empty());
    assert_eq!(
        env.with_storage(|| ZoneOutbox::new().fallback_recipient(nonce))?,
        Address::ZERO
    );
    Ok(())
}

#[test]
fn bridged_credits_use_recipient_policy_from_t13() -> eyre::Result<()> {
    for (hardfork, recipient_allowed, authorized) in [
        (TempoHardfork::T12, true, false),
        (TempoHardfork::T12, false, true),
        (TempoHardfork::T13, true, true),
        (TempoHardfork::T13, false, false),
    ] {
        let (recipient, mint_recipient) = if recipient_allowed {
            (ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID)
        } else {
            (REJECT_ALL_POLICY_ID, ALLOW_ALL_POLICY_ID)
        };
        let mut env = ZoneSpec {
            hardfork,
            tokens: vec![path_usd().with_transfer_policy(TIP403Setup::compound(
                REJECT_ALL_POLICY_ID,
                recipient,
                mint_recipient,
            ))],
            ..spec()
        }
        .apply()?;
        env.with_storage(|| -> eyre::Result<()> {
            let token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            let credited = U256::from(if authorized { 100 } else { 0 });
            let balance = |account| token.balance_of(ITIP20::balanceOfCall { account });
            let mut inbox = ZoneInbox::new();
            assert_eq!(inbox.try_mint(PATH_USD_ADDRESS, ALICE, 100)?, authorized);
            assert_eq!(balance(ALICE)?, credited);

            let mut outbox = ZoneOutbox::new();
            outbox.seed_fallback_recipient(7, BOB)?;
            inbox.process_withdrawal_bounce_back(
                &mut outbox,
                WithdrawalBounceBackDeposit {
                    token: PATH_USD_ADDRESS,
                    to: Address::left_padding_from(&7u64.to_be_bytes()),
                    amount: 100,
                },
            )?;
            assert_eq!(outbox.fallback_recipient(7)?, Address::ZERO);
            assert_eq!(balance(BOB)?, credited);
            assert_eq!(
                inbox.withdrawal_bounce_backs[PATH_USD_ADDRESS][BOB].read()?,
                if authorized { 0 } else { 100 }
            );

            inbox.withdrawal_bounce_backs[PATH_USD_ADDRESS][BOB].write(100)?;
            if authorized {
                assert_eq!(inbox.claim_refund(BOB, PATH_USD_ADDRESS)?, 100);
            } else {
                assert!(inbox.claim_refund(BOB, PATH_USD_ADDRESS).is_err());
            }
            assert_eq!(balance(BOB)?, credited + credited);
            assert_eq!(
                inbox.withdrawal_bounce_backs[PATH_USD_ADDRESS][BOB].read()?,
                if authorized { 0 } else { 100 }
            );
            assert_eq!(balance(RECEIVE_POLICY_GUARD_ADDRESS)?, U256::ZERO);
            Ok(())
        })?;
        assert!(env.pending_withdrawals().is_empty());
    }
    Ok(())
}

#[test]
fn forced_exit_rejects_malformed_outer_encoding() {
    let queued = QueuedDeposit {
        depositType: DepositType::ForcedExit,
        rejected: false,
        depositData: alloy_primitives::Bytes::new(),
    };
    assert!(matches!(
        DecodedQueuedDeposit::try_from(queued),
        Err(ZonePrecompileError::MalformedCalldata)
    ));
}

#[path = "forced_tests.rs"]
mod forced_tests;
