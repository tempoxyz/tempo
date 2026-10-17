use super::*;
use crate::{
    ecies,
    forced_exit_storage::ForcedExitPortalStorage,
    inbox::forced::{ForcedExitResult, OBSERVED},
};
use exithatch::{
    ForcedExitAuthorization, ForcedExitReason as Reason, MAX_SIGNATURE_SIZE, test_utils::*,
};
use proptest::{prelude::*, sample::Index};
use revm::{context_interface::JournalTr, precompile::PrecompileOutput};

const ROOT: Address = address!("7e5f4552091a69125d5dfcb7b8c2659029395bdf");
const PARENT_CHAIN: u64 = 42431;
const ZONE_KEY: [u8; 32] = [0x33; 32];

type Entry = (QueuedDeposit, Option<DecryptionData>);

fn zone_chain_id() -> u64 {
    zone_primitives::constants::zone_chain_id(PARENT_CHAIN, 1).unwrap()
}

/// Rebuild both precompiles with a fresh L1 anchor, as a new zone block would.
fn reload(h: &mut Harness) {
    h.l1_state = L1State::new(h.l1.clone(), PORTAL);
    let env = test_env(&h.ctx);
    h.precompile = ZoneInbox::create(h.l1_state.clone(), &env);
    h.outbox_precompile = crate::create_outbox_precompile(h.l1_state.clone(), &env);
}

fn set_spec(h: &mut Harness, spec: TempoHardfork) {
    h.ctx.cfg.spec = spec;
    reload(h);
}

fn activate(h: &Harness, block: u64, version: u64) -> eyre::Result<()> {
    h.l1.with_storage(block, || {
        ForcedExitPortalStorage::new(PORTAL)
            .forced_exit_version
            .write(version)
    })?;
    Ok(())
}

fn active_harness() -> eyre::Result<Harness> {
    let mut h = Harness::new()?;
    h.ctx.cfg.chain_id = zone_chain_id();
    set_spec(&mut h, TempoHardfork::T14);
    activate(&h, 1, 1)?;
    Ok(h)
}

fn with_zone<T>(h: &mut Harness, f: impl FnOnce() -> eyre::Result<T>) -> eyre::Result<T> {
    let mut storage = test_storage_provider(&mut h.ctx, u64::MAX, false);
    StorageCtx::enter(&mut storage, f)
}

/// The Tempo block the next transition imports; every L1 read is anchored there.
fn anchor(h: &mut Harness) -> eyre::Result<u64> {
    with_zone(h, || Ok(TempoState::new().tempo_block_number()? + 1))
}

fn auth(nonce: u64) -> ForcedExitAuthorization {
    ForcedExitAuthorization {
        account: ROOT,
        zoneChainId: U256::from(zone_chain_id()),
        token: PATH_USD_ADDRESS,
        recipient: BOB,
        nonce: U256::from(nonce),
        admitBefore: 1,
    }
}

fn digest(auth: &ForcedExitAuthorization) -> B256 {
    exithatch::authorization_digest(auth, U256::from(PARENT_CHAIN), PORTAL)
}

fn root_signature(auth: &ForcedExitAuthorization) -> Vec<u8> {
    sign_k256(&k256_key(1), digest(auth))
}

fn payload(auth: &ForcedExitAuthorization) -> Vec<u8> {
    signed_payload(&k256_key(1), auth, PARENT_CHAIN, PORTAL)
}

fn zone_key() -> (k256::SecretKey, B256, u8) {
    let secret = k256::SecretKey::from_slice(&ZONE_KEY).unwrap();
    let (x, parity) = ecies::compressed_x_and_parity(secret.public_key().as_affine());
    (secret, x, parity)
}

fn decryption_for(encrypted: &tempo_contracts::zones::DepositPayload) -> DecryptionData {
    let proof = ecies::compute_ecdh_proof(
        &zone_key().0,
        &encrypted.ephemeralPubkeyX,
        encrypted.ephemeralPubkeyYParity,
    )
    .unwrap();
    DecryptionData {
        sharedSecret: proof.shared_secret,
        sharedSecretYParity: proof.shared_secret_y_parity,
        cpProof: proof.cp_proof,
    }
}

/// Encrypt `plaintext` as admitted request `id`.
fn request(h: &mut Harness, id: u64, plaintext: &[u8]) -> eyre::Result<Entry> {
    let (_, x, parity) = zone_key();
    let encrypted = ecies::encrypt_payload(
        &x,
        parity,
        plaintext,
        ecies::EncryptionContext {
            portal: PORTAL,
            sender: ALICE,
            key_index: U256::ZERO,
        },
        &mut k256::elliptic_curve::rand_core::OsRng,
        Some("forced-exit-v1"),
    )
    .unwrap();
    let block = anchor(h)?;
    h.l1.with_storage(block, || {
        let mut portal = ZonePortalStorage::new(PORTAL);
        portal.encryption_keys[0].x.write(x)?;
        portal.encryption_keys[0].y_parity.write(parity)?;
        portal.token_configs[PATH_USD_ADDRESS].enabled.write(true)?;
        Ok(())
    })?;
    let decryption = decryption_for(&encrypted);
    let entry = ForcedExit {
        requestId: id,
        token: PATH_USD_ADDRESS,
        feePayer: ALICE,
        keyIndex: U256::ZERO,
        requestedAtBlock: 1,
        requestedAtTime: 0,
        encrypted,
    };
    Ok((
        QueuedDeposit {
            depositType: DepositType::ForcedExit,
            depositData: entry.abi_encode().into(),
            rejected: true,
        },
        Some(decryption),
    ))
}

fn set_entry(entry: &mut Entry, f: impl FnOnce(&mut ForcedExit)) {
    let mut forced = ForcedExit::abi_decode(&entry.0.depositData).unwrap();
    f(&mut forced);
    entry.0.depositData = forced.abi_encode().into();
}

/// An ordinary encrypted deposit minting `amount` to `to`.
fn deposit(h: &mut Harness, to: Address, amount: u128) -> eyre::Result<Entry> {
    let (_, x, parity) = zone_key();
    let encrypted = ecies::encrypt_payload(
        &x,
        parity,
        &ecies::build_plaintext(&to, &B256::ZERO),
        ecies::EncryptionContext {
            portal: PORTAL,
            sender: ALICE,
            key_index: U256::ZERO,
        },
        &mut k256::elliptic_curve::rand_core::OsRng,
        None,
    )
    .unwrap();
    let block = anchor(h)?;
    h.l1.with_storage(block, || {
        let mut portal = ZonePortalStorage::new(PORTAL);
        portal.encryption_keys[0].x.write(x)?;
        portal.encryption_keys[0].y_parity.write(parity)
    })?;
    let decryption = decryption_for(&encrypted);
    let deposit = Deposit {
        token: PATH_USD_ADDRESS,
        sender: ALICE,
        amount,
        tempoRefundRecipient: ALICE,
        keyIndex: U256::ZERO,
        encrypted,
    };
    Ok((
        QueuedDeposit {
            depositType: DepositType::Deposit,
            depositData: deposit.abi_encode().into(),
            rejected: false,
        },
        Some(decryption),
    ))
}

/// A failed L1 withdrawal returning `amount` to the owner of `fallback_nonce`.
fn bounce_back(fallback_nonce: u64, amount: u128) -> Entry {
    let mut to = [0u8; 20];
    to[12..].copy_from_slice(&fallback_nonce.to_be_bytes());
    let deposit = WithdrawalBounceBackDeposit {
        token: PATH_USD_ADDRESS,
        to: Address::from(to),
        amount,
    };
    (
        QueuedDeposit {
            depositType: DepositType::WithdrawalBounceBack,
            depositData: deposit.abi_encode().into(),
            rejected: false,
        },
        None,
    )
}

fn queue_hash(entries: &[Entry], tail: B256) -> B256 {
    entries.iter().fold(tail, |tail, (queued, _)| {
        let data = &queued.depositData;
        match queued.depositType {
            DepositType::ForcedExit => {
                exithatch::request_queue_hash(&ForcedExit::abi_decode(data).unwrap(), tail)
            }
            DepositType::Deposit => keccak256(
                (
                    DepositType::Deposit,
                    Deposit::abi_decode(data).unwrap(),
                    tail,
                )
                    .abi_encode_params(),
            ),
            DepositType::WithdrawalBounceBack => keccak256(
                (
                    DepositType::WithdrawalBounceBack,
                    WithdrawalBounceBackDeposit::abi_decode(data).unwrap(),
                    tail,
                )
                    .abi_encode_params(),
            ),
            _ => unreachable!(),
        }
    })
}

struct Executed {
    output: PrecompileOutput,
    /// Every forced-exit classification, in queue order. Empty for reverted transitions.
    results: Vec<ForcedExitResult>,
}

/// Run one `advanceTempo` over `entries`, publishing their queue head at the next anchor.
fn execute(h: &mut Harness, entries: Vec<Entry>) -> eyre::Result<Executed> {
    execute_with(h, entries, Vec::new(), GAS)
}

fn execute_with(
    h: &mut Harness,
    entries: Vec<Entry>,
    enabled_tokens: Vec<EnabledToken>,
    gas: u64,
) -> eyre::Result<Executed> {
    let tail = with_zone(h, || Ok(ZoneInbox::new().processed_deposit_queue_hash()?))?;
    let head = queue_hash(&entries, tail);
    execute_raw(h, entries, head, enabled_tokens, gas)
}

/// Like [`execute_with`], but with an explicit L1 queue head so callers can submit entries that
/// differ from what L1 committed to.
fn execute_raw(
    h: &mut Harness,
    entries: Vec<Entry>,
    head: B256,
    enabled_tokens: Vec<EnabledToken>,
    gas: u64,
) -> eyre::Result<Executed> {
    let block = anchor(h)?;
    h.l1.with_storage(block, || {
        ZonePortalStorage::new(PORTAL)
            .current_deposit_queue_hash
            .write(head)
    })?;
    let (parent_hash, before) = with_zone(h, || {
        Ok((
            TempoState::new().tempo_block_hash()?,
            ZoneInbox::new().processed_deposit_number()?,
        ))
    })?;
    let header = TempoHeader {
        inner: alloy_consensus::Header {
            parent_hash,
            number: block,
            ..Default::default()
        },
        ..Default::default()
    };
    let count = entries.len() as u64;
    let (deposits, decryptions): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
    let call = IZoneInbox::advanceTempoCall {
        header: alloy_rlp::encode(&header).into(),
        deposits,
        decryptions: decryptions.into_iter().flatten().collect(),
        enabledTokens: enabled_tokens,
    };
    reload(h);
    OBSERVED.with(|observed| observed.borrow_mut().clear());
    let output = h.call_with_gas(Address::ZERO, call.abi_encode(), gas)?;
    let observed = OBSERVED.with(|observed| observed.take());
    let results = if output.is_success() {
        let after = with_zone(h, || Ok(ZoneInbox::new().processed_deposit_number()?))?;
        assert_eq!(after, before + count, "every entry advances the cursor");
        observed
    } else {
        Vec::new()
    };
    Ok(Executed { output, results })
}

fn fund_account(h: &mut Harness, account: Address, amount: U256) -> eyre::Result<()> {
    with_zone(h, || {
        Ok(TIP20Token::from_address(PATH_USD_ADDRESS)?.mint(
            ALICE,
            ITIP20::mintCall {
                to: account,
                amount,
            },
        )?)
    })
}

fn fund(h: &mut Harness, amount: u128) -> eyre::Result<()> {
    fund_account(h, ROOT, U256::from(amount))
}

fn consumed_by(h: &mut Harness, account: Address, nonce: u64) -> eyre::Result<bool> {
    with_zone(h, || {
        Ok(ZoneInbox::new().forced_exit_nonces[account][U256::from(nonce)].read()?)
    })
}

fn consumed(h: &mut Harness, nonce: u64) -> eyre::Result<bool> {
    consumed_by(h, ROOT, nonce)
}

fn root_balance(h: &mut Harness) -> eyre::Result<u128> {
    Ok(h.balance(PATH_USD_ADDRESS, ROOT)?.to::<u128>())
}

/// Everything a reverted transition must leave untouched.
#[derive(Debug, PartialEq)]
struct Snapshot {
    logs: Vec<alloy_primitives::Log>,
    processed: u64,
    queue_hash: B256,
    tempo_block: u64,
    root_balance: U256,
    supply: U256,
    pending: usize,
    nonces: Vec<bool>,
}

fn snapshot(h: &mut Harness) -> eyre::Result<Snapshot> {
    let logs = h.ctx.journaled_state.logs().to_vec();
    let root_balance = h.balance(PATH_USD_ADDRESS, ROOT)?;
    let pending = h.pending_withdrawals()?.len();
    with_zone(h, || {
        let inbox = ZoneInbox::new();
        Ok(Snapshot {
            logs,
            processed: inbox.processed_deposit_number()?,
            queue_hash: inbox.processed_deposit_queue_hash()?,
            tempo_block: TempoState::new().tempo_block_number()?,
            root_balance,
            supply: TIP20Token::from_address(PATH_USD_ADDRESS)?.total_supply()?,
            pending,
            nonces: (0..4)
                .map(|n| inbox.forced_exit_nonces[ROOT][U256::from(n)].read())
                .collect::<Result<_, _>>()?,
        })
    })
}

/// One funded account per request; request `id` authorizes nonce `id` from account `id`.
fn funded_requests(
    h: &mut Harness,
    count: u64,
    webauthn: bool,
) -> eyre::Result<(Vec<Address>, Vec<Entry>)> {
    let mut accounts = Vec::new();
    let mut entries = Vec::new();
    for id in 1..=count {
        let mut a = auth(id);
        let signature = if webauthn {
            let key = p256_key(id);
            a.account = p256_account(&key);
            sign_webauthn(&key, digest(&a), MAX_SIGNATURE_SIZE)
        } else {
            let key = k256_key(id);
            a.account = k256_account(&key);
            sign_k256(&key, digest(&a))
        };
        fund_account(h, a.account, U256::ONE)?;
        accounts.push(a.account);
        entries.push(request(h, id, &exithatch::encode_payload(&a, &signature))?);
    }
    Ok((accounts, entries))
}

fn saturate_ordinary_cap(h: &mut Harness, used: u32) -> eyre::Result<()> {
    with_zone(h, || {
        let mut outbox = ZoneOutbox::new();
        outbox.max_withdrawals_per_block.write(1)?;
        outbox
            .current_block_number
            .write(StorageCtx.block_number())?;
        outbox.withdrawals_this_block.write(used)?;
        Ok(())
    })
}

#[test]
fn forced_exit_accepts_earlier_admission_but_rejects_future_height() -> eyre::Result<()> {
    for admission_block in [0, 2] {
        let mut h = active_harness()?;
        fund(&mut h, 42)?;
        let mut entry = request(&mut h, 1, &payload(&auth(1)))?;
        // The transition imports block 1. Earlier admission models deferred portal work.
        set_entry(&mut entry, |e| e.requestedAtBlock = admission_block);
        let before = snapshot(&mut h)?;
        let executed = execute(&mut h, vec![entry])?;
        if admission_block == 0 {
            assert_eq!(executed.results, [ForcedExitResult::Exited]);
            assert_eq!(root_balance(&mut h)?, 0);
            assert_eq!(h.pending_withdrawals()?.len(), 1);
        } else {
            assert!(executed.output.is_revert());
            assert_eq!(snapshot(&mut h)?, before);
        }
    }
    Ok(())
}

#[test]
fn l1_token_pause_rejects_admitted_requests_without_blocking_inbox() -> eyre::Result<()> {
    for paused in [true, false] {
        let mut h = active_harness()?;
        fund(&mut h, 42)?;
        let first = request(&mut h, 1, &payload(&auth(1)))?;
        let second = request(&mut h, 2, &payload(&auth(2)))?;
        // Admission occurred while unpaused; model the final state after a same-block
        // pause (or pause followed by unpause). The Zone-local token remains unpaused.
        let mut pause_slot = tempo_precompiles::storage::Slot::<bool>::new(
            tempo_precompiles::tip20::slots::PAUSED,
            PATH_USD_ADDRESS,
        );
        h.l1.with_storage(0, || pause_slot.write(!paused))?;
        h.l1.with_storage(1, || pause_slot.write(paused))?;

        let executed = execute(&mut h, vec![first, second])?;
        assert!(h.l1.requested(1, &pause_slot));
        assert!(!h.l1.requested(0, &pause_slot));
        assert!(consumed(&mut h, 1)? && consumed(&mut h, 2)?);
        let pending = h.pending_withdrawals()?;
        if paused {
            let rejected = ForcedExitResult::Rejected(Reason::PolicyRejected);
            assert_eq!(executed.results, [rejected.clone(), rejected]);
            assert_eq!(root_balance(&mut h)?, 42);
            assert!(pending.is_empty());
        } else {
            // The first request exits the full balance, leaving nothing for the second.
            assert_eq!(
                executed.results,
                [ForcedExitResult::Exited, ForcedExitResult::Empty]
            );
            assert_eq!(root_balance(&mut h)?, 0);
            assert_eq!(
                (pending.len(), pending[0].amount, pending[0].to),
                (1, 42, BOB)
            );
        }
    }
    Ok(())
}

#[test]
fn forced_full_balance_replay_and_empty_finalize_with_exact_commitment() -> eyre::Result<()> {
    let mut h = active_harness()?;
    fund(&mut h, 42)?;
    let entries = [7, 7, 8]
        .into_iter()
        .zip(1..)
        .map(|(nonce, id)| request(&mut h, id, &payload(&auth(nonce))))
        .collect::<eyre::Result<Vec<_>>>()?;
    let executed = execute(&mut h, entries)?;
    assert_eq!(
        executed.results,
        [
            ForcedExitResult::Exited,
            ForcedExitResult::Rejected(Reason::NonceAlreadyConsumed),
            ForcedExitResult::Empty,
        ]
    );
    assert!(consumed(&mut h, 7)? && consumed(&mut h, 8)?);
    assert_eq!(root_balance(&mut h)?, 0);
    let pending = h.pending_withdrawals()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(h.fallback_recipient(pending[0].fallbackNonce)?, ROOT);
    let withdrawal = tempo_contracts::zones::Withdrawal {
        token: PATH_USD_ADDRESS,
        senderTag: tempo_contracts::zones::Withdrawal::sender_tag(
            ROOT,
            keccak256(payload(&auth(7))),
            pending[0].fallbackNonce,
        ),
        to: BOB,
        amount: 42,
        memo: B256::ZERO,
        gasLimit: 0,
        fallbackNonce: pending[0].fallbackNonce,
        callbackData: Bytes::new(),
        encryptedSender: Bytes::new(),
    };
    let call = IZoneOutbox::finalizeWithdrawalBatchCall {
        blockNumber: h.ctx.block.inner.number.to::<u64>(),
        count: U256::from(1),
        encryptedSenders: vec![Bytes::new()],
    };
    let finalized = call_precompile(
        &mut h.ctx,
        &h.outbox_precompile,
        Address::ZERO,
        &call.abi_encode(),
        GAS,
        false,
        ZONE_OUTBOX_ADDRESS,
        ZONE_OUTBOX_ADDRESS,
    )?;
    assert!(finalized.is_success());
    assert_eq!(
        IZoneOutbox::finalizeWithdrawalBatchCall::abi_decode_returns(&finalized.bytes)?,
        tempo_contracts::zones::Withdrawal::queue_hash(&[withdrawal])
    );
    Ok(())
}

/// A request that must be rejected on its own while the next request still exits.
#[derive(Clone, Copy, Debug)]
enum Bad {
    CorruptTag,
    DirtyVersion,
    WrongVersion,
    Expired,
    WrongSigner,
    WrongToken,
    WrongZone,
    ZeroAccount,
    ZeroRecipient,
    KeychainSignature,
    PolicyRejected,
}

#[test]
fn rejected_requests_are_classified_and_never_stall_the_inbox() -> eyre::Result<()> {
    use Bad::*;
    for case in [
        CorruptTag,
        DirtyVersion,
        WrongVersion,
        Expired,
        WrongSigner,
        WrongToken,
        WrongZone,
        ZeroAccount,
        ZeroRecipient,
        KeychainSignature,
        PolicyRejected,
    ] {
        let mut h = active_harness()?;
        fund(&mut h, 42)?;
        let mut a = auth(1);
        match case {
            Expired => a.admitBefore = 0,
            WrongSigner => a.account = BOB,
            WrongToken => a.token = Address::repeat_byte(5),
            WrongZone => a.zoneChainId += U256::ONE,
            ZeroAccount => a.account = Address::ZERO,
            ZeroRecipient => a.recipient = Address::ZERO,
            PolicyRejected => a.recipient = Address::repeat_byte(0x77),
            _ => {}
        }
        let mut plaintext = payload(&a);
        match case {
            DirtyVersion => plaintext[0] = 1,
            WrongVersion => plaintext[31] = 2,
            KeychainSignature => {
                let envelope = SignatureMutation::Keychain(3).apply(&root_signature(&a), ROOT);
                plaintext = exithatch::encode_payload(&a, &envelope);
            }
            _ => {}
        }
        let mut bad = request(&mut h, 1, &plaintext)?;
        if matches!(case, CorruptTag) {
            set_entry(&mut bad, |e| e.encrypted.tag[0] ^= 1);
        }
        if matches!(case, PolicyRejected) {
            h.l1.with_storage(1, || -> tempo_precompiles::Result<()> {
                let mut portal = ZonePortalStorage::new(PORTAL);
                portal.is_access_enforced.write(true)?;
                portal.role[BOB].write(u8::from(tempo_contracts::zones::ZonePortal::Role::Account))
            })?;
        }
        let good = request(&mut h, 2, &payload(&auth(2)))?;

        let executed = execute(&mut h, vec![bad, good])?;
        let reason = match case {
            CorruptTag | DirtyVersion | WrongVersion => Reason::InvalidPayload,
            PolicyRejected => Reason::PolicyRejected,
            _ => Reason::InvalidAuthorization,
        };
        assert_eq!(
            executed.results,
            [ForcedExitResult::Rejected(reason), ForcedExitResult::Exited],
            "{case:?}"
        );
        // Only an authenticated request consumes its nonce, even when execution rejects it.
        assert_eq!(
            consumed(&mut h, 1)?,
            matches!(case, PolicyRejected),
            "{case:?}"
        );
        assert!(!consumed_by(&mut h, Address::ZERO, 1)?, "{case:?}");
        assert!(consumed(&mut h, 2)?, "{case:?}");
        // A rejection allocates no fallback nonce and moves no funds.
        let pending = h.pending_withdrawals()?;
        assert_eq!(pending.len(), 1, "{case:?}");
        assert_eq!((pending[0].to, pending[0].amount), (BOB, 42), "{case:?}");
        assert_eq!(pending[0].fallbackNonce, 1, "{case:?}");
        assert_eq!(pending[0].txHash, keccak256(payload(&auth(2))), "{case:?}");
        assert_eq!(h.fallback_recipient(1)?, ROOT, "{case:?}");
        assert_eq!(root_balance(&mut h)?, 0, "{case:?}");
        assert_eq!(
            h.balance(PATH_USD_ADDRESS, ZONE_OUTBOX_ADDRESS)?,
            U256::ZERO
        );
        with_zone(&mut h, || {
            assert_eq!(
                TIP20Token::from_address(PATH_USD_ADDRESS)?.total_supply()?,
                U256::ZERO
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn later_bad_proof_rolls_back_earlier_exit_without_an_external_checkpoint() -> eyre::Result<()> {
    let mut h = active_harness()?;
    fund(&mut h, 50)?;
    let first = request(&mut h, 1, &payload(&auth(1)))?;
    let mut second = request(&mut h, 2, &payload(&auth(2)))?;
    second.1.as_mut().unwrap().cpProof.c = B256::ZERO;
    let before = snapshot(&mut h)?;
    assert!(execute(&mut h, vec![first, second])?.output.is_revert());
    assert_eq!(snapshot(&mut h)?, before);
    Ok(())
}

#[test]
fn forced_balance_boundaries_and_classification_order() -> eyre::Result<()> {
    let max = U256::from(u128::MAX);
    // Overflow and Empty are classified before execution policy, so a disabled token does
    // not change them. Only the nonce is consumed.
    for (amount, token_enabled, expected) in [
        (U256::ZERO, false, ForcedExitResult::Empty),
        (
            max + U256::ONE,
            false,
            ForcedExitResult::Rejected(Reason::BalanceOverflow),
        ),
        (U256::ONE, true, ForcedExitResult::Exited),
        (max, true, ForcedExitResult::Exited),
    ] {
        let mut h = active_harness()?;
        if amount > max {
            // The current native mint caps supply at u128::MAX. Seed an oversized liquid
            // balance only to exercise the protocol's defensive overflow branch.
            with_zone(&mut h, || {
                let slot = keccak256(
                    (ROOT, tempo_precompiles::tip20::slots::BALANCES).abi_encode_params(),
                );
                Ok(StorageCtx.sstore(PATH_USD_ADDRESS, U256::from_be_bytes(slot.0), amount)?)
            })?;
        } else {
            fund_account(&mut h, ROOT, amount)?;
        }
        let entry = request(&mut h, 1, &payload(&auth(1)))?;
        h.l1.with_storage(1, || {
            ZonePortalStorage::new(PORTAL).token_configs[PATH_USD_ADDRESS]
                .enabled
                .write(token_enabled)
        })?;
        let executed = execute(&mut h, vec![entry])?;
        assert_eq!(
            executed.results,
            std::slice::from_ref(&expected),
            "{amount}"
        );
        assert!(consumed(&mut h, 1)?);
        let pending = h.pending_withdrawals()?;
        if expected == ForcedExitResult::Exited {
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].amount, amount.to::<u128>());
            assert_eq!(h.balance(PATH_USD_ADDRESS, ROOT)?, U256::ZERO);
        } else {
            assert!(pending.is_empty());
            assert_eq!(h.balance(PATH_USD_ADDRESS, ROOT)?, amount);
        }
    }
    Ok(())
}

#[test]
fn maximum_forced_exit_workload_fits_system_gas_budget() -> eyre::Result<()> {
    const REQUESTS: u64 = 210 / 14; // ZonePortal.FORCED_EXIT_ADMISSION_WEIGHT
    let mut h = active_harness()?;
    let enabled_tokens = (1..=8).map(maximum_metadata_token).collect::<Vec<_>>();
    h.set_token_enablements(&enabled_tokens);
    // Maximum-size WebAuthn roots: the largest admitted ciphertext and the most expensive
    // supported signature, measured rather than estimated.
    let (_, entries) = funded_requests(&mut h, REQUESTS, true)?;
    let executed = execute_with(&mut h, entries, enabled_tokens, u64::MAX)?;
    assert_eq!(
        executed.results,
        vec![ForcedExitResult::Exited; REQUESTS as usize]
    );
    assert_eq!(h.pending_withdrawals()?.len(), REQUESTS as usize);
    // Add a separate full transition for the 20 reserved refund entries. This overcounts
    // header/cursor work rather than hiding it.
    let gas_bound = executed.output.gas_used + failed_deposit_gas(20, 0)?;
    eprintln!(
        "{REQUESTS} max-size WebAuthn forced exits + 8 token initializations + 20 refund bound: \
         {gas_bound} gas (forced transition {})",
        executed.output.gas_used
    );
    assert!(
        gas_bound <= 225_000_000,
        "forced inbox workload exceeds system budget: {gas_bound}"
    );
    let finalize = IZoneOutbox::finalizeWithdrawalBatchCall {
        blockNumber: h.ctx.block.inner.number.to::<u64>(),
        count: U256::from(REQUESTS),
        encryptedSenders: vec![Bytes::new(); REQUESTS as usize],
    };
    let result = call_precompile(
        &mut h.ctx,
        &h.outbox_precompile,
        Address::ZERO,
        &finalize.abi_encode(),
        u64::MAX,
        false,
        ZONE_OUTBOX_ADDRESS,
        ZONE_OUTBOX_ADDRESS,
    )?;
    assert!(result.is_success());
    eprintln!(
        "{REQUESTS} ordinary withdrawals finalization: {} gas",
        result.gas_used
    );
    assert!(result.gas_used < 225_000_000);
    Ok(())
}

#[test]
fn forced_exit_keeps_nonce_consumed_through_pending_credit_recovery() -> eyre::Result<()> {
    let mut h = active_harness()?;
    fund(&mut h, 17)?;
    let entry = request(&mut h, 1, &payload(&auth(1)))?;
    assert_eq!(
        execute(&mut h, vec![entry])?.results,
        [ForcedExitResult::Exited]
    );
    let nonce = h.pending_withdrawals()?[0].fallbackNonce;
    let mut encoded_nonce = [0; 20];
    encoded_nonce[12..].copy_from_slice(&nonce.to_be_bytes());
    with_zone(&mut h, || {
        let mut token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
        token.change_transfer_policy_id(
            ALICE,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: REJECT_ALL_POLICY_ID,
            },
        )?;
        let mut inbox = ZoneInbox::new();
        inbox.process_withdrawal_bounce_back(
            &mut ZoneOutbox::new(),
            WithdrawalBounceBackDeposit {
                token: PATH_USD_ADDRESS,
                to: Address::from(encoded_nonce),
                amount: 17,
            },
        )?;
        assert_eq!(
            inbox.withdrawal_bounce_backs[PATH_USD_ADDRESS][ROOT].read()?,
            17
        );
        token.change_transfer_policy_id(
            ALICE,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: ALLOW_ALL_POLICY_ID,
            },
        )?;
        Ok(())
    })?;
    assert_eq!(h.fallback_recipient(nonce)?, Address::ZERO);
    assert_eq!(root_balance(&mut h)?, 0);
    let claim = IZoneInbox::claimRefundCall {
        token: PATH_USD_ADDRESS,
    };
    assert!(h.call(ROOT, claim.abi_encode())?.is_success());
    assert_eq!(root_balance(&mut h)?, 17);
    assert!(consumed(&mut h, 1)?);
    Ok(())
}

#[test]
fn forced_authorization_nonce_is_shared_across_tokens() -> eyre::Result<()> {
    let mut h = active_harness()?;
    let first = request(&mut h, 1, &payload(&auth(1)))?;
    let mut other_auth = auth(1);
    other_auth.token = address!("20c0000000000000000000000000000000000002");
    let mut second = request(&mut h, 2, &payload(&other_auth))?;
    set_entry(&mut second, |e| e.token = other_auth.token);
    let executed = execute(&mut h, vec![first, second])?;
    assert_eq!(
        executed.results,
        [
            ForcedExitResult::Empty,
            ForcedExitResult::Rejected(Reason::NonceAlreadyConsumed),
        ]
    );
    assert!(consumed(&mut h, 1)?);
    assert!(h.pending_withdrawals()?.is_empty());
    Ok(())
}

#[test]
fn admitted_forced_workload_preserves_ordinary_capacity() -> eyre::Result<()> {
    const REQUESTS: u64 = 15;
    for used in [0, 1] {
        let mut h = active_harness()?;
        let (accounts, entries) = funded_requests(&mut h, REQUESTS, false)?;
        saturate_ordinary_cap(&mut h, used)?;
        let executed = execute_with(&mut h, entries, Vec::new(), 225_000_000)?;
        assert_eq!(
            executed.results,
            vec![ForcedExitResult::Exited; REQUESTS as usize],
            "ordinary slots used={used}"
        );
        let pending = h.pending_withdrawals()?;
        assert_eq!(pending.len(), REQUESTS as usize);
        for (i, account) in accounts.iter().enumerate() {
            assert_eq!(h.balance(PATH_USD_ADDRESS, *account)?, U256::ZERO);
            assert_eq!(pending[i].amount, 1);
            assert_eq!(h.fallback_recipient(pending[i].fallbackNonce)?, *account);
            assert!(consumed_by(&mut h, *account, i as u64 + 1)?);
        }
        with_zone(&mut h, || {
            assert_eq!(TempoState::new().tempo_block_number()?, 1);
            assert_eq!(ZoneOutbox::new().withdrawals_this_block.read()?, used);
            Ok(())
        })?;
    }
    Ok(())
}

/// Forced entries require both the fork and `forcedExitVersion == 1` at the imported anchor.
/// Otherwise the whole transition reverts before any request is classified, whatever the
/// request would have done.
#[test]
fn activation_gate_rejects_the_whole_transition() -> eyre::Result<()> {
    let expected = [
        (42, ForcedExitResult::Exited),
        (0, ForcedExitResult::Empty),
        (42, ForcedExitResult::Rejected(Reason::InvalidPayload)),
    ];
    for (spec, version) in [
        (TempoHardfork::T12, 1),
        (TempoHardfork::T13, 1),
        (TempoHardfork::T14, 0),
        (TempoHardfork::T14, 2),
        (TempoHardfork::T14, u64::MAX),
        (TempoHardfork::T14, 1),
    ] {
        for (balance, result) in expected.clone() {
            let mut h = active_harness()?;
            // Parent and later state disagree with the imported block deliberately.
            activate(&h, 0, u64::from(version != 1))?;
            activate(&h, 1, version)?;
            activate(&h, 2, u64::from(version != 1))?;
            fund(&mut h, balance)?;
            let plaintext = if matches!(result, ForcedExitResult::Rejected(_)) {
                vec![0; 384]
            } else {
                payload(&auth(1))
            };
            let entry = request(&mut h, 1, &plaintext)?;
            set_spec(&mut h, spec);
            let before = snapshot(&mut h)?;
            let executed = execute(&mut h, vec![entry.clone()])?;
            let case = format!("{spec:?} version={version} {result:?}");
            let portal = ForcedExitPortalStorage::new(PORTAL);
            // The fork check precedes anchoring, so a pre-fork transition reads nothing.
            let t14 = spec.is_t14();
            assert_eq!(
                h.l1.requested(1, &portal.forced_exit_version),
                t14,
                "{case}"
            );
            assert!(!h.l1.requested(0, &portal.forced_exit_version), "{case}");
            assert!(!h.l1.requested(2, &portal.forced_exit_version), "{case}");
            if t14 && version == 1 {
                assert_eq!(executed.results, [result], "{case}");
                continue;
            }
            assert!(executed.output.is_revert(), "{case}");
            assert_eq!(snapshot(&mut h)?, before, "{case}");
            if !t14 {
                // The same entry executes as soon as the fork is active.
                set_spec(&mut h, TempoHardfork::T14);
                assert_eq!(execute(&mut h, vec![entry])?.results, [result], "{case}");
            }
        }
    }
    Ok(())
}

/// Request IDs count forced exits only, while the inbox cursor counts every entry. Interleaving
/// other entry types must not affect forced-exit execution.
#[test]
fn mixed_batch_executes_forced_exits_in_queue_order() -> eyre::Result<()> {
    let mut h = active_harness()?;
    h.seed_fallback_recipient(7, ROOT)?;
    let entries = vec![
        deposit(&mut h, ROOT, 900)?,
        request(&mut h, 1, &payload(&auth(1)))?,
        bounce_back(7, 321),
        request(&mut h, 2, &payload(&auth(2)))?,
    ];
    let executed = execute(&mut h, entries)?;
    // The deposit funds the first exit; the bounce-back funds the second.
    assert_eq!(
        executed.results,
        [ForcedExitResult::Exited, ForcedExitResult::Exited]
    );
    let pending = h.pending_withdrawals()?;
    let amounts = pending.iter().map(|p| p.amount).collect::<Vec<_>>();
    assert_eq!(amounts, [900, 321]);
    assert_eq!(root_balance(&mut h)?, 0);
    assert_eq!(h.fallback_recipient(7)?, Address::ZERO);
    assert!(consumed(&mut h, 1)? && consumed(&mut h, 2)?);
    Ok(())
}

#[test]
fn replay_is_rejected_across_batches_and_after_bounce_back() -> eyre::Result<()> {
    let mut h = active_harness()?;
    fund(&mut h, 42)?;
    let first = request(&mut h, 1, &payload(&auth(1)))?;
    assert_eq!(
        execute(&mut h, vec![first])?.results,
        [ForcedExitResult::Exited]
    );
    let fallback_nonce = h.pending_withdrawals()?[0].fallbackNonce;

    // Next Tempo block: the L1 withdrawal bounces, crediting the root again, and the same
    // authorization is replayed (re-encrypted, so the queue entry itself is new).
    activate(&h, 2, 1)?;
    let entries = vec![
        bounce_back(fallback_nonce, 42),
        request(&mut h, 2, &payload(&auth(1)))?,
        request(&mut h, 3, &payload(&auth(2)))?,
    ];
    let executed = execute(&mut h, entries)?;
    assert_eq!(
        executed.results,
        [
            ForcedExitResult::Rejected(Reason::NonceAlreadyConsumed),
            ForcedExitResult::Exited,
        ]
    );
    let pending = h.pending_withdrawals()?;
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[1].amount, 42);
    assert_eq!(pending[1].txHash, keccak256(payload(&auth(2))));
    assert_eq!(root_balance(&mut h)?, 0);
    with_zone(&mut h, || {
        assert_eq!(TempoState::new().tempo_block_number()?, 2);
        Ok(())
    })
}

/// secp256k1 decoding normalizes `v`, so one authorization has several valid encodings with
/// different private request hashes. The replay map, not the decoder, allows a single exit.
#[test]
fn malleated_root_signature_cannot_exit_twice() -> eyre::Result<()> {
    let a = auth(1);
    let signature = root_signature(&a);
    for v in [27, 35] {
        let mut h = active_harness()?;
        fund(&mut h, 42)?;
        let mut malleated = signature.clone();
        malleated[64] += v;
        let malleated = exithatch::encode_payload(&a, &malleated);
        assert_ne!(keccak256(&malleated), keccak256(payload(&a)));
        let entries = vec![
            request(&mut h, 1, &malleated)?,
            request(&mut h, 2, &payload(&a))?,
        ];
        let executed = execute(&mut h, entries)?;
        assert_eq!(
            executed.results,
            [
                ForcedExitResult::Exited,
                ForcedExitResult::Rejected(Reason::NonceAlreadyConsumed),
            ]
        );
        let pending = h.pending_withdrawals()?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].txHash, keccak256(&malleated));
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum PlaintextMutation {
    Payload(PayloadMutation),
    Signature(SignatureMutation),
}

fn plaintext_mutation() -> impl Strategy<Value = PlaintextMutation> {
    prop_oneof![
        payload_mutation().prop_map(PlaintextMutation::Payload),
        signature_mutation().prop_map(PlaintextMutation::Signature),
    ]
}

/// A bad plaintext passes AES-GCM (it is encrypted after mutation) and must be rejected on
/// its own: the transition succeeds, the cursor advances, the nonce is untouched, funds are
/// conserved and the next valid request still exits.
fn bad_plaintext_is_isolated(mutation: PlaintextMutation) -> eyre::Result<()> {
    let a = auth(1);
    let valid = payload(&a);
    let signature = root_signature(&a);
    let (bad, malleated) = match &mutation {
        PlaintextMutation::Payload(m) => (m.apply(&valid), false),
        PlaintextMutation::Signature(m) => {
            let mutated = m.apply(&signature, ROOT);
            let malleated = is_secp256k1_malleation(&signature, &mutated);
            (exithatch::encode_payload(&a, &mutated), malleated)
        }
    };
    // Other lengths never reach execution: the outer entry decoder rejects them.
    if bad == valid || !exithatch::valid_ciphertext_length(bad.len()) {
        return Ok(());
    }
    let mut h = active_harness()?;
    fund(&mut h, 42)?;
    let entries = vec![
        request(&mut h, 1, &bad)?,
        request(&mut h, 2, &payload(&auth(2)))?,
    ];
    let executed = execute(&mut h, entries)?;
    assert!(
        executed.output.is_success(),
        "{mutation:?} stalled the inbox"
    );
    if malleated {
        assert_eq!(
            executed.results,
            [ForcedExitResult::Exited, ForcedExitResult::Empty]
        );
    } else {
        assert!(
            matches!(
                executed.results[0],
                ForcedExitResult::Rejected(Reason::InvalidPayload | Reason::InvalidAuthorization)
            ),
            "{mutation:?}: {:?}",
            executed.results
        );
        assert_eq!(
            executed.results[1],
            ForcedExitResult::Exited,
            "{mutation:?}"
        );
        assert!(!consumed(&mut h, 1)?, "{mutation:?}");
    }
    let pending = h.pending_withdrawals()?;
    assert_eq!(pending.len(), 1, "{mutation:?}");
    assert_eq!(
        root_balance(&mut h)? + pending[0].amount,
        42,
        "{mutation:?}"
    );
    Ok(())
}

#[derive(Clone, Debug)]
enum OuterMutation {
    /// Rewrite one ABI word of the queued `ForcedExit` encoding.
    EntryWord(Index, WordValue),
    /// Set the high byte of one ABI word (dirty padding for narrow types).
    EntryHighByte(Index, u8),
    /// Append a trailing word to the entry encoding.
    EntryTrailingWord,
    SharedSecret(Index, u8),
    SharedSecretParity(u8),
    ProofS(Index, u8),
    ProofC(Index, u8),
}

fn outer_mutation() -> impl Strategy<Value = OuterMutation> {
    let word = prop_oneof![
        prop::sample::select(vec![-32i64, -1, 1, 32]).prop_map(WordValue::Delta),
        Just(WordValue::SelfPointing),
        Just(WordValue::PastEnd),
        Just(WordValue::Zero),
        Just(WordValue::Max),
    ];
    prop_oneof![
        (any::<Index>(), word).prop_map(|(i, w)| OuterMutation::EntryWord(i, w)),
        (any::<Index>(), 1u8..).prop_map(|(i, b)| OuterMutation::EntryHighByte(i, b)),
        Just(OuterMutation::EntryTrailingWord),
        (any::<Index>(), 1u8..).prop_map(|(i, b)| OuterMutation::SharedSecret(i, b)),
        any::<u8>().prop_map(OuterMutation::SharedSecretParity),
        (any::<Index>(), 1u8..).prop_map(|(i, b)| OuterMutation::ProofS(i, b)),
        (any::<Index>(), 1u8..).prop_map(|(i, b)| OuterMutation::ProofC(i, b)),
    ]
}

/// L1 commits to the exact entry encoding and the proof binds the decryption, so any other
/// outer encoding or decryption input must revert the transition with no state change. The
/// only exception is an equivalent SEC1 encoding of the same shared-secret point (`0x05` is
/// accepted for even points), which must behave exactly like the original.
fn outer_mutation_reverts(mutation: OuterMutation) -> eyre::Result<()> {
    let mut h = active_harness()?;
    fund(&mut h, 42)?;
    let original = vec![request(&mut h, 1, &payload(&auth(1)))?];
    let head = queue_hash(&original, B256::ZERO);
    let mut entries = original.clone();
    let (queued, decryption) = &mut entries[0];
    let decryption = decryption.as_mut().unwrap();
    let mut data = queued.depositData.to_vec();
    let words = data.len() / 32;
    match &mutation {
        OuterMutation::EntryWord(i, value) => {
            let at = i.index(words) * 32;
            value.apply(&mut data, at..at + 32);
        }
        OuterMutation::EntryHighByte(i, byte) => data[i.index(words) * 32] = *byte,
        OuterMutation::EntryTrailingWord => data.extend_from_slice(&[0; 32]),
        OuterMutation::SharedSecret(i, byte) => decryption.sharedSecret[i.index(32)] ^= byte,
        OuterMutation::SharedSecretParity(parity) => decryption.sharedSecretYParity = *parity,
        OuterMutation::ProofS(i, byte) => decryption.cpProof.s[i.index(32)] ^= byte,
        OuterMutation::ProofC(i, byte) => decryption.cpProof.c[i.index(32)] ^= byte,
    }
    queued.depositData = data.into();
    let (secret, parity) = (decryption.sharedSecret.0, decryption.sharedSecretYParity);
    if entries == original {
        return Ok(());
    }
    let original_parity = original[0].1.as_ref().unwrap().sharedSecretYParity;
    let before = snapshot(&mut h)?;
    let executed = execute_raw(&mut h, entries, head, Vec::new(), GAS)?;
    if matches!(mutation, OuterMutation::SharedSecretParity(_))
        && crate::chaum_pedersen::recover_point(&secret, parity)
            == crate::chaum_pedersen::recover_point(&secret, original_parity)
    {
        assert_eq!(executed.results, [ForcedExitResult::Exited], "{mutation:?}");
        return Ok(());
    }
    assert!(executed.output.is_revert(), "{mutation:?} executed");
    assert_eq!(snapshot(&mut h)?, before, "{mutation:?}");
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn bad_plaintext_never_stalls_the_inbox(mutation in plaintext_mutation()) {
        bad_plaintext_is_isolated(mutation).unwrap();
    }

    #[test]
    fn mutated_outer_entry_or_decryption_reverts_untouched(mutation in outer_mutation()) {
        outer_mutation_reverts(mutation).unwrap();
    }
}
