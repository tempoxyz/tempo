//! Zone portals under the harness: a zone the factory creates, driven through realistic portal
//! operations, including calls from accounts the portal must refuse.

use std::collections::BTreeMap;

use alloy_consensus::{Signed, TxLegacy};
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::{
    Address, B256, Bytes, FixedBytes, Signature, TxKind, U256, address, keccak256,
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolValue};
use tempo_chainspec::{constants::moderato::MODERATO_CHAIN_ID, hardfork::TempoHardfork};
use tempo_contracts::{
    precompiles::{
        ITIP20, ITIP403Registry, IZoneFactory, PATH_USD_ADDRESS, TIP403_REGISTRY_ADDRESS,
        ZONE_FACTORY_ADDRESS, ZONE_VERIFIER_ADDRESS,
    },
    zones::{
        BlockTransition, DepositQueueTransition, SwapAndDepositRouter, TokenEnablementTransition,
        ZonePortal,
    },
};
use tempo_fuzz_types::{
    AccountInput, BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass, PreState,
    StateInput, TempoBlock, TempoBlockchainInput, TempoExecutionOutcome, TempoHarnessInput,
    TempoHarnessOutcome, TxOutcome,
};
use tempo_invariants::zones::portal::{self, portal_address, withdrawal_chain};

use crate::execute;

/// Dev account 0: the zone factory's owner, funded with pathUSD in the dev genesis.
const OWNER: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const ADMIN: Address = address!("00000000000000000000000000000000000a0001");
const NEW_ADMIN: Address = address!("00000000000000000000000000000000000a0003");
/// An account with no role on the portal.
const MALLORY: Address = address!("00000000000000000000000000000000000a0bad");
const RECIPIENT: Address = address!("00000000000000000000000000000000000000aa");
/// A second dev-genesis token, enabled after the first batch.
const SECOND_TOKEN: Address = address!("20c0000000000000000000000000000000000001");

fn sequencer_key() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(0x51)).unwrap()
}

fn encryption_key() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(0x52)).unwrap()
}

/// Transactions in order, each from its sender at that sender's next nonce.
#[derive(Default)]
struct Txs {
    txs: Vec<Bytes>,
    senders: Vec<Address>,
    nonces: BTreeMap<Address, u64>,
}

impl Txs {
    fn call(&mut self, from: Address, to: Address, input: Vec<u8>, gas_limit: u64) -> &mut Self {
        let nonce = self.nonces.entry(from).or_default();
        let tx = tempo_primitives::TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(MODERATO_CHAIN_ID),
                nonce: *nonce,
                gas_price: 0,
                gas_limit,
                to: TxKind::Call(to),
                value: U256::ZERO,
                input: input.into(),
            },
            Signature::test_signature(),
        ));
        *nonce += 1;
        self.txs.push(tx.encoded_2718().into());
        self.senders.push(from);
        self
    }

    fn block(&mut self, fork: TempoHardfork, number: u64) -> TempoBlock {
        TempoBlock {
            header: BlockHeaderInput::Context(BlockContextInput {
                hardfork: fork,
                block_number: number,
                timestamp: number,
                gas_limit: 500_000_000,
                ..Default::default()
            }),
            txs: std::mem::take(&mut self.txs),
            senders: std::mem::take(&mut self.senders),
        }
    }
}

impl Txs {
    /// A block at `fork` numbered `number` whose header names `parent_hash`, which EIP-2935
    /// then serves as block `number - 1`'s hash.
    fn block_after(&mut self, fork: TempoHardfork, number: u64, parent_hash: B256) -> TempoBlock {
        let context = BlockHeaderInput::Context(BlockContextInput {
            hardfork: fork,
            block_number: number,
            timestamp: number,
            gas_limit: 500_000_000,
            ..Default::default()
        });
        let spec = crate::chain::chain_spec(&ChainSpecInput::default()).unwrap();
        let mut header = crate::chain::header(&spec, &context).unwrap();
        let txs: Vec<_> = self
            .txs
            .iter()
            .map(|tx| tempo_primitives::TempoTxEnvelope::decode_2718_exact(tx).unwrap())
            .collect();
        header.inner.transactions_root = alloy_consensus::proofs::calculate_transaction_root(&txs);
        header.inner.parent_hash = parent_hash;
        TempoBlock {
            header: BlockHeaderInput::Rlp(alloy_rlp::encode(&header).into()),
            txs: std::mem::take(&mut self.txs),
            senders: std::mem::take(&mut self.senders),
        }
    }
}

fn run(pre_state: PreState, blocks: Vec<TempoBlock>) -> TempoExecutionOutcome {
    let input = TempoBlockchainInput {
        chain_spec: ChainSpecInput::default(),
        pre_state,
        blocks: blocks.try_into().unwrap(),
    };
    let TempoHarnessOutcome::Blockchain(outcome) =
        execute::run(TempoHarnessInput::Blockchain(input))
    else {
        panic!("a blockchain input has a blockchain outcome");
    };
    outcome
}

/// The compressed public key of `key`: its x coordinate and parity byte.
fn compressed(key: &PrivateKeySigner) -> (B256, u8) {
    let point = key.credential().verifying_key().to_encoded_point(true);
    let bytes = point.as_bytes();
    (B256::from_slice(&bytes[1..]), bytes[0])
}

fn set_encryption_key(portal: Address) -> ZonePortal::setSequencerEncryptionKeyCall {
    let key = encryption_key();
    let (x, y_parity) = compressed(&key);
    let message = keccak256((portal, x, U256::from(y_parity)).abi_encode());
    let sig = key.sign_hash_sync(&message).unwrap();
    ZonePortal::setSequencerEncryptionKeyCall {
        x,
        yParity: y_parity,
        popV: 27 + u8::from(sig.v()),
        popR: sig.r().into(),
        popS: sig.s().into(),
    }
}

fn deposit(amount: u128, refund: Address) -> ZonePortal::depositCall {
    // The secp256k1 generator, a valid ephemeral key.
    let gx: B256 = "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        .parse()
        .unwrap();
    ZonePortal::depositCall {
        token: PATH_USD_ADDRESS,
        amount,
        keyIndex: U256::ZERO,
        encrypted: ZonePortal::DepositPayload {
            ephemeralPubkeyX: gx,
            ephemeralPubkeyYParity: 2,
            ciphertext: vec![7; 64].into(),
            nonce: FixedBytes::repeat_byte(1),
            tag: FixedBytes::repeat_byte(2),
        },
        tempoRefundRecipient: refund,
    }
}

fn withdrawal(
    to: Address,
    amount: u128,
    gas_limit: u64,
    fallback_nonce: u64,
) -> ZonePortal::Withdrawal {
    ZonePortal::Withdrawal {
        token: PATH_USD_ADDRESS,
        senderTag: B256::repeat_byte(9),
        to,
        amount,
        memo: B256::ZERO,
        gasLimit: gas_limit,
        fallbackNonce: fallback_nonce,
        callbackData: Bytes::new(),
        encryptedSender: Bytes::new(),
    }
}

/// A batch: its index (also its zone height), Tempo anchor, zone block transition, processed
/// deposit and token counts (before, after), and the withdrawals it queues.
struct Batch {
    index: u64,
    tempo_block: u64,
    anchor_hash: B256,
    prev_block_hash: B256,
    next_block_hash: B256,
    deposits: (u64, u64),
    tokens: (u64, u64),
    withdrawal_queue_hash: B256,
}

/// `batch` as the portal's only sequencer signs and submits it.
fn submit_batch(portal: Address, batch: Batch) -> ZonePortal::submitBatch_1Call {
    let Batch {
        index: batch_index,
        tempo_block,
        anchor_hash,
        prev_block_hash,
        next_block_hash,
        deposits,
        tokens,
        withdrawal_queue_hash,
    } = batch;
    let block_transition = BlockTransition {
        prevBlockHash: prev_block_hash,
        nextBlockHash: next_block_hash,
    };
    let deposit_transition = DepositQueueTransition {
        prevProcessedHash: B256::ZERO,
        nextProcessedHash: B256::ZERO,
        prevDepositNumber: deposits.0,
        nextDepositNumber: deposits.1,
    };
    let token_transition = TokenEnablementTransition {
        prevProcessedTokenCount: tokens.0,
        nextProcessedTokenCount: tokens.1,
    };
    let zone_height = U256::from(batch_index);
    let typehash = keccak256(
        "SettlementAttestation(uint32 zoneId,uint64 sequencerSetVersion,uint256 zoneHeight,uint256 withdrawalBatchIndex,address verifier,uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,bytes32 blockTransitionHash,bytes32 depositQueueTransitionHash,bytes32 tokenEnablementTransitionHash,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)",
    );
    let struct_hash = keccak256(
        (
            typehash,
            1u32,
            0u64,
            zone_height,
            U256::from(batch_index),
            ZONE_VERIFIER_ADDRESS,
            tempo_block,
            tempo_block,
            anchor_hash,
            keccak256(block_transition.abi_encode()),
            keccak256(deposit_transition.abi_encode()),
            keccak256(token_transition.abi_encode()),
            withdrawal_queue_hash,
            keccak256(Bytes::new()),
        )
            .abi_encode(),
    );
    let domain = keccak256(
        (
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("ZonePortal"),
            keccak256("1"),
            U256::from(MODERATO_CHAIN_ID),
            portal,
        )
            .abi_encode(),
    );
    let digest = keccak256([&[0x19, 0x01][..], domain.as_slice(), struct_hash.as_slice()].concat());
    let signature = sequencer_key().sign_hash_sync(&digest).unwrap();
    ZonePortal::submitBatch_1Call {
        tempoBlockNumber: tempo_block,
        recentTempoBlockNumber: 0,
        blockTransition: block_transition,
        depositQueueTransition: deposit_transition,
        tokenEnablementTransition: token_transition,
        withdrawalQueueHash: withdrawal_queue_hash,
        verifierConfig: Bytes::new(),
        proof: Bytes::new(),
        nextZoneHeight: zone_height,
        signatures: vec![signature.as_bytes().into()],
    }
}

/// A contract that accepts every withdrawal callback: it returns `onWithdrawalReceived`'s selector.
const RECEIVER: Address = address!("00000000000000000000000000000000000000cb");

fn receiver_code() -> Bytes {
    let mut code = vec![0x63]; // PUSH4 selector
    code.extend_from_slice(&SwapAndDepositRouter::onWithdrawalReceivedCall::SELECTOR);
    // PUSH1 224, SHL, PUSH0, MSTORE, PUSH1 32, PUSH0, RETURN
    code.extend_from_slice(&[0x60, 0xe0, 0x1b, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
    code.into()
}

/// The dev genesis with [`RECEIVER`] deployed.
fn pre_state() -> PreState {
    let receiver = AccountInput {
        code: receiver_code(),
        ..Default::default()
    };
    PreState::Genesis(StateInput {
        accounts: BTreeMap::from([(RECEIVER, receiver)]),
    })
}

/// Two blocks at `fork` that create zone 1 and run its portal through governance, encryption keys,
/// deposits, a batch and withdrawals, interleaved with calls the portal must refuse; and whether
/// each transaction must succeed.
fn scenario(fork: TempoHardfork) -> (Vec<TempoBlock>, Vec<bool>) {
    let portal = portal_address(1);
    let sequencer = sequencer_key().address();
    let mut txs = Txs::default();
    let mut expected = Vec::new();
    let params = IZoneFactory::CreateZoneParams {
        initialToken: PATH_USD_ADDRESS,
        accessMode: false,
        gatewayMode: false,
        allowedAccounts: vec![],
        zoneGateways: vec![],
        admin: ADMIN,
        sequencers: vec![sequencer],
        threshold: 1,
        rpcUrl: "https://zone".into(),
    };
    let migrate = ITIP403Registry::migrateTransferPolicyIdsCall {
        tokens: vec![PATH_USD_ADDRESS, SECOND_TOKEN],
    };
    let approve = ITIP20::approveCall {
        spender: portal,
        amount: U256::MAX,
    };
    // The factory refuses zones whose token has no registered transfer policy.
    txs.call(
        OWNER,
        TIP403_REGISTRY_ADDRESS,
        migrate.abi_encode(),
        1_000_000,
    );
    txs.call(
        OWNER,
        ZONE_FACTORY_ADDRESS,
        IZoneFactory::createZoneCall { params }.abi_encode(),
        30_000_000,
    );
    txs.call(OWNER, PATH_USD_ADDRESS, approve.abi_encode(), 1_000_000);
    expected.extend([true, true, true]);
    macro_rules! on_portal {
        ($from:expr, $call:expr, $succeeds:expr) => {{
            txs.call($from, portal, $call.abi_encode(), 5_000_000);
            expected.push($succeeds);
        }};
    }
    on_portal!(
        ADMIN,
        ZonePortal::setZoneGasRateCall { newZoneGasRate: 1 },
        true
    );
    on_portal!(
        MALLORY,
        ZonePortal::setZoneGasRateCall { newZoneGasRate: 5 },
        false
    );
    // Above MAX_GAS_FEE_RATE.
    let too_high = 1_000_000_000_000_000_001;
    on_portal!(
        ADMIN,
        ZonePortal::setZoneGasRateCall {
            newZoneGasRate: too_high
        },
        false
    );
    on_portal!(
        ADMIN,
        ZonePortal::setBouncebackGasCall {
            newBouncebackGas: 50_000
        },
        true
    );
    on_portal!(
        ADMIN,
        ZonePortal::setMaxTempoGasRateCall {
            newMaxTempoGasRate: 1_000
        },
        true
    );
    on_portal!(sequencer, set_encryption_key(portal), true);
    on_portal!(MALLORY, set_encryption_key(portal), false);
    on_portal!(OWNER, deposit(1_000_000, OWNER), true);
    on_portal!(OWNER, deposit(1_000_000, Address::ZERO), false);
    on_portal!(
        MALLORY,
        ZonePortal::pauseDepositsCall {
            token: PATH_USD_ADDRESS
        },
        false
    );
    on_portal!(
        ADMIN,
        ZonePortal::pauseDepositsCall {
            token: PATH_USD_ADDRESS
        },
        true
    );
    on_portal!(OWNER, deposit(1_000_000, OWNER), false);
    on_portal!(
        ADMIN,
        ZonePortal::resumeDepositsCall {
            token: PATH_USD_ADDRESS
        },
        true
    );
    on_portal!(OWNER, deposit(2_000_000, OWNER), true);
    on_portal!(
        MALLORY,
        ZonePortal::transferAdminCall { newAdmin: MALLORY },
        false
    );
    on_portal!(
        ADMIN,
        ZonePortal::transferAdminCall {
            newAdmin: NEW_ADMIN
        },
        true
    );
    on_portal!(MALLORY, ZonePortal::acceptAdminCall {}, false);
    on_portal!(NEW_ADMIN, ZonePortal::acceptAdminCall {}, true);
    let first = txs.block(fork, 1);

    // A plain transfer, a deposit bounce-back delivered and one parked as a refund, a
    // withdrawal over the callback gas cap that bounces back, and a callback.
    let withdrawals = vec![
        withdrawal(RECIPIENT, 1_000, 0, 1),
        withdrawal(OWNER, 500, 0, 0),
        withdrawal(RECIPIENT, 700, 20_000_000, 2),
        withdrawal(Address::ZERO, 300, 0, 0),
        withdrawal(RECEIVER, 200, 100_000, 3),
    ];
    let anchor = B256::repeat_byte(0xab);
    let batch = submit_batch(
        portal,
        Batch {
            index: 1,
            tempo_block: 1,
            anchor_hash: anchor,
            prev_block_hash: B256::ZERO,
            next_block_hash: B256::repeat_byte(0xb1),
            deposits: (0, 2),
            tokens: (0, 1),
            withdrawal_queue_hash: withdrawal_chain(&withdrawals, B256::ZERO),
        },
    );
    let process = ZonePortal::processWithdrawalsCall {
        withdrawals,
        remainingQueue: B256::ZERO,
    };
    on_portal!(MALLORY, batch, false);
    on_portal!(sequencer, batch, true);
    on_portal!(
        ADMIN,
        ZonePortal::enableTokenCall {
            token: SECOND_TOKEN
        },
        false
    );
    on_portal!(
        NEW_ADMIN,
        ZonePortal::enableTokenCall {
            token: SECOND_TOKEN
        },
        true
    );
    on_portal!(MALLORY, process, false);
    on_portal!(sequencer, process, true);
    on_portal!(
        MALLORY,
        ZonePortal::claimRefundCall {
            token: PATH_USD_ADDRESS
        },
        true
    );
    on_portal!(
        NEW_ADMIN,
        ZonePortal::setZoneGasRateCall { newZoneGasRate: 2 },
        true
    );
    on_portal!(OWNER, deposit(3_000_000, OWNER), true);
    let second = txs.block_after(fork, 2, anchor);
    (vec![first, second], expected)
}

/// The portal checks, state and step.
fn portal_checks() -> impl Iterator<Item = &'static str> {
    portal::CHECKS
        .iter()
        .map(|check| check.id)
        .chain(portal::STEP_CHECKS.iter().map(|check| check.id))
}

#[test]
fn a_zone_runs_through_its_portal_without_breaking_an_invariant() {
    let (blocks, expected) = scenario(TempoHardfork::T12);
    let outcome = run(pre_state(), blocks);

    assert_eq!(outcome.error, ErrorClass::None);
    assert!(
        outcome.invariant_failures.is_empty(),
        "{:#?}",
        outcome.invariant_failures
    );
    let succeeded: Vec<bool> = outcome
        .receipts
        .iter()
        .map(|receipt| receipt.outcome == TxOutcome::Success)
        .collect();
    assert_eq!(succeeded, expected, "{:#?}", outcome.receipts);
    for id in portal_checks().chain([portal::VIEW]) {
        let counts = &outcome.invariant_counts[id];
        assert!(counts.armed > 0, "{id} is never armed: {counts:?}");
        assert_eq!(counts.fired, 0, "{id}");
    }
}

/// From T13 the native zone verifier rejects the stub proof, so only the first block runs.
#[test]
fn a_zone_created_at_t13_breaks_no_invariant() {
    let (mut blocks, expected) = scenario(TempoHardfork::T13);
    blocks.truncate(1);
    let outcome = run(pre_state(), blocks);

    assert_eq!(outcome.error, ErrorClass::None);
    let succeeded: Vec<bool> = outcome
        .receipts
        .iter()
        .map(|receipt| receipt.outcome == TxOutcome::Success)
        .collect();
    assert_eq!(succeeded, expected[..succeeded.len()]);
    assert!(
        outcome.invariant_failures.is_empty(),
        "{:#?}",
        outcome.invariant_failures
    );
    assert!(outcome.invariant_counts[portal::DEPOSIT_QUEUE_HASH].armed > 0);
}
