//! Privacy-enforced log filtering for the zone's redacted RPC.
//!
//! Only whitelisted TIP-20 and receipt-recovery event logs are returned to callers. A caller must
//! appear in an eligible indexed topic or, for `TransferBlocked`, be a stakeholder encoded in the
//! claim receipt. This prevents users from observing other users' token activity.

use alloy_consensus::TxReceipt;
use alloy_network::ReceiptResponse;
use alloy_primitives::{Address, B256};
use alloy_rpc_types_eth::{Filter, FilterSet, Log};
use alloy_sol_types::SolEvent;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::precompiles::{IReceivePolicyGuard, ITIP20, RECEIVE_POLICY_GUARD_ADDRESS};

use crate::types::JsonRpcError;

/// `Transfer(address,address,uint256)`
pub const TRANSFER_TOPIC: B256 = ITIP20::Transfer::SIGNATURE_HASH;

/// `Approval(address,address,uint256)`
pub const APPROVAL_TOPIC: B256 = ITIP20::Approval::SIGNATURE_HASH;

/// `TransferWithMemo(address,address,uint256,bytes32)`
pub const TRANSFER_WITH_MEMO_TOPIC: B256 = ITIP20::TransferWithMemo::SIGNATURE_HASH;

/// `Mint(address,uint256)`
pub const MINT_TOPIC: B256 = ITIP20::Mint::SIGNATURE_HASH;

/// `Burn(address,uint256)`
pub const BURN_TOPIC: B256 = ITIP20::Burn::SIGNATURE_HASH;

/// `TransferBlocked(address,address,uint64,uint256,uint8,bytes)`.
pub const TRANSFER_BLOCKED_TOPIC: B256 = IReceivePolicyGuard::TransferBlocked::SIGNATURE_HASH;

/// All event topic hashes exposed by the redacted RPC.
pub const WHITELISTED_TOPICS: [B256; 6] = [
    TRANSFER_TOPIC,
    APPROVAL_TOPIC,
    TRANSFER_WITH_MEMO_TOPIC,
    MINT_TOPIC,
    BURN_TOPIC,
    TRANSFER_BLOCKED_TOPIC,
];

const TWO_PARTY_TOPICS: [B256; 4] = [
    TRANSFER_TOPIC,
    APPROVAL_TOPIC,
    TRANSFER_WITH_MEMO_TOPIC,
    TRANSFER_BLOCKED_TOPIC,
];
const CALLER_SCOPED_FILTER_ERROR: &str =
    "private log filter must include authenticated caller in topic1 or topic2";

/// Returns `true` if `caller` appears in an eligible indexed-topic position
/// for the log's event type.
///
/// Topic positions checked per event:
/// - **Transfer / TransferWithMemo**: topic1 (from) or topic2 (to)
/// - **Approval**: topic1 (owner) or topic2 (spender)
/// - **Mint**: topic1 (to)
/// - **Burn**: topic1 (from)
/// - **TransferBlocked**: the indexed receiver, or the originator/recovery authority encoded in
///   the receipt
pub fn is_caller_eligible(log: &Log, caller: &Address) -> bool {
    let topics = log.topics();
    let Some(topic0) = log.topic0() else {
        return false;
    };

    let caller_word = caller.into_word();

    if *topic0 == TRANSFER_BLOCKED_TOPIC {
        return is_transfer_blocked_caller_eligible(log, caller);
    }

    if *topic0 == TRANSFER_TOPIC || *topic0 == APPROVAL_TOPIC || *topic0 == TRANSFER_WITH_MEMO_TOPIC
    {
        // topic1 or topic2 must match caller
        topics.get(1) == Some(&caller_word) || topics.get(2) == Some(&caller_word)
    } else if *topic0 == MINT_TOPIC || *topic0 == BURN_TOPIC {
        // topic1 must match caller
        topics.get(1) == Some(&caller_word)
    } else {
        false
    }
}

/// Returns whether the authenticated caller is a stakeholder in a receipt-bearing
/// `ReceivePolicyGuard.TransferBlocked` log.
fn is_transfer_blocked_caller_eligible(log: &Log, caller: &Address) -> bool {
    if log.address() != RECEIVE_POLICY_GUARD_ADDRESS {
        return false;
    }

    let Ok(event) = IReceivePolicyGuard::TransferBlocked::decode_log(&log.inner) else {
        return false;
    };
    let event = event.data;
    let Ok(receipt) = IReceivePolicyGuard::ClaimReceiptV1::try_from(event.receipt) else {
        return false;
    };

    *caller == event.receiver
        || *caller == receipt.originator
        || (!receipt.recoveryAuthority.is_zero() && *caller == receipt.recoveryAuthority)
}

/// Filters logs to only those the caller is allowed to see.
///
/// A log is included only when **both** of the following hold:
/// 1. Its topic0 is one of the [`WHITELISTED_TOPICS`].
/// 2. The `caller` is eligible per [`is_caller_eligible`].
pub fn is_log_visible(log: &Log, caller: &Address) -> bool {
    log.topic0().is_some_and(|t| WHITELISTED_TOPICS.contains(t)) && is_caller_eligible(log, caller)
}

/// Renumbers ordering fields on a sequence of logs so that
/// `(transactionHash, logIndex)` is stable and per-tx, without leaking
/// how many other logs preceded them.
///
/// `logIndex` restarts at `0` for each new tx and increments for each
/// subsequent log within that same tx.
/// `transactionIndex` is always zeroed to hide ordering within the block.
#[derive(Default)]
pub struct LogOrderingRedactor {
    current_tx: Option<B256>,
    next_index: u64,
}

impl LogOrderingRedactor {
    /// Redact the ordering fields of a single already-visible log.
    pub fn redact(&mut self, mut log: Log) -> Log {
        if self.current_tx != log.transaction_hash {
            self.current_tx = log.transaction_hash;
            self.next_index = 0;
        }
        log.transaction_index = Some(0);
        log.log_index = Some(self.next_index);
        self.next_index += 1;
        log
    }
}

/// Filters logs to only those the caller is allowed to see, renumbering the
/// `log_index` via [`LogOrderingRedactor`].
pub fn filter_logs(logs: Vec<Log>, caller: &Address) -> Vec<Log> {
    let mut redactor = LogOrderingRedactor::default();
    logs.into_iter()
        .filter(|log| is_log_visible(log, caller))
        .map(|log| redactor.redact(log))
        .collect()
}

/// Filters a receipt's logs for its sender and recomputes `logsBloom`.
pub fn filter_receipt_logs(mut receipt: TempoTransactionReceipt) -> TempoTransactionReceipt {
    let caller = receipt.from();
    receipt.inner.transaction_index = Some(0);
    receipt.inner.inner.receipt.cumulative_gas_used = receipt.inner.gas_used;
    let logs = core::mem::take(&mut receipt.inner.inner.receipt.logs);
    receipt.inner.inner.receipt.logs = filter_logs(logs, &caller);
    receipt.inner.inner.logs_bloom = receipt.inner.inner.receipt.bloom();
    receipt
}

/// Scopes a user-supplied filter to enabled zone tokens and the receive-policy guard.
pub fn scope_filter_addresses(
    filter: &mut Filter,
    zone_tokens: &[Address],
) -> Result<(), JsonRpcError> {
    let requested_addresses: Vec<Address> = filter.address.iter().copied().collect();

    if requested_addresses.is_empty() {
        let mut allowed_addresses = zone_tokens.to_vec();
        allowed_addresses.push(RECEIVE_POLICY_GUARD_ADDRESS);
        filter.address = FilterSet::from(allowed_addresses);
        return Ok(());
    }

    if requested_addresses
        .iter()
        .all(|address| zone_tokens.contains(address) || *address == RECEIVE_POLICY_GUARD_ADDRESS)
    {
        Ok(())
    } else {
        Err(JsonRpcError::invalid_params("invalid filter address"))
    }
}

/// Scopes a user-supplied filter to only match whitelisted event topics.
///
/// Intersects the user's requested topic0 with [`WHITELISTED_TOPICS`].
/// If the user omitted topic0, restricts to the whitelisted set.
/// If the intersection is empty, sets topic0 to a dummy that will match nothing.
///
/// The post-filter in [`filter_logs`] remains the actual privacy enforcement;
/// this pre-filter reduces DB scan volume and timing side-channels.
pub fn scope_filter(filter: &mut Filter) {
    // --- Topic0 scoping ---
    let user_topic0: Vec<B256> = filter.topics[0].iter().copied().collect();

    let scoped_topic0: Vec<B256> = if user_topic0.is_empty() {
        // User didn't specify — restrict to whitelisted events
        WHITELISTED_TOPICS.to_vec()
    } else {
        // Intersect user's requested topics with whitelist
        user_topic0
            .into_iter()
            .filter(|t| WHITELISTED_TOPICS.contains(t))
            .collect()
    };

    if scoped_topic0.is_empty() {
        // No matching topics — use a dummy topic that will never match
        filter.topics[0] = FilterSet::from(B256::ZERO);
    } else {
        filter.topics[0] = FilterSet::from(scoped_topic0);
    }
}

/// Scopes a user-supplied filter to whitelisted event topics and requires the
/// authenticated caller to appear in an eligible indexed topic before backend
/// log retrieval.
pub fn scope_filter_for_caller(filter: &mut Filter, caller: &Address) -> Result<(), JsonRpcError> {
    scope_filter(filter);
    if filter.topics[0].len() == 1 && filter.topics[0].contains(&B256::ZERO) {
        return Ok(());
    }

    let caller_word = caller.into_word();
    if filter.topics[1].contains(&caller_word) {
        let topic0 = filter.topics[0]
            .iter()
            .copied()
            .filter(|topic| *topic != TRANSFER_BLOCKED_TOPIC)
            .collect::<Vec<_>>();
        if !topic0.is_empty() {
            filter.topics[0] = FilterSet::from(topic0);
            filter.topics[1] = FilterSet::from(caller_word);
            return Ok(());
        }
    }

    if filter.topics[2].contains(&caller_word) {
        let topic0 = filter.topics[0]
            .iter()
            .copied()
            .filter(|topic| TWO_PARTY_TOPICS.contains(topic))
            .collect::<Vec<_>>();
        if !topic0.is_empty() {
            filter.topics[0] = FilterSet::from(topic0);
            filter.topics[2] = FilterSet::from(caller_word);
            return Ok(());
        }
    }

    Err(JsonRpcError::invalid_params(CALLER_SCOPED_FILTER_ERROR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::ReceiptWithBloom;
    use alloy_primitives::{Address, Bytes, LogData, TxHash, U256, address, keccak256};
    use alloy_rpc_types_eth::TransactionReceipt;
    use alloy_sol_types::SolValue;
    use tempo_alloy::rpc::TempoTransactionReceipt;
    use tempo_primitives::{TempoReceipt, TempoTxType};

    /// Build a test `Log` with the given emitting address and topics.
    fn make_log(emitter: Address, topics: Vec<B256>) -> Log {
        Log {
            inner: alloy_primitives::Log {
                address: emitter,
                data: LogData::new_unchecked(topics, Bytes::new()),
            },
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        }
    }

    /// Build a test `Log` carrying real (pre-redaction) ordering metadata so
    /// tests can assert the ordering fields are actually rewritten.
    fn make_log_in_tx(emitter: Address, topics: Vec<B256>, tx_hash: B256, log_index: u64) -> Log {
        let mut log = make_log(emitter, topics);
        log.transaction_hash = Some(tx_hash);
        log.transaction_index = Some(42);
        log.log_index = Some(log_index);
        log
    }

    fn make_transfer_blocked_log(
        emitter: Address,
        receiver: Address,
        originator: Address,
        recovery_authority: Address,
    ) -> Log {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let receipt = IReceivePolicyGuard::ClaimReceiptV1::new(
            token,
            recovery_authority,
            originator,
            receiver,
            1_234,
            42,
            1,
            IReceivePolicyGuard::InboundKind::TRANSFER,
            B256::ZERO,
        );
        let event = IReceivePolicyGuard::TransferBlocked {
            token,
            receiver,
            blockedNonce: receipt.blockedNonce,
            amount: U256::from(100),
            receiptVersion: receipt.version,
            receipt: receipt.abi_encode().into(),
        };
        let mut log = make_log(emitter, Vec::new());
        log.inner.data = event.encode_log_data();
        log
    }

    fn make_receipt(from: Address, logs: Vec<Log>) -> TempoTransactionReceipt {
        let receipt = TempoReceipt {
            tx_type: TempoTxType::Legacy,
            success: true,
            cumulative_gas_used: 21_000,
            logs,
        };

        TempoTransactionReceipt {
            inner: TransactionReceipt {
                inner: ReceiptWithBloom::from(receipt),
                transaction_hash: TxHash::with_last_byte(1),
                transaction_index: Some(0),
                block_hash: Some(B256::with_last_byte(2)),
                block_number: Some(1),
                gas_used: 21_000,
                effective_gas_price: 1,
                blob_gas_used: None,
                blob_gas_price: None,
                from,
                to: Some(Address::ZERO),
                contract_address: None,
            },
            fee_token: None,
            fee_payer: from,
        }
    }

    // ---------------------------------------------------------------
    // is_caller_eligible — Transfer
    // ---------------------------------------------------------------

    #[test]
    fn transfer_eligible_as_sender() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, caller.into_word(), other.into_word()],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn transfer_eligible_as_receiver() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, other.into_word(), caller.into_word()],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn transfer_rejected_when_not_participant() {
        let caller = Address::with_last_byte(1);
        let a = Address::with_last_byte(2);
        let b = Address::with_last_byte(3);
        let log = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, a.into_word(), b.into_word()],
        );
        assert!(!is_caller_eligible(&log, &caller));
    }

    // ---------------------------------------------------------------
    // is_caller_eligible — Approval
    // ---------------------------------------------------------------

    #[test]
    fn approval_eligible_as_owner() {
        let caller = Address::with_last_byte(1);
        let spender = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![APPROVAL_TOPIC, caller.into_word(), spender.into_word()],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn approval_eligible_as_spender() {
        let caller = Address::with_last_byte(1);
        let owner = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![APPROVAL_TOPIC, owner.into_word(), caller.into_word()],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn approval_rejected_when_not_participant() {
        let caller = Address::with_last_byte(1);
        let a = Address::with_last_byte(2);
        let b = Address::with_last_byte(3);
        let log = make_log(
            Address::ZERO,
            vec![APPROVAL_TOPIC, a.into_word(), b.into_word()],
        );
        assert!(!is_caller_eligible(&log, &caller));
    }

    // ---------------------------------------------------------------
    // is_caller_eligible — TransferWithMemo
    // ---------------------------------------------------------------

    #[test]
    fn transfer_with_memo_eligible_as_sender() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![
                TRANSFER_WITH_MEMO_TOPIC,
                caller.into_word(),
                other.into_word(),
            ],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn transfer_with_memo_eligible_as_receiver() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![
                TRANSFER_WITH_MEMO_TOPIC,
                other.into_word(),
                caller.into_word(),
            ],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn transfer_with_memo_rejected_when_not_participant() {
        let caller = Address::with_last_byte(1);
        let a = Address::with_last_byte(2);
        let b = Address::with_last_byte(3);
        let log = make_log(
            Address::ZERO,
            vec![TRANSFER_WITH_MEMO_TOPIC, a.into_word(), b.into_word()],
        );
        assert!(!is_caller_eligible(&log, &caller));
    }

    // ---------------------------------------------------------------
    // is_caller_eligible — Mint / Burn
    // ---------------------------------------------------------------

    #[test]
    fn mint_eligible_as_recipient() {
        let caller = Address::with_last_byte(1);
        let log = make_log(Address::ZERO, vec![MINT_TOPIC, caller.into_word()]);
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn mint_rejected_when_not_recipient() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let log = make_log(Address::ZERO, vec![MINT_TOPIC, other.into_word()]);
        assert!(!is_caller_eligible(&log, &caller));
    }

    #[test]
    fn burn_eligible_as_burner() {
        let caller = Address::with_last_byte(1);
        let log = make_log(Address::ZERO, vec![BURN_TOPIC, caller.into_word()]);
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn burn_rejected_when_not_burner() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let log = make_log(Address::ZERO, vec![BURN_TOPIC, other.into_word()]);
        assert!(!is_caller_eligible(&log, &caller));
    }

    // ---------------------------------------------------------------
    // is_caller_eligible — TransferBlocked
    // ---------------------------------------------------------------

    #[test]
    fn transfer_blocked_visibility_is_receipt_scoped() {
        let receiver = Address::with_last_byte(1);
        let originator = Address::with_last_byte(2);
        let recovery = Address::with_last_byte(3);
        let outsider = Address::with_last_byte(4);
        let log =
            make_transfer_blocked_log(RECEIVE_POLICY_GUARD_ADDRESS, receiver, originator, recovery);

        assert!(is_log_visible(&log, &receiver));
        assert!(is_log_visible(&log, &originator));
        assert!(is_log_visible(&log, &recovery));
        assert!(!is_log_visible(&log, &outsider));

        let filtered = filter_receipt_logs(make_receipt(originator, vec![log.clone()]));
        assert_eq!(filtered.inner.logs().len(), 1);

        let mut spoofed = log.clone();
        spoofed.inner.address = Address::ZERO;
        assert!(!is_log_visible(&spoofed, &receiver));

        let mut malformed = log;
        malformed.inner.data.data = Bytes::new();
        assert!(!is_log_visible(&malformed, &receiver));
    }

    // ---------------------------------------------------------------
    // is_caller_eligible — unknown / empty topic
    // ---------------------------------------------------------------

    #[test]
    fn unknown_topic_rejected() {
        let caller = Address::with_last_byte(1);
        let unknown = B256::with_last_byte(0xff);
        let log = make_log(Address::ZERO, vec![unknown, caller.into_word()]);
        assert!(!is_caller_eligible(&log, &caller));
    }

    #[test]
    fn empty_topics_rejected() {
        let caller = Address::with_last_byte(1);
        let log = make_log(Address::ZERO, vec![]);
        assert!(!is_caller_eligible(&log, &caller));
    }

    // ---------------------------------------------------------------
    // filter_logs
    // ---------------------------------------------------------------

    #[test]
    fn filter_logs_keeps_eligible_and_drops_others() {
        let zone_token = address!("0x000000000000000000000000000000000000aaaa");
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);

        let eligible = make_log(
            zone_token,
            vec![TRANSFER_TOPIC, caller.into_word(), other.into_word()],
        );
        let wrong_topic = make_log(
            zone_token,
            vec![B256::with_last_byte(0x01), caller.into_word()],
        );
        let not_eligible = make_log(
            zone_token,
            vec![TRANSFER_TOPIC, other.into_word(), other.into_word()],
        );

        let logs = vec![eligible.clone(), wrong_topic, not_eligible];
        let result = filter_logs(logs, &caller);

        assert_eq!(result.len(), 1);
        let mut expected = eligible;
        expected.transaction_index = Some(0);
        expected.log_index = Some(0);
        assert_eq!(result[0], expected);
    }

    #[test]
    fn filter_logs_empty_input() {
        let caller = Address::with_last_byte(1);
        let result = filter_logs(vec![], &caller);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_logs_renumbers_log_index_per_transaction() {
        let zone_token = address!("0x000000000000000000000000000000000000aaaa");
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);

        let tx_a = B256::with_last_byte(0xaa);
        let tx_b = B256::with_last_byte(0xbb);

        // tx A: two caller-visible logs separated by one the caller can't see.
        // Real (block-global) log indices are non-contiguous and must be erased.
        let a_visible_0 = make_log_in_tx(
            zone_token,
            vec![TRANSFER_TOPIC, caller.into_word(), other.into_word()],
            tx_a,
            7,
        );
        let a_hidden = make_log_in_tx(
            zone_token,
            vec![TRANSFER_TOPIC, other.into_word(), other.into_word()],
            tx_a,
            8,
        );
        let a_visible_1 = make_log_in_tx(
            zone_token,
            vec![APPROVAL_TOPIC, caller.into_word(), other.into_word()],
            tx_a,
            9,
        );
        // tx B: a single caller-visible log; numbering must restart at 0.
        let b_visible_0 = make_log_in_tx(
            zone_token,
            vec![TRANSFER_TOPIC, other.into_word(), caller.into_word()],
            tx_b,
            3,
        );

        let result = filter_logs(
            vec![a_visible_0, a_hidden, a_visible_1, b_visible_0],
            &caller,
        );

        // Only the caller's three logs survive, in order.
        let ordering: Vec<_> = result
            .iter()
            .map(|log| (log.transaction_hash, log.transaction_index, log.log_index))
            .collect();
        assert_eq!(
            ordering,
            vec![
                // tx A: renumbered 0, 1 among the caller's visible logs.
                (Some(tx_a), Some(0), Some(0)),
                (Some(tx_a), Some(0), Some(1)),
                // tx B: restarts at 0.
                (Some(tx_b), Some(0), Some(0)),
            ]
        );
    }

    #[test]
    fn log_ordering_is_consistent_between_batch_and_stream() {
        // The same visible logs numbered once via `filter_logs` (the batch
        // `eth_getLogs` path) and once by driving `LogOrderingRedactor` a log at a
        // time (the `eth_subscribe("logs")` stream path) must agree, so a log's
        // `(transactionHash, logIndex)` is identical regardless of which RPC
        // surfaced it.
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let tx_a = B256::with_last_byte(0xaa);
        let tx_b = B256::with_last_byte(0xbb);

        let visible = vec![
            make_log_in_tx(
                Address::ZERO,
                vec![TRANSFER_TOPIC, caller.into_word(), other.into_word()],
                tx_a,
                5,
            ),
            make_log_in_tx(
                Address::ZERO,
                vec![APPROVAL_TOPIC, caller.into_word(), other.into_word()],
                tx_a,
                6,
            ),
            make_log_in_tx(
                Address::ZERO,
                vec![TRANSFER_TOPIC, other.into_word(), caller.into_word()],
                tx_b,
                9,
            ),
        ];

        let batch = filter_logs(visible.clone(), &caller);

        // Mirror the WS stream: filter, then feed survivors one at a time.
        let mut redactor = LogOrderingRedactor::default();
        let streamed: Vec<Log> = visible
            .into_iter()
            .filter(|log| is_log_visible(log, &caller))
            .map(|log| redactor.redact(log))
            .collect();

        assert_eq!(batch, streamed);
        let indices: Vec<_> = batch
            .iter()
            .map(|log| (log.transaction_index, log.log_index))
            .collect();
        assert_eq!(
            indices,
            vec![(Some(0), Some(0)), (Some(0), Some(1)), (Some(0), Some(0))]
        );
    }

    #[test]
    fn filter_receipt_logs_recomputes_logs_and_bloom() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let third = Address::with_last_byte(3);
        let hidden_topic = keccak256(b"PolicyUpdated(address,uint256)");

        let visible = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, caller.into_word(), other.into_word()],
        );
        let hidden_transfer = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, other.into_word(), third.into_word()],
        );
        let hidden_event = make_log(Address::ZERO, vec![hidden_topic, caller.into_word()]);

        let filtered = filter_receipt_logs(make_receipt(
            caller,
            vec![
                visible.clone(),
                hidden_transfer.clone(),
                hidden_event.clone(),
            ],
        ));

        let mut expected_visible = visible;
        expected_visible.transaction_index = Some(0);
        expected_visible.log_index = Some(0);

        assert_eq!(
            filtered.inner.logs(),
            std::slice::from_ref(&expected_visible)
        );
        assert_eq!(filtered.inner.transaction_index, Some(0));
        assert_eq!(
            filtered.inner.inner.receipt.cumulative_gas_used,
            filtered.inner.gas_used
        );
        assert_eq!(
            filtered.inner.inner.logs_bloom,
            alloy_primitives::logs_bloom(filtered.inner.logs().iter().map(|log| log.as_ref())),
        );
        assert_ne!(
            filtered.inner.inner.logs_bloom,
            alloy_primitives::logs_bloom(
                [expected_visible, hidden_transfer, hidden_event]
                    .iter()
                    .map(|log| log.as_ref())
            ),
        );
    }

    // ---------------------------------------------------------------
    // scope_filter
    // ---------------------------------------------------------------

    #[test]
    fn scope_filter_scopes_topic0() {
        let mut filter = Filter::default();
        scope_filter(&mut filter);
        for topic in &WHITELISTED_TOPICS {
            assert!(filter.topics[0].contains(topic));
        }
        assert_eq!(filter.topics[0].len(), WHITELISTED_TOPICS.len());
    }

    #[test]
    fn scope_filter_intersects_topic0() {
        let bogus_topic = B256::with_last_byte(0xff);
        let mut filter = Filter::default();
        filter.topics[0] = FilterSet::from(vec![TRANSFER_TOPIC, bogus_topic]);
        scope_filter(&mut filter);
        assert!(filter.topics[0].contains(&TRANSFER_TOPIC));
        assert!(!filter.topics[0].contains(&bogus_topic));
        assert_eq!(filter.topics[0].len(), 1);
    }

    #[test]
    fn scope_filter_empty_intersection() {
        let bogus = B256::with_last_byte(0xff);
        let mut filter = Filter::default();
        filter.topics[0] = FilterSet::from(bogus);
        scope_filter(&mut filter);
        assert_eq!(filter.topics[0], FilterSet::from(B256::ZERO));
    }

    #[test]
    fn scope_filter_for_caller_rejects_broad_filter() {
        let caller = Address::with_last_byte(1);
        let mut filter = Filter::default();

        let err = scope_filter_for_caller(&mut filter, &caller).unwrap_err();

        assert_eq!(err.code, JsonRpcError::invalid_params("").code);
        assert_eq!(err.message, CALLER_SCOPED_FILTER_ERROR);
    }

    #[test]
    fn scope_filter_for_caller_scopes_topic1_caller() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let caller_topic = caller.into_word();
        let other_topic = other.into_word();
        let mut filter = Filter::default();
        filter.topics[1] = FilterSet::from(vec![caller_topic, other_topic]);
        filter.topics[2] = FilterSet::from(other_topic);

        scope_filter_for_caller(&mut filter, &caller).unwrap();

        assert!(!filter.topics[0].contains(&TRANSFER_BLOCKED_TOPIC));
        assert_eq!(filter.topics[0].len(), WHITELISTED_TOPICS.len() - 1);
        assert_eq!(filter.topics[1], FilterSet::from(caller_topic));
        assert_eq!(filter.topics[2], FilterSet::from(other_topic));
    }

    #[test]
    fn scope_filter_for_caller_scopes_topic2_caller_for_two_party_events() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let caller_topic = caller.into_word();
        let other_topic = other.into_word();
        let mut filter = Filter::default();
        filter.topics[0] =
            FilterSet::from(vec![TRANSFER_TOPIC, TRANSFER_BLOCKED_TOPIC, MINT_TOPIC]);
        filter.topics[1] = FilterSet::from(other_topic);
        filter.topics[2] = FilterSet::from(vec![caller_topic, other.into_word()]);

        scope_filter_for_caller(&mut filter, &caller).unwrap();

        assert_eq!(
            filter.topics[0],
            FilterSet::from(vec![TRANSFER_TOPIC, TRANSFER_BLOCKED_TOPIC])
        );
        assert_eq!(filter.topics[1], FilterSet::from(other_topic));
        assert_eq!(filter.topics[2], FilterSet::from(caller_topic));
    }

    #[test]
    fn scope_filter_for_caller_rejects_wrong_caller() {
        let caller = Address::with_last_byte(1);
        let a = Address::with_last_byte(2);
        let b = Address::with_last_byte(3);
        let mut filter = Filter::default();
        filter.topics[0] = FilterSet::from(TRANSFER_TOPIC);
        filter.topics[1] = FilterSet::from(a.into_word());
        filter.topics[2] = FilterSet::from(b.into_word());

        let err = scope_filter_for_caller(&mut filter, &caller).unwrap_err();

        assert_eq!(err.code, JsonRpcError::invalid_params("").code);
        assert_eq!(err.message, CALLER_SCOPED_FILTER_ERROR);
    }

    #[test]
    fn scope_filter_for_caller_rejects_topic2_only_for_one_party_events() {
        let caller = Address::with_last_byte(1);
        let mut filter = Filter::default();
        filter.topics[0] = FilterSet::from(MINT_TOPIC);
        filter.topics[2] = FilterSet::from(caller.into_word());

        let err = scope_filter_for_caller(&mut filter, &caller).unwrap_err();

        assert_eq!(err.code, JsonRpcError::invalid_params("").code);
        assert_eq!(err.message, CALLER_SCOPED_FILTER_ERROR);
    }

    #[test]
    fn scope_filter_addresses_scopes_omitted_address() {
        let token_a = Address::with_last_byte(0xaa);
        let token_b = Address::with_last_byte(0xbb);
        let mut filter = Filter::default();

        scope_filter_addresses(&mut filter, &[token_a, token_b]).unwrap();

        assert!(filter.address.contains(&token_a));
        assert!(filter.address.contains(&token_b));
        assert!(filter.address.contains(&RECEIVE_POLICY_GUARD_ADDRESS));
        assert_eq!(filter.address.len(), 3);
    }

    #[test]
    fn scope_filter_addresses_allows_enabled_addresses() {
        let token = Address::with_last_byte(0xaa);
        for address in [token, RECEIVE_POLICY_GUARD_ADDRESS] {
            let mut filter = Filter {
                address: FilterSet::from(address),
                ..Default::default()
            };

            scope_filter_addresses(&mut filter, &[token]).unwrap();

            assert_eq!(filter.address, FilterSet::from(address));
        }
    }

    #[test]
    fn scope_filter_addresses_rejects_non_zone_token_address() {
        let token = Address::with_last_byte(0xaa);
        let other = Address::with_last_byte(0xcc);
        let mut filter = Filter {
            address: FilterSet::from(vec![token, other]),
            ..Default::default()
        };

        let err = scope_filter_addresses(&mut filter, &[token]).unwrap_err();

        assert_eq!(err.code, JsonRpcError::invalid_params("").code);
        assert_eq!(err.message, "invalid filter address");
    }
}
