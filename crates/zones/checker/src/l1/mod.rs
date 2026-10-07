//! Collection of authenticated Tempo/L1 evidence through a full-import anchor.

mod events;

use alloy_consensus::BlockHeader as _;
use alloy_eips::{BlockId, BlockNumHash};
use alloy_network::{BlockResponse as _, primitives::HeaderResponse as _};
use alloy_primitives::{Address, B256, Bloom, Sealable as _, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_transport::{RpcError, TransportError, TransportErrorKind};
use futures::{StreamExt as _, TryStreamExt as _, stream};
use tempo_alloy::{
    TempoNetwork,
    rpc::{TempoHeaderResponse, TempoTransactionReceipt},
};
use tempo_contracts::precompiles::ITIP20;
use zone_l1::L1BlockTracker;

use crate::AttemptError;

use events::EventCollector;
pub(crate) use events::L1PortalEvent;

/// Bound on concurrent Portal balance reads for one token set.
const BALANCE_CONCURRENCY: usize = 8;

/// Failure acquiring or interpreting exact Tempo state.
#[derive(Debug)]
pub(crate) enum L1ReadError {
    /// Required RPC data is not currently available.
    Unavailable(eyre::Report),
    /// Authenticated protocol evidence cannot be verified.
    Finding(eyre::Report),
    /// Deterministic provider or checker failure prevents verification.
    Disable(eyre::Report),
}

impl From<AttemptError> for L1ReadError {
    fn from(error: AttemptError) -> Self {
        match error {
            AttemptError::Retry(error) => Self::Unavailable(error),
            AttemptError::Disable(error) => Self::Disable(error),
        }
    }
}

impl From<L1ReadError> for AttemptError {
    fn from(error: L1ReadError) -> Self {
        match error {
            L1ReadError::Unavailable(error) => Self::Retry(error),
            L1ReadError::Finding(error) | L1ReadError::Disable(error) => Self::Disable(error),
        }
    }
}

/// Recognized Portal events for an authenticated L1 block or contiguous range, in chain order.
#[derive(Debug, Default)]
pub(crate) struct L1BlockEvidence {
    events: Vec<L1PortalEvent>,
}

/// Header fields bound to the hash reported by the Tempo RPC.
pub(crate) struct ValidatedRpcHeader {
    pub(crate) block: BlockNumHash,
    pub(crate) parent_hash: B256,
    pub(crate) receipts_root: B256,
    pub(crate) logs_bloom: Bloom,
}

/// Authenticate the RPC-reported hash against the decoded Tempo header.
pub(crate) fn validate_rpc_header(
    header: &TempoHeaderResponse,
) -> Result<ValidatedRpcHeader, AttemptError> {
    let reported_hash = header.hash();
    let computed_hash = header.as_ref().hash_slow();
    if reported_hash != computed_hash {
        return Err(AttemptError::disable(eyre::eyre!(
            "Tempo RPC header hash mismatch at block {}: reported {reported_hash}, computed {computed_hash}",
            header.number()
        )));
    }
    Ok(ValidatedRpcHeader {
        block: BlockNumHash::new(header.number(), computed_hash),
        parent_hash: header.parent_hash(),
        receipts_root: header.receipts_root(),
        logs_bloom: header.logs_bloom(),
    })
}

impl L1BlockEvidence {
    /// Return authenticated Portal events in receipt order.
    pub(crate) fn portal_events(&self) -> impl Iterator<Item = &L1PortalEvent> {
        self.events.iter()
    }
}

/// Fetch every Tempo block in `(parent, expected]`, authenticating the complete parent chain.
pub(crate) async fn collect_l1_range_at(
    provider: &DynProvider<TempoNetwork>,
    tracker: &L1BlockTracker,
    portal: Address,
    parent: BlockNumHash,
    expected: BlockNumHash,
) -> Result<L1BlockEvidence, L1ReadError> {
    if expected.number <= parent.number {
        return Err(finding(eyre::eyre!(
            "Tempo full import must advance its accounting anchor"
        )));
    }
    // Walk backwards from the Zone-authenticated tip so every requested hash is bound to it.
    let mut cursor = expected;
    let mut blocks = Vec::new();
    while cursor.number > parent.number {
        let (previous, evidence) =
            if let Some(evidence) = tracker.authenticated_portal_logs(cursor).map_err(finding)? {
                let previous = BlockNumHash::new(cursor.number - 1, evidence.parent_hash);
                (
                    previous,
                    collect_tracked_l1_block_evidence(portal, previous, evidence)?,
                )
            } else {
                fetch_l1_block_at(provider, portal, cursor).await?
            };
        blocks.push(evidence);
        cursor = previous;
    }
    if cursor != parent {
        return Err(finding(eyre::eyre!(
            "Tempo history does not extend the previous accounting anchor"
        )));
    }
    Ok(L1BlockEvidence {
        events: blocks
            .into_iter()
            .rev()
            .flat_map(|block| block.events)
            .collect(),
    })
}

fn collect_tracked_l1_block_evidence(
    portal: Address,
    parent: BlockNumHash,
    evidence: zone_l1::AuthenticatedPortalLogs,
) -> Result<L1BlockEvidence, L1ReadError> {
    let expected_number = parent.number.checked_add(1).ok_or_else(|| {
        disable(eyre::eyre!(
            "Tempo block number overflow after {}",
            parent.number
        ))
    })?;
    if evidence.block.number != expected_number || evidence.parent_hash != parent.hash {
        return Err(finding(eyre::eyre!(
            "Tempo history is not contiguous at block {}",
            evidence.block.number
        )));
    }
    let mut collector = EventCollector::new(portal);
    for log in &evidence.logs {
        collector
            .extract_log(log, evidence.block.number)
            .map_err(finding)?;
    }
    Ok(L1BlockEvidence {
        events: collector.finish(),
    })
}

async fn fetch_l1_block_at(
    provider: &DynProvider<TempoNetwork>,
    portal: Address,
    expected: BlockNumHash,
) -> Result<(BlockNumHash, L1BlockEvidence), L1ReadError> {
    let number = expected.number;
    let block = provider
        .get_block_by_hash(expected.hash)
        .hashes()
        .await
        .map_err(classify_rpc_error)?
        .ok_or_else(|| unavailable(eyre::eyre!("Tempo block {number} is unavailable")))?;
    let header = validate_rpc_header(block.header()).map_err(L1ReadError::from)?;
    if header.block.number != number {
        return Err(disable(eyre::eyre!(
            "Tempo RPC returned block {} for requested block {number}",
            header.block.number
        )));
    }
    let coordinate = header.block;
    if coordinate != expected {
        return Err(finding(eyre::eyre!(
            "Tempo history does not end at the Zone anchor"
        )));
    }
    let receipts = provider
        .get_block_receipts(BlockId::hash(coordinate.hash))
        .await
        .map_err(classify_rpc_error)?
        .ok_or_else(|| {
            unavailable(eyre::eyre!(
                "no receipts for L1 block {number} ({})",
                coordinate.hash
            ))
        })?;
    zone_l1::verify_receipts_against_header(
        coordinate,
        header.receipts_root,
        header.logs_bloom,
        &receipts,
    )
    .map_err(disable)?;
    Ok((
        BlockNumHash::new(number - 1, header.parent_hash),
        collect_l1_block_evidence(portal, coordinate, &receipts)?,
    ))
}

/// Read Portal custody for one token at an exact canonical Tempo block.
pub(crate) async fn portal_balance(
    provider: &DynProvider<TempoNetwork>,
    token: Address,
    portal: Address,
    block: B256,
) -> Result<U256, L1ReadError> {
    ITIP20::new(token, provider)
        .balanceOf(portal)
        .block(BlockId::hash_canonical(block))
        .call()
        .await
        .map_err(classify_contract_error)
}

/// Read Portal custody for every token, concurrently, at one exact canonical Tempo block.
pub(crate) async fn portal_balances(
    provider: &DynProvider<TempoNetwork>,
    portal: Address,
    tokens: impl IntoIterator<Item = Address>,
    block: B256,
) -> Result<Vec<(Address, U256)>, L1ReadError> {
    stream::iter(tokens.into_iter().map(|token| async move {
        portal_balance(provider, token, portal, block)
            .await
            .map(|balance| (token, balance))
    }))
    .buffer_unordered(BALANCE_CONCURRENCY)
    .try_collect()
    .await
}

/// Fetch receipts and collect Portal events for one authenticated L1 block.
fn collect_l1_block_evidence(
    portal: Address,
    block: BlockNumHash,
    receipts: &[TempoTransactionReceipt],
) -> Result<L1BlockEvidence, L1ReadError> {
    let number = block.number;
    let mut event_collector = EventCollector::new(portal);
    for receipt in receipts {
        event_collector
            .extract_receipt(receipt, number)
            .map_err(finding)?;
    }
    let events = event_collector.finish();
    Ok(L1BlockEvidence { events })
}

fn classify_contract_error(error: alloy_contract::Error) -> L1ReadError {
    if error.as_revert_data().is_some() {
        return finding(error);
    }
    match error {
        alloy_contract::Error::TransportError(error) => classify_rpc_error(error).into(),
        error @ (alloy_contract::Error::ContractNotDeployed
        | alloy_contract::Error::ZeroData(..)
        | alloy_contract::Error::AbiError(_)) => finding(error),
        error => disable(error),
    }
}

/// Classify one provider RPC failure using its structured code and message.
pub(crate) fn classify_rpc_error(error: TransportError) -> AttemptError {
    let retryable = match &error {
        RpcError::ErrorResp(error) => {
            // Missing/unavailable resources and internal errors can result from
            // backend import lag or upstream resets during a rollout. Retry these
            // L1 reads without depending on provider-specific message text. The
            // runtime bounds retries; exact hash/canonicality checks are unchanged.
            error.is_retry_err() || matches!(error.code, -32001 | -32002 | -32603)
        }
        RpcError::UnsupportedFeature(_)
        | RpcError::LocalUsageError(_)
        | RpcError::SerError(_)
        | RpcError::DeserError { .. }
        | RpcError::Transport(TransportErrorKind::NonRetryable(_)) => false,
        _ => true,
    };
    if retryable {
        AttemptError::retry(error)
    } else {
        AttemptError::disable(error)
    }
}

fn unavailable(error: impl Into<eyre::Report>) -> L1ReadError {
    L1ReadError::Unavailable(error.into())
}

fn finding(error: impl Into<eyre::Report>) -> L1ReadError {
    L1ReadError::Finding(error.into())
}

fn disable(error: impl Into<eyre::Report>) -> L1ReadError {
    L1ReadError::Disable(error.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_eips::NumHash;
    use alloy_primitives::{B256, Log};
    use alloy_rpc_types_eth::Header as RpcHeader;
    use alloy_sol_types::SolEvent;
    use tempo_alloy::rpc::TempoHeaderResponse;
    use tempo_primitives::TempoHeader;
    use tempo_zone_contracts::ZonePortal;

    const BLOCK: u64 = 100;
    const HASH: B256 = B256::repeat_byte(0x10);

    #[tokio::test]
    async fn checkpoint_deferred_range_preserves_order_and_authenticates_its_parent() {
        use crate::accounting::{State, effects};

        let provider = alloy_provider::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(alloy_transport::mock::Asserter::new())
            .erased();
        let tracker = L1BlockTracker::default();
        let portal = Address::repeat_byte(0x20);
        let token = Address::repeat_byte(0x21);
        let parent = BlockNumHash::new(100, B256::with_last_byte(100));
        let logs = [
            ZonePortal::TokenEnabled {
                token,
                name: "Test".into(),
                symbol: "TST".into(),
                currency: "USD".into(),
            }
            .encode_log_data(),
            ZonePortal::DepositMade {
                newCurrentDepositQueueHash: B256::ZERO,
                sender: Address::ZERO,
                token,
                netAmount: 500,
                fee: 0,
                keyIndex: U256::ZERO,
                ephemeralPubkeyX: B256::ZERO,
                ephemeralPubkeyYParity: 0,
                ciphertext: Default::default(),
                nonce: [0; 12].into(),
                tag: [0; 16].into(),
                tempoRefundRecipient: Address::repeat_byte(4),
                depositNumber: 1,
            }
            .encode_log_data(),
        ];
        for (index, data) in logs.into_iter().enumerate() {
            let number = 101 + index as u64;
            tracker
                .record_with_portal_evidence(
                    BlockNumHash::new(number, B256::with_last_byte(number as u8)),
                    B256::with_last_byte((number - 1) as u8),
                    Default::default(),
                    vec![Log {
                        address: portal,
                        data,
                    }],
                )
                .unwrap();
        }
        let tip = BlockNumHash::new(103, B256::with_last_byte(103));
        tracker
            .record_with_portal_evidence(tip, B256::with_last_byte(102), Default::default(), vec![])
            .unwrap();
        let evidence = collect_l1_range_at(&provider, &tracker, portal, parent, tip)
            .await
            .unwrap();
        let mut state = State::default();
        // Applying a deposit before its deferred enablement would fail with UnknownToken.
        state.apply(&effects::from_tempo(&evidence)).unwrap();
        assert_eq!(
            state.token(token).unwrap().pending_deposits,
            U256::from(500)
        );

        let wrong_parent = BlockNumHash::new(parent.number, B256::ZERO);
        assert!(matches!(
            collect_l1_range_at(&provider, &tracker, portal, wrong_parent, tip).await,
            Err(L1ReadError::Finding(_))
        ));
        assert!(matches!(
            collect_l1_range_at(&provider, &tracker, portal, tip, tip).await,
            Err(L1ReadError::Finding(_))
        ));
    }

    #[tokio::test]
    async fn checkpoint_range_authenticates_archival_rpc_headers_and_receipts() {
        let asserter = alloy_transport::mock::Asserter::new();
        let provider = alloy_provider::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();
        let parent = BlockNumHash::new(100, B256::with_last_byte(100));
        let mut tip = parent;
        let mut responses = Vec::new();
        for number in 101..=103 {
            let header = TempoHeader {
                inner: Header {
                    number,
                    parent_hash: tip.hash,
                    ..Default::default()
                },
                ..Default::default()
            };
            let response = TempoHeaderResponse {
                inner: RpcHeader::new(header),
                timestamp_millis: 0,
            };
            tip = BlockNumHash::new(number, response.inner.hash);
            let mut block = serde_json::to_value(response).unwrap();
            block["transactions"] = serde_json::json!([]);
            block["uncles"] = serde_json::json!([]);
            responses.push(block);
        }
        for block in responses.into_iter().rev() {
            asserter.push_success(&block);
            asserter.push_success(&Vec::<TempoTransactionReceipt>::new());
        }
        let evidence = collect_l1_range_at(
            &provider,
            &L1BlockTracker::default(),
            Address::ZERO,
            parent,
            tip,
        )
        .await
        .unwrap();
        assert_eq!(evidence.portal_events().count(), 0);
    }

    #[test]
    fn acquisition_rpc_codes_are_retryable_without_message_matching() {
        for (code, message, retryable) in [
            (-32001, "block not found", true),
            (-32001, "block not found: canonical hash 0x1234", true),
            (-32001, "transaction not found", true),
            (-32001, "historical state pruned", true),
            (-32001, "", true),
            (-32002, "no healthy upstreams available", true),
            (-32002, "", true),
            (-32603, "internal eth error", true),
            (-32603, "", true),
            (-32000, "invalid input", false),
            (-32600, "invalid request", false),
            (-32601, "method not found", false),
            (-32602, "block not found", false),
            (-32004, "method not supported", false),
            (3, "execution reverted", false),
            (-32005, "rate limit", true),
            (429, "too many requests", true),
        ] {
            let payload = serde_json::from_value(serde_json::json!({
                "code": code, "message": message,
            }))
            .unwrap();
            assert_eq!(
                matches!(
                    classify_rpc_error(RpcError::ErrorResp(payload)),
                    AttemptError::Retry(_)
                ),
                retryable,
                "{code}: {message}"
            );
        }
    }

    #[test]
    fn validates_rpc_hash_against_decoded_header() {
        let header = TempoHeader {
            inner: Header {
                number: BLOCK,
                parent_hash: B256::repeat_byte(0x09),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut response = TempoHeaderResponse {
            inner: RpcHeader::new(header),
            timestamp_millis: 0,
        };
        let validated = validate_rpc_header(&response).unwrap();

        assert_eq!(validated.block, BlockNumHash::new(BLOCK, response.hash()));
        assert_eq!(validated.parent_hash, B256::repeat_byte(0x09));

        response.inner.hash = B256::repeat_byte(0xff);
        assert!(matches!(
            validate_rpc_header(&response),
            Err(AttemptError::Disable(_))
        ));
    }

    #[test]
    fn tracked_evidence_preserves_accounting_events_and_parent_link() {
        let parent = BlockNumHash::new(BLOCK - 1, B256::repeat_byte(0x09));
        let portal = Address::repeat_byte(0x20);
        let token = Address::repeat_byte(0x21);
        let log = Log {
            address: portal,
            data: ZonePortal::TokenEnabled {
                token,
                name: "Test".into(),
                symbol: "TST".into(),
                currency: "USD".into(),
            }
            .encode_log_data(),
        };
        let tracked = zone_l1::AuthenticatedPortalLogs {
            block: NumHash::new(BLOCK, HASH),
            parent_hash: parent.hash,
            logs: vec![log],
        };

        let evidence = collect_tracked_l1_block_evidence(portal, parent, tracked).unwrap();
        assert!(matches!(
            evidence.portal_events().next(),
            Some(L1PortalEvent::TokenEnabled { token: observed }) if *observed == token
        ));
    }

    #[test]
    fn tracked_evidence_rejects_non_contiguous_parent() {
        let tracked = zone_l1::AuthenticatedPortalLogs {
            block: NumHash::new(BLOCK, HASH),
            parent_hash: B256::repeat_byte(0xff),
            logs: vec![],
        };
        let result = collect_tracked_l1_block_evidence(
            Address::ZERO,
            BlockNumHash::new(BLOCK - 1, B256::repeat_byte(0x09)),
            tracked,
        );
        assert!(matches!(result, Err(L1ReadError::Finding(_))));
    }

    #[test]
    fn classifies_retryable_and_terminal_transport_failures() {
        let retryable = alloy_transport::TransportErrorKind::backend_gone();
        assert!(matches!(
            classify_rpc_error(retryable),
            AttemptError::Retry(_)
        ));

        let terminal = alloy_transport::TransportErrorKind::non_retryable_str("invalid request");
        assert!(matches!(
            classify_rpc_error(terminal),
            AttemptError::Disable(_)
        ));
    }
}
