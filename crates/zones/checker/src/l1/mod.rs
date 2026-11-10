//! Collection of authenticated Tempo/L1 evidence through a full-import anchor.

mod events;

use alloy_consensus::BlockHeader as _;
use alloy_eips::{BlockId, BlockNumHash};
use alloy_network::{BlockResponse as _, primitives::HeaderResponse as _};
use alloy_primitives::{Address, B256, Bloom, Sealable as _, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::{EIP1186AccountProofResponse, error::EthRpcErrorCode};
use alloy_transport::{RpcError, TransportError, TransportErrorKind};
use reth_trie_common::AccountProof;
use tempo_alloy::{
    TempoNetwork,
    rpc::{TempoHeaderResponse, TempoTransactionReceipt},
};
use tempo_precompiles::tip20::TIP20Token;
use zone_l1::{L1BlockTracker, MAX_L1_LOOKAHEAD_BLOCKS};

use crate::AttemptError;

use events::EventCollector;
pub(crate) use events::L1PortalEvent;

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
    blocks: Vec<L1BlockEvents>,
    /// State root of the last block, from its authenticated header. `None` when no Tempo block
    /// was imported, as for a checkpoint-only Zone block.
    anchor_state_root: Option<B256>,
}

/// Recognized Portal events from one authenticated L1 block, in receipt order.
#[derive(Debug)]
pub(crate) struct L1BlockEvents {
    /// Timestamp in milliseconds from the authenticated Tempo header.
    pub(crate) timestamp_millis: u64,
    pub(crate) events: Vec<L1PortalEvent>,
}

/// Portal custody at one Tempo anchor.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PortalCustody {
    /// Balances proven against the anchor's authenticated state root.
    Proven(Vec<(Address, U256)>),
    /// The anchor is more than [`MAX_L1_LOOKAHEAD_BLOCKS`] behind the Tempo tip and the RPC no
    /// longer serves its state proofs.
    OutsideProofWindow,
}

/// Header fields bound to the hash reported by the Tempo RPC.
pub(crate) struct ValidatedRpcHeader {
    pub(crate) block: BlockNumHash,
    pub(crate) parent_hash: B256,
    pub(crate) state_root: B256,
    pub(crate) receipts_root: B256,
    pub(crate) logs_bloom: Bloom,
    pub(crate) timestamp_millis: u64,
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
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
        logs_bloom: header.logs_bloom(),
        timestamp_millis: header.as_ref().timestamp_millis(),
    })
}

impl L1BlockEvidence {
    /// Return authenticated Portal events in receipt order.
    pub(crate) fn portal_events(&self) -> impl Iterator<Item = &L1PortalEvent> {
        self.blocks.iter().flat_map(|block| block.events.iter())
    }

    /// Return authenticated Portal events grouped by their L1 block, in chain order.
    pub(crate) fn blocks(&self) -> &[L1BlockEvents] {
        &self.blocks
    }

    /// Return the authenticated state root of the last imported Tempo block, if any.
    pub(crate) fn anchor_state_root(&self) -> Option<B256> {
        self.anchor_state_root
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
    let mut anchor_state_root = None;
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
        anchor_state_root = anchor_state_root.or(evidence.anchor_state_root);
        blocks.push(evidence);
        cursor = previous;
    }
    if cursor != parent {
        return Err(finding(eyre::eyre!(
            "Tempo history does not extend the previous accounting anchor"
        )));
    }
    Ok(L1BlockEvidence {
        blocks: blocks
            .into_iter()
            .rev()
            .flat_map(|block| block.blocks)
            .collect(),
        anchor_state_root,
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
        blocks: vec![L1BlockEvents {
            timestamp_millis: evidence.timestamp_millis,
            events: collector.finish(),
        }],
        anchor_state_root: Some(evidence.state_root),
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
    let header = validate_rpc_header(block.header())?;
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
        collect_l1_block_evidence(
            portal,
            coordinate,
            header.timestamp_millis,
            header.state_root,
            &receipts,
        )?,
    ))
}

/// Read Portal custody for every token at `anchor`, proven against its authenticated
/// `state_root` with one `eth_getMultiProof` request.
///
/// Returns [`PortalCustody::OutsideProofWindow`] only for anchors more than
/// [`MAX_L1_LOOKAHEAD_BLOCKS`] behind the Tempo tip, such as during replay after a rebuild.
/// A refused proof for a more recent anchor disables the checker because the RPC does not meet
/// observe mode's proof-window requirement.
pub(crate) async fn portal_balances(
    provider: &DynProvider<TempoNetwork>,
    portal: Address,
    tokens: impl IntoIterator<Item = Address>,
    anchor: BlockNumHash,
    state_root: B256,
) -> Result<PortalCustody, L1ReadError> {
    let slots = tokens
        .into_iter()
        .map(|token| {
            let slot = TIP20Token::from_address(token)
                .map_err(|error| disable(eyre::Report::new(error)))?
                .balances[portal]
                .slot();
            Ok((token, B256::from(slot)))
        })
        .collect::<Result<Vec<_>, L1ReadError>>()?;
    if slots.is_empty() {
        return Ok(PortalCustody::Proven(Vec::new()));
    }
    let targets = slots
        .iter()
        .map(|&(token, slot)| (token, vec![slot]))
        .collect::<Vec<_>>();
    let proofs = match provider
        .client()
        .request::<_, Vec<EIP1186AccountProofResponse>>(
            "eth_getMultiProof",
            (targets, BlockId::hash_canonical(anchor.hash)),
        )
        .await
    {
        Ok(proofs) => proofs,
        Err(RpcError::ErrorResp(error))
            if error.code == i64::from(EthRpcErrorCode::PrunedHistory.code()) =>
        {
            let tip = provider
                .get_block_number()
                .await
                .map_err(classify_rpc_error)?;
            if tip.saturating_sub(anchor.number) > MAX_L1_LOOKAHEAD_BLOCKS {
                return Ok(PortalCustody::OutsideProofWindow);
            }
            return Err(disable(eyre::eyre!(
                "Tempo RPC refused eth_getMultiProof for block {} at tip {tip}; observe mode \
                 requires --rpc.eth-proof-window >= {MAX_L1_LOOKAHEAD_BLOCKS}",
                anchor.number
            )));
        }
        Err(error) => return Err(classify_rpc_error(error).into()),
    };
    // A proof that does not verify is an RPC fault, not a Zone finding: retry, then disable.
    if proofs.len() != slots.len() {
        return Err(unavailable(eyre::eyre!(
            "Tempo RPC returned {} proofs for {} tokens",
            proofs.len(),
            slots.len()
        )));
    }
    slots
        .into_iter()
        .zip(proofs)
        .map(|((token, slot), proof)| {
            verify_balance_proof(token, slot, state_root, proof).map(|balance| (token, balance))
        })
        .collect::<eyre::Result<_>>()
        .map(PortalCustody::Proven)
        .map_err(unavailable)
}

/// Verify one TIP-20 balance slot of `token` against an authenticated Tempo state root.
fn verify_balance_proof(
    token: Address,
    slot: B256,
    state_root: B256,
    response: EIP1186AccountProofResponse,
) -> eyre::Result<U256> {
    eyre::ensure!(
        response.address == token,
        "Tempo RPC returned a proof for {} instead of {token}",
        response.address
    );
    let proof = AccountProof::from_eip1186_proof(response);
    let [storage] = proof.storage_proofs.as_slice() else {
        eyre::bail!(
            "Tempo RPC returned {} storage proofs for {token}, expected one",
            proof.storage_proofs.len()
        );
    };
    eyre::ensure!(
        storage.key == slot,
        "Tempo RPC proved slot {} of {token} instead of {slot}",
        storage.key
    );
    proof
        .verify(state_root)
        .map_err(|error| eyre::eyre!("invalid Portal custody proof for {token}: {error}"))?;
    Ok(storage.value)
}

/// Fetch receipts and collect Portal events for one authenticated L1 block.
fn collect_l1_block_evidence(
    portal: Address,
    block: BlockNumHash,
    timestamp_millis: u64,
    state_root: B256,
    receipts: &[TempoTransactionReceipt],
) -> Result<L1BlockEvidence, L1ReadError> {
    let number = block.number;
    let mut event_collector = EventCollector::new(portal);
    for receipt in receipts {
        event_collector
            .extract_receipt(receipt, number)
            .map_err(finding)?;
    }
    Ok(L1BlockEvidence {
        blocks: vec![L1BlockEvents {
            timestamp_millis,
            events: event_collector.finish(),
        }],
        anchor_state_root: Some(state_root),
    })
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
    use crate::accounting::{State, effects};
    use alloy_consensus::Header;
    use alloy_eips::NumHash;
    use alloy_primitives::{B256, Bytes, Log, U64, address, keccak256};
    use alloy_rpc_types_eth::{EIP1186StorageProof, Header as RpcHeader};
    use alloy_sol_types::SolEvent;
    use reth_trie_common::{
        EMPTY_ROOT_HASH, HashBuilder, Nibbles, TrieAccount, proof::ProofRetainer,
    };
    use tempo_alloy::rpc::TempoHeaderResponse;
    use tempo_contracts::zones::ZonePortal;
    use tempo_primitives::TempoHeader;

    const BLOCK: u64 = 100;
    const HASH: B256 = B256::repeat_byte(0x10);
    const ANCHOR: BlockNumHash = BlockNumHash::new(BLOCK, HASH);

    #[tokio::test]
    async fn checkpoint_deferred_range_preserves_order_and_authenticates_its_parent() {
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
                    B256::repeat_byte(number as u8),
                    number * 1_000,
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
            .record_with_portal_evidence(
                tip,
                B256::with_last_byte(102),
                B256::repeat_byte(103),
                103_000,
                Default::default(),
                vec![],
            )
            .unwrap();
        let evidence = collect_l1_range_at(&provider, &tracker, portal, parent, tip)
            .await
            .unwrap();
        assert_eq!(
            evidence
                .blocks()
                .iter()
                .map(|block| block.timestamp_millis)
                .collect::<Vec<_>>(),
            vec![101_000, 102_000, 103_000]
        );
        assert_eq!(evidence.anchor_state_root(), Some(B256::repeat_byte(103)));
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
                    state_root: B256::repeat_byte(number as u8),
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
        assert_eq!(evidence.anchor_state_root(), Some(B256::repeat_byte(103)));
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
            state_root: B256::ZERO,
            timestamp_millis: 0,
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
            state_root: B256::ZERO,
            timestamp_millis: 0,
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

    /// Build a Tempo state root and an EIP-1186 proof of one TIP-20 balance slot.
    fn balance_proof(
        token: Address,
        slot: B256,
        value: U256,
    ) -> (B256, EIP1186AccountProofResponse) {
        let storage_path = Nibbles::unpack(keccak256(slot));
        let mut storage =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([storage_path]));
        storage.add_leaf(storage_path, &alloy_rlp::encode_fixed_size(&value));
        let storage_root = storage.root();
        let storage_proof = proof_nodes(storage, storage_path);

        let code_hash = keccak256([0xef]);
        let account = |storage_root| {
            alloy_rlp::encode(TrieAccount {
                storage_root,
                code_hash,
                ..Default::default()
            })
        };
        let token_path = Nibbles::unpack(keccak256(token));
        let mut accounts = [
            (token_path, account(storage_root)),
            (
                Nibbles::unpack(keccak256(Address::repeat_byte(0x99))),
                account(EMPTY_ROOT_HASH),
            ),
        ];
        accounts.sort_by_key(|(path, _)| *path);
        let mut state =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([token_path]));
        for (path, account) in &accounts {
            state.add_leaf(*path, account);
        }
        let state_root = state.root();
        let account_proof = proof_nodes(state, token_path);

        let response = EIP1186AccountProofResponse {
            address: token,
            balance: U256::ZERO,
            code_hash,
            nonce: 0,
            storage_hash: storage_root,
            account_proof,
            storage_proof: vec![EIP1186StorageProof {
                key: slot.into(),
                value,
                proof: storage_proof,
            }],
        };
        (state_root, response)
    }

    fn proof_nodes(mut builder: HashBuilder, path: Nibbles) -> Vec<Bytes> {
        builder
            .take_proof_nodes()
            .matching_nodes_sorted(&path)
            .into_iter()
            .map(|(_, node)| node)
            .collect()
    }

    fn balance_slot(token: Address, portal: Address) -> B256 {
        B256::from(TIP20Token::from_address(token).unwrap().balances[portal].slot())
    }

    #[test]
    fn verifies_portal_balance_proof_against_state_root() {
        let token = address!("20c0000000000000000000000000000000000001");
        let slot = balance_slot(token, Address::repeat_byte(0x20));
        let value = U256::from(1_000);
        let (root, response) = balance_proof(token, slot, value);

        assert_eq!(
            verify_balance_proof(token, slot, root, response.clone()).unwrap(),
            value
        );

        let error =
            verify_balance_proof(token, slot, B256::repeat_byte(1), response.clone()).unwrap_err();
        assert!(
            error.to_string().contains("invalid Portal custody proof"),
            "{error}"
        );

        let mut inflated = response.clone();
        inflated.storage_proof[0].value = value + U256::ONE;
        let error = verify_balance_proof(token, slot, root, inflated).unwrap_err();
        assert!(
            error.to_string().contains("invalid Portal custody proof"),
            "{error}"
        );

        let error =
            verify_balance_proof(token, B256::repeat_byte(2), root, response.clone()).unwrap_err();
        assert!(error.to_string().contains("instead of"), "{error}");

        let mut other_account = response.clone();
        other_account.address = Address::repeat_byte(3);
        let error = verify_balance_proof(token, slot, root, other_account).unwrap_err();
        assert!(error.to_string().contains("instead of"), "{error}");

        let mut no_storage = response;
        no_storage.storage_proof.clear();
        let error = verify_balance_proof(token, slot, root, no_storage).unwrap_err();
        assert!(error.to_string().contains("expected one"), "{error}");
    }

    #[tokio::test]
    async fn portal_balances_prove_custody_at_the_anchor() {
        let asserter = alloy_transport::mock::Asserter::new();
        let provider = alloy_provider::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();
        let token = address!("20c0000000000000000000000000000000000001");
        let portal = Address::repeat_byte(0x20);
        let value = U256::from(1_000);
        let (root, proof) = balance_proof(token, balance_slot(token, portal), value);
        asserter.push_success(&vec![proof]);

        assert_eq!(
            portal_balances(&provider, portal, [token], ANCHOR, root)
                .await
                .unwrap(),
            PortalCustody::Proven(vec![(token, value)])
        );
        // No enabled tokens: nothing to prove and no request.
        assert_eq!(
            portal_balances(&provider, portal, [], ANCHOR, root)
                .await
                .unwrap(),
            PortalCustody::Proven(Vec::new())
        );
    }

    #[tokio::test]
    async fn portal_balances_reject_an_unverifiable_proof_as_unavailable() {
        let asserter = alloy_transport::mock::Asserter::new();
        let provider = alloy_provider::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();
        let token = address!("20c0000000000000000000000000000000000001");
        let portal = Address::repeat_byte(0x20);
        let (root, proof) = balance_proof(token, balance_slot(token, portal), U256::from(1_000));
        asserter.push_success(&vec![proof.clone()]);
        asserter.push_success(&Vec::<EIP1186AccountProofResponse>::new());

        let error = portal_balances(&provider, portal, [token], ANCHOR, B256::repeat_byte(1))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, L1ReadError::Unavailable(error) if error.to_string().contains("invalid Portal custody proof")),
            "{error:?}"
        );
        let error = portal_balances(&provider, portal, [token], ANCHOR, root)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, L1ReadError::Unavailable(error) if error.to_string().contains("0 proofs for 1 tokens")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn refused_proofs_skip_only_anchors_outside_the_required_window() {
        let token = address!("20c0000000000000000000000000000000000001");
        let portal = Address::repeat_byte(0x20);
        for (tip, outside) in [
            (BLOCK + MAX_L1_LOOKAHEAD_BLOCKS + 1, true),
            (BLOCK + MAX_L1_LOOKAHEAD_BLOCKS, false),
        ] {
            let asserter = alloy_transport::mock::Asserter::new();
            let provider = alloy_provider::ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect_mocked_client(asserter.clone())
                .erased();
            asserter.push_failure(
                serde_json::from_value(serde_json::json!({
                    "code": EthRpcErrorCode::PrunedHistory.code(),
                    "message": "distance to target block exceeds maximum proof window",
                }))
                .unwrap(),
            );
            asserter.push_success(&U64::from(tip));

            let result =
                portal_balances(&provider, portal, [token], ANCHOR, B256::repeat_byte(1)).await;
            if outside {
                assert_eq!(result.unwrap(), PortalCustody::OutsideProofWindow);
            } else {
                assert!(
                    matches!(&result, Err(L1ReadError::Disable(error)) if error.to_string().contains("--rpc.eth-proof-window")),
                    "{result:?}"
                );
            }
        }
    }
}
