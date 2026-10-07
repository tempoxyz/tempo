//! Batch-boundary settlement attestation construction and validation.

use std::{collections::HashMap, sync::Arc};

use alloy_consensus::TxReceipt as _;
use alloy_eips::BlockHashOrNumber;
use alloy_primitives::{B256, Sealable as _, U256};
use alloy_provider::{DynProvider, Provider as _};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolEvent as _, SolValue as _};
use eyre::{OptionExt as _, WrapErr as _};
use reth_provider::HeaderProvider;
use reth_storage_api::ReceiptProvider;
use tempo_alloy::TempoNetwork;
use tempo_primitives::TempoHeader;
use tempo_zone_contracts::{
    IZoneOutbox, LegacyTempoAdvanced, TempoAdvanced, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
    ZonePortal,
};
use tracing::info;
use zone_chainspec::ZoneChainSpec;
use zone_prover::VerifierMode;

use zone_sequencer::{
    BatchAnchorConfig, SettlementAbi,
    attestation::{AttestationDomain, SettlementAttestation},
};

/// Shared signing and L1-validation context for settlement attestations.
#[derive(Clone)]
pub(crate) struct AttestationContext {
    pub(crate) domain: AttestationDomain,
    /// Portal sequencer-set version validated against the manifest at startup.
    pub(crate) pinned_sequencer_set_version: Option<u64>,
    /// `None` on an rpc-only member: it holds no individual key and never signs.
    pub(crate) signer: Option<PrivateKeySigner>,
    pub(crate) addresses: HashMap<zone_p2p::P2pPeerId, alloy_primitives::Address>,
    pub(crate) l1_provider: DynProvider<TempoNetwork>,
    pub(crate) chain_spec: Arc<ZoneChainSpec>,
    pub(crate) anchor_config: BatchAnchorConfig,
}

impl AttestationContext {
    pub(crate) fn new(
        domain: AttestationDomain,
        pinned_sequencer_set_version: Option<u64>,
        signer: Option<PrivateKeySigner>,
        addresses: HashMap<zone_p2p::P2pPeerId, alloy_primitives::Address>,
        l1_provider: DynProvider<TempoNetwork>,
        chain_spec: Arc<ZoneChainSpec>,
        anchor_config: BatchAnchorConfig,
    ) -> Self {
        Self {
            domain,
            pinned_sequencer_set_version,
            signer,
            addresses,
            l1_provider,
            chain_spec,
            anchor_config,
        }
    }
}

/// Check the manifest's settlement quorum against `ZonePortal` before any role task starts.
///
/// A quorum node the portal has not registered can never settle, and an unreachable threshold
/// stalls settlement — both otherwise surface as a mysterious stall at the next batch boundary.
///
/// Extra registered signers only warn: deregistering is a cleanup task, and failing on it would
/// make every membership change a window in which no node can start.
///
/// A configured portal must already be deployed at the current L1 tip. The persisted Zone genesis
/// anchor may still predate portal deployment so the creation block can be replayed; this live-tip
/// check is deliberately independent of that historical anchor.
pub(crate) async fn validate_registered_sequencer_set(
    manifest: &zone_p2p::ZoneManifest,
    portal_address: alloy_primitives::Address,
    l1_provider: &alloy_provider::DynProvider<tempo_alloy::TempoNetwork>,
) -> eyre::Result<Option<u64>> {
    // Programmatic synthetic test harnesses use zero to mean no Portal; the production CLI
    // rejects a zero address before node launch.
    if portal_address.is_zero() {
        info!(target: "zone::p2p", "No ZonePortal configured; skipping the manifest quorum check");
        return Ok(None);
    }
    let portal_code = l1_provider
        .get_code_at(portal_address)
        .await
        .map_err(|err| eyre::eyre!("failed to check portal {portal_address} deployment: {err}"))?;
    eyre::ensure!(
        !portal_code.is_empty(),
        "ZonePortal {portal_address} is not deployed at the current L1 tip; refusing to start P2P before its sequencer set can be validated"
    );

    // Read at the chain tip rather than the finalized head: a fresh or local L1 may have no
    // finalized block at all, and an unfinalized registration satisfying this check early is
    // harmless for a startup sanity check.
    let portal = ZonePortal::new(portal_address, l1_provider);
    let quorum: Vec<_> = manifest.quorum_nodes().collect();
    let (sequencer_set_version, threshold, registered_count) = l1_provider
        .multicall()
        .add(portal.sequencerSetVersion())
        .add(portal.sequencerThreshold())
        .add(portal.sequencerCount())
        .aggregate()
        .await
        .wrap_err("failed reading the registered sequencer set from ZonePortal")?;
    let mut registration_calls = l1_provider.multicall().dynamic();
    for (_, address) in &quorum {
        registration_calls = registration_calls.add_dynamic(portal.isSequencer(*address));
    }
    let registered = registration_calls
        .aggregate()
        .await
        .wrap_err("failed reading the registered sequencers from ZonePortal")?;
    let validated_version = portal
        .sequencerSetVersion()
        .call()
        .await
        .wrap_err("failed re-reading the ZonePortal sequencer-set version")?;
    eyre::ensure!(
        validated_version == sequencer_set_version,
        "ZonePortal sequencer set changed during startup validation ({sequencer_set_version} -> {validated_version})"
    );

    for ((node, address), is_registered) in quorum.iter().zip(registered) {
        let name = node.name();
        eyre::ensure!(
            is_registered,
            "manifest quorum node `{name}` ({address}) is not a registered ZonePortal sequencer"
        );
    }
    eyre::ensure!(
        threshold > 0 && usize::from(threshold) <= quorum.len(),
        "ZonePortal settlement threshold {threshold} is not reachable by the manifest's {} quorum nodes",
        quorum.len()
    );
    if registered_count > U256::from(quorum.len()) {
        tracing::warn!(
            target: "zone::p2p",
            %registered_count,
            manifest_quorum = quorum.len(),
            "ZonePortal has registered sequencers the manifest does not list; they hold a share of the threshold this zone never signs for"
        );
    }

    info!(target: "zone::p2p", threshold, sequencer_set_version, quorum_nodes = quorum.len(), "Checked the manifest quorum against ZonePortal");
    Ok(Some(sequencer_set_version))
}

#[derive(Debug, Clone, Copy)]
struct BlockCommitments {
    tempo_block_hash: B256,
    tempo_block_number: u64,
    processed_deposit_hash: B256,
    processed_deposit_number: u64,
    processed_token_count: u64,
    withdrawal: Option<(B256, u64)>,
}

/// Extract commitments produced by the deterministic system transactions in a zone block.
fn block_commitments<P>(provider: &P, number: u64) -> eyre::Result<Option<BlockCommitments>>
where
    P: ReceiptProvider,
{
    let receipts = provider
        .receipts_by_block(BlockHashOrNumber::Number(number))?
        .ok_or_eyre(format!(
            "receipts for canonical block {number} are not persisted"
        ))?;
    let mut anchor_hash = None;
    let mut tempo_block_number = None;
    let mut processed_deposit_hash = None;
    let mut processed_deposit_number = None;
    let mut processed_token_count = None;
    let mut withdrawal = None;

    for receipt in receipts {
        for log in receipt.logs() {
            if log.address == ZONE_INBOX_ADDRESS {
                match log.topics().first().copied() {
                    Some(TempoAdvanced::SIGNATURE_HASH) => {
                        let event = TempoAdvanced::decode_log(log).wrap_err_with(|| {
                            format!("invalid post-T13 TempoAdvanced log in block {number}")
                        })?;
                        anchor_hash = Some(event.tempoBlockHash);
                        tempo_block_number = Some(event.tempoBlockNumber);
                        processed_deposit_hash = Some(event.newProcessedDepositQueueHash);
                        processed_deposit_number = Some(event.lastProcessedDepositNumber);
                        processed_token_count = Some(event.lastProcessedEnabledTokenCount);
                    }
                    Some(LegacyTempoAdvanced::SIGNATURE_HASH) => {
                        let event = LegacyTempoAdvanced::decode_log(log).wrap_err_with(|| {
                            format!("invalid legacy TempoAdvanced log in block {number}")
                        })?;
                        anchor_hash = Some(event.tempoBlockHash);
                        tempo_block_number = Some(event.tempoBlockNumber);
                        processed_deposit_hash = Some(event.newProcessedDepositQueueHash);
                        processed_deposit_number = Some(event.lastProcessedDepositNumber);
                        processed_token_count = Some(0);
                    }
                    _ => {}
                }
            } else if log.address == ZONE_OUTBOX_ADDRESS
                && log.topics().first() == Some(&IZoneOutbox::BatchFinalized::SIGNATURE_HASH)
            {
                let event = IZoneOutbox::BatchFinalized::decode_log(log)
                    .wrap_err_with(|| format!("invalid BatchFinalized log in block {number}"))?;
                withdrawal = Some((event.withdrawalQueueHash, event.withdrawalBatchIndex));
            }
        }
    }

    // Checkpoint-only blocks have no BatchFinalized or TempoAdvanced event. They are not
    // settlement boundaries and must remain transparent to the previous-boundary scan.
    let Some(withdrawal) = withdrawal else {
        return Ok(None);
    };

    Ok(Some(BlockCommitments {
        tempo_block_hash: anchor_hash
            .ok_or_eyre(format!("block {number} is missing TempoAdvanced"))?,
        tempo_block_number: tempo_block_number
            .ok_or_eyre(format!("block {number} is missing its Tempo block number"))?,
        processed_deposit_hash: processed_deposit_hash
            .ok_or_eyre(format!("block {number} is missing its deposit commitment"))?,
        processed_deposit_number: processed_deposit_number
            .ok_or_eyre(format!("block {number} is missing its deposit number"))?,
        processed_token_count: processed_token_count
            .ok_or_eyre(format!("block {number} is missing its token cursor"))?,
        withdrawal: Some(withdrawal),
    }))
}

/// Get the previous batch's (i.e the last block in the previous batch) block_hash,
/// deposit_hash, processed_deposit_number, processed_token_count, and withdrawal batch index.
/// These values identify the transition independently of L1 submission progress.
fn previous_batch<P>(provider: &P, number: u64) -> eyre::Result<(B256, B256, u64, u64, u64)>
where
    P: HeaderProvider<Header = TempoHeader> + ReceiptProvider,
{
    for candidate in (1..number).rev() {
        if let Some(commitments) = block_commitments(provider, candidate)? {
            let hash = provider
                .sealed_header(candidate)?
                .map(|header| header.hash())
                .ok_or_eyre(format!("missing prior batch-boundary header {candidate}"))?;
            return Ok((
                hash,
                commitments.processed_deposit_hash,
                commitments.processed_deposit_number,
                commitments.processed_token_count,
                commitments
                    .withdrawal
                    .expect("boundary commitments include withdrawal finalization")
                    .1,
            ));
        }
    }
    // A fresh ZonePortal has not accepted any zone tip yet, so its blockHash is zero. The first
    // batch must extend that on-chain value rather than the local zone genesis hash.
    Ok((B256::ZERO, B256::ZERO, 0, 0, 0))
}

/// Certify a zone batch transition independently of whether its predecessor has landed on L1.
/// Live signer/verifier configuration and L1 anchors still apply; portal position is enforced
/// when submitting the batch, not when collecting signatures for it.
pub(crate) async fn build_settlement_attestation<P>(
    provider: &P,
    number: u64,
    context: &AttestationContext,
    anchor: (u64, B256),
    verifier_mode: VerifierMode,
) -> eyre::Result<Option<SettlementAttestation>>
where
    P: HeaderProvider<Header = TempoHeader> + ReceiptProvider,
{
    let Some(commitments) = block_commitments(provider, number)? else {
        return Ok(None);
    };
    let (withdrawal_queue_hash, withdrawal_batch_index) = commitments
        .withdrawal
        .expect("boundary commitments include withdrawal finalization");
    let next_tip = provider
        .sealed_header(number)?
        .ok_or_eyre(format!("missing batch-tip header {number}"))?
        .hash();
    let (
        previous_tip,
        previous_deposit_hash,
        previous_deposit_number,
        previous_token_count,
        previous_batch_index,
    ) = previous_batch(provider, number)?;
    let expected_batch_index = previous_batch_index
        .checked_add(1)
        .ok_or_eyre("previous zone withdrawal batch index overflow")?;
    eyre::ensure!(
        withdrawal_batch_index == expected_batch_index,
        "zone withdrawal batch index {withdrawal_batch_index} does not follow previous zone batch index {previous_batch_index}"
    );
    let settlement_abi = SettlementAbi::from_l1(&context.l1_provider, &context.chain_spec).await?;

    let portal = ZonePortal::new(context.domain.portal_address, context.l1_provider.clone());
    let (set_version, verifier) = context
        .l1_provider
        .multicall()
        .add(portal.sequencerSetVersion())
        .add(portal.verifier())
        .aggregate()
        .await?;
    validate_sequencer_set_version(context.pinned_sequencer_set_version, set_version)?;

    let (anchor_block_number, anchor_block_hash) = anchor;
    validate_settlement_anchor(
        context,
        commitments.tempo_block_number,
        commitments.tempo_block_hash,
        anchor_block_number,
        anchor_block_hash,
    )
    .await?;

    Ok(Some(SettlementAttestation {
        zoneId: context.domain.zone_id,
        sequencerSetVersion: set_version,
        zoneHeight: U256::from(number),
        withdrawalBatchIndex: U256::from(withdrawal_batch_index),
        verifier,
        tempoBlockNumber: commitments.tempo_block_number,
        anchorBlockNumber: anchor_block_number,
        anchorBlockHash: anchor_block_hash,
        blockTransitionHash: alloy_primitives::keccak256((previous_tip, next_tip).abi_encode()),
        depositQueueTransitionHash: alloy_primitives::keccak256(
            (
                previous_deposit_hash,
                commitments.processed_deposit_hash,
                previous_deposit_number,
                commitments.processed_deposit_number,
            )
                .abi_encode(),
        ),
        tokenEnablementTransitionHash: settlement_abi
            .token_transition_hash(previous_token_count, commitments.processed_token_count),
        withdrawalQueueHash: withdrawal_queue_hash,
        verifierConfigHash: verifier_mode.config_hash(),
    }))
}

fn validate_sequencer_set_version(
    pinned_version: Option<u64>,
    live_version: u64,
) -> eyre::Result<()> {
    if let Some(pinned_version) = pinned_version {
        eyre::ensure!(
            live_version == pinned_version,
            "portal signer-set version {live_version} does not match startup-pinned version {pinned_version}"
        );
    }
    Ok(())
}

/// Verify that the proposed Tempo and anchor endpoints are canonical and that the anchor remains
/// available through EIP-2935. The prover verifies the full ancestry between those endpoints.
async fn validate_settlement_anchor(
    context: &AttestationContext,
    tempo_block_number: u64,
    tempo_block_hash: B256,
    anchor_block_number: u64,
    anchor_block_hash: B256,
) -> eyre::Result<()> {
    let current_l1_block = context.l1_provider.get_block_number().await?;
    validate_settlement_anchor_height(
        tempo_block_number,
        anchor_block_number,
        current_l1_block,
        context.anchor_config.history_window(),
    )?;

    let anchor_header = context
        .l1_provider
        .get_header_by_number(anchor_block_number.into())
        .await?
        .ok_or_eyre(format!(
            "missing proposed L1 anchor header {anchor_block_number}"
        ))?
        .inner
        .inner;
    eyre::ensure!(
        anchor_header.hash_slow() == anchor_block_hash,
        "proposed L1 anchor hash does not match finalized L1"
    );

    let tempo_header = context
        .l1_provider
        .get_header_by_number(tempo_block_number.into())
        .await?
        .ok_or_eyre(format!("missing Tempo header {tempo_block_number}"))?
        .inner
        .inner;
    eyre::ensure!(
        tempo_header.hash_slow() == tempo_block_hash,
        "zone batch's Tempo block hash does not match finalized L1"
    );
    Ok(())
}

fn validate_settlement_anchor_height(
    tempo_block_number: u64,
    anchor_block_number: u64,
    current_l1_block: u64,
    history_window: u64,
) -> eyre::Result<()> {
    eyre::ensure!(
        anchor_block_number >= tempo_block_number,
        "proposed L1 anchor predates the zone batch's Tempo block"
    );
    eyre::ensure!(
        anchor_block_number <= current_l1_block,
        "proposed L1 anchor is ahead of the current L1 tip"
    );
    eyre::ensure!(
        current_l1_block.saturating_sub(anchor_block_number) < history_window,
        "proposed L1 anchor fell outside the EIP-2935 history window"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, Log};
    use alloy_provider::{ProviderBuilder, mock::Asserter};
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use reth_provider::test_utils::MockEthProvider;
    use tempo_alloy::TempoNetwork;
    use tempo_primitives::{TempoPrimitives, TempoReceipt, TempoTxType};
    use zone_p2p::ZoneManifest;

    #[test]
    fn settlement_anchor_accepts_current_tip_and_rejects_future() {
        validate_settlement_anchor_height(100, 100, 100, 10).unwrap();

        let err = validate_settlement_anchor_height(100, 101, 100, 10).unwrap_err();
        assert!(
            err.to_string()
                .contains("proposed L1 anchor is ahead of the current L1 tip")
        );
    }

    #[test]
    fn checkpoint_only_block_is_not_a_settlement_boundary() {
        let provider = MockEthProvider::<TempoPrimitives>::new();
        provider.add_receipts(1, Vec::new());
        assert!(block_commitments(&provider, 1).unwrap().is_none());
    }

    #[test]
    fn legacy_tempo_advanced_preserves_zero_token_cursor() {
        let provider = MockEthProvider::<TempoPrimitives>::new();
        let tempo_advanced = LegacyTempoAdvanced {
            tempoBlockHash: B256::repeat_byte(0x21),
            tempoBlockNumber: 101,
            depositsProcessed: U256::ZERO,
            newProcessedDepositQueueHash: B256::ZERO,
            lastProcessedDepositNumber: 0,
        };
        let batch_finalized = IZoneOutbox::BatchFinalized {
            withdrawalQueueHash: B256::ZERO,
            withdrawalBatchIndex: 1,
        };
        provider.add_receipts(
            1,
            vec![TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 0,
                logs: vec![
                    Log {
                        address: ZONE_INBOX_ADDRESS,
                        data: tempo_advanced.encode_log_data(),
                    },
                    Log {
                        address: ZONE_OUTBOX_ADDRESS,
                        data: batch_finalized.encode_log_data(),
                    },
                ],
            }],
        );

        let commitments = block_commitments(&provider, 1).unwrap().unwrap();
        assert_eq!(commitments.processed_token_count, 0);
    }

    #[test]
    fn previous_batch_skips_checkpoint_only_blocks_across_t13() {
        let provider = MockEthProvider::<TempoPrimitives>::new();

        let mut first_boundary_header = TempoHeader::default();
        first_boundary_header.inner.number = 1;
        let first_boundary_hash = first_boundary_header.hash_slow();
        provider.add_header(first_boundary_hash, first_boundary_header);

        let first_deposit_hash = B256::repeat_byte(0x11);
        let first_tempo_advanced = LegacyTempoAdvanced {
            tempoBlockHash: B256::repeat_byte(0x21),
            tempoBlockNumber: 101,
            depositsProcessed: U256::from(3),
            newProcessedDepositQueueHash: first_deposit_hash,
            lastProcessedDepositNumber: 7,
        };
        let first_batch_finalized = IZoneOutbox::BatchFinalized {
            withdrawalQueueHash: B256::repeat_byte(0x31),
            withdrawalBatchIndex: 1,
        };
        provider.add_receipts(
            1,
            vec![TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 0,
                logs: vec![
                    Log {
                        address: ZONE_INBOX_ADDRESS,
                        data: first_tempo_advanced.encode_log_data(),
                    },
                    Log {
                        address: ZONE_OUTBOX_ADDRESS,
                        data: first_batch_finalized.encode_log_data(),
                    },
                ],
            }],
        );

        for number in [2, 3] {
            let mut header = TempoHeader::default();
            header.inner.number = number;
            provider.add_header(header.hash_slow(), header);
            provider.add_receipts(number, Vec::new());
        }

        let mut current_boundary_header = TempoHeader::default();
        current_boundary_header.inner.number = 4;
        provider.add_header(current_boundary_header.hash_slow(), current_boundary_header);
        let current_tempo_advanced = TempoAdvanced {
            tempoBlockHash: B256::repeat_byte(0x24),
            tempoBlockNumber: 104,
            depositsProcessed: U256::from(5),
            newProcessedDepositQueueHash: B256::repeat_byte(0x14),
            lastProcessedDepositNumber: 12,
            lastProcessedEnabledTokenCount: 15,
        };
        let current_batch_finalized = IZoneOutbox::BatchFinalized {
            withdrawalQueueHash: B256::repeat_byte(0x34),
            withdrawalBatchIndex: 2,
        };
        provider.add_receipts(
            4,
            vec![TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 0,
                logs: vec![
                    Log {
                        address: ZONE_INBOX_ADDRESS,
                        data: current_tempo_advanced.encode_log_data(),
                    },
                    Log {
                        address: ZONE_OUTBOX_ADDRESS,
                        data: current_batch_finalized.encode_log_data(),
                    },
                ],
            }],
        );

        let commitments = block_commitments(&provider, 4).unwrap().unwrap();
        assert_eq!(commitments.processed_token_count, 15);
        let previous = previous_batch(&provider, 4).unwrap();
        assert_eq!(previous, (first_boundary_hash, first_deposit_hash, 7, 0, 1));
        assert_eq!(
            SettlementAbi::T13.token_transition_hash(previous.3, commitments.processed_token_count),
            alloy_primitives::keccak256((0_u64, 15_u64).abi_encode())
        );
    }

    fn attestation_fixture(
        indices: [u64; 2],
    ) -> (
        MockEthProvider<TempoPrimitives>,
        AttestationContext,
        Asserter,
        TempoHeader,
    ) {
        let provider = MockEthProvider::<TempoPrimitives>::new();
        let mut l1_header = TempoHeader::default();
        l1_header.inner.number = 104;
        for (number, index) in (1_u64..).zip(indices) {
            let mut header = TempoHeader::default();
            header.inner.number = number;
            provider.add_header(header.hash_slow(), header);
            provider.add_receipts(
                number,
                vec![TempoReceipt {
                    tx_type: TempoTxType::Legacy,
                    success: true,
                    cumulative_gas_used: 0,
                    logs: vec![
                        Log {
                            address: ZONE_INBOX_ADDRESS,
                            data: TempoAdvanced {
                                tempoBlockHash: l1_header.hash_slow(),
                                tempoBlockNumber: 104,
                                depositsProcessed: U256::from(10),
                                newProcessedDepositQueueHash: B256::repeat_byte(number as u8),
                                lastProcessedDepositNumber: number * 10,
                                lastProcessedEnabledTokenCount: number * 3,
                            }
                            .encode_log_data(),
                        },
                        Log {
                            address: ZONE_OUTBOX_ADDRESS,
                            data: IZoneOutbox::BatchFinalized {
                                withdrawalQueueHash: B256::repeat_byte((number + 10) as u8),
                                withdrawalBatchIndex: index,
                            }
                            .encode_log_data(),
                        },
                    ],
                }],
            );
        }
        let l1 = Asserter::new();
        let context = AttestationContext::new(
            AttestationDomain {
                l1_chain_id: 42431,
                portal_address: alloy_primitives::Address::repeat_byte(7),
                zone_id: 7,
            },
            Some(1),
            None,
            HashMap::new(),
            ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect_mocked_client(l1.clone())
                .erased(),
            Arc::new(ZoneChainSpec {
                inner: tempo_chainspec::spec::DEV.clone(),
            }),
            BatchAnchorConfig::default(),
        );
        (provider, context, l1, l1_header)
    }

    #[tokio::test]
    async fn settlement_builds_successive_batches_without_portal_progress() {
        let (provider, context, l1, l1_header) = attestation_fixture([1, 2]);
        let verifier = alloy_primitives::Address::repeat_byte(8);
        let mut previous_tip = B256::ZERO;
        let mut previous_deposit = B256::ZERO;
        for number in 1_u64..=2 {
            let header = tempo_alloy::rpc::TempoHeaderResponse {
                inner: alloy_rpc_types_eth::Header::new(l1_header.clone()),
                timestamp_millis: 0,
            };
            l1.push_success(&header);
            // The only portal values supplied are signing configuration. Neither the submitted
            // zone tip nor the submitted batch index is read, even for the second boundary.
            let metadata: Vec<Bytes> =
                vec![1_u64.abi_encode().into(), verifier.abi_encode().into()];
            l1.push_success(&Bytes::from((U256::ZERO, metadata).abi_encode_params()));
            l1.push_success(&104_u64);
            l1.push_success(&header);
            l1.push_success(&header);

            let attestation = build_settlement_attestation(
                &provider,
                number,
                &context,
                (104, l1_header.hash_slow()),
                VerifierMode::NitroV1,
            )
            .await
            .unwrap()
            .unwrap();
            let next_tip = provider.sealed_header(number).unwrap().unwrap().hash();
            let next_deposit = B256::repeat_byte(number as u8);
            assert_eq!(attestation.zoneHeight, U256::from(number));
            assert_eq!(attestation.withdrawalBatchIndex, U256::from(number));
            assert_eq!(attestation.sequencerSetVersion, 1);
            assert_eq!(attestation.verifier, verifier);
            assert_eq!(
                attestation.blockTransitionHash,
                alloy_primitives::keccak256((previous_tip, next_tip).abi_encode())
            );
            assert_eq!(
                attestation.depositQueueTransitionHash,
                alloy_primitives::keccak256(
                    (
                        previous_deposit,
                        next_deposit,
                        (number - 1) * 10,
                        number * 10
                    )
                        .abi_encode()
                )
            );
            assert_eq!(
                attestation.tokenEnablementTransitionHash,
                SettlementAbi::T13.token_transition_hash((number - 1) * 3, number * 3)
            );
            assert!(l1.read_q().is_empty());
            previous_tip = next_tip;
            previous_deposit = next_deposit;
        }
    }

    #[tokio::test]
    async fn settlement_rejects_nonconsecutive_zone_batch_indices() {
        for (indices, number, expected_error) in [
            ([2, 3], 1, "does not follow previous zone batch index 0"),
            ([1, 3], 2, "does not follow previous zone batch index 1"),
            ([1, 1], 2, "does not follow previous zone batch index 1"),
            (
                [u64::MAX, 0],
                2,
                "previous zone withdrawal batch index overflow",
            ),
        ] {
            let (provider, context, _, l1_header) = attestation_fixture(indices);
            let error = build_settlement_attestation(
                &provider,
                number,
                &context,
                (104, l1_header.hash_slow()),
                VerifierMode::NitroV1,
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains(expected_error), "{error}");
        }
    }

    fn test_manifest() -> ZoneManifest {
        let public_keys = [1_u64, 2, 3].map(|seed| PrivateKey::from_seed(seed).public_key());
        let mut input = format!(
            "zone_id = 7\nsequencer_set_version = 0\nleader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(public_keys[0].as_ref())
        );
        for (index, public_key) in public_keys.iter().enumerate() {
            let number = index + 1;
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{number}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"0x{number:040x}\"\naddress = \"127.0.0.1:{}\"\n",
                const_hex::encode_prefixed(public_key.as_ref()),
                9200 + index,
            ));
        }
        ZoneManifest::parse(&input).expect("valid test manifest")
    }

    #[tokio::test]
    async fn undeployed_portal_is_rejected_before_p2p_startup() {
        let asserter = Asserter::new();
        asserter.push_success(&Bytes::new());
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();
        let portal_address = alloy_primitives::Address::repeat_byte(0x11);

        let err = validate_registered_sequencer_set(&test_manifest(), portal_address, &provider)
            .await
            .expect_err("an undeployed configured portal must prevent P2P startup");

        assert!(
            err.to_string().contains(&format!(
                "ZonePortal {portal_address} is not deployed at the current L1 tip"
            )),
            "unexpected error: {err}"
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn synthetic_test_harness_can_skip_an_unconfigured_portal() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();

        let pinned_version = validate_registered_sequencer_set(
            &test_manifest(),
            alloy_primitives::Address::ZERO,
            &provider,
        )
        .await
        .expect("synthetic nodes have no configured ZonePortal");
        assert_eq!(pinned_version, None);

        assert!(
            asserter.read_q().is_empty(),
            "the zero-address test bypass must not issue an L1 request"
        );
    }

    #[test]
    fn settlement_rejects_runtime_sequencer_set_rotation() {
        validate_sequencer_set_version(Some(7), 7).expect("unchanged version must remain valid");
        let err = validate_sequencer_set_version(Some(7), 8)
            .expect_err("runtime rotation must fail closed");
        assert!(err.to_string().contains("startup-pinned version 7"));
        validate_sequencer_set_version(None, 8)
            .expect("synthetic nodes without a Portal have no pinned version");
    }
}
