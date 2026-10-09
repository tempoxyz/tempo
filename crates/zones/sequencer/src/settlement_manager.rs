use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Weak},
    time::Duration,
};

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_provider::{DynProvider, Provider as _};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue as _;
use eyre::OptionExt as _;
use parking_lot::Mutex;
use tempo_alloy::TempoNetwork;
use tempo_zone_contracts::ZonePortal;
use tokio::sync::mpsc;
use tracing::info;
use zone_chainspec::ZoneChainSpec;
use zone_p2p::{P2pCommand, P2pPeerId};
use zone_prover::VerifierMode;

use crate::{
    BatchAnchorConfig, PreparedBatch, SettlementAbi,
    attestation::{
        AttestationDomain, SettlementAttestation, SettlementCertificate,
        SignedSettlementAttestation,
    },
    settlement::BatchSubmitError,
};

const SETTLEMENT_REBROADCAST_INTERVAL: Duration = Duration::from_millis(500);

/// Prepares settlement certificates and routes follower signatures to active preparations.
#[derive(Clone)]
pub struct SettlementManager {
    domain: AttestationDomain,
    pinned_sequencer_set_version: Option<u64>,
    signer: PrivateKeySigner,
    addresses: HashMap<P2pPeerId, Address>,
    l1_provider: DynProvider<TempoNetwork>,
    chain_spec: Arc<ZoneChainSpec>,
    anchor_config: BatchAnchorConfig,
    p2p_tx: mpsc::Sender<P2pCommand>,
    pending: PendingSettlements,
}

impl std::fmt::Debug for SettlementManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SettlementManager")
            .finish_non_exhaustive()
    }
}

impl SettlementManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: AttestationDomain,
        pinned_sequencer_set_version: Option<u64>,
        signer: PrivateKeySigner,
        addresses: HashMap<P2pPeerId, Address>,
        l1_provider: DynProvider<TempoNetwork>,
        chain_spec: Arc<ZoneChainSpec>,
        anchor_config: BatchAnchorConfig,
        p2p_tx: mpsc::Sender<P2pCommand>,
    ) -> Self {
        Self {
            domain,
            pinned_sequencer_set_version,
            signer,
            addresses,
            l1_provider,
            chain_spec,
            anchor_config,
            p2p_tx,
            pending: PendingSettlements::default(),
        }
    }

    /// Prepare and collect the certificate for one exact batch, anchor, and verifier mode.
    pub async fn prepare(
        &self,
        prepared: &PreparedBatch,
        verifier_mode: VerifierMode,
    ) -> Result<SettlementCertificate, BatchSubmitError> {
        let status = self.settlement_status().await?;
        if status.portal_zone_height >= U256::from(prepared.batch.zone_height) {
            return Err(BatchSubmitError::PortalAdvanced);
        }
        let config = status.config;
        let mut threshold = status.threshold;

        self.validate_anchor(prepared).await?;
        let attestation = settlement_attestation(self.domain, &config, prepared, verifier_mode);
        let signed =
            SignedSettlementAttestation::sign(attestation.clone(), self.domain, &self.signer)?;
        let digest = self.domain.settlement_digest(&attestation);
        let mut signatures = BTreeMap::from([(self.signer.address(), signed.signature)]);
        let mut pending = self.pending.subscribe(digest)?;

        self.broadcast(&attestation, digest)?;
        let mut rebroadcast = tokio::time::interval_at(
            tokio::time::Instant::now() + SETTLEMENT_REBROADCAST_INTERVAL,
            SETTLEMENT_REBROADCAST_INTERVAL,
        );
        rebroadcast.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        while signatures.len() < threshold {
            tokio::select! {
                signature = pending.receiver.recv() => {
                    let signature = signature.ok_or_eyre("settlement signature route closed")?;
                    if signature.attestation != attestation {
                        tracing::warn!(target: "zone::p2p", %digest, "Rejected mismatched settlement signature");
                        continue;
                    }
                    match signature.recover_signer(self.domain) {
                        Ok(signer) => { signatures.entry(signer).or_insert(signature.signature); }
                        Err(error) => tracing::warn!(target: "zone::p2p", %error, "Rejected settlement signature"),
                    }
                }
                _ = rebroadcast.tick() => {
                    self.validate_anchor(prepared).await?;
                    let live = self.settlement_status().await?;
                    if live.portal_zone_height >= U256::from(prepared.batch.zone_height) {
                        return Err(BatchSubmitError::PortalAdvanced);
                    }
                    if live.config != config {
                        return Err(eyre::eyre!(
                            "portal settlement configuration changed while collecting signatures"
                        )
                        .into());
                    }
                    threshold = live.threshold;
                    self.broadcast(&attestation, digest)?;
                }
            }
        }

        Ok(SettlementCertificate {
            height: prepared.batch.zone_height,
            digest,
            attestation,
            signatures: signatures.into_values().collect(),
        })
    }

    async fn settlement_status(&self) -> Result<SettlementStatus, BatchSubmitError> {
        let portal = ZonePortal::new(self.domain.portal_address, self.l1_provider.clone());
        let settlement_abi = SettlementAbi::from_l1(&self.l1_provider, &self.chain_spec).await?;
        let (sequencer_set_version, threshold, verifier, portal_zone_height) = self
            .l1_provider
            .multicall()
            .add(portal.sequencerSetVersion())
            .add(portal.sequencerThreshold())
            .add(portal.verifier())
            .add(portal.zoneHeight())
            .aggregate()
            .await
            .map_err(|error| eyre::eyre!(error))?;
        if let Some(pinned) = self.pinned_sequencer_set_version
            && sequencer_set_version != pinned
        {
            return Err(eyre::eyre!(
                "portal signer-set version {sequencer_set_version} does not match startup-pinned version {pinned}"
            )
            .into());
        }
        let threshold = usize::from(threshold);
        if threshold == 0 {
            return Err(eyre::eyre!("portal sequencer threshold is zero").into());
        }

        Ok(SettlementStatus {
            config: SettlementConfig {
                abi: settlement_abi,
                sequencer_set_version,
                verifier,
            },
            threshold,
            portal_zone_height,
        })
    }

    /// Authenticate and route one follower response to its pending settlement.
    pub fn add_signature(&self, follower: P2pPeerId, encoded: &[u8]) -> eyre::Result<()> {
        let signed = SignedSettlementAttestation::decode(encoded)?;
        let expected = self
            .addresses
            .get(&follower)
            .ok_or_eyre("unknown follower identity")?;
        let signer = signed.recover_signer(self.domain)?;
        eyre::ensure!(
            signer == *expected,
            "settlement signer does not match authenticated peer"
        );
        let digest = self.domain.settlement_digest(&signed.attestation);
        self.pending.route(digest, signed)
    }

    fn broadcast(&self, attestation: &SettlementAttestation, digest: B256) -> eyre::Result<()> {
        match self
            .p2p_tx
            .try_send(P2pCommand::BroadcastSettlementProposal(
                attestation.encode(),
            )) {
            Ok(()) => {
                info!(target: "zone::p2p", %digest, height = %attestation.zoneHeight, "Broadcast settlement proposal")
            }
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                eyre::bail!("P2P command channel closed");
            }
        }
        Ok(())
    }

    async fn validate_anchor(&self, prepared: &PreparedBatch) -> Result<(), BatchSubmitError> {
        let anchor_number = prepared.anchor_block_number();
        let current = self
            .l1_provider
            .get_block_number()
            .await
            .map_err(|error| eyre::eyre!(error))?;
        if anchor_number < prepared.batch.tempo_block_number {
            return Err(BatchSubmitError::PreparedAnchorInvalid(eyre::eyre!(
                "prepared L1 anchor predates the batch Tempo block"
            )));
        }
        if anchor_number > current {
            return Err(BatchSubmitError::PreparedAnchorInvalid(eyre::eyre!(
                "prepared L1 anchor block is ahead of the current L1 tip"
            )));
        }
        if current.saturating_sub(anchor_number) >= self.anchor_config.history_window() {
            return Err(BatchSubmitError::PreparedAnchorInvalid(eyre::eyre!(
                "prepared L1 anchor block fell outside the EIP-2935 history window"
            )));
        }
        let canonical = self
            .l1_provider
            .get_header_by_number(anchor_number.into())
            .await
            .map_err(|error| eyre::eyre!(error))?
            .ok_or_else(|| eyre::eyre!("prepared L1 anchor block {anchor_number} not found"))?;
        if canonical.inner.hash != prepared.anchor.block_hash() {
            return Err(BatchSubmitError::PreparedAnchorInvalid(eyre::eyre!(
                "prepared L1 anchor hash is no longer canonical"
            )));
        }
        Ok(())
    }
}

/// Portal configuration that must remain fixed while collecting signatures.
#[derive(PartialEq, Eq)]
struct SettlementConfig {
    abi: SettlementAbi,
    sequencer_set_version: u64,
    verifier: Address,
}

struct SettlementStatus {
    config: SettlementConfig,
    threshold: usize,
    portal_zone_height: U256,
}

fn settlement_attestation(
    domain: AttestationDomain,
    config: &SettlementConfig,
    prepared: &PreparedBatch,
    verifier_mode: VerifierMode,
) -> SettlementAttestation {
    let batch = &prepared.batch;
    SettlementAttestation {
        zoneId: domain.zone_id,
        sequencerSetVersion: config.sequencer_set_version,
        zoneHeight: U256::from(batch.zone_height),
        withdrawalBatchIndex: U256::from(batch.withdrawal_batch_index),
        verifier: config.verifier,
        tempoBlockNumber: batch.tempo_block_number,
        anchorBlockNumber: prepared.anchor_block_number(),
        anchorBlockHash: prepared.anchor.block_hash(),
        blockTransitionHash: keccak256((batch.prev_block_hash, batch.next_block_hash).abi_encode()),
        depositQueueTransitionHash: keccak256(
            (
                batch.prev_processed_deposit_hash,
                batch.next_processed_deposit_hash,
                batch.prev_deposit_number,
                batch.next_deposit_number,
            )
                .abi_encode(),
        ),
        tokenEnablementTransitionHash: config.abi.token_transition_hash(
            batch.prev_processed_token_count,
            batch.next_processed_token_count,
        ),
        withdrawalQueueHash: batch.withdrawal_queue_hash,
        verifierConfigHash: verifier_mode.config_hash(),
    }
}

#[derive(Clone, Default)]
struct PendingSettlements {
    senders: Arc<Mutex<HashMap<B256, Weak<mpsc::UnboundedSender<SignedSettlementAttestation>>>>>,
}

impl PendingSettlements {
    fn subscribe(&self, digest: B256) -> eyre::Result<PendingSettlement> {
        let mut senders = self.senders.lock();
        senders.retain(|_, sender| sender.strong_count() > 0);
        eyre::ensure!(
            !senders.contains_key(&digest),
            "settlement digest is already pending"
        );
        let (sender, receiver) = mpsc::unbounded_channel();
        let sender = Arc::new(sender);
        senders.insert(digest, Arc::downgrade(&sender));
        Ok(PendingSettlement {
            _sender: sender,
            receiver,
        })
    }

    fn route(&self, digest: B256, signed: SignedSettlementAttestation) -> eyre::Result<()> {
        let mut senders = self.senders.lock();
        let Some(sender) = senders.get(&digest).and_then(|sender| sender.upgrade()) else {
            senders.remove(&digest);
            eyre::bail!("settlement response has no pending request");
        };
        if sender.send(signed).is_err() {
            senders.remove(&digest);
            eyre::bail!("pending settlement receiver closed");
        }
        Ok(())
    }
}

struct PendingSettlement {
    _sender: Arc<mpsc::UnboundedSender<SignedSettlementAttestation>>,
    receiver: mpsc::UnboundedReceiver<SignedSettlementAttestation>,
}

#[cfg(test)]
mod tests {
    use alloy_signer_local::PrivateKeySigner;

    use super::*;

    fn domain() -> AttestationDomain {
        AttestationDomain {
            l1_chain_id: 1337,
            portal_address: Address::repeat_byte(0x11),
            zone_id: 7,
        }
    }

    fn signed(height: u64) -> SignedSettlementAttestation {
        SignedSettlementAttestation::sign(
            SettlementAttestation {
                zoneId: 7,
                sequencerSetVersion: 1,
                zoneHeight: U256::from(height),
                withdrawalBatchIndex: U256::from(height),
                verifier: Address::repeat_byte(0x22),
                tempoBlockNumber: height,
                anchorBlockNumber: height,
                anchorBlockHash: B256::repeat_byte(height as u8),
                blockTransitionHash: B256::repeat_byte(0x33),
                depositQueueTransitionHash: B256::repeat_byte(0x44),
                tokenEnablementTransitionHash: B256::repeat_byte(0x55),
                withdrawalQueueHash: B256::repeat_byte(0x66),
                verifierConfigHash: B256::repeat_byte(0x77),
            },
            domain(),
            &PrivateKeySigner::random(),
        )
        .unwrap()
    }

    #[test]
    fn routes_concurrent_settlements_by_digest() {
        let pending = PendingSettlements::default();
        let first_digest = B256::repeat_byte(1);
        let second_digest = B256::repeat_byte(2);
        let mut first = pending.subscribe(first_digest).unwrap();
        let mut second = pending.subscribe(second_digest).unwrap();
        let first_signature = signed(120);
        let second_signature = signed(240);

        pending
            .route(second_digest, second_signature.clone())
            .unwrap();
        pending
            .route(first_digest, first_signature.clone())
            .unwrap();

        assert_eq!(first.receiver.try_recv().unwrap(), first_signature);
        assert_eq!(second.receiver.try_recv().unwrap(), second_signature);
    }

    #[test]
    fn dropping_request_releases_digest() {
        let pending = PendingSettlements::default();
        let digest = B256::repeat_byte(1);
        let request = pending.subscribe(digest).unwrap();
        assert!(pending.subscribe(digest).is_err());

        drop(request);

        assert!(pending.subscribe(digest).is_ok());
    }

    #[test]
    fn fallback_requires_signatures_for_the_new_verifier_digest() {
        let prepared = PreparedBatch {
            batch: crate::BatchData {
                zone_height: 120,
                tempo_block_number: 100,
                prev_block_hash: B256::repeat_byte(1),
                next_block_hash: B256::repeat_byte(2),
                prev_processed_deposit_hash: B256::ZERO,
                next_processed_deposit_hash: B256::ZERO,
                prev_deposit_number: 0,
                next_deposit_number: 0,
                prev_processed_token_count: 0,
                next_processed_token_count: 0,
                withdrawal_queue_hash: B256::ZERO,
                withdrawal_batch_index: 1,
            },
            anchor: crate::BatchAnchor::Direct {
                block_hash: B256::repeat_byte(3),
            },
        };
        let config = SettlementConfig {
            abi: SettlementAbi::T13,
            sequencer_set_version: 1,
            verifier: Address::repeat_byte(4),
        };
        let signer = PrivateKeySigner::random();
        let nitro = settlement_attestation(domain(), &config, &prepared, VerifierMode::NitroV1);
        let fallback = settlement_attestation(domain(), &config, &prepared, VerifierMode::NoProof);
        assert_eq!(
            fallback.verifierConfigHash,
            VerifierMode::NoProof.config_hash()
        );
        let nitro_digest = domain().settlement_digest(&nitro);
        let fallback_digest = domain().settlement_digest(&fallback);
        assert_ne!(nitro_digest, fallback_digest);

        let pending = PendingSettlements::default();
        let nitro_request = pending.subscribe(nitro_digest).unwrap();
        drop(nitro_request);
        let mut fallback_request = pending.subscribe(fallback_digest).unwrap();
        let stale = SignedSettlementAttestation::sign(nitro, domain(), &signer).unwrap();
        assert!(pending.route(nitro_digest, stale).is_err());
        assert!(fallback_request.receiver.try_recv().is_err());
        let fresh = SignedSettlementAttestation::sign(fallback, domain(), &signer).unwrap();
        pending.route(fallback_digest, fresh.clone()).unwrap();
        assert_eq!(fallback_request.receiver.try_recv().unwrap(), fresh);
    }
}
