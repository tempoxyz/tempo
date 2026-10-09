//! Sequencer background task orchestration.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{sync::Arc, time::Duration};

use alloy_chains::Chain;
use alloy_primitives::Address;
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::TransportResult;
use reth_chain_state::{CanonStateSubscriptions, PersistedBlockSubscriptions};
use reth_storage_api::{BlockReader, StateProviderFactory};
use tempo_alloy::{TempoNetwork, provider::ext::TempoProviderBuilderExt};
use tempo_primitives::{Block, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope};
use tokio::sync::Notify;
use zone_chainspec::ZoneChainSpec;

pub mod abi {
    pub use tempo_zone_contracts::*;
}

pub mod attestation;
mod encryption_key;
mod metrics;
pub mod monitor;
pub mod nonce_keys;
mod proofs;
mod prover;
mod prover_config;
mod rpc;
pub mod settlement;
mod settlement_manager;
pub mod withdrawals;

pub use encryption_key::{
    EncryptionKeyProof, encryption_key_identity, prove_encryption_key_possession,
    register_encryption_key,
};
pub use monitor::{ZoneMonitorConfig, ZoneMonitorSharedState};
pub use proofs::{
    ProofCollectorConfig, ProofCollectorHandle, StoredBlockProof, create_proof_collector,
};
pub use prover::{
    SHADOW_PROVER_QUEUE_CAPACITY, SettlementProof, SettlementProver, SettlementProverConfig,
    ShadowProofAnchor, ShadowProver, ShadowProverConfig, spawn_settlement_prover,
    spawn_shadow_prover,
};
pub use prover_config::{HardforkProverAddress, ProverAddresses};
pub use settlement::{
    BatchAnchor, BatchAnchorConfig, BatchData, BatchSubmitter, PortalZoneAnchor, PreparedBatch,
    SettlementAbi, resolve_portal_zone_anchor,
};
pub use settlement_manager::SettlementManager;
pub use withdrawals::{
    DEFAULT_MAX_IN_FLIGHT_WITHDRAWAL_BATCHES, DEFAULT_MAX_WITHDRAWAL_BATCH_GAS,
    MAX_WITHDRAWAL_BATCH_GAS, SharedWithdrawalStore, WithdrawalBatchLimits,
    WithdrawalProcessorConfig, WithdrawalStore,
};

use crate::rpc::rpc_connection_config;

/// Native Zone node provider capabilities required by sequencer components.
///
/// This is a zero-method convenience trait over Reth's storage and canonical-state
/// interfaces. Keeping the bounds here lets sequencer components use native Tempo
/// blocks and receipts without depending on an RPC representation.
pub trait ZoneSequencerProvider:
    BlockReader<
        Block = Block,
        Header = TempoHeader,
        Transaction = TempoTxEnvelope,
        Receipt = TempoReceipt,
    > + CanonStateSubscriptions<Primitives = TempoPrimitives>
    + StateProviderFactory
    + Clone
    + Send
    + Sync
    + 'static
{
}

impl<T> ZoneSequencerProvider for T where
    T: BlockReader<
            Block = Block,
            Header = TempoHeader,
            Transaction = TempoTxEnvelope,
            Receipt = TempoReceipt,
        > + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static
{
}

/// Upper bound for sequencer transaction fees on Tempo L1.
pub(crate) const TEMPO_L1_MAX_FEE_PER_GAS: u128 =
    tempo_chainspec::constants::gas::TEMPO_T1_BASE_FEE as u128;

/// Configuration for all zone sequencer background tasks.
#[derive(Debug, Clone)]
pub struct ZoneSequencerConfig {
    /// Zone chainspec containing the inherited Tempo hardfork schedule.
    pub chain_spec: Arc<ZoneChainSpec>,
    /// ZonePortal contract address on Tempo L1.
    pub portal_address: Address,
    /// Tempo L1 RPC URL.
    pub l1_rpc_url: String,
    /// Interval between WebSocket reconnection attempts for long-lived RPC clients.
    pub retry_connection_interval: Duration,
    /// Fallback interval for reconciling the canonical Zone head.
    ///
    /// Canonical-state notifications normally trigger reconciliation immediately.
    pub zone_poll_interval: Duration,
    /// How often the withdrawal processor polls the L1 queue.
    pub withdrawal_poll_interval: Duration,
    /// Gas and concurrency limits for withdrawal processing transactions.
    pub withdrawal_batch_limits: WithdrawalBatchLimits,
    /// ZoneOutbox contract address on Zone L2.
    pub outbox_address: Address,
    /// ZoneInbox contract address on Zone L2.
    pub inbox_address: Address,
    /// EIP-2935 history and safety-margin limits used by the batch submitter.
    pub batch_anchor_config: BatchAnchorConfig,
}

/// Handles returned by [`spawn_zone_sequencer`] for managing background tasks.
pub struct ZoneSequencerHandle {
    /// Join handle for the withdrawal processor task.
    pub withdrawal_handle: tokio::task::JoinHandle<()>,
    /// Join handle for the zone monitor task (which also handles batch submission).
    pub monitor_handle: tokio::task::JoinHandle<()>,
}

/// Spawn all zone sequencer background tasks.
///
/// This is the top-level POC entrypoint that starts:
/// - **Zone monitor** — prepares the next persisted Zone batch while the preceding batch is being
///   submitted to the ZonePortal. Submission remains ordered, and confirmed state only advances
///   after a successful L1 receipt.
/// - **Withdrawal processor** — polls the ZonePortal withdrawal queue on Tempo L1 and calls
///   `processWithdrawals` for each pending withdrawal.
/// - **Settlement prover** — when `settlement_prover` is set, settlement waits for a successful
///   SPF execution and Nitro NSM attestation before submitting the batch. The prover is owned by
///   the caller so it outlives individual leader generations.
///
/// Both tasks share a single L1 provider and nonce manager to prevent signing/nonce contention
/// when submitting concurrent L1 transactions.
///
/// `shutdown` stops both tasks gracefully: it is observed at their poll boundaries, so an
/// in-flight L1 transaction resolves before teardown.
pub async fn spawn_zone_sequencer<P>(
    config: ZoneSequencerConfig,
    signer: PrivateKeySigner,
    zone_provider: P,
    prover: Option<SettlementProver>,
    settlements: Option<SettlementManager>,
    shutdown: tokio_util::sync::CancellationToken,
) -> ZoneSequencerHandle
where
    P: ZoneSequencerProvider + PersistedBlockSubscriptions,
{
    // Build a single shared L1 provider with the sequencer wallet.
    // Both the batch submitter (inside the zone monitor) and the withdrawal
    // processor use this provider, ensuring nonces are tracked in one place.
    let l1_provider = connect_l1_provider(
        &config.l1_rpc_url,
        config.retry_connection_interval,
        signer.clone(),
    )
    .await
    .expect("valid L1 RPC URL");
    let sequencer_address = signer.address();

    let withdrawal_store: SharedWithdrawalStore = Default::default();
    let withdrawal_notify = Arc::new(Notify::new());
    let withdrawal_repair_notify = Arc::new(Notify::new());

    let withdrawal_config = WithdrawalProcessorConfig {
        portal_address: config.portal_address,
        fallback_poll_interval: config.withdrawal_poll_interval,
        sequencer_address,
        batch_limits: config.withdrawal_batch_limits,
    };

    let monitor_config = ZoneMonitorConfig {
        chain_spec: config.chain_spec.clone(),
        outbox_address: config.outbox_address,
        inbox_address: config.inbox_address,
        poll_interval: config.zone_poll_interval,
        portal_address: config.portal_address,
        batch_anchor_config: config.batch_anchor_config,
        settlements,
    };
    let withdrawal_handle = withdrawals::spawn_withdrawal_processor(
        withdrawal_config,
        l1_provider.clone(),
        withdrawal_store.clone(),
        withdrawal_notify.clone(),
        withdrawal_repair_notify.clone(),
        shutdown.clone(),
    );
    let monitor_shared_state = ZoneMonitorSharedState::new(
        withdrawal_store,
        withdrawal_notify,
        withdrawal_repair_notify,
    );
    let monitor_handle = monitor::spawn_zone_monitor(
        monitor_config,
        zone_provider,
        l1_provider,
        signer,
        monitor_shared_state,
        prover,
        shutdown,
    );

    ZoneSequencerHandle {
        withdrawal_handle,
        monitor_handle,
    }
}

/// Build the shared L1 provider used by all sequencer-side L1 transaction tasks.
async fn connect_l1_provider(
    l1_rpc_url: &str,
    retry_connection_interval: Duration,
    signer: PrivateKeySigner,
) -> TransportResult<DynProvider<TempoNetwork>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .with_nonce_key_filler()
        .wallet(signer)
        .connect_with_config(l1_rpc_url, rpc_connection_config(retry_connection_interval))
        .await?
        .erased();
    let l1_chain = Chain::from_id(provider.get_chain_id().await?);
    if !provider.client().is_local()
        && let Some(avg_block_time) = l1_chain.average_blocktime_hint()
    {
        provider
            .client()
            .set_poll_interval(avg_block_time.mul_f32(0.6));
    }

    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_provider::Provider;
    use futures::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        net::{TcpListener, TcpStream},
        time::{Duration, timeout},
    };
    use tokio_tungstenite::{accept_async, tungstenite::Message};

    async fn serve_block_number(
        stream: TcpStream,
        result: &'static str,
        close_after_response: bool,
    ) {
        let mut ws = accept_async(stream).await.unwrap();
        while let Some(message) = ws.next().await {
            let message = message.unwrap();
            let Message::Text(text) = message else {
                continue;
            };
            let request: Value = serde_json::from_str(&text).unwrap();
            let rpc_result = match request["method"].as_str() {
                Some("eth_chainId") => "0xa5bf",
                Some("eth_blockNumber") => result,
                _ => continue,
            };

            let response = json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": rpc_result,
            });
            ws.send(Message::Text(response.to_string().into()))
                .await
                .unwrap();

            if close_after_response && request["method"] == "eth_blockNumber" {
                let _ = ws.close(None).await;
                break;
            }
        }
    }

    #[tokio::test]
    async fn l1_provider_reconnects_after_wss_backend_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}");
        let connections = Arc::new(AtomicUsize::new(0));
        let server_connections = connections.clone();

        let server = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.unwrap();
            server_connections.fetch_add(1, Ordering::SeqCst);

            // Drop the listener while closing the first connection so the
            // provider's immediate reconnect attempt fails. With the configured
            // 10ms retry interval below, it should recover quickly once the
            // listener comes back; Alloy's default 3s interval would miss the
            // test timeout.
            drop(listener);
            serve_block_number(first_stream, "0x1", true).await;

            tokio::time::sleep(Duration::from_millis(100)).await;

            let listener = TcpListener::bind(addr).await.unwrap();
            let (second_stream, _) = listener.accept().await.unwrap();
            server_connections.fetch_add(1, Ordering::SeqCst);
            serve_block_number(second_stream, "0x2", false).await;
        });

        let provider =
            connect_l1_provider(&url, Duration::from_millis(10), PrivateKeySigner::random())
                .await
                .unwrap();

        assert_eq!(provider.get_block_number().await.unwrap(), 1);
        assert_eq!(
            provider.client().poll_interval(),
            Duration::from_millis(250),
            "chain metadata must not override Alloy's local transport interval"
        );

        let second_block = timeout(Duration::from_secs(2), provider.get_block_number())
            .await
            .expect("provider should reconnect after first WSS backend closes")
            .unwrap();
        assert_eq!(second_block, 2);
        assert!(
            connections.load(Ordering::SeqCst) >= 2,
            "provider should have opened a replacement WSS connection"
        );

        server.abort();
    }
}
