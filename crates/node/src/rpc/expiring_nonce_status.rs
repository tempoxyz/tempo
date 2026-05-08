use crate::{node::TempoNode, rpc::TempoEthApi};
use alloy::consensus::transaction::SignerRecoverable;
use alloy_eips::{BlockId, BlockNumberOrTag, Decodable2718};
use alloy_primitives::Bytes;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_ethereum::evm::revm::database::StateProviderDatabase;
use reth_node_api::FullNodeTypes;
use reth_node_core::rpc::result::invalid_params_rpc_err;
use reth_primitives_traits::AlloyBlockHeader as _;
use reth_provider::{BlockIdReader, BlockNumReader, ChainSpecProvider, HeaderProvider};
use reth_rpc_eth_api::{
    RpcNodeCore,
    helpers::{LoadState, SpawnBlocking},
};
use serde::{Deserialize, Serialize};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_evm::TempoStateAccess;
use tempo_precompiles::{nonce::NonceManager, storage::Handler};
use tempo_primitives::{TempoTxEnvelope, transaction::TEMPO_EXPIRING_NONCE_KEY};

/// Request for `tempo_getExpiringNonceStatus`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExpiringNonceStatusRequest {
    /// Signed expiring-nonce transaction bytes.
    pub signed_transaction: Bytes,
}

/// Response for `tempo_getExpiringNonceStatus`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExpiringNonceStatusResponse {
    /// Status of the expiring-nonce transaction.
    pub status: ExpiringNonceStatus,
}

/// Status values returned by `tempo_getExpiringNonceStatus`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ExpiringNonceStatus {
    /// No finalized canonical block at or after `validBefore` exists yet.
    Pending,
    /// Finalized canonical state proves the expiring nonce was seen before expiry.
    Included,
    /// Finalized canonical state at or after `validBefore` proves the expiring nonce was not seen.
    Expired,
    /// Historical state needed to classify the transaction is unavailable.
    Unavailable,
}

#[rpc(server, namespace = "tempo")]
pub trait TempoExpiringNonceStatusApi {
    /// Classifies an expiring-nonce transaction as pending, included, expired, or unavailable.
    #[method(name = "getExpiringNonceStatus")]
    async fn get_expiring_nonce_status(
        &self,
        request: ExpiringNonceStatusRequest,
    ) -> RpcResult<ExpiringNonceStatusResponse>;
}

/// Implementation of `tempo_getExpiringNonceStatus`.
#[derive(Debug, Clone)]
pub struct TempoExpiringNonceStatus<N: FullNodeTypes<Types = TempoNode>> {
    eth_api: TempoEthApi<N>,
}

impl<N: FullNodeTypes<Types = TempoNode>> TempoExpiringNonceStatus<N> {
    pub fn new(eth_api: TempoEthApi<N>) -> Self {
        Self { eth_api }
    }
}

#[async_trait::async_trait]
impl<N> TempoExpiringNonceStatusApiServer for TempoExpiringNonceStatus<N>
where
    N: FullNodeTypes<Types = TempoNode>,
    N::Provider: BlockIdReader
        + BlockNumReader
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + HeaderProvider
        + Send
        + Sync
        + 'static,
{
    async fn get_expiring_nonce_status(
        &self,
        request: ExpiringNonceStatusRequest,
    ) -> RpcResult<ExpiringNonceStatusResponse> {
        let envelope = TempoTxEnvelope::decode_2718(&mut request.signed_transaction.as_ref())
            .map_err(|err| invalid_params_rpc_err(format!("invalid signed transaction: {err}")))?;

        let aa_tx = envelope
            .as_aa()
            .ok_or_else(|| invalid_params_rpc_err("transaction is not a Tempo transaction"))?;
        if aa_tx.tx().nonce_key != TEMPO_EXPIRING_NONCE_KEY {
            return Err(invalid_params_rpc_err(
                "transaction is not an expiring-nonce transaction",
            ));
        }

        let valid_before = aa_tx
            .tx()
            .valid_before
            .ok_or_else(|| {
                invalid_params_rpc_err("expiring-nonce transaction is missing validBefore")
            })?
            .get();
        let sender = envelope.recover_signer().map_err(|err| {
            invalid_params_rpc_err(format!("invalid transaction signature: {err}"))
        })?;
        let expiring_nonce_hash = aa_tx.expiring_nonce_hash(sender);

        let status = self
            .eth_api
            .spawn_blocking_io_fut(async move |this| {
                let provider = this.provider();

                let finalized = match provider.finalized_block_num_hash() {
                    Ok(Some(finalized)) => finalized,
                    Ok(None) => return Ok(ExpiringNonceStatus::Pending),
                    Err(_) => return Ok(ExpiringNonceStatus::Unavailable),
                };

                let proof_blocks =
                    match find_expiry_proof_blocks(provider, finalized.number, valid_before) {
                        Ok(Some(proof_blocks)) => proof_blocks,
                        Ok(None) => return Ok(ExpiringNonceStatus::Pending),
                        Err(()) => return Ok(ExpiringNonceStatus::Unavailable),
                    };
                debug_assert!(proof_blocks.first_expired_block > proof_blocks.live_block);

                let Ok(state) = this
                    .state_at_block_id_or_latest(Some(BlockId::Number(BlockNumberOrTag::Number(
                        proof_blocks.live_block,
                    ))))
                    .await
                else {
                    return Ok(ExpiringNonceStatus::Unavailable);
                };
                let spec = provider.chain_spec().tempo_hardfork_at(valid_before);
                let mut db = StateProviderDatabase::new(state);
                let Ok(seen_expiry) = db.with_read_only_storage_ctx(spec, || {
                    NonceManager::new().expiring_nonce_seen[expiring_nonce_hash].read()
                }) else {
                    return Ok(ExpiringNonceStatus::Unavailable);
                };

                Ok(classify_seen_expiry(seen_expiry, valid_before))
            })
            .await?;

        Ok(ExpiringNonceStatusResponse { status })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpiryProofBlocks {
    /// First finalized block whose timestamp is at or after `validBefore`.
    first_expired_block: u64,
    /// Latest retained finalized block before `validBefore`; replay state is read here.
    live_block: u64,
}

fn find_expiry_proof_blocks<P>(
    provider: &P,
    finalized_block: u64,
    valid_before: u64,
) -> Result<Option<ExpiryProofBlocks>, ()>
where
    P: BlockNumReader + HeaderProvider,
{
    let finalized_header = provider
        .header_by_number(finalized_block)
        .map_err(|_| ())?
        .ok_or(())?;
    if finalized_header.timestamp() < valid_before {
        return Ok(None);
    }

    let earliest_block = provider.earliest_block_number().map_err(|_| ())?;
    let earliest_header = provider
        .header_by_number(earliest_block)
        .map_err(|_| ())?
        .ok_or(())?;
    if earliest_header.timestamp() >= valid_before {
        return Err(());
    }

    let mut low = earliest_block;
    let mut high = finalized_block;
    while low < high {
        let mid = low + (high - low) / 2;
        let header = provider.header_by_number(mid).map_err(|_| ())?.ok_or(())?;
        if header.timestamp() < valid_before {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    // The first finalized block at/after expiry proves the transaction can no
    // longer be included, but expiring-nonce replay state is bounded and can be
    // cleared after expiry. Read the latest retained pre-expiry state instead.
    let live_block = live_block_before_expiry(low, earliest_block).ok_or(())?;
    Ok(Some(ExpiryProofBlocks {
        first_expired_block: low,
        live_block,
    }))
}

fn live_block_before_expiry(first_expired_block: u64, earliest_retained_block: u64) -> Option<u64> {
    let live_block = first_expired_block.checked_sub(1)?;
    (live_block >= earliest_retained_block).then_some(live_block)
}

fn classify_seen_expiry(seen_expiry: u64, valid_before: u64) -> ExpiringNonceStatus {
    if seen_expiry == 0 {
        ExpiringNonceStatus::Expired
    } else if seen_expiry == valid_before {
        ExpiringNonceStatus::Included
    } else {
        ExpiringNonceStatus::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::{ExpiringNonceStatus, classify_seen_expiry, live_block_before_expiry};

    #[test]
    fn live_block_before_expiry_returns_latest_retained_pre_expiry_block() {
        assert_eq!(live_block_before_expiry(10, 0), Some(9));
        assert_eq!(live_block_before_expiry(10, 9), Some(9));
    }

    #[test]
    fn live_block_before_expiry_returns_none_when_pre_expiry_state_is_unavailable() {
        assert_eq!(live_block_before_expiry(0, 0), None);
        assert_eq!(live_block_before_expiry(10, 10), None);
    }

    #[test]
    fn classify_seen_expiry_returns_expired_for_zero_storage() {
        assert_eq!(classify_seen_expiry(0, 100), ExpiringNonceStatus::Expired);
    }

    #[test]
    fn classify_seen_expiry_returns_included_only_for_exact_valid_before_match() {
        assert_eq!(
            classify_seen_expiry(100, 100),
            ExpiringNonceStatus::Included
        );
    }

    #[test]
    fn classify_seen_expiry_returns_unavailable_for_unexpected_nonzero_storage() {
        assert_eq!(
            classify_seen_expiry(99, 100),
            ExpiringNonceStatus::Unavailable
        );
        assert_eq!(
            classify_seen_expiry(101, 100),
            ExpiringNonceStatus::Unavailable
        );
    }
}
