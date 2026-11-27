//! Sending L1 transactions and waiting for their receipts.

use std::time::Duration;

use alloy_contract::{CallBuilder, CallDecoder};
use alloy_network::Network;
use alloy_provider::Provider;

/// How often [`send_and_confirm`] asks L1 for the receipt.
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Sends `call` with `eth_sendRawTransaction` and polls `eth_getTransactionReceipt` until it
/// has a receipt. It never returns otherwise, so callers bound it with a timeout.
///
/// Hankie's RPC does not serve `eth_sendRawTransactionSync`, so the sequencer cannot use
/// `send_sync`. Alloy's `get_receipt` is not used either: it falls back to the client's poll
/// interval, which is 7 seconds for a remote chain alloy does not know, such as hankie.
pub async fn send_and_confirm<P, D, N>(
    call: &CallBuilder<P, D, N>,
) -> alloy_contract::Result<N::ReceiptResponse>
where
    P: Provider<N>,
    D: CallDecoder,
    N: Network,
{
    let pending = call.send().await?;
    let hash = *pending.tx_hash();
    loop {
        if let Some(receipt) = pending.provider().get_transaction_receipt(hash).await? {
            return Ok(receipt);
        }
        tokio::time::sleep(RECEIPT_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use alloy_network::ReceiptResponse as _;
    use alloy_primitives::{Address, B256, Bytes};
    use alloy_provider::{ProviderBuilder, mock::Asserter};
    use tempo_alloy::TempoNetwork;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn polls_until_the_receipt_exists() {
        let l1 = Asserter::new();
        let hash = B256::repeat_byte(0x42);
        // The chain ID filler asks first.
        l1.push_success(&"0x1");
        l1.push_success(&hash);
        l1.push_success(&serde_json::Value::Null);
        l1.push_success(&serde_json::Value::Null);
        l1.push_success(&serde_json::json!({
            "transactionHash": hash,
            "transactionIndex": "0x0",
            "blockHash": B256::repeat_byte(0x01),
            "blockNumber": "0x1",
            "from": Address::ZERO,
            "to": Address::ZERO,
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x0",
            "contractAddress": null,
            "logs": [],
            "logsBloom": format!("{:#x}", alloy_primitives::Bloom::ZERO),
            "status": "0x1",
            "type": "0x0",
            "feePayer": Address::ZERO,
        }));
        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(l1.clone());
        let call = CallBuilder::new_raw(&provider, Bytes::new())
            .to(Address::ZERO)
            .nonce(0)
            .gas(21_000)
            .max_fee_per_gas(1)
            .max_priority_fee_per_gas(0);

        let receipt = send_and_confirm(&call).await.unwrap();

        assert_eq!(receipt.transaction_hash(), hash);
        assert!(l1.read_q().is_empty());
    }
}
