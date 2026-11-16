//! Runs test setups against a node over RPC.

use std::time::Duration;

use super::{SetupCall, TIP20Setup};
use crate::{TIP403_REGISTRY_ADDRESS, tip403_registry::ITIP403Registry};
use alloy::{
    network::{Network, ReceiptResponse, TransactionBuilder},
    primitives::Address,
    providers::Provider,
};

/// Gas limit of each call [`TIP20Setup::apply_rpc`] sends. Fixed, because estimating a call that
/// depends on an earlier, unmined one fails.
const SETUP_CALL_GAS: u64 = 5_000_000;

/// How long [`TIP20Setup::apply_rpc`] waits for each call to be mined.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

impl TIP20Setup {
    /// Performs [`Self::calls`] over RPC and returns the token address.
    ///
    /// Sends every call before awaiting any receipt, so `provider` must sign for each caller and
    /// fill consecutive nonces. Reads the registry's next policy ID first when there is a transfer
    /// policy, so policies created concurrently by others can race it. Fails if a call reverts or
    /// isn't mined within a minute.
    pub async fn apply_rpc<N: Network>(self, provider: &impl Provider<N>) -> eyre::Result<Address> {
        let next_policy_id = match self.transfer_policy {
            Some(_) => {
                ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider)
                    .policyIdCounter()
                    .call()
                    .await?
            }
            None => 0,
        };
        let (token, calls) = self.calls(next_policy_id);
        let mut pending = Vec::new();
        // Sent one at a time so the provider fills consecutive nonces in order.
        for SetupCall { caller, call } in calls {
            let tx = N::TransactionRequest::default()
                .with_from(caller)
                .with_kind(call.to)
                .with_input(call.input)
                .with_gas_limit(SETUP_CALL_GAS);
            pending.push(
                provider
                    .send_transaction(tx)
                    .await?
                    .with_timeout(Some(RECEIPT_TIMEOUT)),
            );
        }
        for receipt in
            futures::future::try_join_all(pending.into_iter().map(|tx| tx.get_receipt())).await?
        {
            eyre::ensure!(
                receipt.status(),
                "setup call {} reverted",
                receipt.transaction_hash()
            );
        }
        Ok(token)
    }
}
