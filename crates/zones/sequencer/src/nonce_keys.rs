//! Nonce keys and nonce allocation for zone sequencer L1 operations.
//!
//! Hankie's pool currently admits protocol nonce key 0 only, so all sequencer
//! L1 operations share key 0 on this branch. Tasks that send from the same L1
//! account take their nonces from one [`NonceLane`].

use std::sync::Arc;

use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_transport::TransportResult;
use parking_lot::Mutex;
use tempo_alloy::TempoNetwork;
use tokio::sync::Notify;

/// Nonce key for `submitBatch` calls.
pub const SUBMIT_BATCH_NONCE_KEY: U256 = U256::ZERO;

/// Nonce key for `processWithdrawals` calls.
pub const PROCESS_WITHDRAWAL_NONCE_KEY: U256 = U256::ZERO;

/// Nonce key for admin operations (`enableToken`, `setZoneGasRate`, `setMaxTempoGasRate`,
/// `setBouncebackGas`, `setSequencerEncryptionKey`, `pause`, `abdicate`,
/// `pauseDeposits`, `resumeDeposits`).
pub const ADMIN_OPS_NONCE_KEY: U256 = U256::ZERO;

/// Gives out the key-0 nonces of one L1 account to every task that sends from it.
///
/// The batch submitter, the withdrawal processor and the `setLeader` relayer send from the
/// same account at the same time, so each of them reading the nonce from L1 would give two
/// transactions the same nonce. The RPC's `pending` nonce does not help: it can only count
/// transactions in the pool of one validator, and that pool is lost when the validator
/// restarts. So the lane keeps the next nonce in this process and reads the committed
/// (`latest`) nonce from L1 only when it has no value it trusts: before the first lease, and
/// after a lease ends without a receipt.
///
/// Before it reads, the lane waits until no lease is out. Every sender waits for the receipt
/// of its transaction (`eth_sendRawTransactionSync`), so at that point the committed nonce
/// counts every transaction that landed. A transaction that timed out can still land later.
/// Then the next transaction with its nonce is refused or skipped, that lease ends without a
/// receipt, and the lane reads the nonce again.
#[derive(Debug, Clone)]
pub struct NonceLane {
    inner: Arc<Lane>,
}

#[derive(Debug)]
struct Lane {
    address: Address,
    state: Mutex<LaneState>,
    /// Signalled when `next` becomes known or the last lease ends.
    changed: Notify,
}

#[derive(Debug, Default)]
struct LaneState {
    /// The nonce for the next lease, or `None` when it must be read from L1.
    next: Option<u64>,
    /// Leases not dropped yet, including one that is reading the nonce from L1.
    leased: usize,
}

impl NonceLane {
    /// Creates a lane for `address`. It reads the nonce from L1 on the first lease.
    pub fn new(address: Address) -> Self {
        Self {
            inner: Arc::new(Lane {
                address,
                state: Mutex::default(),
                changed: Notify::new(),
            }),
        }
    }

    /// The account whose nonces this lane gives out.
    pub fn address(&self) -> Address {
        self.inner.address
    }

    /// Takes the next nonce when the lane knows it, without waiting.
    ///
    /// Returns `None` when the nonce must be read from L1 first. A caller that holds leases in
    /// futures it polls itself must use this and drain them, because [`Self::lease`] waits for
    /// every lease to end.
    pub fn try_lease(&self) -> Option<NonceLease> {
        let mut state = self.inner.state.lock();
        let nonce = state.next?;
        state.next = Some(nonce + 1);
        state.leased += 1;
        Some(NonceLease {
            lane: self.clone(),
            nonce,
            landed: false,
        })
    }

    /// Takes the next nonce, reading it from L1 when the lane does not know it.
    pub async fn lease<P: Provider<TempoNetwork>>(
        &self,
        provider: &P,
    ) -> TransportResult<NonceLease> {
        let mut lease = loop {
            let changed = self.inner.changed.notified();
            {
                let mut state = self.inner.state.lock();
                if state.next.is_none() && state.leased == 0 {
                    state.leased += 1;
                    break NonceLease {
                        lane: self.clone(),
                        nonce: 0,
                        landed: false,
                    };
                }
            }
            if let Some(lease) = self.try_lease() {
                return Ok(lease);
            }
            changed.await;
        };

        // This lease counts in `leased`, so nobody else gives out a nonce or reads one until
        // `next` is set. If the read fails, dropping the lease lets the next caller read.
        lease.nonce = provider
            .get_transaction_count(self.inner.address)
            .latest()
            .await?;
        self.inner.state.lock().next = Some(lease.nonce + 1);
        self.inner.changed.notify_waiters();
        Ok(lease)
    }
}

/// One nonce taken from a [`NonceLane`].
///
/// Call [`Self::landed`] once the transaction has a receipt, even a reverted one. Dropping
/// the lease without it makes the lane read the nonce from L1 again.
#[derive(Debug)]
pub struct NonceLease {
    lane: NonceLane,
    nonce: u64,
    landed: bool,
}

impl NonceLease {
    /// The nonce to sign the transaction with.
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Marks the transaction as included on L1, so its nonce is used.
    pub fn landed(mut self) {
        self.landed = true;
    }
}

impl Drop for NonceLease {
    fn drop(&mut self) {
        let lane = &self.lane.inner;
        let mut state = lane.state.lock();
        state.leased -= 1;
        if !self.landed {
            state.next = None;
        }
        if state.leased == 0 {
            lane.changed.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_provider::{DynProvider, ProviderBuilder, mock::Asserter};
    use tokio::time::timeout;

    use super::*;

    fn mock_provider(asserter: Asserter) -> DynProvider<TempoNetwork> {
        ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter)
            .erased()
    }

    #[tokio::test]
    async fn leases_count_up_from_one_committed_read() {
        let l1 = Asserter::new();
        l1.push_success(&"0x7");
        let provider = mock_provider(l1.clone());
        let lane = NonceLane::new(Address::repeat_byte(0x11));

        assert!(lane.try_lease().is_none(), "the nonce is not read yet");
        let first = lane.lease(&provider).await.unwrap();
        let second = lane.lease(&provider).await.unwrap();
        let third = lane.try_lease().unwrap();

        assert_eq!((first.nonce(), second.nonce(), third.nonce()), (7, 8, 9));
        assert!(l1.read_q().is_empty());
        first.landed();
        second.landed();
        third.landed();
        assert_eq!(lane.try_lease().unwrap().nonce(), 10);
    }

    #[tokio::test]
    async fn a_lease_without_receipt_rereads_after_every_lease_ends() {
        let l1 = Asserter::new();
        l1.push_success(&"0x3");
        let provider = mock_provider(l1.clone());
        let lane = NonceLane::new(Address::repeat_byte(0x11));

        let failed = lane.lease(&provider).await.unwrap();
        let in_flight = lane.lease(&provider).await.unwrap();
        drop(failed);
        assert!(lane.try_lease().is_none());

        // The read waits until the second lease ends too. Nonce 4 cannot land without nonce 3,
        // so L1 then reports 3 again.
        l1.push_success(&"0x3");
        let waiting = tokio::spawn({
            let lane = lane.clone();
            async move { lane.lease(&provider).await.unwrap().nonce() }
        });
        tokio::task::yield_now().await;
        assert_eq!(l1.read_q().len(), 1, "no read while a lease is out");

        drop(in_flight);
        let nonce = timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(nonce, 3);
        assert!(l1.read_q().is_empty());
    }
}
