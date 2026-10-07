//! Decoded L1 Portal events with their canonical receipt provenance.

use alloy_network::ReceiptResponse as _;
use alloy_primitives::{Address, Log};
use alloy_sol_types::SolEvent;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_zone_contracts::ZonePortal;

use crate::decode_event;

/// Semantic value of one recognized Zone Portal event.
#[derive(Debug)]
pub(crate) enum L1PortalEvent {
    /// A user deposit escrowed on L1 — new external backing entering the bridge.
    DepositMade {
        token: Address,
        net_amount: u128,
    },
    /// A TIP-20 token newly enabled for bridging.
    TokenEnabled {
        token: Address,
    },
    WithdrawalProcessed {
        token: Address,
        amount: u128,
        callback_success: bool,
    },
    /// A withdrawal bounce-back — recycles existing Portal backing, not a new
    /// external deposit.  Kept distinct from [`Self::DepositMade`].
    WithdrawalBounceBack {
        token: Address,
        amount: u128,
    },
    /// A deposit bounce-back processed on L1 (fee deducted, refund sent).
    DepositBounceBack {
        token: Address,
        amount: u128,
        bounceback_fee: u128,
    },
    /// A deposit bounce-back still pending on L1.
    DepositBounceBackPending {
        token: Address,
        amount: u128,
        bounceback_fee: u128,
    },
    RefundClaimed {
        token: Address,
        amount: u128,
    },
}

/// Builds ordered event evidence while receipts are visited once.
#[derive(Default)]
pub(super) struct EventCollector {
    portal: Address,
    events: Vec<L1PortalEvent>,
}

impl EventCollector {
    /// Create a collector that only decodes logs from `portal`.
    pub(super) fn new(portal: Address) -> Self {
        Self {
            portal,
            ..Default::default()
        }
    }

    /// Decode recognized Portal logs from one canonical receipt.
    ///
    /// Failed receipts are skipped entirely. Only logs from `portal` are
    /// decoded. Recognized-but-irrelevant topics (pausing, admin, gas-rate
    /// updates, etc.) are ignored; a truly unrecognized topic fails closed. A
    /// known event that fails ABI decoding returns a contextual error.
    pub(super) fn extract_receipt(
        &mut self,
        receipt: &TempoTransactionReceipt,
        block: u64,
    ) -> eyre::Result<()> {
        if !receipt.status() {
            return Ok(());
        }
        for log in receipt.logs() {
            self.extract_log(&log.inner, block)?;
        }
        Ok(())
    }

    /// Decode one receipt-authenticated log when it was emitted by the configured Portal.
    pub(super) fn extract_log(&mut self, log: &Log, block: u64) -> eyre::Result<()> {
        if log.address == self.portal
            && let Some(event) = decode_portal_event(log, block)?
        {
            self.events.push(event);
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Vec<L1PortalEvent> {
        self.events
    }
}

/// Decode one Portal event and fail closed on unknown protocol topics.
///
/// Only logs emitted from `portal` are passed to this function. A known event
/// that fails ABI decoding returns a contextual error.
fn decode_portal_event(log: &Log, block: u64) -> eyre::Result<Option<L1PortalEvent>> {
    let topic = log
        .topics()
        .first()
        .ok_or_else(|| eyre::eyre!("topicless Portal log in block {block}"))?;
    macro_rules! ignored {
        ($event:ty, $name:literal) => {{
            decode_event::<$event>(log, $name, block)?;
            return Ok(None);
        }};
    }
    Ok(Some(match *topic {
        ZonePortal::DepositMade::SIGNATURE_HASH => {
            let e = decode_event::<ZonePortal::DepositMade>(log, "DepositMade", block)?;
            L1PortalEvent::DepositMade {
                token: e.token,
                net_amount: e.netAmount,
            }
        }
        ZonePortal::TokenEnabled::SIGNATURE_HASH => {
            let e = decode_event::<ZonePortal::TokenEnabled>(log, "TokenEnabled", block)?;
            L1PortalEvent::TokenEnabled { token: e.token }
        }
        ZonePortal::BatchSubmitted_0::SIGNATURE_HASH => {
            ignored!(ZonePortal::BatchSubmitted_0, "BatchSubmitted_0")
        }
        ZonePortal::BatchSubmitted_1::SIGNATURE_HASH => {
            ignored!(ZonePortal::BatchSubmitted_1, "BatchSubmitted_1")
        }
        ZonePortal::WithdrawalProcessed::SIGNATURE_HASH => {
            let e =
                decode_event::<ZonePortal::WithdrawalProcessed>(log, "WithdrawalProcessed", block)?;
            L1PortalEvent::WithdrawalProcessed {
                token: e.token,
                amount: e.amount,
                callback_success: e.callbackSuccess,
            }
        }
        ZonePortal::WithdrawalBounceBack::SIGNATURE_HASH => {
            let e = decode_event::<ZonePortal::WithdrawalBounceBack>(
                log,
                "WithdrawalBounceBack",
                block,
            )?;
            L1PortalEvent::WithdrawalBounceBack {
                token: e.token,
                amount: e.amount,
            }
        }
        ZonePortal::DepositBounceBack::SIGNATURE_HASH => {
            let e = decode_event::<ZonePortal::DepositBounceBack>(log, "DepositBounceBack", block)?;
            L1PortalEvent::DepositBounceBack {
                token: e.token,
                amount: e.amount,
                bounceback_fee: e.bouncebackFee,
            }
        }
        ZonePortal::DepositBounceBackPending::SIGNATURE_HASH => {
            let e = decode_event::<ZonePortal::DepositBounceBackPending>(
                log,
                "DepositBounceBackPending",
                block,
            )?;
            L1PortalEvent::DepositBounceBackPending {
                token: e.token,
                amount: e.amount,
                bounceback_fee: e.bouncebackFee,
            }
        }
        ZonePortal::RefundClaimed::SIGNATURE_HASH => {
            let e = decode_event::<ZonePortal::RefundClaimed>(log, "RefundClaimed", block)?;
            L1PortalEvent::RefundClaimed {
                token: e.token,
                amount: e.amount,
            }
        }
        ZonePortal::DepositsPaused::SIGNATURE_HASH => {
            ignored!(ZonePortal::DepositsPaused, "DepositsPaused")
        }
        ZonePortal::DepositsResumed::SIGNATURE_HASH => {
            ignored!(ZonePortal::DepositsResumed, "DepositsResumed")
        }
        ZonePortal::PortalPaused::SIGNATURE_HASH => {
            ignored!(ZonePortal::PortalPaused, "PortalPaused")
        }
        ZonePortal::PortalResumed::SIGNATURE_HASH => {
            ignored!(ZonePortal::PortalResumed, "PortalResumed")
        }
        ZonePortal::AbdicationScheduled::SIGNATURE_HASH => {
            ignored!(ZonePortal::AbdicationScheduled, "AbdicationScheduled")
        }
        ZonePortal::RpcUrlUpdated::SIGNATURE_HASH => {
            ignored!(ZonePortal::RpcUrlUpdated, "RpcUrlUpdated")
        }
        ZonePortal::SequencerEncryptionKeyUpdated::SIGNATURE_HASH => ignored!(
            ZonePortal::SequencerEncryptionKeyUpdated,
            "SequencerEncryptionKeyUpdated"
        ),
        ZonePortal::ZoneGasRateUpdated::SIGNATURE_HASH => {
            ignored!(ZonePortal::ZoneGasRateUpdated, "ZoneGasRateUpdated")
        }
        ZonePortal::MaxTempoGasRateUpdated::SIGNATURE_HASH => {
            ignored!(ZonePortal::MaxTempoGasRateUpdated, "MaxTempoGasRateUpdated")
        }
        ZonePortal::BouncebackGasUpdated::SIGNATURE_HASH => {
            ignored!(ZonePortal::BouncebackGasUpdated, "BouncebackGasUpdated")
        }
        ZonePortal::AdminTransferStarted::SIGNATURE_HASH => {
            ignored!(ZonePortal::AdminTransferStarted, "AdminTransferStarted")
        }
        ZonePortal::AdminTransferred::SIGNATURE_HASH => {
            ignored!(ZonePortal::AdminTransferred, "AdminTransferred")
        }
        ZonePortal::RoleUpdated::SIGNATURE_HASH => ignored!(ZonePortal::RoleUpdated, "RoleUpdated"),
        ZonePortal::EnforcementModesUpdated::SIGNATURE_HASH => ignored!(
            ZonePortal::EnforcementModesUpdated,
            "EnforcementModesUpdated"
        ),
        ZonePortal::LeaderUpdated::SIGNATURE_HASH => {
            ignored!(ZonePortal::LeaderUpdated, "LeaderUpdated")
        }
        ZonePortal::SequencerSetUpdated::SIGNATURE_HASH => {
            ignored!(ZonePortal::SequencerSetUpdated, "SequencerSetUpdated")
        }
        _ => {
            eyre::bail!("unsupported Portal event {topic} in block {block}");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::ReceiptWithBloom;
    use alloy_primitives::{B256, Bloom, U256, address};
    use alloy_rpc_types_eth::TransactionReceipt;
    use tempo_alloy::rpc::TempoTransactionReceipt;
    use tempo_primitives::{TempoReceipt, TempoTxType};

    const PORTAL: Address = address!("0x0000000000000000000000000000000000000abc");
    const BLOCK: u64 = 100;

    fn receipt(
        success: bool,
        hash: B256,
        logs: Vec<alloy_rpc_types_eth::Log>,
    ) -> TempoTransactionReceipt {
        TempoTransactionReceipt {
            inner: TransactionReceipt {
                inner: ReceiptWithBloom::new(
                    TempoReceipt {
                        tx_type: TempoTxType::Legacy,
                        success,
                        cumulative_gas_used: 0,
                        logs,
                    },
                    Bloom::ZERO,
                ),
                transaction_hash: hash,
                transaction_index: Some(0),
                block_hash: Some(B256::ZERO),
                block_number: Some(BLOCK),
                gas_used: 0,
                effective_gas_price: 0,
                blob_gas_used: None,
                blob_gas_price: None,
                from: Address::ZERO,
                to: Some(Address::ZERO),
                contract_address: None,
            },
            fee_token: None,
            fee_payer: Address::ZERO,
        }
    }

    fn log(data: alloy_primitives::LogData) -> alloy_rpc_types_eth::Log {
        alloy_rpc_types_eth::Log {
            inner: Log {
                address: PORTAL,
                data,
            },
            ..Default::default()
        }
    }
    fn deposit() -> alloy_rpc_types_eth::Log {
        log(ZonePortal::DepositMade {
            newCurrentDepositQueueHash: B256::repeat_byte(1),
            sender: Address::ZERO,
            token: Address::repeat_byte(3),
            netAmount: 500,
            fee: 10,
            keyIndex: U256::ZERO,
            ephemeralPubkeyX: B256::ZERO,
            ephemeralPubkeyYParity: 0,
            ciphertext: Default::default(),
            nonce: [0; 12].into(),
            tag: [0; 16].into(),
            tempoRefundRecipient: Address::repeat_byte(4),
            depositNumber: 7,
        }
        .encode_log_data())
    }
    fn token() -> alloy_rpc_types_eth::Log {
        log(ZonePortal::TokenEnabled {
            token: Address::repeat_byte(5),
            name: "Test".into(),
            symbol: "TST".into(),
            currency: "USD".into(),
        }
        .encode_log_data())
    }
    fn batch(index: U256) -> alloy_rpc_types_eth::Log {
        log(ZonePortal::BatchSubmitted_1 {
            withdrawalBatchIndex: 3,
            withdrawalQueueIndex: index,
            nextProcessedDepositQueueHash: B256::ZERO,
            nextBlockHash: B256::repeat_byte(6),
            withdrawalQueueHash: B256::repeat_byte(7),
            lastProcessedDepositNumber: 9,
            lastProcessedEnabledTokenCount: 10,
        }
        .encode_log_data())
    }
    fn withdrawal() -> alloy_rpc_types_eth::Log {
        log(ZonePortal::WithdrawalProcessed {
            to: Address::repeat_byte(8),
            senderTag: B256::repeat_byte(9),
            token: Address::repeat_byte(10),
            amount: 1000,
            callbackSuccess: true,
        }
        .encode_log_data())
    }
    fn withdrawal_bounce() -> alloy_rpc_types_eth::Log {
        log(ZonePortal::WithdrawalBounceBack {
            newCurrentDepositQueueHash: B256::repeat_byte(11),
            fallbackNonce: 42,
            token: Address::repeat_byte(12),
            amount: 777,
            depositNumber: 5,
        }
        .encode_log_data())
    }
    fn deposit_bounce() -> alloy_rpc_types_eth::Log {
        log(ZonePortal::DepositBounceBack {
            tempoRefundRecipient: Address::repeat_byte(13),
            token: Address::repeat_byte(14),
            amount: 300,
            bouncebackFee: 5,
        }
        .encode_log_data())
    }
    fn pending() -> alloy_rpc_types_eth::Log {
        log(ZonePortal::DepositBounceBackPending {
            tempoRefundRecipient: Address::repeat_byte(15),
            token: Address::repeat_byte(16),
            amount: 200,
            bouncebackFee: 3,
        }
        .encode_log_data())
    }
    fn refund() -> alloy_rpc_types_eth::Log {
        log(ZonePortal::RefundClaimed {
            recipient: Address::repeat_byte(17),
            token: Address::repeat_byte(18),
            amount: 42,
        }
        .encode_log_data())
    }

    fn collect(receipts: &[TempoTransactionReceipt]) -> eyre::Result<Vec<L1PortalEvent>> {
        let mut collector = EventCollector::new(PORTAL);
        for receipt in receipts {
            collector.extract_receipt(receipt, BLOCK)?;
        }
        Ok(collector.finish())
    }

    #[test]
    fn extract_all_portal_event_variants_in_order() {
        let events = collect(&[receipt(
            true,
            B256::ZERO,
            vec![
                deposit(),
                token(),
                batch(U256::ONE),
                withdrawal(),
                withdrawal_bounce(),
                deposit_bounce(),
                pending(),
                refund(),
            ],
        )])
        .unwrap();
        assert_eq!(events.len(), 7);
        assert!(matches!(
            events[0],
            L1PortalEvent::DepositMade {
                net_amount: 500,
                ..
            }
        ));
        assert!(matches!(events[1], L1PortalEvent::TokenEnabled { .. }));
        assert!(matches!(
            events[2],
            L1PortalEvent::WithdrawalProcessed { .. }
        ));
        assert!(matches!(
            events[3],
            L1PortalEvent::WithdrawalBounceBack { .. }
        ));
        assert!(matches!(events[4], L1PortalEvent::DepositBounceBack { .. }));
        assert!(matches!(
            events[5],
            L1PortalEvent::DepositBounceBackPending { .. }
        ));
        assert!(matches!(
            events[6],
            L1PortalEvent::RefundClaimed { amount: 42, .. }
        ));
    }

    #[test]
    fn rejects_unknown_topics_and_ignores_non_protocol_logs() {
        let unknown = log(alloy_primitives::LogData::new_unchecked(
            vec![B256::repeat_byte(0xff)],
            Default::default(),
        ));
        assert!(collect(&[receipt(true, B256::ZERO, vec![unknown])]).is_err());
        let mut wrong = deposit();
        wrong.inner.address = Address::repeat_byte(99);
        let events = collect(&[
            receipt(true, B256::ZERO, vec![wrong]),
            receipt(false, B256::ZERO, vec![deposit()]),
        ])
        .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn reject_malformed_known_event() {
        let bad = log(alloy_primitives::LogData::new_unchecked(
            vec![ZonePortal::DepositMade::SIGNATURE_HASH],
            vec![0xde, 0xad].into(),
        ));
        assert!(
            collect(&[receipt(true, B256::ZERO, vec![bad])])
                .unwrap_err()
                .to_string()
                .contains("malformed DepositMade")
        );
    }

    #[test]
    fn reject_non_canonical_trailing_data() {
        let original = deposit();
        let mut bytes = original.inner.data.data.to_vec();
        bytes.extend([0; 32]);
        let bad = log(alloy_primitives::LogData::new_unchecked(
            original.inner.topics().to_vec(),
            bytes.into(),
        ));
        assert!(
            collect(&[receipt(true, B256::ZERO, vec![bad])])
                .unwrap_err()
                .to_string()
                .contains("non-canonical DepositMade")
        );
    }

    #[test]
    fn retains_canonical_order_across_receipts() {
        let mut noise = log(alloy_primitives::LogData::new_unchecked(
            vec![B256::repeat_byte(0xff)],
            Default::default(),
        ));
        noise.inner.address = Address::repeat_byte(99);
        let receipts = [
            receipt(false, B256::ZERO, vec![deposit()]),
            receipt(true, B256::repeat_byte(1), vec![deposit()]),
            receipt(
                true,
                B256::repeat_byte(2),
                vec![noise, withdrawal(), token()],
            ),
        ];
        let mut collector = EventCollector::new(PORTAL);
        for receipt in &receipts {
            collector.extract_receipt(receipt, BLOCK).unwrap();
        }
        let events = collector.finish();

        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], L1PortalEvent::DepositMade { .. }));
        assert!(matches!(
            events[1],
            L1PortalEvent::WithdrawalProcessed { .. }
        ));
        assert!(matches!(
            events[2],
            L1PortalEvent::TokenEnabled { token } if token == Address::repeat_byte(5)
        ));
    }
}
