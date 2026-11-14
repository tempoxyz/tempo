//! The system transaction that opens a zone block.

use alloy_consensus::{SignableTransaction as _, TxLegacy};
use alloy_primitives::U256;
use alloy_sol_types::SolCall as _;
use reth_primitives_traits::Recovered;
use tempo_contracts::zones::{DecryptionData, EnabledToken, IZoneInbox, QueuedDeposit};
use tempo_primitives::{
    TempoHeader, TempoTxEnvelope,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use zone_primitives::constants::ZONE_INBOX_ADDRESS;

/// Builds the system `advanceTempo` transaction that opens a zone block, importing `header` with
/// its deposits, their decryptions and the tokens it enables.
pub fn build_advance_tempo_tx_from_parts(
    header: &TempoHeader,
    deposits: Vec<QueuedDeposit>,
    decryptions: Vec<DecryptionData>,
    enabled_tokens: Vec<EnabledToken>,
    chain_id: u64,
) -> Recovered<TempoTxEnvelope> {
    let calldata = IZoneInbox::advanceTempoCall {
        header: alloy_rlp::encode(header).into(),
        deposits,
        decryptions,
        enabledTokens: enabled_tokens,
    }
    .abi_encode();

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: ZONE_INBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };

    Recovered::new_unchecked(
        TempoTxEnvelope::Legacy(tx.into_signed(TEMPO_SYSTEM_TX_SIGNATURE)),
        TEMPO_SYSTEM_TX_SENDER,
    )
}
