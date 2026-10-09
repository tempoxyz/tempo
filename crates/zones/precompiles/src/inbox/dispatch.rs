//! ABI dispatch for the [`ZoneInbox`] precompile.

use alloy_primitives::{Address, Bytes};
use revm::precompile::PrecompileResult;
use tempo_precompiles::{
    EncodePrecompileResult, charge_input_cost, dispatch, dispatch::typed, storage::Handler, view,
};
use tempo_zone_contracts::IZoneInbox;
use zone_primitives::constants::TEMPO_STATE_ADDRESS;

use super::ZoneInbox;
use crate::storage::{L1State, L1StorageReader};

impl ZoneInbox {
    /// Dispatch an Inbox ABI call using execution-local L1 state.
    pub(crate) fn call<P>(
        &mut self,
        l1: &L1State<P>,
        calldata: &[u8],
        msg_sender: Address,
    ) -> PrecompileResult
    where
        P: L1StorageReader,
    {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IZoneInbox::IZoneInboxCalls {
                    processedDepositQueueHash(call) => {
                        view(call, |_| self.processed_deposit_queue_hash.read())
                    },
                    processedDepositNumber(call) => {
                        view(call, |_| self.processed_deposit_number.read())
                    },
                    processedTokenEnablementHash(call) => {
                        view(call, |_| self.processed_token_enablement_hash.read())
                    },
                    #[schedule(since = T13)]
                    processedEnabledTokenCount(call) => {
                        view(call, |_| self.processed_enabled_token_count.read())
                    },
                    tempoPortal(call) => view(call, |_| Ok(l1.portal())),
                    tempoState(call) => view(call, |_| Ok(TEMPO_STATE_ADDRESS)),
                    refunds(call) => typed::view(call, |call| {
                       self.view_refund(l1, msg_sender, call.token, call.owner)
                    }),
                    claimRefund(call) => crate::dispatch::mutate(call, msg_sender, |caller, call| {
                        self.claim_refund(caller, call.token)
                    }),
                    advanceTempo(call) => {
                        if self.storage.is_static() {
                            Ok(self.storage.revert_output(Bytes::new()))
                        } else {
                            self.advance_tempo(l1, l1.portal(), msg_sender, call)
                                .encode_precompile_result(0, 0, |()| Bytes::new())
                        }
                    },
                    #[schedule(since = T13)]
                    advanceTempoHeaders(call) => {
                        if self.storage.is_static() {
                            Ok(self.storage.revert_output(Bytes::new()))
                        } else {
                            self.advance_tempo_headers(l1, msg_sender, call)
                                .encode_precompile_result(0, 0, |()| Bytes::new())
                        }
                    },
                }
            },
        )
    }
}
