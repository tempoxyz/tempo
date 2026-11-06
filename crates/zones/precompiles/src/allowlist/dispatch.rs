//! ABI dispatch for the [`ZoneAllowlist`] precompile.

use alloy_primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::zones::IZoneAllowlist;
use tempo_precompiles::{charge_input_cost, dispatch, dispatch::typed, storage::Handler, view};

use super::ZoneAllowlist;
use crate::storage::{L1State, L1StorageReader};

impl ZoneAllowlist {
    /// Dispatch an allowlist ABI call using execution-local L1 state for sequencer checks.
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
                IZoneAllowlist::IZoneAllowlistCalls {
                    admin(call) => view(call, |_| self.admin.read()),
                    enabled(call) => view(call, |_| self.is_enabled()),
                    count(call) => typed::view(call, |_| self.count(l1, msg_sender)),
                    isAllowed(call) => typed::view(call, |call| {
                        self.view_is_allowed(l1, msg_sender, call.account)
                    }),
                    accounts(call) => typed::view(call, |call| {
                        self.view_accounts(l1, msg_sender, call.offset, call.limit)
                    }),
                    setAdmin(call) => crate::dispatch::mutate(call, msg_sender, |caller, call| {
                        self.set_admin(l1, caller, call.newAdmin)
                    }),
                    setEnabled(call) => crate::dispatch::mutate(call, msg_sender, |caller, call| {
                        self.set_enabled(caller, call.enabled)
                    }),
                    setAllowed(call) => crate::dispatch::mutate(call, msg_sender, |caller, call| {
                        self.set_allowed(caller, call.accounts, call.allowed)
                    }),
                }
            },
        )
    }
}
