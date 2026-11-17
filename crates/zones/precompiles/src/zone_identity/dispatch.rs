//! ABI dispatch for the [`ZoneIdentity`] precompile.

use alloy_primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::zones::IZoneIdentity;
use tempo_precompiles::{charge_input_cost, dispatch, storage::Handler};

use super::ZoneIdentity;
use crate::{
    dispatch::{mutate, view},
    error::ZoneResult,
    storage::{L1State, L1StorageReader},
};

impl ZoneIdentity {
    /// Dispatches a ZoneIdentity ABI call. The registrar is read from the portal on the finalized
    /// Tempo anchor in `l1`.
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
        let registrar = || Self::registrar(l1);

        dispatch!(
            calldata,
            |call| match call {
                IZoneIdentity::IZoneIdentityCalls {
                    createOrg(call) => mutate(call, msg_sender, |caller, call| {
                        self.create_org(caller, registrar()?, call.admin)
                    }),
                    setOrgAdmin(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_org_admin(caller, registrar()?, call.orgId, call.admin)
                    }),
                    addMember(call) => mutate(call, msg_sender, |caller, call| {
                        self.add_member(caller, registrar()?, call.orgId, call.account)
                    }),
                    removeMember(call) => mutate(call, msg_sender, |caller, call| {
                        self.remove_member(caller, registrar()?, call.account)
                    }),
                    setFrozen(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_frozen(caller, registrar()?, call.account, call.frozen)
                    }),
                    setOutbound(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_outbound(caller, registrar()?, call.fromOrg, call.toOrg, call.tokenMask)
                    }),
                    setInbound(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_inbound(caller, registrar()?, call.toOrg, call.fromOrg, call.tokenMask)
                    }),
                    orgAdmin(call) => view(call, |call| self.org_admin(registrar()?, call.orgId)),
                    tokenBit(call) => view(call, |call| -> ZoneResult<_> {
                        let stored = self.token_bits[call.token].read()?;
                        Ok(IZoneIdentity::tokenBitReturn {
                            bit: stored.saturating_sub(1),
                            hasBit: stored != 0,
                        })
                    }),
                    orgOf(call) => view(call, |call| {
                        self.org_of(msg_sender, registrar()?, call.account).map(|member| {
                            IZoneIdentity::orgOfReturn {
                                orgId: member.org,
                                frozen: member.frozen,
                            }
                        })
                    }),
                    edge(call) => view(call, |call| {
                        self.edge(msg_sender, registrar()?, call.fromOrg, call.toOrg)
                    }),
                }
            },
        )
    }
}
