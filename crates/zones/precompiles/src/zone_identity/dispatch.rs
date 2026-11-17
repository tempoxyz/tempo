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
    /// Dispatches a ZoneIdentity ABI call. The portal admin is read from the finalized Tempo
    /// anchor in `l1`.
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
        let portal_admin =
            || -> ZoneResult<Address> { Ok(l1.read_portal(|portal| &portal.admin)?) };

        dispatch!(
            calldata,
            |call| match call {
                IZoneIdentity::IZoneIdentityCalls {
                    setRegistrar(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_registrar(caller, portal_admin()?, call.registrar)
                    }),
                    setEnforced(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_enforced(caller, portal_admin()?, call.enforced)
                    }),
                    createOrg(call) => mutate(call, msg_sender, |caller, call| {
                        self.create_org(caller, call.admin)
                    }),
                    setOrgAdmin(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_org_admin(caller, call.orgId, call.admin)
                    }),
                    registerToken(call) => mutate(call, msg_sender, |caller, call| {
                        self.register_token(caller, call.token)
                    }),
                    addMember(call) => mutate(call, msg_sender, |caller, call| {
                        self.add_member(caller, call.orgId, call.account, call.l1Only)
                    }),
                    removeMember(call) => mutate(call, msg_sender, |caller, call| {
                        self.remove_member(caller, call.account)
                    }),
                    setFrozen(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_frozen(caller, call.account, call.frozen)
                    }),
                    setOutbound(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_outbound(caller, call.fromOrg, call.toOrg, call.tokenMask)
                    }),
                    setInbound(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_inbound(caller, call.toOrg, call.fromOrg, call.tokenMask)
                    }),
                    registrar(call) => view(call, |_| -> ZoneResult<_> {
                        Ok(self.registrar.read()?)
                    }),
                    enforced(call) => view(call, |_| -> ZoneResult<_> {
                        Ok(self.enforced.read()?)
                    }),
                    orgAdmin(call) => view(call, |call| self.org_admin(call.orgId)),
                    tokenBit(call) => view(call, |call| -> ZoneResult<_> {
                        let stored = self.token_bits[call.token].read()?;
                        Ok(IZoneIdentity::tokenBitReturn {
                            bit: stored.saturating_sub(1),
                            registered: stored != 0,
                        })
                    }),
                    orgOf(call) => view(call, |call| {
                        self.org_of(msg_sender, call.account).map(|member| {
                            IZoneIdentity::orgOfReturn {
                                orgId: member.org,
                                l1Only: member.l1_only,
                                frozen: member.frozen,
                            }
                        })
                    }),
                    edge(call) => view(call, |call| {
                        self.edge(msg_sender, call.fromOrg, call.toOrg)
                    }),
                }
            },
        )
    }
}
