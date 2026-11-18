//! ABI dispatch for the [`ZoneIdentity`] precompile.

use alloy_primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::zones::IZoneIdentity;
use tempo_precompiles::{charge_input_cost, dispatch, storage::StorageCtx};

use super::ZoneIdentity;
use crate::{
    dispatch::{mutate, view},
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
        let registrar = || l1.read_portal(|portal| &portal.identity_registrar);

        // Every read is priced as cold, so a call's gas does not reveal which slots earlier calls
        // warmed, such as the admin slot of an account's org.
        StorageCtx::default().with_cold_pricing(|| dispatch!(
            calldata,
            |call| match call {
                IZoneIdentity::IZoneIdentityCalls {
                    createOrg(call) => mutate(call, msg_sender, |caller, call| {
                        self.create_org(caller, registrar()?, call.admin)
                    }),
                    setOrgAdmin(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_org_admin(caller, registrar()?, call.orgId, call.admin)
                    }),
                    addMembers(call) => mutate(call, msg_sender, |caller, call| {
                        self.add_members(caller, registrar()?, call.orgId, &call.accounts)
                    }),
                    removeMember(call) => mutate(call, msg_sender, |caller, call| {
                        self.remove_member(caller, call.account)
                    }),
                    setFrozen(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_frozen(caller, call.account, call.frozen)
                    }),
                    setEdge(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_edge(caller, registrar()?, call.from, call.to, &call.tokens, call.allowed)
                    }),
                    orgAdmin(call) => view(call, |call| self.org_admin(registrar()?, call.orgId)),
                    orgOf(call) => view(call, |call| {
                        self.org_of(msg_sender, registrar()?, call.account).map(|member| {
                            IZoneIdentity::orgOfReturn {
                                orgId: member.org,
                                frozen: member.frozen,
                            }
                        })
                    }),
                    edge(call) => view(call, |call| {
                        self.edge(msg_sender, registrar()?, call.from, call.to, call.token)
                    }),
                }
            },
        ))
    }
}
