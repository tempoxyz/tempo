//! ABI dispatch for the [`ZoneIdentity`] precompile.

use alloy_primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::zones::IZoneIdentity;
use tempo_precompiles::{charge_input_cost, dispatch, storage::StorageCtx};

use super::{L1Target, ZoneIdentity};
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
                        self.add_members(caller, call.orgId, &call.accounts)
                    }),
                    removeMember(call) => mutate(call, msg_sender, |caller, call| {
                        self.remove_member(caller, call.account)
                    }),
                    setEdge(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_edge(caller, call.fromOrg, call.toOrg, &call.tokens, call.allowed)
                    }),
                    setL1Target(call) => mutate(call, msg_sender, |caller, call| {
                        let rules = L1Target {
                            deposit_from: call.depositFrom,
                            withdraw_to: call.withdrawTo,
                        };
                        self.set_l1_target(caller, call.orgId, call.target, &call.tokens, rules)
                    }),
                    setL1Policy(call) => mutate(call, msg_sender, |caller, call| {
                        self.set_l1_policy(caller, call.orgId, &call.tokens, call.policy.into())
                    }),
                    orgAdmin(call) => view(call, |call| self.org_admin(call.orgId)),
                    orgOf(call) => view(call, |call| {
                        self.org_of(msg_sender, registrar()?, call.account)
                    }),
                    edge(call) => view(call, |call| {
                        self.edge(msg_sender, registrar()?, call.fromOrg, call.toOrg, call.token)
                    }),
                    l1Target(call) => view(call, |call| {
                        self.l1_target(msg_sender, registrar()?, call.orgId, call.target, call.token).map(
                            |rules| IZoneIdentity::l1TargetReturn {
                                depositFrom: rules.deposit_from,
                                withdrawTo: rules.withdraw_to,
                            },
                        )
                    }),
                    l1Policy(call) => view(call, |call| {
                        self.l1_policy(msg_sender, registrar()?, call.orgId, call.token)
                            .map(IZoneIdentity::L1Policy::from)
                    }),
                }
            },
        ))
    }
}
