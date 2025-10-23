use crate::{
    Precompile,
    linking_usd::LinkingUSD,
    metadata, mutate, mutate_void,
    storage::PrecompileStorageProvider,
    tip20::{IRolesAuth, ITIP20, RolesAuthError, TIP20Error},
    view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<S: PrecompileStorageProvider> Precompile for LinkingUSD<'_, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .unwrap();

        match selector {
            // Metadata
            ITIP20::nameCall::SELECTOR => metadata::<ITIP20::nameCall>(self.name()),
            ITIP20::symbolCall::SELECTOR => metadata::<ITIP20::symbolCall>(self.symbol()),
            ITIP20::decimalsCall::SELECTOR => metadata::<ITIP20::decimalsCall>(self.decimals()),
            ITIP20::totalSupplyCall::SELECTOR => {
                metadata::<ITIP20::totalSupplyCall>(self.total_supply())
            }
            ITIP20::currencyCall::SELECTOR => metadata::<ITIP20::currencyCall>(self.currency()),
            ITIP20::quoteTokenCall::SELECTOR => metadata::<ITIP20::quoteTokenCall>(Address::ZERO),
            ITIP20::pausedCall::SELECTOR => metadata::<ITIP20::pausedCall>(self.paused()),
            ITIP20::supplyCapCall::SELECTOR => {
                metadata::<ITIP20::supplyCapCall>(self.token.supply_cap())
            }
            ITIP20::transferPolicyIdCall::SELECTOR => {
                metadata::<ITIP20::transferPolicyIdCall>(self.token.transfer_policy_id())
            }

            // View functions
            ITIP20::balanceOfCall::SELECTOR => {
                view::<ITIP20::balanceOfCall>(calldata, |call| self.balance_of(call))
            }
            ITIP20::allowanceCall::SELECTOR => {
                view::<ITIP20::allowanceCall>(calldata, |call| self.allowance(call))
            }
            ITIP20::noncesCall::SELECTOR => {
                view::<ITIP20::noncesCall>(calldata, |call| self.token.nonces(call))
            }

            // Mutating functions that work normally
            ITIP20::approveCall::SELECTOR => {
                mutate::<ITIP20::approveCall, TIP20Error>(calldata, msg_sender, |sender, call| {
                    self.approve(sender, call)
                })
            }
            ITIP20::mintCall::SELECTOR => {
                mutate_void::<ITIP20::mintCall, TIP20Error>(calldata, msg_sender, |sender, call| {
                    self.mint(sender, call)
                })
            }
            ITIP20::mintWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::mintWithMemoCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |sender, call| self.token.mint_with_memo(sender, call),
                )
            }
            ITIP20::burnCall::SELECTOR => {
                mutate_void::<ITIP20::burnCall, TIP20Error>(calldata, msg_sender, |sender, call| {
                    self.burn(sender, call)
                })
            }
            ITIP20::burnWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::burnWithMemoCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |sender, call| self.token.burn_with_memo(sender, call),
                )
            }
            ITIP20::burnBlockedCall::SELECTOR => {
                mutate_void::<ITIP20::burnBlockedCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |sender, call| self.token.burn_blocked(sender, call),
                )
            }
            ITIP20::pauseCall::SELECTOR => mutate_void::<ITIP20::pauseCall, TIP20Error>(
                calldata,
                msg_sender,
                |sender, call| self.pause(sender, call),
            ),
            ITIP20::unpauseCall::SELECTOR => mutate_void::<ITIP20::unpauseCall, TIP20Error>(
                calldata,
                msg_sender,
                |sender, call| self.unpause(sender, call),
            ),
            ITIP20::permitCall::SELECTOR => mutate_void::<ITIP20::permitCall, TIP20Error>(
                calldata,
                msg_sender,
                |sender, call| self.token.permit(sender, call),
            ),
            ITIP20::changeTransferPolicyIdCall::SELECTOR => {
                mutate_void::<ITIP20::changeTransferPolicyIdCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |sender, call| self.token.change_transfer_policy_id(sender, call),
                )
            }
            ITIP20::setSupplyCapCall::SELECTOR => {
                mutate_void::<ITIP20::setSupplyCapCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |sender, call| self.token.set_supply_cap(sender, call),
                )
            }

            // Transfer functions that are disabled for LinkingUSD
            ITIP20::transferCall::SELECTOR => {
                mutate::<ITIP20::transferCall, TIP20Error>(calldata, msg_sender, |sender, call| {
                    self.transfer(sender, call)
                })
            }
            ITIP20::transferFromCall::SELECTOR => mutate::<ITIP20::transferFromCall, TIP20Error>(
                calldata,
                msg_sender,
                |sender, call| self.transfer_from(sender, call),
            ),
            ITIP20::transferWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::transferWithMemoCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |sender, call| self.transfer_with_memo(sender, call),
                )
            }
            ITIP20::transferFromWithMemoCall::SELECTOR => {
                mutate::<ITIP20::transferFromWithMemoCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |sender, call| self.transfer_from_with_memo(sender, call),
                )
            }

            // RolesAuth functions
            IRolesAuth::hasRoleCall::SELECTOR => {
                view::<IRolesAuth::hasRoleCall>(calldata, |call| {
                    self.get_roles_contract().has_role(call)
                })
            }
            IRolesAuth::getRoleAdminCall::SELECTOR => {
                view::<IRolesAuth::getRoleAdminCall>(calldata, |call| {
                    self.get_roles_contract().get_role_admin(call)
                })
            }
            IRolesAuth::grantRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::grantRoleCall, RolesAuthError>(
                    calldata,
                    msg_sender,
                    |sender, call| self.get_roles_contract().grant_role(sender, call),
                )
            }
            IRolesAuth::revokeRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::revokeRoleCall, RolesAuthError>(
                    calldata,
                    msg_sender,
                    |sender, call| self.get_roles_contract().revoke_role(sender, call),
                )
            }
            IRolesAuth::renounceRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::renounceRoleCall, RolesAuthError>(
                    calldata,
                    msg_sender,
                    |sender, call| self.get_roles_contract().renounce_role(sender, call),
                )
            }
            IRolesAuth::setRoleAdminCall::SELECTOR => {
                mutate_void::<IRolesAuth::setRoleAdminCall, RolesAuthError>(
                    calldata,
                    msg_sender,
                    |sender, call| self.get_roles_contract().set_role_admin(sender, call),
                )
            }

            _ => Err(PrecompileError::Other("Unknown selector".to_string())),
        }
    }
}
