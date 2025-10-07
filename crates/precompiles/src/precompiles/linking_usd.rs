use crate::{
    contracts::{
        LinkingUSD, StorageProvider,
        types::{ITIP20, TIP20Error},
    },
    precompiles::{Precompile, metadata, mutate, mutate_void, view},
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<S: StorageProvider> Precompile for LinkingUSD<'_, S> {
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
            ITIP20::linkingTokenCall::SELECTOR => {
                metadata::<ITIP20::linkingTokenCall>(self.linking_token())
            }

            // View functions
            ITIP20::balanceOfCall::SELECTOR => {
                view::<ITIP20::balanceOfCall>(calldata, |call| self.balance_of(call))
            }
            ITIP20::allowanceCall::SELECTOR => {
                view::<ITIP20::allowanceCall>(calldata, |call| self.allowance(call))
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
            ITIP20::burnCall::SELECTOR => {
                mutate_void::<ITIP20::burnCall, TIP20Error>(calldata, msg_sender, |sender, call| {
                    self.burn(sender, call)
                })
            }

            // Transfer functions that are disabled for LinkingUSD
            ITIP20::transferCall::SELECTOR => {
                mutate::<ITIP20::transferCall, TIP20Error>(calldata, msg_sender, |_sender, call| {
                    self.transfer(call.to, call.amount)
                })
            }
            ITIP20::transferFromCall::SELECTOR => mutate::<ITIP20::transferFromCall, TIP20Error>(
                calldata,
                msg_sender,
                |_sender, call| self.transfer_from(call.from, call.to, call.amount),
            ),
            ITIP20::transferWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::transferWithMemoCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |_sender, call| self.transfer_with_memo(call.to, call.amount, *call.memo),
                )
            }

            _ => Err(PrecompileError::Other("Unknown selector".to_string())),
        }
    }
}
