use super::Bridge;
use crate::{Precompile, dispatch_call, input_cost, mutate, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::IBridge::IBridgeCalls;

impl Precompile for Bridge {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(calldata, IBridgeCalls::abi_decode, |call| match call {
            // View functions
            IBridgeCalls::owner(c) => view(c, |_| self.owner()),
            IBridgeCalls::paused(c) => view(c, |_| self.paused()),
            IBridgeCalls::getTip20ForOriginToken(c) => {
                view(c, |c| self.get_tip20_for_origin_token(c))
            }
            IBridgeCalls::getTokenMapping(c) => view(c, |c| self.get_token_mapping(c)),
            IBridgeCalls::getDeposit(c) => view(c, |c| self.get_deposit(c)),
            IBridgeCalls::hasValidatorSignedDeposit(c) => {
                view(c, |c| self.has_validator_signed_deposit(c))
            }
            IBridgeCalls::getBurn(c) => view(c, |c| self.get_burn(c)),

            // Mutating functions
            IBridgeCalls::changeOwner(c) => {
                mutate_void(c, msg_sender, |s, c| self.change_owner(s, c))
            }
            IBridgeCalls::pause(c) => mutate_void(c, msg_sender, |s, _| self.pause(s)),
            IBridgeCalls::unpause(c) => mutate_void(c, msg_sender, |s, _| self.unpause(s)),
            IBridgeCalls::registerTokenMapping(c) => {
                mutate_void(c, msg_sender, |s, c| self.register_token_mapping(s, c))
            }
            IBridgeCalls::registerDeposit(c) => {
                mutate(c, msg_sender, |s, c| self.register_deposit(s, c))
            }
            IBridgeCalls::submitDepositVote(c) => {
                mutate_void(c, msg_sender, |s, c| self.submit_deposit_vote(s, c))
            }
            IBridgeCalls::finalizeDeposit(c) => {
                mutate_void(c, msg_sender, |s, c| self.finalize_deposit(s, c))
            }
            IBridgeCalls::burnForUnlock(c) => {
                mutate(c, msg_sender, |s, c| self.burn_for_unlock(s, c))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expect_precompile_revert,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{Address, B256},
        sol_types::{SolCall, SolValue},
    };
    use tempo_contracts::precompiles::{BridgeError, IBridge, IBridge::IBridgeCalls};

    #[test]
    fn test_function_selector_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut bridge = Bridge::new();

            // Initialize with owner
            bridge.initialize(owner)?;

            // Test invalid selector - should return Ok with reverted status
            let result = bridge.call(&[0x12, 0x34, 0x56, 0x78], sender)?;
            assert!(result.reverted);

            // Test insufficient calldata
            let result = bridge.call(&[0x12, 0x34], sender);
            assert!(matches!(result, Err(PrecompileError::Other(_))));

            Ok(())
        })
    }

    #[test]
    fn test_owner_view_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut bridge = Bridge::new();

            // Initialize with owner
            bridge.initialize(owner)?;

            // Call owner() via dispatch
            let owner_call = IBridge::ownerCall {};
            let calldata = owner_call.abi_encode();

            let result = bridge.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);

            // Verify we get the correct owner
            let decoded = Address::abi_decode(&result.bytes)?;
            assert_eq!(decoded, owner);

            Ok(())
        })
    }

    #[test]
    fn test_register_token_mapping_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let origin_chain_id = 1u64;
        let origin_token = Address::random();
        let tempo_tip20 = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut bridge = Bridge::new();

            // Initialize with owner
            bridge.initialize(owner)?;

            // Register token mapping via dispatch
            let register_call = IBridge::registerTokenMappingCall {
                originChainId: origin_chain_id,
                originToken: origin_token,
                tempoTip20: tempo_tip20,
            };
            let calldata = register_call.abi_encode();

            let result = bridge.call(&calldata, owner)?;
            assert!(!result.reverted);

            // Verify mapping was registered
            let mapping = bridge.get_token_mapping(IBridge::getTokenMappingCall {
                originChainId: origin_chain_id,
                originToken: origin_token,
            })?;
            assert_eq!(mapping.tempoTip20, tempo_tip20);
            assert!(mapping.active);

            Ok(())
        })
    }

    #[test]
    fn test_unauthorized_register_token_mapping_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let non_owner = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut bridge = Bridge::new();

            // Initialize with owner
            bridge.initialize(owner)?;

            // Try to register token mapping as non-owner
            let register_call = IBridge::registerTokenMappingCall {
                originChainId: 1,
                originToken: Address::random(),
                tempoTip20: Address::random(),
            };
            let calldata = register_call.abi_encode();

            let result = bridge.call(&calldata, non_owner);
            expect_precompile_revert(&result, BridgeError::unauthorized());

            Ok(())
        })
    }

    #[test]
    fn test_register_deposit_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let sender = Address::random();
        let origin_chain_id = 1u64;
        let origin_token = Address::random();
        let tempo_tip20 = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut bridge = Bridge::new();
            bridge.initialize(owner)?;

            // Register token mapping first
            bridge.register_token_mapping(
                owner,
                IBridge::registerTokenMappingCall {
                    originChainId: origin_chain_id,
                    originToken: origin_token,
                    tempoTip20: tempo_tip20,
                },
            )?;

            // Register deposit via dispatch
            let deposit_call = IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
                originTxHash: B256::random(),
                originLogIndex: 0,
                tempoRecipient: recipient,
                amount: 1000000,
                originBlockNumber: 12345,
            };
            let calldata = deposit_call.abi_encode();

            let result = bridge.call(&calldata, sender)?;
            assert!(!result.reverted);

            // Decode the returned requestId
            let request_id = B256::abi_decode(&result.bytes)?;
            assert!(!request_id.is_zero());

            Ok(())
        })
    }

    #[test]
    fn test_get_deposit_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let sender = Address::random();
        let origin_chain_id = 1u64;
        let origin_token = Address::random();
        let tempo_tip20 = Address::random();
        let recipient = Address::random();
        let amount = 1000000u64;

        StorageCtx::enter(&mut storage, || {
            let mut bridge = Bridge::new();
            bridge.initialize(owner)?;

            // Register token mapping
            bridge.register_token_mapping(
                owner,
                IBridge::registerTokenMappingCall {
                    originChainId: origin_chain_id,
                    originToken: origin_token,
                    tempoTip20: tempo_tip20,
                },
            )?;

            // Register deposit
            let request_id = bridge.register_deposit(
                sender,
                IBridge::registerDepositCall {
                    originChainId: origin_chain_id,
                    originEscrow: Address::repeat_byte(0xEE),
                    originToken: origin_token,
                    originTxHash: B256::random(),
                    originLogIndex: 0,
                    tempoRecipient: recipient,
                    amount,
                    originBlockNumber: 12345,
                },
            )?;

            // Get deposit via dispatch
            let get_call = IBridge::getDepositCall {
                requestId: request_id,
            };
            let calldata = get_call.abi_encode();

            let result = bridge.call(&calldata, sender)?;
            assert!(!result.reverted);

            // Decode and verify
            let deposit = IBridge::DepositRequest::abi_decode(&result.bytes)?;
            assert_eq!(deposit.tempoRecipient, recipient);
            assert_eq!(deposit.amount, amount);

            Ok(())
        })
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut bridge = Bridge::new();

            let unsupported = check_selector_coverage(
                &mut bridge,
                IBridgeCalls::SELECTORS,
                "IBridge",
                IBridgeCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
