//! ABI dispatch for the [`AccountKeychain`] precompile.

use super::{AccountKeychain, SignatureType, TokenLimit, authorizeKeyCall};
use crate::{
    IntoPrecompileResult, Precompile, dispatch_call, input_cost, mutate_void, unknown_selector,
    view,
};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::IAccountKeychain::{IAccountKeychainCalls, setAllowedCallsCall};

mod legacy {
    alloy::sol! {
        enum SignatureType {
            Secp256k1,
            P256,
            WebAuthn,
        }

        struct TokenLimit {
            address token;
            uint256 amount;
        }

        function authorizeKey(
            address keyId,
            SignatureType signatureType,
            uint64 expiry,
            bool enforceLimits,
            TokenLimit[] calldata limits
        ) external;

        function getRemainingLimit(
            address account,
            address keyId,
            address token
        ) external view returns (uint256);
    }
}

impl Precompile for AccountKeychain {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        // Pre-T3 compatibility: accept the legacy authorizeKey selector used before TIP-1011.
        if !self.storage.spec().is_t3()
            && calldata.len() >= 4
            && calldata[..4] == legacy::authorizeKeyCall::SELECTOR
        {
            let legacy_call = legacy::authorizeKeyCall::abi_decode(calldata).map_err(|_| {
                PrecompileError::Other("invalid legacy authorizeKey calldata".into())
            })?;

            let signature_type = match legacy_call.signatureType {
                legacy::SignatureType::Secp256k1 => SignatureType::Secp256k1,
                legacy::SignatureType::P256 => SignatureType::P256,
                legacy::SignatureType::WebAuthn => SignatureType::WebAuthn,
                legacy::SignatureType::__Invalid => {
                    return Err(PrecompileError::Other(
                        "invalid legacy signature type".into(),
                    ));
                }
            };

            let call = authorizeKeyCall {
                keyId: legacy_call.keyId,
                signatureType: signature_type,
                expiry: legacy_call.expiry,
                enforceLimits: legacy_call.enforceLimits,
                limits: legacy_call
                    .limits
                    .into_iter()
                    .map(|limit| TokenLimit {
                        token: limit.token,
                        amount: limit.amount,
                        period: 0,
                    })
                    .collect(),
                enforceAllowedCalls: false,
                allowedCalls: vec![],
            };

            return mutate_void(call, msg_sender, |sender, c| self.authorize_key(sender, c));
        }

        dispatch_call(
            calldata,
            IAccountKeychainCalls::abi_decode,
            |call| match call {
                IAccountKeychainCalls::authorizeKey(call) => {
                    if !self.storage.spec().is_t3() {
                        return unknown_selector(
                            authorizeKeyCall::SELECTOR,
                            self.storage.gas_used(),
                        );
                    }
                    mutate_void(call, msg_sender, |sender, c| self.authorize_key(sender, c))
                }
                IAccountKeychainCalls::revokeKey(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.revoke_key(sender, c))
                }
                IAccountKeychainCalls::updateSpendingLimit(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.update_spending_limit(sender, c)
                    })
                }
                IAccountKeychainCalls::setAllowedCalls(call) => {
                    if !self.storage.spec().is_t3() {
                        return unknown_selector(
                            setAllowedCallsCall::SELECTOR,
                            self.storage.gas_used(),
                        );
                    }
                    mutate_void(call, msg_sender, |sender, c| {
                        self.set_allowed_calls(sender, c)
                    })
                }
                IAccountKeychainCalls::getKey(call) => view(call, |c| self.get_key(c)),
                IAccountKeychainCalls::getRemainingLimit(call) => {
                    if !self.storage.spec().is_t3() {
                        return self
                            .get_remaining_limit(call)
                            .into_precompile_result(0, |ret| {
                                legacy::getRemainingLimitCall::abi_encode_returns(&ret).into()
                            });
                    }
                    view(call, |c| self.get_remaining_limit_with_period(c))
                }
                IAccountKeychainCalls::getAllowedCalls(call) => {
                    if !self.storage.spec().is_t3() {
                        return unknown_selector(
                            tempo_contracts::precompiles::IAccountKeychain::getAllowedCallsCall::SELECTOR,
                            self.storage.gas_used(),
                        );
                    }
                    view(call, |c| self.get_allowed_calls(c))
                }
                IAccountKeychainCalls::getTransactionKey(call) => {
                    view(call, |c| self.get_transaction_key(c, msg_sender))
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Precompile,
        account_keychain::getRemainingLimitCall,
        storage::{Handler, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::primitives::U256;
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_account_keychain_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = AccountKeychain::new();

            let unsupported = check_selector_coverage(
                &mut fee_manager,
                IAccountKeychainCalls::SELECTORS,
                "IAccountKeychain",
                IAccountKeychainCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }

    #[test]
    fn test_legacy_authorize_key_selector_supported_pre_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let calldata = legacy::authorizeKeyCall {
                keyId: key_id,
                signatureType: legacy::SignatureType::Secp256k1,
                expiry: u64::MAX,
                enforceLimits: true,
                limits: vec![legacy::TokenLimit {
                    token,
                    amount: U256::from(100),
                }],
            }
            .abi_encode();

            let _ = keychain.call(&calldata, account)?;

            let key = keychain.keys[account][key_id].read()?;
            assert_eq!(key.expiry, u64::MAX);

            let limit_key = AccountKeychain::spending_limit_key(account, key_id);
            let remaining = keychain.spending_limits[limit_key][token].read()?;
            assert_eq!(remaining, U256::from(100));

            Ok(())
        })
    }

    #[test]
    fn test_new_authorize_key_selector_rejected_pre_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let account = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let calldata = authorizeKeyCall {
                keyId: Address::random(),
                signatureType: SignatureType::Secp256k1,
                expiry: u64::MAX,
                enforceLimits: true,
                limits: vec![TokenLimit {
                    token: Address::random(),
                    amount: U256::from(100),
                    period: 0,
                }],
                enforceAllowedCalls: false,
                allowedCalls: vec![],
            }
            .abi_encode();

            let result = keychain.call(&calldata, account)?;
            assert!(result.reverted);

            Ok(())
        })
    }

    #[test]
    fn test_get_remaining_limit_uses_legacy_return_shape_pre_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let authorize_calldata = legacy::authorizeKeyCall {
                keyId: key_id,
                signatureType: legacy::SignatureType::Secp256k1,
                expiry: u64::MAX,
                enforceLimits: true,
                limits: vec![legacy::TokenLimit {
                    token,
                    amount: U256::from(123),
                }],
            }
            .abi_encode();
            let _ = keychain.call(&authorize_calldata, account)?;

            let get_limit_calldata = getRemainingLimitCall {
                account,
                keyId: key_id,
                token,
            }
            .abi_encode();

            let output = keychain.call(&get_limit_calldata, account)?;
            assert!(!output.reverted);
            assert_eq!(
                output.bytes.len(),
                32,
                "pre-T3 should return legacy uint256"
            );

            let remaining = legacy::getRemainingLimitCall::abi_decode_returns(&output.bytes)?;
            assert_eq!(remaining, U256::from(123));

            Ok(())
        })
    }
}
