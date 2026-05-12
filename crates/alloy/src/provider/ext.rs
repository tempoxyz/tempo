use alloy_contract::Result as ContractResult;
use alloy_primitives::{Address, U256};
use alloy_provider::{
    Identity, Provider, ProviderBuilder,
    fillers::{JoinFill, RecommendedFillers},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    IAccountKeychain::{IAccountKeychainInstance, KeyInfo},
    INonce::INonceInstance,
    NONCE_PRECOMPILE_ADDRESS, getAllowedCallsReturn, getRemainingLimitReturn,
};
use tempo_primitives::transaction::{CallScope, TEMPO_EXPIRING_NONCE_KEY};

use crate::{
    TempoFillers, TempoNetwork,
    fillers::{ExpiringNonceFiller, NonceKeyFiller, Random2DNonceFiller},
};

/// Extension trait for [`Provider`] with Tempo-specific functionality.
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait TempoProviderExt: Provider<TempoNetwork> {
    /// Returns a typed instance for the Account Keychain precompile.
    fn account_keychain(&self) -> IAccountKeychainInstance<&Self, TempoNetwork>
    where
        Self: Sized,
    {
        IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, self)
    }

    /// Returns a typed instance for the Nonce Manager precompile.
    fn nonce_manager(&self) -> INonceInstance<&Self, TempoNetwork>
    where
        Self: Sized,
    {
        INonceInstance::new(NONCE_PRECOMPILE_ADDRESS, self)
    }

    /// Returns the current nonce for an account and nonce key.
    ///
    /// Protocol nonce key `0` uses `eth_getTransactionCount`. Expiring nonce transactions always
    /// use nonce `0`; all other nonce keys are read from the Nonce Manager precompile.
    async fn get_transaction_count_with_nonce_key(
        &self,
        account: Address,
        nonce_key: U256,
    ) -> ContractResult<u64>
    where
        Self: Sized,
    {
        if nonce_key.is_zero() {
            return self
                .get_transaction_count(account)
                .await
                .map_err(Into::into);
        }

        if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
            return Ok(0);
        }

        self.nonce_manager()
            .getNonce(account, nonce_key)
            .call()
            .await
    }

    /// Returns information about a key authorized for an account.
    async fn get_keychain_key(&self, account: Address, key_id: Address) -> ContractResult<KeyInfo>
    where
        Self: Sized,
    {
        self.account_keychain().getKey(account, key_id).call().await
    }

    /// Returns the remaining spending limit for an account/key/token tuple.
    async fn get_keychain_remaining_limit(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
    ) -> ContractResult<U256>
    where
        Self: Sized,
    {
        self.get_keychain_remaining_limit_with_period(account, key_id, token)
            .await
            .map(|getRemainingLimitReturn { remaining, .. }| remaining)
    }

    /// Returns the remaining spending limit together with the current period end.
    async fn get_keychain_remaining_limit_with_period(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
    ) -> ContractResult<getRemainingLimitReturn>
    where
        Self: Sized,
    {
        self.account_keychain()
            .getRemainingLimitWithPeriod(account, key_id, token)
            .call()
            .await
    }

    /// Returns the configured call scopes for an account key.
    ///
    /// `None` means unrestricted. `Some(vec![])` means scoped deny-all.
    async fn get_keychain_allowed_calls(
        &self,
        account: Address,
        key_id: Address,
    ) -> ContractResult<Option<Vec<CallScope>>>
    where
        Self: Sized,
    {
        self.account_keychain()
            .getAllowedCalls(account, key_id)
            .call()
            .await
            .map(|getAllowedCallsReturn { isScoped, scopes }| {
                isScoped.then(|| scopes.into_iter().map(Into::into).collect())
            })
    }

    /// Returns the key ID used in the current transaction context.
    async fn get_keychain_transaction_key(&self) -> ContractResult<Address>
    where
        Self: Sized,
    {
        self.account_keychain().getTransactionKey().call().await
    }

    /// Returns `true` if the given Tempo hardfork is active on the connected chain.
    ///
    /// Queries the node's `tempo_forkSchedule` RPC to determine the currently active hardfork.
    async fn is_hardfork_active(
        &self,
        hardfork: TempoHardfork,
    ) -> Result<bool, alloy_transport::TransportError>
    where
        Self: Sized,
    {
        #[derive(Debug, serde::Deserialize)]
        struct Response {
            active: String,
        }

        let resp: Response = self.raw_request("tempo_forkSchedule".into(), ()).await?;

        Ok(resp
            .active
            .parse::<TempoHardfork>()
            .is_ok_and(|h| h >= hardfork))
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<P> TempoProviderExt for P where P: Provider<TempoNetwork> {}

/// Extension trait for [`ProviderBuilder`] with Tempo-specific functionality.
pub trait TempoProviderBuilderExt {
    /// Returns a provider builder with the recommended Tempo fillers and the random 2D nonce filler.
    ///
    /// See [`Random2DNonceFiller`] for more information on random 2D nonces.
    fn with_random_2d_nonces(
        self,
    ) -> ProviderBuilder<
        Identity,
        JoinFill<Identity, TempoFillers<Random2DNonceFiller>>,
        TempoNetwork,
    >;

    /// Returns a provider builder with the recommended Tempo fillers and the expiring nonce filler.
    ///
    /// See [`ExpiringNonceFiller`] for more information on expiring nonces ([TIP-1009]).
    ///
    /// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
    fn with_expiring_nonces(
        self,
    ) -> ProviderBuilder<
        Identity,
        JoinFill<Identity, TempoFillers<ExpiringNonceFiller>>,
        TempoNetwork,
    >;

    /// Returns a provider builder with the recommended Tempo fillers and the nonce key filler.
    ///
    /// The nonce key filler requires `nonce_key` to be set on the transaction request and
    /// fills the correct next nonce by querying the chain, with caching for batched sends.
    ///
    /// See [`NonceKeyFiller`] for more information.
    fn with_nonce_key_filler(
        self,
    ) -> ProviderBuilder<Identity, JoinFill<Identity, TempoFillers<NonceKeyFiller>>, TempoNetwork>;
}

impl TempoProviderBuilderExt
    for ProviderBuilder<
        Identity,
        JoinFill<Identity, <TempoNetwork as RecommendedFillers>::RecommendedFillers>,
        TempoNetwork,
    >
{
    fn with_random_2d_nonces(
        self,
    ) -> ProviderBuilder<
        Identity,
        JoinFill<Identity, TempoFillers<Random2DNonceFiller>>,
        TempoNetwork,
    > {
        ProviderBuilder::default().filler(TempoFillers::default())
    }

    fn with_expiring_nonces(
        self,
    ) -> ProviderBuilder<
        Identity,
        JoinFill<Identity, TempoFillers<ExpiringNonceFiller>>,
        TempoNetwork,
    > {
        ProviderBuilder::default().filler(TempoFillers::default())
    }

    fn with_nonce_key_filler(
        self,
    ) -> ProviderBuilder<Identity, JoinFill<Identity, TempoFillers<NonceKeyFiller>>, TempoNetwork>
    {
        ProviderBuilder::default().filler(TempoFillers::default())
    }
}

#[cfg(test)]
mod tests {
    use alloy::sol_types::SolCall;
    use alloy_primitives::{Address, Bytes, U64, U256};
    use alloy_provider::{Identity, ProviderBuilder, fillers::JoinFill, mock::Asserter};
    use tempo_contracts::precompiles::{
        IAccountKeychain::{
            CallScope as AbiCallScope, KeyInfo, SelectorRule as AbiSelectorRule, SignatureType,
            getAllowedCallsCall, getKeyCall, getRemainingLimitWithPeriodCall,
            getTransactionKeyCall,
        },
        INonce::getNonceCall,
        getAllowedCallsReturn, getRemainingLimitReturn,
    };
    use tempo_primitives::transaction::{CallScope, SelectorRule, TEMPO_EXPIRING_NONCE_KEY};

    use crate::{
        TempoFillers, TempoNetwork,
        fillers::{ExpiringNonceFiller, NonceKeyFiller, Random2DNonceFiller},
        provider::ext::{TempoProviderBuilderExt, TempoProviderExt},
    };

    fn mock_provider(asserter: Asserter) -> impl alloy_provider::Provider<TempoNetwork> {
        ProviderBuilder::<_, _, TempoNetwork>::default().connect_mocked_client(asserter)
    }

    #[test]
    fn test_with_random_nonces() {
        let _: ProviderBuilder<_, JoinFill<Identity, TempoFillers<Random2DNonceFiller>>, _> =
            ProviderBuilder::new_with_network::<TempoNetwork>().with_random_2d_nonces();
    }

    #[test]
    fn test_with_expiring_nonces() {
        let _: ProviderBuilder<_, JoinFill<Identity, TempoFillers<ExpiringNonceFiller>>, _> =
            ProviderBuilder::new_with_network::<TempoNetwork>().with_expiring_nonces();
    }

    #[test]
    fn test_with_nonce_key_filler() {
        let _: ProviderBuilder<_, JoinFill<Identity, TempoFillers<NonceKeyFiller>>, _> =
            ProviderBuilder::new_with_network::<TempoNetwork>().with_nonce_key_filler();
    }

    #[tokio::test]
    async fn test_get_keychain_key() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let account = Address::repeat_byte(0x11);
        let key_id = Address::repeat_byte(0x22);
        let expected = KeyInfo {
            signatureType: SignatureType::P256,
            keyId: key_id,
            expiry: 1_234_567_890,
            enforceLimits: true,
            isRevoked: false,
        };

        asserter.push_success(&Bytes::from(getKeyCall::abi_encode_returns(&expected)));

        let actual = provider
            .get_keychain_key(account, key_id)
            .await
            .expect("key info call succeeds");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_get_transaction_count_with_protocol_nonce_key() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let account = Address::repeat_byte(0x11);
        let expected = 42_u64;

        asserter.push_success(&U64::from(expected));

        let actual = provider
            .get_transaction_count_with_nonce_key(account, U256::ZERO)
            .await
            .expect("protocol nonce query succeeds");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_get_transaction_count_with_expiring_nonce_key() {
        let provider = mock_provider(Asserter::new());

        let actual = provider
            .get_transaction_count_with_nonce_key(
                Address::repeat_byte(0x11),
                TEMPO_EXPIRING_NONCE_KEY,
            )
            .await
            .expect("expiring nonce query succeeds");

        assert_eq!(actual, 0);
    }

    #[tokio::test]
    async fn test_get_transaction_count_with_2d_nonce_key() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let account = Address::repeat_byte(0x11);
        let nonce_key = U256::from(7_u64);
        let expected = 42_u64;

        asserter.push_success(&Bytes::from(getNonceCall::abi_encode_returns(&expected)));

        let actual = provider
            .get_transaction_count_with_nonce_key(account, nonce_key)
            .await
            .expect("2D nonce query succeeds");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_nonce_manager_accessor() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let account = Address::repeat_byte(0x11);
        let nonce_key = U256::from(7_u64);
        let expected = 42_u64;

        asserter.push_success(&Bytes::from(getNonceCall::abi_encode_returns(&expected)));

        let actual = provider
            .nonce_manager()
            .getNonce(account, nonce_key)
            .call()
            .await
            .expect("typed nonce manager call succeeds");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_get_keychain_remaining_limit() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let account = Address::repeat_byte(0x11);
        let key_id = Address::repeat_byte(0x22);
        let token = Address::repeat_byte(0x33);
        let expected = U256::from(42_u64);

        asserter.push_success(&Bytes::from(
            getRemainingLimitWithPeriodCall::abi_encode_returns(&getRemainingLimitReturn {
                remaining: expected,
                periodEnd: 0,
            }),
        ));

        let actual = provider
            .get_keychain_remaining_limit(account, key_id, token)
            .await
            .expect("remaining limit call succeeds");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_get_keychain_remaining_limit_with_period() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let account = Address::repeat_byte(0x11);
        let key_id = Address::repeat_byte(0x22);
        let token = Address::repeat_byte(0x33);
        let expected = getRemainingLimitReturn {
            remaining: U256::from(42_u64),
            periodEnd: 123,
        };

        asserter.push_success(&Bytes::from(
            getRemainingLimitWithPeriodCall::abi_encode_returns(&expected),
        ));

        let actual = provider
            .get_keychain_remaining_limit_with_period(account, key_id, token)
            .await
            .expect("remaining limit with period call succeeds");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_get_keychain_allowed_calls_maps_unrestricted_to_none() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let account = Address::repeat_byte(0x11);
        let key_id = Address::repeat_byte(0x22);

        asserter.push_success(&Bytes::from(getAllowedCallsCall::abi_encode_returns(
            &getAllowedCallsReturn {
                isScoped: false,
                scopes: vec![],
            },
        )));

        let actual = provider
            .get_keychain_allowed_calls(account, key_id)
            .await
            .expect("allowed calls query succeeds");

        assert_eq!(actual, None);
    }

    #[tokio::test]
    async fn test_get_keychain_allowed_calls_maps_scopes() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let account = Address::repeat_byte(0x11);
        let key_id = Address::repeat_byte(0x22);
        let expected = vec![CallScope {
            target: Address::repeat_byte(0x33),
            selector_rules: vec![SelectorRule {
                selector: [0xaa, 0xbb, 0xcc, 0xdd],
                recipients: vec![Address::repeat_byte(0x44)],
            }],
        }];

        asserter.push_success(&Bytes::from(getAllowedCallsCall::abi_encode_returns(
            &getAllowedCallsReturn {
                isScoped: true,
                scopes: vec![AbiCallScope {
                    target: Address::repeat_byte(0x33),
                    selectorRules: vec![AbiSelectorRule {
                        selector: [0xaa, 0xbb, 0xcc, 0xdd].into(),
                        recipients: vec![Address::repeat_byte(0x44)],
                    }],
                }],
            },
        )));

        let actual = provider
            .get_keychain_allowed_calls(account, key_id)
            .await
            .expect("allowed calls query succeeds");

        assert_eq!(actual, Some(expected));
    }

    #[tokio::test]
    async fn test_get_keychain_transaction_key() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let expected = Address::repeat_byte(0x44);

        asserter.push_success(&Bytes::from(getTransactionKeyCall::abi_encode_returns(
            &expected,
        )));

        let actual = provider
            .get_keychain_transaction_key()
            .await
            .expect("transaction key call succeeds");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_account_keychain_accessor() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());
        let account = Address::repeat_byte(0x11);
        let key_id = Address::repeat_byte(0x22);
        let expected = KeyInfo {
            signatureType: SignatureType::Secp256k1,
            keyId: key_id,
            expiry: u64::MAX,
            enforceLimits: false,
            isRevoked: true,
        };

        asserter.push_success(&Bytes::from(getKeyCall::abi_encode_returns(&expected)));

        let actual = provider
            .account_keychain()
            .getKey(account, key_id)
            .call()
            .await
            .expect("typed instance call succeeds");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_get_keychain_key_propagates_errors() {
        let asserter = Asserter::new();
        let provider = mock_provider(asserter.clone());

        asserter.push_failure_msg("boom");

        let err = provider
            .get_keychain_key(Address::repeat_byte(0x11), Address::repeat_byte(0x22))
            .await
            .expect_err("errors should propagate");

        assert!(matches!(err, alloy_contract::Error::TransportError(_)));
        assert!(err.to_string().contains("boom"));
    }
}
