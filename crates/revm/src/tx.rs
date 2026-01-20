use crate::TempoInvalidTransaction;
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, Typed2718, crypto::secp256k1};
use alloy_evm::{FromRecoveredTx, FromTxWithEncoded, IntoTxEnv};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use reth_evm::TransactionEnv;
use revm::context::{
    Transaction, TxEnv,
    either::Either,
    result::InvalidTransaction,
    transaction::{
        AccessList, AccessListItem, RecoveredAuthority, RecoveredAuthorization, SignedAuthorization,
    },
};
use tempo_primitives::{
    AASigned, TempoSignature, TempoTransaction, TempoTxEnvelope,
    transaction::{
        Call, RecoveredTempoAuthorization, SignedKeyAuthorization, calc_gas_balance_spending,
    },
};

/// Tempo transaction environment for AA features.
#[derive(Debug, Clone, Default)]
pub struct TempoBatchCallEnv {
    /// Signature bytes for Tempo transactions
    pub signature: TempoSignature,

    /// validBefore timestamp
    pub valid_before: Option<u64>,

    /// validAfter timestamp
    pub valid_after: Option<u64>,

    /// Multiple calls for Tempo transactions
    pub aa_calls: Vec<Call>,

    /// Authorization list (EIP-7702 with Tempo signatures)
    ///
    /// Each authorization lazily recovers the authority on first access and caches the result.
    /// The signature is preserved for gas calculation.
    pub tempo_authorization_list: Vec<RecoveredTempoAuthorization>,

    /// Nonce key for 2D nonce system
    pub nonce_key: U256,

    /// Whether the transaction is a subblock transaction.
    pub subblock_transaction: bool,

    /// Optional key authorization for provisioning access keys
    pub key_authorization: Option<SignedKeyAuthorization>,

    /// Transaction signature hash (for signature verification)
    pub signature_hash: B256,

    /// Optional access key ID override for gas estimation.
    /// When provided in eth_call/eth_estimateGas, enables spending limits simulation
    /// This is not used in actual transaction execution - the key_id is recovered from the signature.
    pub override_key_id: Option<Address>,
}
/// Tempo transaction environment.
#[derive(Debug, Clone, Default, derive_more::Deref, derive_more::DerefMut)]
pub struct TempoTxEnv {
    /// Inner Ethereum [`TxEnv`].
    #[deref]
    #[deref_mut]
    pub inner: TxEnv,

    /// Optional fee token preference specified for the transaction.
    pub fee_token: Option<Address>,

    /// Whether the transaction is a system transaction.
    pub is_system_tx: bool,

    /// Optional fee payer specified for the transaction.
    ///
    /// - Some(Some(address)) corresponds to a successfully recovered fee payer
    /// - Some(None) corresponds to a failed recovery and means that transaction is invalid
    /// - None corresponds to a transaction without a fee payer
    pub fee_payer: Option<Option<Address>>,

    /// AA-specific transaction environment (boxed to keep TempoTxEnv lean for non-AA tx)
    pub tempo_tx_env: Option<Box<TempoBatchCallEnv>>,
}

impl TempoTxEnv {
    /// Resolves fee payer from the signature.
    pub fn fee_payer(&self) -> Result<Address, TempoInvalidTransaction> {
        if let Some(fee_payer) = self.fee_payer {
            fee_payer.ok_or(TempoInvalidTransaction::InvalidFeePayerSignature)
        } else {
            Ok(self.caller())
        }
    }

    /// Returns true if the transaction is a subblock transaction.
    pub fn is_subblock_transaction(&self) -> bool {
        self.tempo_tx_env
            .as_ref()
            .is_some_and(|aa| aa.subblock_transaction)
    }

    /// Returns the first top-level call in the transaction.
    pub fn first_call(&self) -> Option<(&TxKind, &[u8])> {
        if let Some(aa) = self.tempo_tx_env.as_ref() {
            aa.aa_calls
                .first()
                .map(|call| (&call.to, call.input.as_ref()))
        } else {
            Some((&self.inner.kind, &self.inner.data))
        }
    }

    /// Invokes the given closure for each top-level call in the transaction and
    /// returns true if all calls returned true.
    pub fn calls(&self) -> impl Iterator<Item = (&TxKind, &[u8])> {
        if let Some(aa) = self.tempo_tx_env.as_ref() {
            Either::Left(
                aa.aa_calls
                    .iter()
                    .map(|call| (&call.to, call.input.as_ref())),
            )
        } else {
            Either::Right(core::iter::once((
                &self.inner.kind,
                self.inner.input().as_ref(),
            )))
        }
    }
}

impl From<TxEnv> for TempoTxEnv {
    fn from(inner: TxEnv) -> Self {
        Self {
            inner,
            ..Default::default()
        }
    }
}

impl Transaction for TempoTxEnv {
    type AccessListItem<'a> = &'a AccessListItem;
    type Authorization<'a> = &'a Either<SignedAuthorization, RecoveredAuthorization>;

    fn tx_type(&self) -> u8 {
        self.inner.tx_type()
    }

    fn kind(&self) -> TxKind {
        self.inner.kind()
    }

    fn caller(&self) -> Address {
        self.inner.caller()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_price(&self) -> u128 {
        self.inner.gas_price()
    }

    fn value(&self) -> U256 {
        self.inner.value()
    }

    fn nonce(&self) -> u64 {
        Transaction::nonce(&self.inner)
    }

    fn chain_id(&self) -> Option<u64> {
        self.inner.chain_id()
    }

    fn access_list(&self) -> Option<impl Iterator<Item = Self::AccessListItem<'_>>> {
        self.inner.access_list()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.inner.max_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> u128 {
        self.inner.max_fee_per_blob_gas()
    }

    fn authorization_list_len(&self) -> usize {
        self.inner.authorization_list_len()
    }

    fn authorization_list(&self) -> impl Iterator<Item = Self::Authorization<'_>> {
        self.inner.authorization_list()
    }

    fn input(&self) -> &Bytes {
        self.inner.input()
    }

    fn blob_versioned_hashes(&self) -> &[B256] {
        self.inner.blob_versioned_hashes()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.max_priority_fee_per_gas()
    }

    fn max_balance_spending(&self) -> Result<U256, InvalidTransaction> {
        calc_gas_balance_spending(self.gas_limit(), self.max_fee_per_gas())
            .checked_add(self.value())
            .ok_or(InvalidTransaction::OverflowPaymentInTransaction)
    }

    fn effective_balance_spending(
        &self,
        base_fee: u128,
        _blob_price: u128,
    ) -> Result<U256, InvalidTransaction> {
        calc_gas_balance_spending(self.gas_limit(), self.effective_gas_price(base_fee))
            .checked_add(self.value())
            .ok_or(InvalidTransaction::OverflowPaymentInTransaction)
    }
}

impl TransactionEnv for TempoTxEnv {
    fn set_gas_limit(&mut self, gas_limit: u64) {
        self.inner.set_gas_limit(gas_limit);
    }

    fn nonce(&self) -> u64 {
        Transaction::nonce(&self.inner)
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.inner.set_nonce(nonce);
    }

    fn set_access_list(&mut self, access_list: AccessList) {
        self.inner.set_access_list(access_list);
    }
}

impl IntoTxEnv<Self> for TempoTxEnv {
    fn into_tx_env(self) -> Self {
        self
    }
}

impl FromRecoveredTx<EthereumTxEnvelope<TxEip4844>> for TempoTxEnv {
    fn from_recovered_tx(tx: &EthereumTxEnvelope<TxEip4844>, sender: Address) -> Self {
        TxEnv::from_recovered_tx(tx, sender).into()
    }
}

impl FromRecoveredTx<AASigned> for TempoTxEnv {
    fn from_recovered_tx(aa_signed: &AASigned, caller: Address) -> Self {
        let tx = aa_signed.tx();
        let signature = aa_signed.signature();

        // Populate the key_id cache for Keychain signatures before cloning
        // This parallelizes recovery during Tx->TxEnv conversion, and the cache is preserved when cloned
        if let Some(keychain_sig) = signature.as_keychain() {
            let _ = keychain_sig.key_id(&aa_signed.signature_hash());
        }

        let TempoTransaction {
            chain_id,
            fee_token,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            calls,
            access_list,
            nonce_key,
            nonce,
            fee_payer_signature,
            valid_before,
            valid_after,
            key_authorization,
            tempo_authorization_list,
        } = tx;

        // Extract to/value/input from calls (use first call or defaults)
        let (to, value, input) = if let Some(first_call) = calls.first() {
            (first_call.to, first_call.value, first_call.input.clone())
        } else {
            (
                alloy_primitives::TxKind::Create,
                alloy_primitives::U256::ZERO,
                alloy_primitives::Bytes::new(),
            )
        };

        Self {
            inner: TxEnv {
                tx_type: tx.ty(),
                caller,
                gas_limit: *gas_limit,
                gas_price: *max_fee_per_gas,
                kind: to,
                value,
                data: input,
                nonce: *nonce, // AA: nonce maps to TxEnv.nonce
                chain_id: Some(*chain_id),
                gas_priority_fee: Some(*max_priority_fee_per_gas),
                access_list: access_list.clone(),
                // Convert Tempo authorization list to RecoveredAuthorization upfront
                authorization_list: tempo_authorization_list
                    .iter()
                    .map(|auth| {
                        let authority = auth
                            .recover_authority()
                            .map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid);
                        Either::Right(RecoveredAuthorization::new_unchecked(
                            auth.inner().clone(),
                            authority,
                        ))
                    })
                    .collect(),
                ..Default::default()
            },
            fee_token: *fee_token,
            is_system_tx: false,
            fee_payer: fee_payer_signature.map(|sig| {
                secp256k1::recover_signer(&sig, tx.fee_payer_signature_hash(caller)).ok()
            }),
            // Bundle AA-specific fields into TempoBatchCallEnv
            tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                signature: signature.clone(),
                valid_before: *valid_before,
                valid_after: *valid_after,
                aa_calls: calls.clone(),
                // Recover authorizations upfront to avoid recovery during execution
                tempo_authorization_list: tempo_authorization_list
                    .iter()
                    .map(|auth| RecoveredTempoAuthorization::recover(auth.clone()))
                    .collect(),
                nonce_key: *nonce_key,
                subblock_transaction: aa_signed.tx().subblock_proposer().is_some(),
                key_authorization: key_authorization.clone(),
                signature_hash: aa_signed.signature_hash(),
                // override_key_id is only used for gas estimation, not actual execution
                override_key_id: None,
            })),
        }
    }
}

impl FromRecoveredTx<TempoTxEnvelope> for TempoTxEnv {
    fn from_recovered_tx(tx: &TempoTxEnvelope, sender: Address) -> Self {
        match tx {
            tx @ TempoTxEnvelope::Legacy(inner) => Self {
                inner: TxEnv::from_recovered_tx(inner.tx(), sender),
                fee_token: None,
                is_system_tx: tx.is_system_tx(),
                fee_payer: None,
                tempo_tx_env: None, // Non-AA transaction
            },
            TempoTxEnvelope::Eip2930(tx) => TxEnv::from_recovered_tx(tx.tx(), sender).into(),
            TempoTxEnvelope::Eip1559(tx) => TxEnv::from_recovered_tx(tx.tx(), sender).into(),
            TempoTxEnvelope::Eip7702(tx) => TxEnv::from_recovered_tx(tx.tx(), sender).into(),
            TempoTxEnvelope::AA(tx) => Self::from_recovered_tx(tx, sender),
        }
    }
}

impl FromTxWithEncoded<EthereumTxEnvelope<TxEip4844>> for TempoTxEnv {
    fn from_encoded_tx(
        tx: &EthereumTxEnvelope<TxEip4844>,
        sender: Address,
        _encoded: Bytes,
    ) -> Self {
        Self::from_recovered_tx(tx, sender)
    }
}

impl FromTxWithEncoded<AASigned> for TempoTxEnv {
    fn from_encoded_tx(tx: &AASigned, sender: Address, _encoded: Bytes) -> Self {
        Self::from_recovered_tx(tx, sender)
    }
}

impl FromTxWithEncoded<TempoTxEnvelope> for TempoTxEnv {
    fn from_encoded_tx(tx: &TempoTxEnvelope, sender: Address, _encoded: Bytes) -> Self {
        Self::from_recovered_tx(tx, sender)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::TxKind;
    use proptest::prelude::*;
    use revm::context::{Transaction, result::InvalidTransaction};
    use tempo_primitives::transaction::{Call, calc_gas_balance_spending, validate_calls};

    fn create_call(to: TxKind) -> Call {
        Call {
            to,
            value: alloy_primitives::U256::ZERO,
            input: alloy_primitives::Bytes::new(),
        }
    }

    #[test]
    fn test_validate_empty_calls_list() {
        let result = validate_calls(&[], false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_validate_single_call_ok() {
        let calls = vec![create_call(TxKind::Call(alloy_primitives::Address::ZERO))];
        assert!(validate_calls(&calls, false).is_ok());
    }

    #[test]
    fn test_validate_single_create_ok() {
        let calls = vec![create_call(TxKind::Create)];
        assert!(validate_calls(&calls, false).is_ok());
    }

    #[test]
    fn test_validate_create_with_authorization_list_fails() {
        let calls = vec![create_call(TxKind::Create)];
        let result = validate_calls(&calls, true); // has_authorization_list = true
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CREATE"));
    }

    #[test]
    fn test_validate_create_not_first_call_fails() {
        let calls = vec![
            create_call(TxKind::Call(alloy_primitives::Address::ZERO)),
            create_call(TxKind::Create), // CREATE as second call - should fail
        ];
        let result = validate_calls(&calls, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("first call"));
    }

    #[test]
    fn test_validate_multiple_creates_fails() {
        let calls = vec![
            create_call(TxKind::Create),
            create_call(TxKind::Create), // Second CREATE - should fail
        ];
        let result = validate_calls(&calls, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("first call"));
    }

    #[test]
    fn test_validate_create_first_then_calls_ok() {
        let calls = vec![
            create_call(TxKind::Create),
            create_call(TxKind::Call(alloy_primitives::Address::ZERO)),
            create_call(TxKind::Call(alloy_primitives::Address::random())),
        ];
        // No auth list, so CREATE is allowed
        assert!(validate_calls(&calls, false).is_ok());
    }

    #[test]
    fn test_validate_multiple_calls_ok() {
        let calls = vec![
            create_call(TxKind::Call(alloy_primitives::Address::ZERO)),
            create_call(TxKind::Call(alloy_primitives::Address::random())),
            create_call(TxKind::Call(alloy_primitives::Address::random())),
        ];
        assert!(validate_calls(&calls, false).is_ok());
    }

    #[test]
    fn test_tx_env() {
        let tx_env = super::TempoTxEnv::default();

        // Test default values
        assert_eq!(tx_env.inner.nonce, 0);
        assert!(tx_env.inner.access_list.is_empty());
        assert!(tx_env.fee_token.is_none());
        assert!(!tx_env.is_system_tx);
        assert!(tx_env.fee_payer.is_none());
        assert!(tx_env.tempo_tx_env.is_none());
    }

    #[test]
    fn test_transaction_env_set_gas_limit() {
        use reth_evm::TransactionEnv;

        let mut tx_env = super::TempoTxEnv::default();

        tx_env.set_gas_limit(21000);
        assert_eq!(tx_env.inner.gas_limit, 21000);

        tx_env.set_gas_limit(100_000);
        assert_eq!(tx_env.inner.gas_limit, 100_000);
    }

    #[test]
    fn test_transaction_env_nonce() {
        use reth_evm::TransactionEnv;

        let mut tx_env = super::TempoTxEnv::default();
        assert_eq!(TransactionEnv::nonce(&tx_env), 0);

        tx_env.set_nonce(42);
        assert_eq!(TransactionEnv::nonce(&tx_env), 42);

        tx_env.set_nonce(u64::MAX);
        assert_eq!(TransactionEnv::nonce(&tx_env), u64::MAX);
    }

    #[test]
    fn test_transaction_env_set_access_list() {
        use reth_evm::TransactionEnv;
        use revm::context::transaction::{AccessList, AccessListItem};

        let mut tx_env = super::TempoTxEnv::default();
        assert!(tx_env.inner.access_list.is_empty());

        let access_list = AccessList(vec![
            AccessListItem {
                address: alloy_primitives::Address::ZERO,
                storage_keys: vec![alloy_primitives::B256::ZERO],
            },
            AccessListItem {
                address: alloy_primitives::Address::repeat_byte(0x01),
                storage_keys: vec![
                    alloy_primitives::B256::repeat_byte(0x01),
                    alloy_primitives::B256::repeat_byte(0x02),
                ],
            },
        ]);

        tx_env.set_access_list(access_list);
        assert_eq!(tx_env.inner.access_list.0.len(), 2);
        assert_eq!(
            tx_env.inner.access_list.0[0].address,
            alloy_primitives::Address::ZERO
        );
        assert_eq!(tx_env.inner.access_list.0[0].storage_keys.len(), 1);
        assert_eq!(tx_env.inner.access_list.0[1].storage_keys.len(), 2);
    }

    #[test]
    fn test_transaction_env_combined_operations() {
        use reth_evm::TransactionEnv;
        use revm::context::transaction::{AccessList, AccessListItem};

        let mut tx_env = super::TempoTxEnv::default();

        // Set all values
        tx_env.set_gas_limit(50_000);
        tx_env.set_nonce(100);
        tx_env.set_access_list(AccessList(vec![AccessListItem {
            address: alloy_primitives::Address::repeat_byte(0xAB),
            storage_keys: vec![],
        }]));

        // Verify all values are set correctly
        assert_eq!(tx_env.inner.gas_limit, 50_000);
        assert_eq!(TransactionEnv::nonce(&tx_env), 100);
        assert_eq!(tx_env.inner.access_list.0.len(), 1);
        assert_eq!(
            tx_env.inner.access_list.0[0].address,
            alloy_primitives::Address::repeat_byte(0xAB)
        );
    }

    #[test]
    fn test_transaction_env_from_tx_env() {
        use reth_evm::TransactionEnv;
        use revm::context::TxEnv;

        let inner = TxEnv {
            gas_limit: 75_000,
            nonce: 55,
            ..Default::default()
        };

        let tx_env: super::TempoTxEnv = inner.into();

        assert_eq!(tx_env.inner.gas_limit, 75_000);
        assert_eq!(TransactionEnv::nonce(&tx_env), 55);
        assert!(tx_env.fee_token.is_none());
        assert!(!tx_env.is_system_tx);
        assert!(tx_env.fee_payer.is_none());
        assert!(tx_env.tempo_tx_env.is_none());
    }

    #[test]
    fn test_first_call_without_aa() {
        use alloy_primitives::{Address, Bytes};
        use revm::context::TxEnv;

        // Test without tempo_tx_env (non-AA transaction)
        let addr = Address::repeat_byte(0x42);
        let data = Bytes::from(vec![0x01, 0x02, 0x03]);

        let tx_env = super::TempoTxEnv {
            inner: TxEnv {
                kind: TxKind::Call(addr),
                data: data.clone(),
                ..Default::default()
            },
            ..Default::default()
        };

        let first_call = tx_env.first_call();
        assert!(first_call.is_some());
        let (kind, input) = first_call.unwrap();
        assert_eq!(*kind, TxKind::Call(addr));
        assert_eq!(input, data.as_ref());
    }

    #[test]
    fn test_first_call_with_aa() {
        use alloy_primitives::{Address, Bytes, U256};
        use tempo_primitives::transaction::Call;

        // Test with tempo_tx_env (AA transaction)
        let addr1 = Address::repeat_byte(0x11);
        let addr2 = Address::repeat_byte(0x22);
        let input1 = Bytes::from(vec![0xAA, 0xBB]);
        let input2 = Bytes::from(vec![0xCC, 0xDD]);

        let tx_env = super::TempoTxEnv {
            tempo_tx_env: Some(Box::new(super::TempoBatchCallEnv {
                aa_calls: vec![
                    Call {
                        to: TxKind::Call(addr1),
                        value: U256::ZERO,
                        input: input1.clone(),
                    },
                    Call {
                        to: TxKind::Call(addr2),
                        value: U256::from(100),
                        input: input2,
                    },
                ],
                ..Default::default()
            })),
            ..Default::default()
        };

        let first_call = tx_env.first_call();
        assert!(first_call.is_some());
        let (kind, input) = first_call.unwrap();
        assert_eq!(*kind, TxKind::Call(addr1));
        assert_eq!(input, input1.as_ref());
    }

    #[test]
    fn test_first_call_with_empty_aa_calls() {
        // Test with tempo_tx_env but empty calls list
        let tx_env = super::TempoTxEnv {
            tempo_tx_env: Some(Box::new(super::TempoBatchCallEnv {
                aa_calls: vec![],
                ..Default::default()
            })),
            ..Default::default()
        };

        assert!(tx_env.first_call().is_none());
    }

    #[test]
    fn test_calls() {
        use alloy_primitives::{Address, Bytes, U256};
        use revm::context::TxEnv;
        use tempo_primitives::transaction::Call;

        let addr1 = Address::repeat_byte(0x11);
        let addr2 = Address::repeat_byte(0x22);
        let input1 = Bytes::from(vec![0x01]);
        let input2 = Bytes::from(vec![0x02, 0x03]);
        let input3 = Bytes::from(vec![0x04, 0x05, 0x06]);

        // Non-AA transaction: returns single call from inner TxEnv
        let non_aa_tx = super::TempoTxEnv {
            inner: TxEnv {
                kind: TxKind::Call(addr1),
                data: input1.clone(),
                ..Default::default()
            },
            ..Default::default()
        };
        let calls: Vec<_> = non_aa_tx.calls().collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(*calls[0].0, TxKind::Call(addr1));
        assert_eq!(calls[0].1, input1.as_ref());

        // AA transaction with multiple calls
        let aa_tx = super::TempoTxEnv {
            tempo_tx_env: Some(Box::new(super::TempoBatchCallEnv {
                aa_calls: vec![
                    Call {
                        to: TxKind::Call(addr1),
                        value: U256::ZERO,
                        input: input1.clone(),
                    },
                    Call {
                        to: TxKind::Call(addr2),
                        value: U256::from(50),
                        input: input2.clone(),
                    },
                    Call {
                        to: TxKind::Create,
                        value: U256::from(100),
                        input: input3.clone(),
                    },
                ],
                ..Default::default()
            })),
            ..Default::default()
        };
        let calls: Vec<_> = aa_tx.calls().collect();
        assert_eq!(calls.len(), 3);
        assert_eq!(*calls[0].0, TxKind::Call(addr1));
        assert_eq!(calls[0].1, input1.as_ref());
        assert_eq!(*calls[1].0, TxKind::Call(addr2));
        assert_eq!(calls[1].1, input2.as_ref());
        assert_eq!(*calls[2].0, TxKind::Create);
        assert_eq!(calls[2].1, input3.as_ref());

        // AA transaction with empty calls list
        let empty_aa_tx = super::TempoTxEnv {
            tempo_tx_env: Some(Box::new(super::TempoBatchCallEnv {
                aa_calls: vec![],
                ..Default::default()
            })),
            ..Default::default()
        };
        let calls: Vec<_> = empty_aa_tx.calls().collect();
        assert!(calls.is_empty());
    }

    /// Strategy for random U256 values.
    fn arb_u256() -> impl Strategy<Value = alloy_primitives::U256> {
        any::<[u64; 4]>().prop_map(alloy_primitives::U256::from_limbs)
    }

    /// Helper to create a TempoTxEnv with the given gas/fee/value parameters.
    fn make_tx_env(
        gas_limit: u64,
        gas_price: u128,
        value: alloy_primitives::U256,
    ) -> super::TempoTxEnv {
        super::TempoTxEnv {
            inner: revm::context::TxEnv {
                gas_limit,
                gas_price,
                value,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Property: max_balance_spending never panics, returns Ok or OverflowPaymentInTransaction
        #[test]
        fn proptest_max_balance_spending_no_panic(
            gas_limit in any::<u64>(),
            max_fee_per_gas in any::<u128>(),
            value in arb_u256(),
        ) {
            let tx_env = make_tx_env(gas_limit, max_fee_per_gas, value);
            let result = tx_env.max_balance_spending();
            prop_assert!(
                result.is_ok()
                    || result == Err(InvalidTransaction::OverflowPaymentInTransaction)
            );
        }

        /// Property: max_balance_spending returns overflow when gas*price + value overflows U256
        #[test]
        fn proptest_max_balance_spending_overflow_detection(
            gas_limit in any::<u64>(),
            max_fee_per_gas in any::<u128>(),
            value in arb_u256(),
        ) {
            let tx_env = make_tx_env(gas_limit, max_fee_per_gas, value);
            let gas_spending = calc_gas_balance_spending(gas_limit, max_fee_per_gas);
            let result = tx_env.max_balance_spending();

            match gas_spending.checked_add(value) {
                Some(expected) => prop_assert_eq!(result, Ok(expected)),
                None => prop_assert_eq!(result, Err(InvalidTransaction::OverflowPaymentInTransaction)),
            }
        }

        /// Property: effective_balance_spending <= max_balance_spending (when both succeed)
        /// Uses constrained ranges to ensure we don't overflow and actually test the property.
        #[test]
        fn proptest_effective_le_max_balance_spending(
            gas_limit in 0u64..30_000_000u64,  // realistic gas limits
            max_fee_per_gas in 0u128..1_000_000_000_000u128,  // up to 1000 gwei
            max_priority_fee in 0u128..100_000_000_000u128,   // up to 100 gwei
            base_fee in 0u128..500_000_000_000u128,           // up to 500 gwei
            value in 0u128..10_000_000_000_000_000_000_000u128,  // up to 10k ETH in wei
        ) {
            let mut tx_env = make_tx_env(gas_limit, max_fee_per_gas, alloy_primitives::U256::from(value));
            tx_env.inner.gas_priority_fee = Some(max_priority_fee);

            let max_result = tx_env.max_balance_spending();
            let effective_result = tx_env.effective_balance_spending(base_fee, 0);

            // With constrained inputs, both should succeed
            let max_spending = max_result.expect("max_balance_spending should succeed with constrained inputs");
            let effective_spending = effective_result.expect("effective_balance_spending should succeed with constrained inputs");

            prop_assert!(
                effective_spending <= max_spending,
                "effective_balance_spending ({}) should be <= max_balance_spending ({})",
                effective_spending,
                max_spending
            );
        }

        /// Property: effective_balance_spending with base_fee=0 uses only priority fee (EIP-1559)
        ///
        /// For EIP-1559 transactions with base_fee=0:
        /// effective_gas_price = min(max_fee_per_gas, base_fee + priority_fee) = min(max_fee, priority_fee)
        /// This test verifies the computation matches expectations.
        #[test]
        fn proptest_effective_balance_spending_zero_base_fee(
            gas_limit in 0u64..30_000_000u64,
            max_fee_per_gas in 0u128..1_000_000_000_000u128,
            priority_fee in 0u128..500_000_000_000u128,
            value in 0u128..10_000_000_000_000_000_000_000u128,
        ) {
            use revm::context::Transaction;

            let mut tx_env = make_tx_env(gas_limit, max_fee_per_gas, alloy_primitives::U256::from(value));
            // Set tx_type to EIP-1559 and priority fee
            tx_env.inner.tx_type = 2; // EIP-1559
            tx_env.inner.gas_priority_fee = Some(priority_fee);

            let result = tx_env.effective_balance_spending(0, 0);

            // For EIP-1559: effective_gas_price = min(max_fee, 0 + priority_fee) = min(max_fee, priority_fee)
            let effective_price = std::cmp::min(max_fee_per_gas, priority_fee);
            let expected_gas_spending = calc_gas_balance_spending(gas_limit, effective_price);
            let expected = expected_gas_spending.checked_add(alloy_primitives::U256::from(value));

            match expected {
                Some(expected_val) => prop_assert_eq!(result, Ok(expected_val)),
                None => prop_assert_eq!(result, Err(InvalidTransaction::OverflowPaymentInTransaction)),
            }
        }

        /// Property: calls() returns exactly aa_calls.len() for AA transactions
        #[test]
        fn proptest_calls_count_aa_tx(num_calls in 0usize..20) {
            let aa_tx = super::TempoTxEnv {
                tempo_tx_env: Some(Box::new(super::TempoBatchCallEnv {
                    aa_calls: (0..num_calls)
                        .map(|_| Call {
                            to: TxKind::Call(alloy_primitives::Address::ZERO),
                            value: alloy_primitives::U256::ZERO,
                            input: alloy_primitives::Bytes::new(),
                        })
                        .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            };
            prop_assert_eq!(aa_tx.calls().count(), num_calls);
        }

    }

    #[test]
    fn test_calls_count_non_aa_tx() {
        let non_aa_tx = make_tx_env(21_000, 0, alloy_primitives::U256::ZERO);
        assert_eq!(non_aa_tx.calls().count(), 1);
    }
}
