use crate::TempoInvalidTransaction;
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, Typed2718, crypto::secp256k1};
use alloy_evm::{FromRecoveredTx, FromTxWithEncoded, IntoTxEnv};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_sol_types::SolCall;
use reth_evm::TransactionEnv;
use revm::context::{
    Transaction, TxEnv,
    either::Either,
    result::InvalidTransaction,
    transaction::{
        AccessList, AccessListItem, RecoveredAuthority, RecoveredAuthorization, SignedAuthorization,
    },
};
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::{nonce::NonceManager, tip20::TIP20Token};
use tempo_primitives::{
    AASigned, TempoSignature, TempoTransaction, TempoTxEnvelope, TxFeeToken,
    transaction::{
        Call, RecoveredTempoAuthorization, SignedKeyAuthorization, calc_gas_balance_spending,
        envelope::TIP20_PAYMENT_PREFIX,
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
}

/// Storage slots that a transaction may access.
///
/// This is populated during transaction-to-environment conversion and used for
/// optimization in both validation and payload building.
#[derive(Debug, Clone, Default)]
pub struct StorageSlots {
    /// Storage slot of the 2D nonce (None if tx has no nonce key).
    pub nonce_key: Option<U256>,
    /// Storage slot for sender's fee token balance (None if tx has no fee token).
    pub fee_token_balance: Option<U256>,
    /// Storage slots for TIP-20 transfer senders' balances (empty if no TIP-20 transfers).
    pub tip20_from_balances: Vec<U256>,
    /// Storage slots for TIP-20 transfer recipients' balances (empty if no TIP-20 transfers).
    pub tip20_to_balances: Vec<U256>,
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

    /// Storage slots this tx may access (None if not computed)
    pub storage_slots: Option<StorageSlots>,
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

    /// Returns the storage slot for the 2D nonce key, if available.
    pub fn nonce_key_slot(&self) -> Option<U256> {
        self.storage_slots.as_ref()?.nonce_key
    }

    /// Returns the storage slot for the sender's fee token balance, if available.
    pub fn fee_token_balance_slot(&self) -> Option<U256> {
        self.storage_slots.as_ref()?.fee_token_balance
    }

    /// Returns the storage slots for TIP-20 transfer senders' balances.
    ///
    /// - `None` means not computed (e.g., non-AA transaction, RPC compat)
    /// - `Some(&[])` means computed but no TIP-20 transfers found
    /// - `Some(&[slot1, slot2, ...])` means N TIP-20 transfers found with their balance slots
    pub fn tip20_from_balance_slots(&self) -> Option<&[U256]> {
        self.storage_slots
            .as_ref()
            .map(|s| s.tip20_from_balances.as_slice())
    }

    /// Returns the storage slots for TIP-20 transfer recipients' balances.
    ///
    /// - `None` means not computed (e.g., non-AA transaction, RPC compat)
    /// - `Some(&[])` means computed but no TIP-20 transfers found
    /// - `Some(&[slot1, slot2, ...])` means N TIP-20 transfers found with their balance slots
    pub fn tip20_to_balance_slots(&self) -> Option<&[U256]> {
        self.storage_slots
            .as_ref()
            .map(|s| s.tip20_to_balances.as_slice())
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
        let tx_env = TxEnv::from_recovered_tx(tx, sender);
        let (tip20_from_balances, tip20_to_balances) =
            extract_tip20_balance_slots_single(&tx_env.kind, &tx_env.data, sender);
        let storage_slots = Some(StorageSlots {
            nonce_key: None,
            fee_token_balance: None,
            tip20_from_balances,
            tip20_to_balances,
        });
        Self {
            inner: tx_env,
            fee_token: None,
            is_system_tx: false,
            fee_payer: None,
            tempo_tx_env: None,
            storage_slots,
        }
    }
}

impl FromRecoveredTx<TxFeeToken> for TempoTxEnv {
    fn from_recovered_tx(tx: &TxFeeToken, caller: Address) -> Self {
        let TxFeeToken {
            chain_id,
            nonce,
            gas_limit,
            to,
            value,
            input,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list,
            authorization_list,
            fee_token,
            fee_payer_signature,
        } = tx;

        // Compute storage slots
        let storage_slots = {
            // Compute fee token balance slot if present
            let fee_token_balance_slot = fee_token.map(|fee_token_address| {
                TIP20Token::from_address(fee_token_address)
                    .unwrap()
                    .balances
                    .at(caller)
                    .slot()
            });

            // Check if this is also a TIP-20 transfer
            let (tip20_from_balances, tip20_to_balances) =
                extract_tip20_balance_slots_single(to, input, caller);

            Some(StorageSlots {
                nonce_key: None,
                fee_token_balance: fee_token_balance_slot,
                tip20_from_balances,
                tip20_to_balances,
            })
        };

        Self {
            inner: TxEnv {
                tx_type: tx.ty(),
                caller,
                gas_limit: *gas_limit,
                gas_price: *max_fee_per_gas,
                kind: *to,
                value: *value,
                data: input.clone(),
                nonce: *nonce,
                chain_id: Some(*chain_id),
                gas_priority_fee: Some(*max_priority_fee_per_gas),
                access_list: access_list.clone(),
                authorization_list: authorization_list
                    .iter()
                    .map(|auth| {
                        Either::Right(RecoveredAuthorization::new_unchecked(
                            auth.inner().clone(),
                            auth.signature()
                                .ok()
                                .and_then(|signature| {
                                    secp256k1::recover_signer(&signature, auth.signature_hash())
                                        .ok()
                                })
                                .map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid),
                        ))
                    })
                    .collect(),
                ..Default::default()
            },
            fee_token: *fee_token,
            is_system_tx: false,
            fee_payer: fee_payer_signature.map(|sig| {
                sig.recover_address_from_prehash(&tx.fee_payer_signature_hash(caller))
                    .ok()
            }),
            tempo_tx_env: None, // Non-AA transaction
            storage_slots,
        }
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
        let nonce_key = tx.nonce_key;
        let sender = caller;
        let slot = NonceManager::new().nonces.at(sender).at(nonce_key).slot();

        let fee_token_balance_slot = tx.fee_token.map(|fee_token_address| {
            TIP20Token::from_address(fee_token_address)
                .unwrap()
                .balances
                .at(sender)
                .slot()
        });

        // Extract TIP-20 balance slots from all calls
        let (tip20_from_balances, tip20_to_balances) =
            extract_tip20_balance_slots(&tx.calls, sender);

        let storage_slots = Some(StorageSlots {
            nonce_key: Some(slot),
            fee_token_balance: fee_token_balance_slot,
            tip20_from_balances,
            tip20_to_balances,
        });

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
                sig.recover_address_from_prehash(&tx.fee_payer_signature_hash(caller))
                    .ok()
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
            })),
            storage_slots,
        }
    }
}

impl FromRecoveredTx<TempoTxEnvelope> for TempoTxEnv {
    fn from_recovered_tx(tx: &TempoTxEnvelope, sender: Address) -> Self {
        match tx {
            tx @ TempoTxEnvelope::Legacy(inner) => {
                let inner_tx = inner.tx();
                let tx_env = TxEnv::from_recovered_tx(inner_tx, sender);
                let (tip20_from_balances, tip20_to_balances) =
                    extract_tip20_balance_slots_single(&tx_env.kind, &tx_env.data, sender);
                let storage_slots = Some(StorageSlots {
                    nonce_key: None,
                    fee_token_balance: None,
                    tip20_from_balances,
                    tip20_to_balances,
                });
                Self {
                    inner: tx_env,
                    fee_token: None,
                    is_system_tx: tx.is_system_tx(),
                    fee_payer: None,
                    tempo_tx_env: None,
                    storage_slots,
                }
            }
            TempoTxEnvelope::Eip2930(tx) => {
                let inner_tx = tx.tx();
                let tx_env = TxEnv::from_recovered_tx(inner_tx, sender);
                let (tip20_from_balances, tip20_to_balances) =
                    extract_tip20_balance_slots_single(&tx_env.kind, &tx_env.data, sender);
                let storage_slots = Some(StorageSlots {
                    nonce_key: None,
                    fee_token_balance: None,
                    tip20_from_balances,
                    tip20_to_balances,
                });
                Self {
                    inner: tx_env,
                    fee_token: None,
                    is_system_tx: false,
                    fee_payer: None,
                    tempo_tx_env: None,
                    storage_slots,
                }
            }
            TempoTxEnvelope::Eip1559(tx) => {
                let inner_tx = tx.tx();
                let tx_env = TxEnv::from_recovered_tx(inner_tx, sender);
                let (tip20_from_balances, tip20_to_balances) =
                    extract_tip20_balance_slots_single(&tx_env.kind, &tx_env.data, sender);
                let storage_slots = Some(StorageSlots {
                    nonce_key: None,
                    fee_token_balance: None,
                    tip20_from_balances,
                    tip20_to_balances,
                });
                Self {
                    inner: tx_env,
                    fee_token: None,
                    is_system_tx: false,
                    fee_payer: None,
                    tempo_tx_env: None,
                    storage_slots,
                }
            }
            TempoTxEnvelope::Eip7702(tx) => {
                let inner_tx = tx.tx();
                let tx_env = TxEnv::from_recovered_tx(inner_tx, sender);
                let (tip20_from_balances, tip20_to_balances) =
                    extract_tip20_balance_slots_single(&tx_env.kind, &tx_env.data, sender);
                let storage_slots = Some(StorageSlots {
                    nonce_key: None,
                    fee_token_balance: None,
                    tip20_from_balances,
                    tip20_to_balances,
                });
                Self {
                    inner: tx_env,
                    fee_token: None,
                    is_system_tx: false,
                    fee_payer: None,
                    tempo_tx_env: None,
                    storage_slots,
                }
            }
            TempoTxEnvelope::AA(tx) => Self::from_recovered_tx(tx, sender),
            TempoTxEnvelope::FeeToken(tx) => Self::from_recovered_tx(tx.tx(), sender),
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

impl FromTxWithEncoded<TxFeeToken> for TempoTxEnv {
    fn from_encoded_tx(tx: &TxFeeToken, sender: Address, _encoded: Bytes) -> Self {
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

/// Extracts TIP-20 balance slots from a single transaction call.
///
/// Returns `(from_balance_slots, to_balance_slots)` if the transaction is a TIP-20 transfer,
/// empty vecs otherwise.
fn extract_tip20_balance_slots_single(
    to: &TxKind,
    input: &Bytes,
    sender: Address,
) -> (Vec<U256>, Vec<U256>) {
    if let Some(to_addr) = to.to() {
        if to_addr.starts_with(&TIP20_PAYMENT_PREFIX) {
            if let Some((from_addr, to_addr_transfer)) = decode_transfer_addresses(input, sender) {
                if let Ok(token) = TIP20Token::from_address(*to_addr) {
                    return (
                        vec![token.balances.at(from_addr).slot()],
                        vec![token.balances.at(to_addr_transfer).slot()],
                    );
                }
            }
        }
    }
    (vec![], vec![])
}

/// Extracts TIP-20 balance slots from all calls in an AA transaction.
///
/// Iterates through each call, identifies TIP-20 transfers, and computes the storage slots
/// for both sender and recipient balances.
///
/// Returns a tuple of `(from_balance_slots, to_balance_slots)` for all TIP-20 transfers found.
fn extract_tip20_balance_slots(calls: &[Call], sender: Address) -> (Vec<U256>, Vec<U256>) {
    let mut tip20_from_balances = Vec::new();
    let mut tip20_to_balances = Vec::new();

    for call in calls {
        let (from_slots, to_slots) =
            extract_tip20_balance_slots_single(&call.to, &call.input, sender);
        tip20_from_balances.extend(from_slots);
        tip20_to_balances.extend(to_slots);
    }

    (tip20_from_balances, tip20_to_balances)
}

/// Decodes a TIP-20/ERC-20 transfer call and extracts sender and recipient addresses.
///
/// Returns `Some((from, to))` if the calldata is a valid transfer call, `None` otherwise.
/// Supports: `transfer`, `transferWithMemo`, `transferFrom`, and `transferFromWithMemo`.
///
/// For `transfer()` calls, the sender is the transaction signer (`tx_sender` parameter).
/// For `transferFrom()` calls, the sender is decoded from the calldata.
fn decode_transfer_addresses(calldata: &Bytes, tx_sender: Address) -> Option<(Address, Address)> {
    // Try transfer(address,uint256) - sender is tx_sender
    if let Ok(call) = ITIP20::transferCall::abi_decode(calldata) {
        return Some((tx_sender, call.to));
    }

    // Try transferWithMemo(address,uint256,bytes32) - sender is tx_sender
    if let Ok(call) = ITIP20::transferWithMemoCall::abi_decode(calldata) {
        return Some((tx_sender, call.to));
    }

    // Try transferFrom(address,address,uint256) - sender is in calldata
    if let Ok(call) = ITIP20::transferFromCall::abi_decode(calldata) {
        return Some((call.from, call.to));
    }

    // Try transferFromWithMemo(address,address,uint256,bytes32) - sender is in calldata
    if let Ok(call) = ITIP20::transferFromWithMemoCall::abi_decode(calldata) {
        return Some((call.from, call.to));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, address};
    use alloy_sol_types::SolCall;
    use tempo_contracts::precompiles::ITIP20;
    use tempo_precompiles::{
        storage::{hashmap::HashMapStorageProvider, thread_local::StorageCtx},
        tip20::token_id_to_address,
    };

    #[test]
    fn test_extract_tip20_balance_slots() {
        let mut storage = HashMapStorageProvider::new(1);
        let tx_sender = address!("1111111111111111111111111111111111111111");
        let recipient = address!("2222222222222222222222222222222222222222");
        let from_addr = address!("3333333333333333333333333333333333333333");
        let to_addr = address!("4444444444444444444444444444444444444444");

        // Create a TIP-20 token address (token_id = 1)
        let tip20_token = token_id_to_address(1);

        // Create 4 calls with different transfer function types
        let calls = vec![
            // 1. transfer(address,uint256)
            Call {
                to: TxKind::Call(tip20_token),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: recipient,
                    amount: U256::from(1000),
                }
                .abi_encode()
                .into(),
            },
            // 2. transferWithMemo(address,uint256,bytes32)
            Call {
                to: TxKind::Call(tip20_token),
                value: U256::ZERO,
                input: ITIP20::transferWithMemoCall {
                    to: recipient,
                    amount: U256::from(2000),
                    memo: [0u8; 32].into(),
                }
                .abi_encode()
                .into(),
            },
            // 3. transferFrom(address,address,uint256)
            Call {
                to: TxKind::Call(tip20_token),
                value: U256::ZERO,
                input: ITIP20::transferFromCall {
                    from: from_addr,
                    to: to_addr,
                    amount: U256::from(3000),
                }
                .abi_encode()
                .into(),
            },
            // 4. transferFromWithMemo(address,address,uint256,bytes32)
            Call {
                to: TxKind::Call(tip20_token),
                value: U256::ZERO,
                input: ITIP20::transferFromWithMemoCall {
                    from: from_addr,
                    to: to_addr,
                    amount: U256::from(4000),
                    memo: [1u8; 32].into(),
                }
                .abi_encode()
                .into(),
            },
        ];

        // Extract balance slots within StorageCtx
        let result = StorageCtx::enter(&mut storage, || {
            let (from_slots, to_slots) = extract_tip20_balance_slots(&calls, tx_sender);

            // Verify we got 4 slots for each (one per transfer call)
            assert_eq!(from_slots.len(), 4, "Should have 4 from_slots");
            assert_eq!(to_slots.len(), 4, "Should have 4 to_slots");

            // Verify the slots are for the correct addresses
            let token = TIP20Token::from_address(tip20_token)?;

            // Call 1: transfer (sender = tx_sender, recipient)
            assert_eq!(from_slots[0], token.balances.at(tx_sender).slot());
            assert_eq!(to_slots[0], token.balances.at(recipient).slot());

            // Call 2: transferWithMemo (sender = tx_sender, recipient)
            assert_eq!(from_slots[1], token.balances.at(tx_sender).slot());
            assert_eq!(to_slots[1], token.balances.at(recipient).slot());

            // Call 3: transferFrom (sender = from_addr, recipient = to_addr)
            assert_eq!(from_slots[2], token.balances.at(from_addr).slot());
            assert_eq!(to_slots[2], token.balances.at(to_addr).slot());

            // Call 4: transferFromWithMemo (sender = from_addr, recipient = to_addr)
            assert_eq!(from_slots[3], token.balances.at(from_addr).slot());
            assert_eq!(to_slots[3], token.balances.at(to_addr).slot());

            Ok::<_, tempo_precompiles::error::TempoPrecompileError>(())
        });

        assert!(result.is_ok(), "Test should complete successfully");
    }
}
