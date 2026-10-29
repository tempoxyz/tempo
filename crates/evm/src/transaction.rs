//! EVM2 transaction envelope and conversion helpers.

use alloy_consensus::{
    Signed, Transaction, TxEip1559, TxEip2930, TxEip7702, TxLegacy, Typed2718,
    transaction::{Either, Recovered, TxHashRef},
};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind};
pub use evm2::ethereum::RecoveredTxEnvelope;
use evm2::ethereum::{LazyTxEip7702, TxEnvelope as EthTxEnvelope};
use reth_evm::{FromRecoveredTx, FromTxWithEncoded, TransactionEnvMut};
use reth_primitives_traits::WithEncoded;
use std::{borrow::Borrow, ops::Deref, sync::Arc};
use tempo_primitives::{AASigned, TempoTxEnvelope};

/// Identifies the kind of execution represented by a transaction environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionContext {
    /// Execution or validation of a signed transaction.
    Transaction {
        /// Canonical hash of the signed transaction.
        tx_hash: B256,
    },
    /// Non-committing execution of an RPC transaction request.
    Simulation,
}

/// Recovered Tempo AA transaction and block-local execution metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TempoAaTx {
    transaction: Arc<Recovered<AASigned>>,
    fee_payer: Option<Address>,
    expiring_nonce_idx: Option<usize>,
    override_key_id: Option<Address>,
}

impl TempoAaTx {
    fn new(transaction: Recovered<AASigned>) -> Self {
        let fee_payer = transaction
            .inner()
            .tx()
            .recover_fee_payer(transaction.signer())
            .ok();
        Self {
            transaction: Arc::new(transaction),
            fee_payer,
            expiring_nonce_idx: None,
            override_key_id: None,
        }
    }

    /// Returns the transaction's index among expiring-nonce transactions in the block.
    pub const fn expiring_nonce_idx(&self) -> Option<usize> {
        self.expiring_nonce_idx
    }

    fn set_expiring_nonce_idx(&mut self, index: Option<usize>) {
        self.expiring_nonce_idx = index;
    }

    /// Returns the access-key override used by RPC simulation.
    pub const fn override_key_id(&self) -> Option<Address> {
        self.override_key_id
    }

    fn set_override_key_id(&mut self, key_id: Option<Address>) {
        self.override_key_id = key_id;
    }
}

impl Deref for TempoAaTx {
    type Target = Recovered<AASigned>;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

/// Recovered transaction envelope consumed by the Tempo EVM2 handlers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TempoEvmTx {
    /// Legacy transaction.
    Legacy {
        /// Recovered transaction without its signature.
        transaction: Recovered<TxLegacy>,
        /// Whether the original envelope carried Tempo's system transaction signature.
        is_system: bool,
    },
    /// EIP-2930 access-list transaction.
    Eip2930(Recovered<TxEip2930>),
    /// EIP-1559 dynamic-fee transaction.
    Eip1559(Recovered<TxEip1559>),
    /// EIP-7702 set-code transaction.
    Eip7702(Recovered<LazyTxEip7702>),
    /// Tempo account-abstraction transaction.
    AA(TempoAaTx),
}

impl TempoEvmTx {
    /// Returns the contained legacy transaction, if this is legacy.
    pub const fn as_legacy(&self) -> Option<&Recovered<TxLegacy>> {
        match self {
            Self::Legacy { transaction, .. } => Some(transaction),
            Self::Eip2930(_) | Self::Eip1559(_) | Self::Eip7702(_) | Self::AA(_) => None,
        }
    }

    /// Returns the contained EIP-2930 transaction, if this is EIP-2930.
    pub const fn as_eip2930(&self) -> Option<&Recovered<TxEip2930>> {
        match self {
            Self::Eip2930(transaction) => Some(transaction),
            Self::Legacy { .. } | Self::Eip1559(_) | Self::Eip7702(_) | Self::AA(_) => None,
        }
    }

    /// Returns the contained EIP-1559 transaction, if this is EIP-1559.
    pub const fn as_eip1559(&self) -> Option<&Recovered<TxEip1559>> {
        match self {
            Self::Eip1559(transaction) => Some(transaction),
            Self::Legacy { .. } | Self::Eip2930(_) | Self::Eip7702(_) | Self::AA(_) => None,
        }
    }

    /// Returns the contained EIP-7702 transaction, if this is EIP-7702.
    pub const fn as_eip7702(&self) -> Option<&Recovered<LazyTxEip7702>> {
        match self {
            Self::Eip7702(transaction) => Some(transaction),
            Self::Legacy { .. } | Self::Eip2930(_) | Self::Eip1559(_) | Self::AA(_) => None,
        }
    }

    /// Returns the contained Tempo AA transaction, if this is Tempo AA.
    pub const fn as_aa(&self) -> Option<&TempoAaTx> {
        match self {
            Self::AA(transaction) => Some(transaction),
            Self::Legacy { .. } | Self::Eip2930(_) | Self::Eip1559(_) | Self::Eip7702(_) => None,
        }
    }

    /// Returns the recovered transaction signer.
    pub fn signer(&self) -> Address {
        match self {
            Self::Legacy { transaction, .. } => transaction.signer(),
            Self::Eip2930(transaction) => transaction.signer(),
            Self::Eip1559(transaction) => transaction.signer(),
            Self::Eip7702(transaction) => transaction.signer(),
            Self::AA(transaction) => transaction.transaction.signer(),
        }
    }

    /// Returns whether this is a Tempo system transaction.
    pub const fn is_system_tx(&self) -> bool {
        matches!(
            self,
            Self::Legacy {
                is_system: true,
                ..
            }
        )
    }

    /// Resolves the account that pays this transaction's protocol fee.
    pub fn fee_payer(&self) -> Result<Address, alloy_consensus::crypto::RecoveryError> {
        let sender = self.signer();
        match self {
            Self::AA(transaction) => transaction
                .fee_payer
                .ok_or_else(alloy_consensus::crypto::RecoveryError::new),
            Self::Legacy { .. } | Self::Eip2930(_) | Self::Eip1559(_) | Self::Eip7702(_) => {
                Ok(sender)
            }
        }
    }

    /// Returns the transaction gas limit.
    pub fn gas_limit(&self) -> u64 {
        match self {
            Self::Legacy { transaction, .. } => transaction.gas_limit(),
            Self::Eip2930(transaction) => transaction.gas_limit(),
            Self::Eip1559(transaction) => transaction.gas_limit(),
            Self::Eip7702(transaction) => transaction.gas_limit(),
            Self::AA(transaction) => transaction.gas_limit(),
        }
    }

    /// Returns the transaction's effective gas price for `base_fee`.
    pub fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        match self {
            Self::Legacy { transaction, .. } => transaction.effective_gas_price(base_fee),
            Self::Eip2930(transaction) => transaction.effective_gas_price(base_fee),
            Self::Eip1559(transaction) => transaction.effective_gas_price(base_fee),
            Self::Eip7702(transaction) => transaction.effective_gas_price(base_fee),
            Self::AA(transaction) => transaction.effective_gas_price(base_fee),
        }
    }

    /// Returns the transaction-level fee-token override, if present.
    pub fn fee_token(&self) -> Option<Address> {
        self.as_aa().and_then(|tx| tx.inner().tx().fee_token)
    }

    /// Returns whether this is a Tempo account-abstraction transaction.
    pub const fn is_aa(&self) -> bool {
        matches!(self, Self::AA(_))
    }

    /// Iterates over calls made by this transaction.
    pub fn calls(&self) -> impl Iterator<Item = (TxKind, &Bytes)> {
        match self {
            Self::AA(transaction) => Either::Left(
                transaction
                    .inner()
                    .tx()
                    .calls
                    .iter()
                    .map(|call| (call.to, &call.input)),
            ),
            Self::Legacy { transaction, .. } => {
                Either::Right(core::iter::once((transaction.kind(), transaction.input())))
            }
            Self::Eip2930(transaction) => {
                Either::Right(core::iter::once((transaction.kind(), transaction.input())))
            }
            Self::Eip1559(transaction) => {
                Either::Right(core::iter::once((transaction.kind(), transaction.input())))
            }
            Self::Eip7702(transaction) => Either::Right(core::iter::once((
                TxKind::Call(transaction.to),
                &transaction.input,
            ))),
        }
    }
}

impl Typed2718 for TempoEvmTx {
    fn ty(&self) -> u8 {
        match self {
            Self::Legacy { transaction, .. } => transaction.ty(),
            Self::Eip2930(transaction) => transaction.ty(),
            Self::Eip1559(transaction) => transaction.ty(),
            Self::Eip7702(transaction) => transaction.ty(),
            Self::AA(transaction) => transaction.ty(),
        }
    }
}

impl From<Recovered<TempoTxEnvelope>> for TempoEvmTx {
    fn from(recovered: Recovered<TempoTxEnvelope>) -> Self {
        let (transaction, signer) = recovered.into_parts();
        let is_system = transaction.is_system_tx();

        match transaction {
            TempoTxEnvelope::Legacy(transaction) => Self::Legacy {
                transaction: Recovered::new_unchecked(transaction.strip_signature(), signer),
                is_system,
            },
            TempoTxEnvelope::Eip2930(transaction) => Self::Eip2930(Recovered::new_unchecked(
                transaction.strip_signature(),
                signer,
            )),
            TempoTxEnvelope::Eip1559(transaction) => Self::Eip1559(Recovered::new_unchecked(
                transaction.strip_signature(),
                signer,
            )),
            TempoTxEnvelope::Eip7702(transaction) => Self::Eip7702(Recovered::new_unchecked(
                LazyTxEip7702::from_recovered_authorizations(transaction.strip_signature()),
                signer,
            )),
            TempoTxEnvelope::AA(transaction) => Self::AA(TempoAaTx::new(Recovered::new_unchecked(
                transaction,
                signer,
            ))),
        }
    }
}

/// Cached EVM2 transaction plus the identity of the signed transaction it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TempoTxEnv {
    evm_tx: TempoEvmTx,
    execution_context: ExecutionContext,
    tx_hash: B256,
    unique_tx_identifier: B256,
    fee_payer_override: Option<Address>,
}

impl TempoTxEnv {
    /// Creates an RPC simulation environment from Reth's normalized Ethereum transaction.
    pub fn from_recovered_eth(transaction: RecoveredTxEnvelope) -> Option<Self> {
        let (transaction, signer) = transaction.into_parts();
        let signature = Signature::test_signature();
        let envelope = match transaction {
            EthTxEnvelope::Legacy(transaction) => {
                TempoTxEnvelope::Legacy(Signed::new_unhashed(transaction, signature))
            }
            EthTxEnvelope::Eip2930(transaction) => {
                TempoTxEnvelope::Eip2930(Signed::new_unhashed(transaction, signature))
            }
            EthTxEnvelope::Eip1559(transaction) => {
                TempoTxEnvelope::Eip1559(Signed::new_unhashed(transaction, signature))
            }
            EthTxEnvelope::Eip4844(_) => return None,
            EthTxEnvelope::Eip7702(transaction) => {
                let transaction_env = &transaction;
                let envelope = TempoTxEnvelope::Eip7702(Signed::new_unhashed(
                    TxEip7702 {
                        chain_id: transaction_env.chain_id,
                        nonce: transaction_env.nonce,
                        gas_limit: transaction_env.gas_limit,
                        max_fee_per_gas: transaction_env.max_fee_per_gas,
                        max_priority_fee_per_gas: transaction_env.max_priority_fee_per_gas,
                        to: transaction_env.to,
                        value: transaction_env.value,
                        access_list: transaction_env.access_list.clone(),
                        authorization_list: transaction_env
                            .authorization_list
                            .iter()
                            .map(|authorization| {
                                authorization.as_signed().cloned().unwrap_or_else(|| {
                                    authorization.inner().clone().into_signed(signature)
                                })
                            })
                            .collect(),
                        input: transaction_env.input.clone(),
                    },
                    signature,
                ));
                // Keep the recovered authorizations: re-recovering the placeholder signatures
                // above would yield wrong authorities.
                return Some(Self {
                    evm_tx: TempoEvmTx::Eip7702(Recovered::new_unchecked(transaction, signer)),
                    execution_context: ExecutionContext::Simulation,
                    tx_hash: *envelope.tx_hash(),
                    unique_tx_identifier: envelope.unique_tx_identifier(signer),
                    fee_payer_override: None,
                });
            }
        };

        let mut env = Self::from(Recovered::new_unchecked(envelope, signer));
        env.execution_context = ExecutionContext::Simulation;
        Some(env)
    }

    /// Returns the transaction consumed by EVM2.
    pub const fn evm_tx(&self) -> &TempoEvmTx {
        &self.evm_tx
    }

    /// Returns the contained legacy transaction, if this is legacy.
    pub const fn as_legacy(&self) -> Option<&TxLegacy> {
        match self.evm_tx.as_legacy() {
            Some(transaction) => Some(transaction.inner()),
            None => None,
        }
    }

    /// Returns the contained EIP-2930 transaction, if this is EIP-2930.
    pub const fn as_eip2930(&self) -> Option<&TxEip2930> {
        match self.evm_tx.as_eip2930() {
            Some(transaction) => Some(transaction.inner()),
            None => None,
        }
    }

    /// Returns the contained EIP-1559 transaction, if this is EIP-1559.
    pub const fn as_eip1559(&self) -> Option<&TxEip1559> {
        match self.evm_tx.as_eip1559() {
            Some(transaction) => Some(transaction.inner()),
            None => None,
        }
    }

    /// Returns the contained EIP-7702 transaction, if this is EIP-7702.
    pub const fn as_eip7702(&self) -> Option<&LazyTxEip7702> {
        match self.evm_tx.as_eip7702() {
            Some(transaction) => Some(transaction.inner()),
            None => None,
        }
    }

    /// Returns the contained Tempo AA transaction, if this is Tempo AA.
    pub const fn as_aa(&self) -> Option<&TempoAaTx> {
        self.evm_tx.as_aa()
    }

    /// Returns the original transaction hash.
    pub const fn tx_hash(&self) -> B256 {
        self.tx_hash
    }

    /// Returns whether this environment represents a signed transaction or an RPC simulation.
    pub const fn execution_context(&self) -> ExecutionContext {
        self.execution_context
    }

    /// Returns the sender-scoped identifier used by replay-sensitive protocol features.
    pub const fn unique_tx_identifier(&self) -> B256 {
        self.unique_tx_identifier
    }

    /// Returns the hash used to derive TIP-20 channel reserve identifiers.
    pub const fn channel_open_context_hash(&self) -> B256 {
        self.unique_tx_identifier()
    }

    /// Resolves the account paying this transaction's protocol fee.
    pub fn fee_payer(&self) -> Result<Address, alloy_consensus::crypto::RecoveryError> {
        self.fee_payer_override
            .map(Ok)
            .unwrap_or_else(|| self.evm_tx.fee_payer())
    }

    /// Sets RPC-only transaction metadata that cannot be derived from a final signed envelope.
    pub fn with_simulation_overrides(
        mut self,
        unique_tx_identifier: B256,
        fee_payer: Option<Address>,
        key_id: Option<Address>,
    ) -> Self {
        self.execution_context = ExecutionContext::Simulation;
        self.unique_tx_identifier = unique_tx_identifier;
        self.fee_payer_override = fee_payer;
        if let TempoEvmTx::AA(transaction) = &mut self.evm_tx {
            transaction.set_override_key_id(key_id);
        }
        self
    }

    /// Sets the transaction's block-local expiring nonce index.
    pub fn set_expiring_nonce_idx(&mut self, index: Option<usize>) {
        if let TempoEvmTx::AA(transaction) = &mut self.evm_tx {
            transaction.set_expiring_nonce_idx(index);
        }
    }
}

impl Borrow<TempoEvmTx> for TempoTxEnv {
    fn borrow(&self) -> &TempoEvmTx {
        &self.evm_tx
    }
}

impl Typed2718 for TempoTxEnv {
    fn ty(&self) -> u8 {
        self.evm_tx.ty()
    }
}

/// Delegates to the transaction inside each [`TempoEvmTx`] variant.
macro_rules! delegate {
    ($tx:expr, $inner:ident => $expr:expr) => {
        match $tx {
            TempoEvmTx::Legacy {
                transaction: $inner,
                ..
            } => $expr,
            TempoEvmTx::Eip2930($inner) => $expr,
            TempoEvmTx::Eip1559($inner) => $expr,
            TempoEvmTx::Eip7702($inner) => $expr,
            TempoEvmTx::AA($inner) => $expr,
        }
    };
}

impl Transaction for TempoTxEnv {
    fn chain_id(&self) -> Option<u64> {
        delegate!(&self.evm_tx, tx => tx.inner().chain_id())
    }

    fn nonce(&self) -> u64 {
        delegate!(&self.evm_tx, tx => tx.inner().nonce())
    }

    fn gas_limit(&self) -> u64 {
        self.evm_tx.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        delegate!(&self.evm_tx, tx => tx.inner().gas_price())
    }

    fn max_fee_per_gas(&self) -> u128 {
        delegate!(&self.evm_tx, tx => tx.inner().max_fee_per_gas())
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        delegate!(&self.evm_tx, tx => tx.inner().max_priority_fee_per_gas())
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        delegate!(&self.evm_tx, tx => tx.inner().max_fee_per_blob_gas())
    }

    fn priority_fee_or_price(&self) -> u128 {
        delegate!(&self.evm_tx, tx => tx.inner().priority_fee_or_price())
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.evm_tx.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        delegate!(&self.evm_tx, tx => tx.inner().is_dynamic_fee())
    }

    fn kind(&self) -> TxKind {
        delegate!(&self.evm_tx, tx => tx.inner().kind())
    }

    fn is_create(&self) -> bool {
        delegate!(&self.evm_tx, tx => tx.inner().is_create())
    }

    fn value(&self) -> alloy_primitives::U256 {
        delegate!(&self.evm_tx, tx => tx.inner().value())
    }

    fn input(&self) -> &Bytes {
        delegate!(&self.evm_tx, tx => tx.inner().input())
    }

    fn access_list(&self) -> Option<&alloy_eips::eip2930::AccessList> {
        delegate!(&self.evm_tx, tx => tx.inner().access_list())
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        delegate!(&self.evm_tx, tx => tx.inner().blob_versioned_hashes())
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        delegate!(&self.evm_tx, tx => tx.inner().authorization_list())
    }
}

impl From<Recovered<TempoTxEnvelope>> for TempoTxEnv {
    fn from(recovered: Recovered<TempoTxEnvelope>) -> Self {
        let tx_hash = *recovered.inner().tx_hash();
        let unique_tx_identifier = recovered.inner().unique_tx_identifier(recovered.signer());
        Self {
            evm_tx: recovered.into(),
            execution_context: ExecutionContext::Transaction { tx_hash },
            tx_hash,
            unique_tx_identifier,
            fee_payer_override: None,
        }
    }
}

impl FromRecoveredTx<TempoTxEnvelope> for TempoTxEnv {
    fn from_recovered_tx(tx: Recovered<TempoTxEnvelope>) -> Self {
        tx.into()
    }
}

impl FromTxWithEncoded<TempoTxEnvelope> for TempoTxEnv {
    fn from_tx_with_encoded(tx: WithEncoded<Recovered<TempoTxEnvelope>>) -> Self {
        let is_simulation = tx.encoded_bytes().is_empty();
        let mut tx_env = Self::from_recovered_tx(tx.1);
        if is_simulation {
            tx_env.execution_context = ExecutionContext::Simulation;
        }
        tx_env
    }
}

impl TransactionEnvMut for TempoTxEnv {
    fn set_gas_limit(&mut self, gas_limit: u64) {
        match &mut self.evm_tx {
            TempoEvmTx::Legacy { transaction, .. } => transaction.inner_mut().gas_limit = gas_limit,
            TempoEvmTx::Eip2930(tx) => tx.inner_mut().gas_limit = gas_limit,
            TempoEvmTx::Eip1559(tx) => tx.inner_mut().gas_limit = gas_limit,
            TempoEvmTx::Eip7702(tx) => tx.inner_mut().gas_limit = gas_limit,
            TempoEvmTx::AA(tx) => {
                Arc::make_mut(&mut tx.transaction)
                    .inner_mut()
                    .tx_mut()
                    .gas_limit = gas_limit;
            }
        }
    }

    fn set_access_list(&mut self, access_list: AccessList) {
        match &mut self.evm_tx {
            TempoEvmTx::Legacy { transaction, .. } => {
                let signer = transaction.signer();
                let TxLegacy {
                    chain_id,
                    nonce,
                    gas_price,
                    gas_limit,
                    to,
                    value,
                    input,
                } = transaction.inner().clone();
                self.evm_tx = TempoEvmTx::Eip2930(Recovered::new_unchecked(
                    TxEip2930 {
                        chain_id: chain_id.unwrap_or_default(),
                        nonce,
                        gas_price,
                        gas_limit,
                        to,
                        value,
                        access_list,
                        input,
                    },
                    signer,
                ));
            }
            TempoEvmTx::Eip2930(tx) => tx.inner_mut().access_list = access_list,
            TempoEvmTx::Eip1559(tx) => tx.inner_mut().access_list = access_list,
            TempoEvmTx::Eip7702(tx) => tx.inner_mut().access_list = access_list,
            TempoEvmTx::AA(tx) => {
                Arc::make_mut(&mut tx.transaction)
                    .inner_mut()
                    .tx_mut()
                    .access_list = access_list;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip7702, transaction::TxHashRef};
    use alloy_eips::eip2930::AccessListItem;
    use alloy_primitives::{B256, Signature, U256, keccak256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use core::num::NonZeroU64;
    use proptest::prelude::*;
    use tempo_primitives::{
        TempoSignature, TempoTransaction,
        transaction::{
            Call, envelope::TEMPO_SYSTEM_TX_SIGNATURE, tempo_transaction::TEMPO_EXPIRING_NONCE_KEY,
            tt_signature::PrimitiveSignature,
        },
    };

    const SIGNER: Address = Address::new([0x11; 20]);

    fn convert(transaction: TempoTxEnvelope) -> TempoEvmTx {
        Recovered::new_unchecked(transaction, SIGNER).into()
    }

    fn legacy_env(transaction: TxLegacy, signer: Address) -> TempoTxEnv {
        Recovered::new_unchecked(
            TempoTxEnvelope::Legacy(Signed::new_unhashed(
                transaction,
                Signature::test_signature(),
            )),
            signer,
        )
        .into()
    }

    fn aa_env(transaction: TempoTransaction, signer: Address) -> TempoTxEnv {
        let signature =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        Recovered::new_unchecked(
            TempoTxEnvelope::AA(AASigned::new_unhashed(transaction, signature)),
            signer,
        )
        .into()
    }

    #[test]
    fn converts_standard_transactions() {
        let legacy = convert(TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy::default(),
            Signature::test_signature(),
        )));
        let eip2930 = convert(TempoTxEnvelope::Eip2930(Signed::new_unhashed(
            TxEip2930::default(),
            Signature::test_signature(),
        )));
        let eip1559 = convert(TempoTxEnvelope::Eip1559(Signed::new_unhashed(
            TxEip1559::default(),
            Signature::test_signature(),
        )));

        assert_eq!(legacy.ty(), 0);
        assert_eq!(eip2930.ty(), 1);
        assert_eq!(eip1559.ty(), 2);
        assert_eq!(legacy.signer(), SIGNER);
        assert!(legacy.as_legacy().is_some());
        assert!(eip2930.as_eip2930().is_some());
        assert!(eip1559.as_eip1559().is_some());
        assert!(!legacy.is_system_tx());
    }

    #[test]
    fn converts_eip7702_to_lazy_authorizations() {
        let transaction = convert(TempoTxEnvelope::Eip7702(Signed::new_unhashed(
            TxEip7702::default(),
            Signature::test_signature(),
        )));

        assert_eq!(transaction.ty(), 4);
        assert_eq!(transaction.signer(), SIGNER);
        assert!(transaction.as_eip7702().is_some());
    }

    #[test]
    fn preserves_system_transaction_marker() {
        let transaction = convert(TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy::default(),
            TEMPO_SYSTEM_TX_SIGNATURE,
        )));

        assert!(transaction.is_system_tx());
    }

    #[test]
    fn preserves_aa_transaction_and_recovered_signer() {
        let signed = AASigned::new_unhashed(TempoTransaction::default(), TempoSignature::default());
        let transaction = convert(TempoTxEnvelope::AA(signed.clone()));
        let recovered = transaction.as_aa().expect("AA transaction");

        assert_eq!(transaction.ty(), 0x76);
        assert_eq!(recovered.signer(), SIGNER);
        assert_eq!(recovered.inner(), &signed);
        assert_ne!(*recovered.inner().hash(), B256::ZERO);
    }

    #[test]
    fn empty_encoded_transaction_marks_simulation_and_preserves_identity() {
        let make_recovered = |nonce| {
            Recovered::new_unchecked(
                TempoTxEnvelope::AA(AASigned::new_unhashed(
                    TempoTransaction {
                        nonce,
                        ..Default::default()
                    },
                    TempoSignature::default(),
                )),
                SIGNER,
            )
        };
        let recovered = make_recovered(0);
        let identity = recovered.inner().unique_tx_identifier(SIGNER);
        let simulation =
            TempoTxEnv::from_tx_with_encoded(WithEncoded::new(Bytes::new(), recovered.clone()));
        assert_eq!(simulation.execution_context(), ExecutionContext::Simulation);
        assert_eq!(simulation.channel_open_context_hash(), identity);

        let next =
            TempoTxEnv::from_tx_with_encoded(WithEncoded::new(Bytes::new(), make_recovered(1)));
        assert_ne!(
            simulation.channel_open_context_hash(),
            next.channel_open_context_hash()
        );

        let transaction = TempoTxEnv::from_tx_with_encoded(WithEncoded::new(
            Bytes::from_static(b"signed transaction"),
            recovered.clone(),
        ));
        assert_eq!(
            transaction.execution_context(),
            ExecutionContext::Transaction {
                tx_hash: *recovered.inner().tx_hash(),
            }
        );
        assert_eq!(transaction.channel_open_context_hash(), identity);
    }

    #[test]
    fn test_from_recovered_tx_expiring_nonce_hash() {
        let caller = Address::repeat_byte(0xAA);

        let make_aa_signed = |nonce_key: U256| -> AASigned {
            let tx = TempoTransaction {
                chain_id: 1,
                gas_limit: 1_000_000,
                nonce_key,
                nonce: 0,
                valid_before: Some(NonZeroU64::new(100).unwrap()),
                calls: vec![Call {
                    to: TxKind::Call(Address::repeat_byte(0x42)),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                ..Default::default()
            };
            let sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                Signature::test_signature(),
            ));
            AASigned::new_unhashed(tx, sig)
        };

        // Expiring nonce txs and channel opens share the same encode_for_signing||sender hash.
        let expiring_signed = make_aa_signed(TEMPO_EXPIRING_NONCE_KEY);
        let expiring_env: TempoTxEnv =
            Recovered::new_unchecked(TempoTxEnvelope::AA(expiring_signed.clone()), caller).into();
        let expected_identifier = expiring_signed.expiring_nonce_hash(caller);
        assert_eq!(
            expiring_env.execution_context(),
            ExecutionContext::Transaction {
                tx_hash: *expiring_signed.hash(),
            }
        );
        assert_eq!(
            expiring_env.channel_open_context_hash(),
            expected_identifier,
            "expiring nonce channel opens must use the sender-scoped transaction identifier"
        );

        // Regular 2D nonce txs still use the same encode_for_signing||sender construction.
        let regular_signed = make_aa_signed(U256::from(42));
        let regular_env: TempoTxEnv =
            Recovered::new_unchecked(TempoTxEnvelope::AA(regular_signed.clone()), caller).into();
        assert_eq!(
            regular_env.channel_open_context_hash(),
            regular_signed.expiring_nonce_hash(caller),
            "non-expiring AA channel opens must use encode_for_signing||sender"
        );
    }

    #[test]
    fn test_legacy_channel_open_context_hash_uses_encoded_signing_payload_and_sender() {
        let caller = Address::repeat_byte(0xAA);
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 7,
            gas_price: 1,
            gas_limit: 21_000,
            to: TxKind::Call(Address::repeat_byte(0x42)),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope =
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()));
        let tx_hash = *envelope.tx_hash();
        let TempoTxEnvelope::Legacy(signed) = &envelope else {
            unreachable!()
        };
        let tx_env: TempoTxEnv = Recovered::new_unchecked(envelope.clone(), caller).into();
        let signature_hash = signed.signature_hash();
        assert_ne!(
            signature_hash, tx_hash,
            "legacy signature hash is the unsigned signing hash, not the signed tx hash"
        );

        let mut signature_hash_and_sender = [0u8; 52];
        signature_hash_and_sender[..32].copy_from_slice(signature_hash.as_slice());
        signature_hash_and_sender[32..].copy_from_slice(caller.as_slice());
        let signature_hash_context = keccak256(signature_hash_and_sender);
        let encoded_payload_context = envelope.unique_tx_identifier(caller);
        assert_ne!(
            encoded_payload_context, signature_hash_context,
            "channel opens must use the encoded signing payload, not signature_hash||sender"
        );
        assert_eq!(tx_env.channel_open_context_hash(), encoded_payload_context);
    }

    #[test]
    fn test_tx_env() {
        let tx_env = legacy_env(TxLegacy::default(), SIGNER);
        assert_eq!(tx_env.evm_tx().gas_limit(), 0);
        assert_eq!(tx_env.evm_tx().signer(), SIGNER);
        assert!(!tx_env.evm_tx().is_system_tx());
        assert!(tx_env.evm_tx().fee_token().is_none());
        assert!(tx_env.as_aa().is_none());
    }

    #[test]
    fn test_fee_payer_without_signature_uses_caller() {
        let tx_env = aa_env(TempoTransaction::default(), SIGNER);
        assert_eq!(tx_env.fee_payer().unwrap(), SIGNER);
    }

    #[test]
    fn test_fee_payer_invalid_signature_rejected() {
        let tx_env = aa_env(
            TempoTransaction {
                fee_payer_signature: Some(Signature::new(U256::ZERO, U256::ZERO, false)),
                ..Default::default()
            },
            SIGNER,
        );
        assert!(tx_env.fee_payer().is_err());
        assert_eq!(tx_env.as_aa().unwrap().fee_payer, None);
    }

    #[test]
    fn test_fee_payer_resolving_to_sender_is_allowed_in_tx_env() {
        let tx_env = aa_env(TempoTransaction::default(), SIGNER).with_simulation_overrides(
            B256::ZERO,
            Some(SIGNER),
            None,
        );
        assert_eq!(tx_env.fee_payer().unwrap(), SIGNER);
    }

    #[test]
    fn test_has_fee_payer_signature() {
        let without_signature = aa_env(TempoTransaction::default(), SIGNER);
        assert!(
            without_signature
                .as_aa()
                .unwrap()
                .inner()
                .tx()
                .fee_payer_signature
                .is_none()
        );

        let with_signature = aa_env(
            TempoTransaction {
                fee_payer_signature: Some(Signature::test_signature()),
                ..Default::default()
            },
            SIGNER,
        );
        assert!(
            with_signature
                .as_aa()
                .unwrap()
                .inner()
                .tx()
                .fee_payer_signature
                .is_some()
        );
    }

    #[test]
    fn test_transaction_env_set_gas_limit() {
        let tx_env = legacy_env(
            TxLegacy {
                gas_limit: 21_000,
                ..Default::default()
            },
            SIGNER,
        );
        assert_eq!(tx_env.evm_tx().gas_limit(), 21_000);

        let tx_env = legacy_env(
            TxLegacy {
                gas_limit: 1_000_000,
                ..Default::default()
            },
            SIGNER,
        );
        assert_eq!(tx_env.evm_tx().gas_limit(), 1_000_000);
    }

    #[test]
    fn test_transaction_env_nonce() {
        let tx_env = legacy_env(TxLegacy::default(), SIGNER);
        assert_eq!(tx_env.as_legacy().unwrap().nonce, 0);

        let tx_env = legacy_env(
            TxLegacy {
                nonce: 42,
                ..Default::default()
            },
            SIGNER,
        );
        assert_eq!(tx_env.as_legacy().unwrap().nonce, 42);

        let tx_env = legacy_env(
            TxLegacy {
                nonce: u64::MAX,
                ..Default::default()
            },
            SIGNER,
        );
        assert_eq!(tx_env.as_legacy().unwrap().nonce, u64::MAX);
    }

    #[test]
    fn test_transaction_env_set_access_list() {
        let access_list = AccessList(vec![
            AccessListItem {
                address: Address::ZERO,
                storage_keys: vec![B256::ZERO],
            },
            AccessListItem {
                address: Address::repeat_byte(1),
                storage_keys: vec![B256::repeat_byte(1), B256::repeat_byte(2)],
            },
        ]);
        let transaction = convert(TempoTxEnvelope::Eip2930(Signed::new_unhashed(
            TxEip2930 {
                access_list: access_list.clone(),
                ..Default::default()
            },
            Signature::test_signature(),
        )));
        assert_eq!(transaction.as_eip2930().unwrap().access_list, access_list);
    }

    #[test]
    fn test_transaction_env_combined_operations() {
        let access_list = AccessList(vec![AccessListItem {
            address: Address::repeat_byte(0xab),
            storage_keys: Vec::new(),
        }]);
        let transaction = convert(TempoTxEnvelope::Eip2930(Signed::new_unhashed(
            TxEip2930 {
                gas_limit: 50_000,
                nonce: 100,
                access_list: access_list.clone(),
                ..Default::default()
            },
            Signature::test_signature(),
        )));
        let transaction = transaction.as_eip2930().unwrap();
        assert_eq!(transaction.gas_limit, 50_000);
        assert_eq!(transaction.nonce, 100);
        assert_eq!(transaction.access_list, access_list);
    }

    #[test]
    fn test_transaction_env_from_tx_env() {
        let tx_env = legacy_env(
            TxLegacy {
                gas_limit: 75_000,
                nonce: 55,
                ..Default::default()
            },
            SIGNER,
        );
        assert_eq!(tx_env.evm_tx().gas_limit(), 75_000);
        assert_eq!(tx_env.as_legacy().unwrap().nonce, 55);
        assert_eq!(tx_env.evm_tx().signer(), SIGNER);
        assert!(tx_env.evm_tx().fee_token().is_none());
        assert!(!tx_env.evm_tx().is_system_tx());
        assert!(tx_env.as_aa().is_none());
    }

    #[test]
    fn test_first_call_without_aa() {
        // Test without an AA transaction.
        let address = Address::repeat_byte(0x42);
        let input = Bytes::from_static(&[1, 2, 3]);
        let tx_env = legacy_env(
            TxLegacy {
                to: TxKind::Call(address),
                input: input.clone(),
                ..Default::default()
            },
            SIGNER,
        );
        let first_call = tx_env.evm_tx().calls().next();
        assert!(first_call.is_some());
        let (kind, data) = first_call.unwrap();
        assert_eq!(kind, TxKind::Call(address));
        assert_eq!(data, &input);
    }

    #[test]
    fn test_first_call_with_aa() {
        // Test with an AA transaction.
        let first_address = Address::repeat_byte(0x11);
        let second_address = Address::repeat_byte(0x22);
        let first_input = Bytes::from_static(&[0xaa, 0xbb]);
        let tx_env = aa_env(
            TempoTransaction {
                calls: vec![
                    Call {
                        to: TxKind::Call(first_address),
                        value: U256::ZERO,
                        input: first_input.clone(),
                    },
                    Call {
                        to: TxKind::Call(second_address),
                        value: U256::from(100),
                        input: Bytes::from_static(&[0xcc, 0xdd]),
                    },
                ],
                ..Default::default()
            },
            SIGNER,
        );
        let first_call = tx_env.evm_tx().calls().next();
        assert!(first_call.is_some());
        let (kind, input) = first_call.unwrap();
        assert_eq!(kind, TxKind::Call(first_address));
        assert_eq!(input, &first_input);
    }

    #[test]
    fn test_first_call_with_empty_aa_calls() {
        // Test with an AA transaction but empty calls list.
        let tx_env = aa_env(TempoTransaction::default(), SIGNER);
        assert!(tx_env.evm_tx().calls().next().is_none());
    }

    #[test]
    fn test_calls() {
        let first = Address::repeat_byte(0x11);
        let second = Address::repeat_byte(0x22);
        let first_input = Bytes::from_static(&[1]);
        let second_input = Bytes::from_static(&[2, 3]);
        let create_input = Bytes::from_static(&[4, 5, 6]);

        // Non-AA transaction: returns single call from the Ethereum transaction.
        let non_aa_tx = legacy_env(
            TxLegacy {
                to: TxKind::Call(first),
                input: first_input.clone(),
                ..Default::default()
            },
            SIGNER,
        );
        let calls: Vec<_> = non_aa_tx.evm_tx().calls().collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, TxKind::Call(first));
        assert_eq!(calls[0].1, &first_input);

        // AA transaction with multiple calls.
        let tx_env = aa_env(
            TempoTransaction {
                calls: vec![
                    Call {
                        to: TxKind::Call(first),
                        value: U256::ZERO,
                        input: first_input.clone(),
                    },
                    Call {
                        to: TxKind::Call(second),
                        value: U256::from(50),
                        input: second_input.clone(),
                    },
                    Call {
                        to: TxKind::Create,
                        value: U256::from(100),
                        input: create_input.clone(),
                    },
                ],
                ..Default::default()
            },
            SIGNER,
        );
        let calls: Vec<_> = tx_env.evm_tx().calls().collect();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, TxKind::Call(first));
        assert_eq!(calls[0].1, &first_input);
        assert_eq!(calls[1].0, TxKind::Call(second));
        assert_eq!(calls[1].1, &second_input);
        assert_eq!(calls[2].0, TxKind::Create);
        assert_eq!(calls[2].1, &create_input);

        // AA transaction with empty calls list.
        let empty_aa_tx = aa_env(TempoTransaction::default(), SIGNER);
        let calls: Vec<_> = empty_aa_tx.evm_tx().calls().collect();
        assert!(calls.is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Property: calls() returns exactly aa_calls.len() for AA transactions
        #[test]
        fn proptest_calls_count_aa_tx(num_calls in 0usize..20) {
            let tx = aa_env(
                TempoTransaction {
                    calls: (0..num_calls)
                        .map(|_| Call {
                            to: TxKind::Call(Address::ZERO),
                            value: U256::ZERO,
                            input: Bytes::new(),
                        })
                        .collect(),
                    ..Default::default()
                },
                SIGNER,
            );
            prop_assert_eq!(tx.evm_tx().calls().count(), num_calls);
        }
    }

    #[test]
    fn test_calls_count_non_aa_tx() {
        assert_eq!(
            legacy_env(TxLegacy::default(), SIGNER)
                .evm_tx()
                .calls()
                .count(),
            1
        );
    }

    #[test]
    fn prepared_env_mutation_preserves_sponsor_and_original_transaction() {
        let sponsor = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x22)).unwrap();
        let mut transaction = TempoTransaction {
            gas_limit: 1_000_000,
            fee_payer_signature: Some(Signature::test_signature()),
            ..Default::default()
        };
        transaction.fee_payer_signature = Some(
            sponsor
                .sign_hash_sync(&transaction.fee_payer_signature_hash(SIGNER))
                .unwrap(),
        );
        let env = aa_env(transaction, SIGNER);
        assert_eq!(env.fee_payer().unwrap(), sponsor.address());
        let hash = env.tx_hash();
        let identifier = env.unique_tx_identifier();
        let access_list = AccessList(vec![AccessListItem {
            address: Address::repeat_byte(0x33),
            storage_keys: vec![B256::ZERO],
        }]);
        for gas_limit in [900_000, 500_000, 250_000] {
            let mut probe = env.clone();
            probe.set_gas_limit(gas_limit);
            probe.set_access_list(access_list.clone());
            assert_eq!(probe.gas_limit(), gas_limit);
            assert_eq!(probe.evm_tx().gas_limit(), gas_limit);
            assert_eq!(probe.access_list(), Some(&access_list));
            assert_eq!(probe.as_aa().unwrap().inner().tx().access_list, access_list);
            assert_eq!(probe.fee_payer().unwrap(), sponsor.address());
            assert_eq!(probe.evm_tx().fee_payer().unwrap(), sponsor.address());
            assert_eq!(probe.tx_hash(), hash);
            assert_eq!(probe.unique_tx_identifier(), identifier);
            assert_ne!(
                probe
                    .as_aa()
                    .unwrap()
                    .inner()
                    .tx()
                    .recover_fee_payer(SIGNER)
                    .unwrap(),
                sponsor.address(),
            );
        }
        assert_eq!(env.gas_limit(), 1_000_000);
        assert!(env.access_list().unwrap().0.is_empty());
    }

    #[test]
    fn prepared_env_mutation_upgrades_legacy_access_list() {
        let original = legacy_env(
            TxLegacy {
                nonce: 7,
                gas_price: 42,
                gas_limit: 100_000,
                to: TxKind::Call(Address::repeat_byte(0x33)),
                input: Bytes::from_static(&[1, 2, 3]),
                ..Default::default()
            },
            SIGNER,
        );
        let mut probe = original.clone();
        let access_list = AccessList(vec![AccessListItem {
            address: Address::repeat_byte(0x44),
            storage_keys: vec![B256::ZERO],
        }]);
        probe.set_gas_limit(80_000);
        probe.set_access_list(access_list.clone());
        let transaction = probe.as_eip2930().unwrap();
        assert_eq!(transaction.gas_limit, 80_000);
        assert_eq!(transaction.access_list, access_list);
        assert_eq!(probe.gas_limit(), 80_000);
        assert_eq!(probe.access_list(), Some(&access_list));
        assert_eq!(probe.chain_id(), Some(0));
        assert_eq!(probe.ty(), 1);
        assert_eq!(probe.nonce(), original.nonce());
        assert_eq!(probe.gas_price(), original.gas_price());
        assert_eq!(probe.kind(), original.kind());
        assert_eq!(probe.input(), original.input());
        assert_eq!(probe.evm_tx().signer(), SIGNER);
        assert_eq!(original.gas_limit(), 100_000);
        assert_eq!(original.access_list(), None);
    }
}
