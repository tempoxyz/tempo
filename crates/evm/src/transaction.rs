//! EVM2 transaction envelope and conversion helpers.

use alloy_consensus::{
    Signed, Transaction, TxEip1559, TxEip2930, TxEip7702, TxLegacy, Typed2718,
    transaction::{Either, Recovered, SignerRecoverable, TxHashRef},
};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind};
pub use evm2::ethereum::RecoveredTxEnvelope;
use evm2::ethereum::{LazyTxEip7702, TxEnvelope as EthTxEnvelope};
use reth_evm::{FromRecoveredTx, FromTxWithEncoded};
use std::{borrow::Borrow, boxed::Box, ops::Deref};
use tempo_primitives::{AASigned, TempoTxEnvelope};

/// Recovered Tempo AA transaction and block-local execution metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TempoAaTx {
    transaction: Box<Recovered<AASigned>>,
    expiring_nonce_idx: Option<usize>,
    override_key_id: Option<Address>,
}

impl TempoAaTx {
    fn new(transaction: Recovered<AASigned>) -> Self {
        Self {
            transaction: Box::new(transaction),
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
    pub const fn signer(&self) -> Address {
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
            Self::AA(transaction) => transaction.inner().tx().recover_fee_payer(sender),
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
            Self::Eip7702(transaction) => transaction.gas_limit,
            Self::AA(transaction) => transaction.gas_limit(),
        }
    }

    /// Returns the transaction's effective gas price for `base_fee`.
    pub fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        match self {
            Self::Legacy { transaction, .. } => transaction.effective_gas_price(base_fee),
            Self::Eip2930(transaction) => transaction.effective_gas_price(base_fee),
            Self::Eip1559(transaction) => transaction.effective_gas_price(base_fee),
            Self::Eip7702(transaction) => {
                base_fee.map_or(transaction.max_fee_per_gas, |base_fee| {
                    transaction.max_fee_per_gas.min(
                        u128::from(base_fee).saturating_add(transaction.max_priority_fee_per_gas),
                    )
                })
            }
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

/// Cached EVM2 transaction plus the original recovered Tempo envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TempoTxEnv {
    evm_tx: TempoEvmTx,
    recovered: Recovered<TempoTxEnvelope>,
    unique_tx_identifier_override: Option<B256>,
    fee_payer_override: Option<Address>,
}

impl TempoTxEnv {
    /// Creates an RPC simulation environment from Reth's normalized Ethereum transaction.
    pub fn from_recovered_eth(transaction: RecoveredTxEnvelope) -> Option<Self> {
        let (transaction, signer) = transaction.into_parts();
        let (evm_tx, recovered) = match transaction {
            EthTxEnvelope::Legacy(transaction) => {
                let envelope = TempoTxEnvelope::Legacy(Signed::new_unhashed(
                    transaction.clone(),
                    Signature::test_signature(),
                ));
                (
                    TempoEvmTx::Legacy {
                        transaction: Recovered::new_unchecked(transaction, signer),
                        is_system: false,
                    },
                    Recovered::new_unchecked(envelope, signer),
                )
            }
            EthTxEnvelope::Eip2930(transaction) => {
                let envelope = TempoTxEnvelope::Eip2930(Signed::new_unhashed(
                    transaction.clone(),
                    Signature::test_signature(),
                ));
                (
                    TempoEvmTx::Eip2930(Recovered::new_unchecked(transaction, signer)),
                    Recovered::new_unchecked(envelope, signer),
                )
            }
            EthTxEnvelope::Eip1559(transaction) => {
                let envelope = TempoTxEnvelope::Eip1559(Signed::new_unhashed(
                    transaction.clone(),
                    Signature::test_signature(),
                ));
                (
                    TempoEvmTx::Eip1559(Recovered::new_unchecked(transaction, signer)),
                    Recovered::new_unchecked(envelope, signer),
                )
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
                                    authorization
                                        .inner()
                                        .clone()
                                        .into_signed(Signature::test_signature())
                                })
                            })
                            .collect(),
                        input: transaction_env.input.clone(),
                    },
                    Signature::test_signature(),
                ));
                (
                    TempoEvmTx::Eip7702(Recovered::new_unchecked(transaction, signer)),
                    Recovered::new_unchecked(envelope, signer),
                )
            }
        };

        Some(Self {
            evm_tx,
            recovered,
            unique_tx_identifier_override: None,
            fee_payer_override: None,
        })
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

    /// Returns the original recovered Tempo transaction.
    pub const fn recovered(&self) -> &Recovered<TempoTxEnvelope> {
        &self.recovered
    }

    /// Returns the original transaction envelope.
    pub const fn transaction(&self) -> &TempoTxEnvelope {
        self.recovered.inner()
    }

    /// Returns the original transaction hash.
    pub fn tx_hash(&self) -> B256 {
        *self.recovered.inner().tx_hash()
    }

    /// Returns the sender-scoped identifier used by replay-sensitive protocol features.
    pub fn unique_tx_identifier(&self) -> B256 {
        self.unique_tx_identifier_override.unwrap_or_else(|| {
            self.recovered
                .inner()
                .unique_tx_identifier(self.recovered.signer())
        })
    }

    /// Returns the hash used to derive TIP-20 channel reserve identifiers.
    pub fn channel_open_context_hash(&self) -> B256 {
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
        self.unique_tx_identifier_override = Some(unique_tx_identifier);
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

impl Transaction for TempoTxEnv {
    fn chain_id(&self) -> Option<u64> {
        self.transaction().chain_id()
    }

    fn nonce(&self) -> u64 {
        self.transaction().nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.transaction().gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.transaction().gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.transaction().max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.transaction().max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.transaction().max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.transaction().priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.transaction().effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.transaction().is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.transaction().kind()
    }

    fn is_create(&self) -> bool {
        self.transaction().is_create()
    }

    fn value(&self) -> alloy_primitives::U256 {
        self.transaction().value()
    }

    fn input(&self) -> &Bytes {
        self.transaction().input()
    }

    fn access_list(&self) -> Option<&alloy_eips::eip2930::AccessList> {
        self.transaction().access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.transaction().blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        self.transaction().authorization_list()
    }
}

impl From<TempoTxEnvelope> for TempoTxEnv {
    fn from(transaction: TempoTxEnvelope) -> Self {
        transaction
            .try_into_recovered()
            .expect("consensus transaction must have a recoverable signer")
            .into()
    }
}

impl From<Recovered<TempoTxEnvelope>> for TempoTxEnv {
    fn from(recovered: Recovered<TempoTxEnvelope>) -> Self {
        Self {
            evm_tx: recovered.clone().into(),
            recovered,
            unique_tx_identifier_override: None,
            fee_payer_override: None,
        }
    }
}

impl FromRecoveredTx<TempoTxEnvelope> for TempoTxEnv {
    fn from_recovered_tx(tx: Recovered<TempoTxEnvelope>) -> Self {
        tx.into()
    }
}

impl FromTxWithEncoded<TempoTxEnvelope> for TempoTxEnv {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip7702, transaction::TxHashRef};
    use alloy_eips::eip2930::{AccessList, AccessListItem};
    use alloy_primitives::{B256, Signature, U256, keccak256};
    use core::num::NonZeroU64;
    use proptest::prelude::*;
    use tempo_primitives::{
        TempoSignature, TempoTransaction,
        transaction::{
            Call, calc_gas_balance_spending, envelope::TEMPO_SYSTEM_TX_SIGNATURE,
            tempo_transaction::TEMPO_EXPIRING_NONCE_KEY, tt_signature::PrimitiveSignature,
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

    /// Strategy for random U256 values.
    fn arb_u256() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(U256::from_limbs)
    }

    /// Helper to create a TempoTxEnv with the given gas/fee/value parameters.
    fn make_eip1559_env(
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        value: U256,
    ) -> TempoTxEnv {
        Recovered::new_unchecked(
            TempoTxEnvelope::Eip1559(Signed::new_unhashed(
                TxEip1559 {
                    gas_limit,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    value,
                    ..Default::default()
                },
                Signature::test_signature(),
            )),
            SIGNER,
        )
        .into()
    }

    fn max_balance_spending(tx_env: &TempoTxEnv) -> Result<U256, ()> {
        let tx = tx_env.as_eip1559().unwrap();
        calc_gas_balance_spending(tx.gas_limit, tx.max_fee_per_gas)
            .checked_add(tx.value)
            .ok_or(())
    }

    fn effective_balance_spending(tx_env: &TempoTxEnv, base_fee: u64) -> Result<U256, ()> {
        let tx = tx_env.as_eip1559().unwrap();
        calc_gas_balance_spending(
            tx.gas_limit,
            tx_env.evm_tx().effective_gas_price(Some(base_fee)),
        )
        .checked_add(tx.value)
        .ok_or(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Property: max_balance_spending never panics, returns Ok or overflow
        #[test]
        fn proptest_max_balance_spending_no_panic(
            gas_limit in any::<u64>(),
            max_fee_per_gas in any::<u128>(),
            value in arb_u256(),
        ) {
            let tx_env = make_eip1559_env(gas_limit, max_fee_per_gas, 0, value);
            let result = max_balance_spending(&tx_env);
            prop_assert!(result.is_ok() || result == Err(()));
        }

        /// Property: max_balance_spending returns overflow when gas*price + value overflows U256
        #[test]
        fn proptest_max_balance_spending_overflow_detection(
            gas_limit in any::<u64>(),
            max_fee_per_gas in any::<u128>(),
            value in arb_u256(),
        ) {
            let tx_env = make_eip1559_env(gas_limit, max_fee_per_gas, 0, value);
            let gas_spending = calc_gas_balance_spending(gas_limit, max_fee_per_gas);
            let result = max_balance_spending(&tx_env);

            match gas_spending.checked_add(value) {
                Some(expected) => prop_assert_eq!(result, Ok(expected)),
                None => prop_assert_eq!(result, Err(())),
            }
        }

        /// Property: effective_balance_spending <= max_balance_spending (when both succeed)
        /// Uses constrained ranges to ensure we don't overflow and actually test the property.
        #[test]
        fn proptest_effective_le_max_balance_spending(
            gas_limit in 0u64..30_000_000u64,  // realistic gas limits
            max_fee_per_gas in 0u128..1_000_000_000_000u128,  // up to 1000 gwei
            max_priority_fee in 0u128..100_000_000_000u128,   // up to 100 gwei
            base_fee in 0u64..500_000_000_000u64,             // up to 500 gwei
            value in 0u128..10_000_000_000_000_000_000_000u128,  // up to 10k ETH in wei
        ) {
            let tx_env = make_eip1559_env(
                gas_limit,
                max_fee_per_gas,
                max_priority_fee,
                U256::from(value),
            );

            let max_result = max_balance_spending(&tx_env);
            let effective_result = effective_balance_spending(&tx_env, base_fee);

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
            let tx_env = make_eip1559_env(
                gas_limit,
                max_fee_per_gas,
                priority_fee,
                U256::from(value),
            );
            let result = effective_balance_spending(&tx_env, 0);

            // For EIP-1559: effective_gas_price = min(max_fee, 0 + priority_fee) = min(max_fee, priority_fee)
            let effective_price = std::cmp::min(max_fee_per_gas, priority_fee);
            let expected_gas_spending = calc_gas_balance_spending(gas_limit, effective_price);
            let expected = expected_gas_spending.checked_add(U256::from(value));

            match expected {
                Some(expected_val) => prop_assert_eq!(result, Ok(expected_val)),
                None => prop_assert_eq!(result, Err(())),
            }
        }

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
}
