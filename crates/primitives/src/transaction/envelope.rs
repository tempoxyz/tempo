use super::tt_signed::AASigned;
use crate::{TempoTransaction, subblock::PartialValidatorKey};
use alloy_consensus::{
    EthereumTxEnvelope, SignableTransaction, Signed, Transaction, TxEip1559, TxEip2930, TxEip7702,
    TxLegacy, TxType, TypedTransaction,
    crypto::RecoveryError,
    error::{UnsupportedTransactionType, ValueError},
    transaction::Either,
};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, hex};
use core::fmt;
use tempo_contracts::precompiles::ITIP20;

/// TIP20 payment address prefix (12 bytes for payment classification)
/// Same as TIP20_TOKEN_PREFIX
pub const TIP20_PAYMENT_PREFIX: [u8; 12] = hex!("20C000000000000000000000");

/// Fake signature for Tempo system transactions.
pub const TEMPO_SYSTEM_TX_SIGNATURE: Signature = Signature::new(U256::ZERO, U256::ZERO, false);

/// Fake sender for Tempo system transactions.
pub const TEMPO_SYSTEM_TX_SENDER: Address = Address::ZERO;

/// Tempo transaction envelope containing all supported transaction types
///
/// Transaction types included:
/// - Legacy transactions
/// - EIP-2930 access list transactions
/// - EIP-1559 dynamic fee transactions
/// - EIP-7702 authorization list transactions
/// - Tempo transactions
#[derive(Clone, Debug, alloy_consensus::TransactionEnvelope)]
#[envelope(
    tx_type_name = TempoTxType,
    typed = TempoTypedTransaction,
    arbitrary_cfg(any(test, feature = "arbitrary")),
    serde_cfg(feature = "serde")
)]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
#[allow(clippy::large_enum_variant)]
pub enum TempoTxEnvelope {
    /// Legacy transaction (type 0x00)
    #[envelope(ty = 0)]
    Legacy(Signed<TxLegacy>),

    /// EIP-2930 access list transaction (type 0x01)
    #[envelope(ty = 1)]
    Eip2930(Signed<TxEip2930>),

    /// EIP-1559 dynamic fee transaction (type 0x02)
    #[envelope(ty = 2)]
    Eip1559(Signed<TxEip1559>),

    /// EIP-7702 authorization list transaction (type 0x04)
    #[envelope(ty = 4)]
    Eip7702(Signed<TxEip7702>),

    /// Tempo transaction (type 0x76)
    #[envelope(ty = 0x76, typed = TempoTransaction)]
    AA(AASigned),
}

impl TryFrom<TxType> for TempoTxType {
    type Error = UnsupportedTransactionType<TxType>;

    fn try_from(value: TxType) -> Result<Self, Self::Error> {
        Ok(match value {
            TxType::Legacy => Self::Legacy,
            TxType::Eip2930 => Self::Eip2930,
            TxType::Eip1559 => Self::Eip1559,
            TxType::Eip4844 => return Err(UnsupportedTransactionType::new(TxType::Eip4844)),
            TxType::Eip7702 => Self::Eip7702,
        })
    }
}

impl TryFrom<TempoTxType> for TxType {
    type Error = UnsupportedTransactionType<TempoTxType>;

    fn try_from(value: TempoTxType) -> Result<Self, Self::Error> {
        Ok(match value {
            TempoTxType::Legacy => Self::Legacy,
            TempoTxType::Eip2930 => Self::Eip2930,
            TempoTxType::Eip1559 => Self::Eip1559,
            TempoTxType::Eip7702 => Self::Eip7702,
            TempoTxType::AA => {
                return Err(UnsupportedTransactionType::new(TempoTxType::AA));
            }
        })
    }
}

impl alloy_consensus::InMemorySize for TempoTxType {
    fn size(&self) -> usize {
        size_of::<Self>()
    }
}

impl TempoTxEnvelope {
    /// Returns the fee token preference if this is a fee token transaction
    pub fn fee_token(&self) -> Option<Address> {
        match self {
            Self::AA(tx) => tx.tx().fee_token,
            _ => None,
        }
    }

    /// Resolves fee payer for the transaction.
    pub fn fee_payer(&self, sender: Address) -> Result<Address, RecoveryError> {
        match self {
            Self::AA(tx) => tx.tx().recover_fee_payer(sender),
            _ => Ok(sender),
        }
    }

    /// Return the [`TempoTxType`] of the inner txn.
    pub const fn tx_type(&self) -> TempoTxType {
        match self {
            Self::Legacy(_) => TempoTxType::Legacy,
            Self::Eip2930(_) => TempoTxType::Eip2930,
            Self::Eip1559(_) => TempoTxType::Eip1559,
            Self::Eip7702(_) => TempoTxType::Eip7702,
            Self::AA(_) => TempoTxType::AA,
        }
    }

    /// Returns true if this is a fee token transaction
    pub fn is_fee_token(&self) -> bool {
        matches!(self, Self::AA(_))
    }

    /// Returns the authorization list if present (for EIP-7702 transactions)
    pub fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        match self {
            Self::Eip7702(tx) => Some(&tx.tx().authorization_list),
            _ => None,
        }
    }

    /// Returns the Tempo authorization list if present (for Tempo transactions)
    pub fn tempo_authorization_list(
        &self,
    ) -> Option<&[crate::transaction::TempoSignedAuthorization]> {
        match self {
            Self::AA(tx) => Some(&tx.tx().tempo_authorization_list),
            _ => None,
        }
    }

    /// Returns true if this is a Tempo system transaction
    pub fn is_system_tx(&self) -> bool {
        matches!(self, Self::Legacy(tx) if tx.signature() == &TEMPO_SYSTEM_TX_SIGNATURE)
    }

    /// Returns true if this is a valid Tempo system transaction, i.e all gas fields and nonce are zero.
    pub fn is_valid_system_tx(&self, chain_id: u64) -> bool {
        self.max_fee_per_gas() == 0
            && self.gas_limit() == 0
            && self.value().is_zero()
            && self.chain_id() == Some(chain_id)
            && self.nonce() == 0
    }

    /// [TIP-20 payment] classification: `to` address has the `0x20c0` prefix.
    ///
    /// A transaction is considered a payment if its `to` address carries the TIP-20 prefix.
    /// For AA transactions, every call must target a TIP-20 address.
    ///
    /// # NOTE
    /// Consensus-level classifier, used during block validation, against `general_gas_limit`.
    /// See [`is_payment_v2`](Self::is_payment_v2) for the stricter builder-level variant.
    ///
    /// [TIP-20 payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
    pub fn is_payment_v1(&self) -> bool {
        match self {
            Self::Legacy(tx) => is_tip20_call(tx.tx().to.to()),
            Self::Eip2930(tx) => is_tip20_call(tx.tx().to.to()),
            Self::Eip1559(tx) => is_tip20_call(tx.tx().to.to()),
            Self::Eip7702(tx) => is_tip20_call(Some(&tx.tx().to)),
            Self::AA(tx) => tx.tx().calls.iter().all(|call| is_tip20_call(call.to.to())),
        }
    }

    /// Strict [TIP-20 payment] classification: `0x20c0` prefix AND recognized calldata.
    ///
    /// Like [`is_payment_v1`](Self::is_payment_v1), but additionally requires calldata to match a
    /// recognized payment selector with exact ABI-encoded length.
    ///
    /// # NOTE
    /// Builder-level classifier, used by the transaction pool and payload builder to prevent DoS of
    /// the payment lane. NOT enforced during block validation — a future TIP will enshrine this
    /// stricter classification at the protocol level.
    ///
    /// [TIP-20 payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
    pub fn is_payment_v2(&self) -> bool {
        match self {
            Self::Legacy(tx) => is_tip20_payment(tx.tx().to.to(), &tx.tx().input),
            Self::Eip2930(tx) => is_tip20_payment(tx.tx().to.to(), &tx.tx().input),
            Self::Eip1559(tx) => is_tip20_payment(tx.tx().to.to(), &tx.tx().input),
            Self::Eip7702(tx) => is_tip20_payment(Some(&tx.tx().to), &tx.tx().input),
            Self::AA(tx) => {
                !tx.tx().calls.is_empty()
                    && tx
                        .tx()
                        .calls
                        .iter()
                        .all(|call| is_tip20_payment(call.to.to(), &call.input))
            }
        }
    }

    /// Returns the proposer of the subblock if this is a subblock transaction.
    pub fn subblock_proposer(&self) -> Option<PartialValidatorKey> {
        let Self::AA(tx) = &self else { return None };
        tx.tx().subblock_proposer()
    }

    /// Returns the [`AASigned`] transaction if this is a Tempo transaction.
    pub fn as_aa(&self) -> Option<&AASigned> {
        match self {
            Self::AA(tx) => Some(tx),
            _ => None,
        }
    }

    /// Returns the nonce key of this transaction if it's an [`AASigned`] transaction.
    pub fn nonce_key(&self) -> Option<U256> {
        self.as_aa().map(|tx| tx.tx().nonce_key)
    }

    /// Returns true if this is a Tempo transaction
    pub fn is_aa(&self) -> bool {
        matches!(self, Self::AA(_))
    }

    /// Returns iterator over the calls in the transaction.
    pub fn calls(&self) -> impl Iterator<Item = (TxKind, &Bytes)> {
        if let Some(aa) = self.as_aa() {
            Either::Left(aa.tx().calls.iter().map(|call| (call.to, &call.input)))
        } else {
            Either::Right(core::iter::once((self.kind(), self.input())))
        }
    }
}

impl alloy_consensus::transaction::SignerRecoverable for TempoTxEnvelope {
    fn recover_signer(
        &self,
    ) -> Result<alloy_primitives::Address, alloy_consensus::crypto::RecoveryError> {
        match self {
            Self::Legacy(tx) if tx.signature() == &TEMPO_SYSTEM_TX_SIGNATURE => Ok(Address::ZERO),
            Self::Legacy(tx) => alloy_consensus::transaction::SignerRecoverable::recover_signer(tx),
            Self::Eip2930(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer(tx)
            }
            Self::Eip1559(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer(tx)
            }
            Self::Eip7702(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer(tx)
            }
            Self::AA(tx) => alloy_consensus::transaction::SignerRecoverable::recover_signer(tx),
        }
    }

    fn recover_signer_unchecked(
        &self,
    ) -> Result<alloy_primitives::Address, alloy_consensus::crypto::RecoveryError> {
        match self {
            Self::Legacy(tx) if tx.signature() == &TEMPO_SYSTEM_TX_SIGNATURE => Ok(Address::ZERO),
            Self::Legacy(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
            Self::Eip2930(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
            Self::Eip1559(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
            Self::Eip7702(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
            Self::AA(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
        }
    }
}

impl alloy_consensus::transaction::TxHashRef for TempoTxEnvelope {
    fn tx_hash(&self) -> &B256 {
        match self {
            Self::Legacy(tx) => tx.hash(),
            Self::Eip2930(tx) => tx.hash(),
            Self::Eip1559(tx) => tx.hash(),
            Self::Eip7702(tx) => tx.hash(),
            Self::AA(tx) => tx.hash(),
        }
    }
}

impl fmt::Display for TempoTxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy => write!(f, "Legacy"),
            Self::Eip2930 => write!(f, "EIP-2930"),
            Self::Eip1559 => write!(f, "EIP-1559"),
            Self::Eip7702 => write!(f, "EIP-7702"),
            Self::AA => write!(f, "AA"),
        }
    }
}

impl<Eip4844> TryFrom<EthereumTxEnvelope<Eip4844>> for TempoTxEnvelope {
    type Error = ValueError<EthereumTxEnvelope<Eip4844>>;

    fn try_from(value: EthereumTxEnvelope<Eip4844>) -> Result<Self, Self::Error> {
        match value {
            EthereumTxEnvelope::Legacy(tx) => Ok(Self::Legacy(tx)),
            EthereumTxEnvelope::Eip2930(tx) => Ok(Self::Eip2930(tx)),
            tx @ EthereumTxEnvelope::Eip4844(_) => Err(ValueError::new_static(
                tx,
                "EIP-4844 transactions are not supported",
            )),
            EthereumTxEnvelope::Eip1559(tx) => Ok(Self::Eip1559(tx)),
            EthereumTxEnvelope::Eip7702(tx) => Ok(Self::Eip7702(tx)),
        }
    }
}

impl From<Signed<TxLegacy>> for TempoTxEnvelope {
    fn from(value: Signed<TxLegacy>) -> Self {
        Self::Legacy(value)
    }
}

impl From<Signed<TxEip2930>> for TempoTxEnvelope {
    fn from(value: Signed<TxEip2930>) -> Self {
        Self::Eip2930(value)
    }
}

impl From<Signed<TxEip1559>> for TempoTxEnvelope {
    fn from(value: Signed<TxEip1559>) -> Self {
        Self::Eip1559(value)
    }
}

impl From<Signed<TxEip7702>> for TempoTxEnvelope {
    fn from(value: Signed<TxEip7702>) -> Self {
        Self::Eip7702(value)
    }
}

impl From<AASigned> for TempoTxEnvelope {
    fn from(value: AASigned) -> Self {
        Self::AA(value)
    }
}

impl From<Signed<TempoTypedTransaction>> for TempoTxEnvelope {
    fn from(value: Signed<TempoTypedTransaction>) -> Self {
        let sig = *value.signature();
        let tx = value.strip_signature();
        tx.into_envelope(sig)
    }
}

impl SignableTransaction<Signature> for TempoTypedTransaction {
    fn set_chain_id(&mut self, chain_id: alloy_primitives::ChainId) {
        self.as_dyn_signable_mut().set_chain_id(chain_id);
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Legacy(tx) => tx.encode_for_signing(out),
            Self::Eip2930(tx) => tx.encode_for_signing(out),
            Self::Eip1559(tx) => tx.encode_for_signing(out),
            Self::Eip7702(tx) => tx.encode_for_signing(out),
            Self::AA(tx) => tx.encode_for_signing(out),
        }
    }

    fn payload_len_for_signature(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.payload_len_for_signature(),
            Self::Eip2930(tx) => tx.payload_len_for_signature(),
            Self::Eip1559(tx) => tx.payload_len_for_signature(),
            Self::Eip7702(tx) => tx.payload_len_for_signature(),
            Self::AA(tx) => tx.payload_len_for_signature(),
        }
    }
}

impl TempoTypedTransaction {
    /// Converts this typed transaction into a signed [`TempoTxEnvelope`]
    pub fn into_envelope(self, sig: Signature) -> TempoTxEnvelope {
        match self {
            Self::Legacy(tx) => tx.into_signed(sig).into(),
            Self::Eip2930(tx) => tx.into_signed(sig).into(),
            Self::Eip1559(tx) => tx.into_signed(sig).into(),
            Self::Eip7702(tx) => tx.into_signed(sig).into(),
            Self::AA(tx) => tx.into_signed(sig.into()).into(),
        }
    }

    /// Returns a dyn mutable reference to the underlying transaction
    pub fn as_dyn_signable_mut(&mut self) -> &mut dyn SignableTransaction<Signature> {
        match self {
            Self::Legacy(tx) => tx,
            Self::Eip2930(tx) => tx,
            Self::Eip1559(tx) => tx,
            Self::Eip7702(tx) => tx,
            Self::AA(tx) => tx,
        }
    }
}

impl TryFrom<TypedTransaction> for TempoTypedTransaction {
    type Error = UnsupportedTransactionType<TxType>;

    fn try_from(value: TypedTransaction) -> Result<Self, Self::Error> {
        Ok(match value {
            TypedTransaction::Legacy(tx) => Self::Legacy(tx),
            TypedTransaction::Eip2930(tx) => Self::Eip2930(tx),
            TypedTransaction::Eip1559(tx) => Self::Eip1559(tx),
            TypedTransaction::Eip4844(..) => {
                return Err(UnsupportedTransactionType::new(TxType::Eip4844));
            }
            TypedTransaction::Eip7702(tx) => Self::Eip7702(tx),
        })
    }
}

impl From<TempoTxEnvelope> for TempoTypedTransaction {
    fn from(value: TempoTxEnvelope) -> Self {
        match value {
            TempoTxEnvelope::Legacy(tx) => Self::Legacy(tx.into_parts().0),
            TempoTxEnvelope::Eip2930(tx) => Self::Eip2930(tx.into_parts().0),
            TempoTxEnvelope::Eip1559(tx) => Self::Eip1559(tx.into_parts().0),
            TempoTxEnvelope::Eip7702(tx) => Self::Eip7702(tx.into_parts().0),
            TempoTxEnvelope::AA(tx) => Self::AA(tx.into_parts().0),
        }
    }
}

impl From<TempoTransaction> for TempoTypedTransaction {
    fn from(value: TempoTransaction) -> Self {
        Self::AA(value)
    }
}

/// Returns `true` if `to` has the TIP-20 payment prefix.
fn is_tip20_call(to: Option<&Address>) -> bool {
    to.is_some_and(|to| to.starts_with(&TIP20_PAYMENT_PREFIX))
}

/// Returns `true` if `to` has the TIP-20 payment prefix and `input` is recognized payment
/// calldata (selector + exact ABI-encoded length).
fn is_tip20_payment(to: Option<&Address>, input: &[u8]) -> bool {
    is_tip20_call(to) && ITIP20::ITIP20Calls::is_payment(input)
}

#[cfg(feature = "rpc")]
impl reth_rpc_convert::SignableTxRequest<TempoTxEnvelope>
    for alloy_rpc_types_eth::TransactionRequest
{
    async fn try_build_and_sign(
        self,
        signer: impl alloy_network::TxSigner<alloy_primitives::Signature> + Send,
    ) -> Result<TempoTxEnvelope, reth_rpc_convert::SignTxRequestError> {
        reth_rpc_convert::SignableTxRequest::<
            EthereumTxEnvelope<alloy_consensus::TxEip4844>,
        >::try_build_and_sign(self, signer)
        .await
        .and_then(|tx| {
            tx.try_into()
                .map_err(|_| reth_rpc_convert::SignTxRequestError::InvalidTransactionRequest)
        })
    }
}

#[cfg(feature = "rpc")]
impl reth_rpc_convert::TryIntoSimTx<TempoTxEnvelope> for alloy_rpc_types_eth::TransactionRequest {
    fn try_into_sim_tx(self) -> Result<TempoTxEnvelope, ValueError<Self>> {
        let tx = self.clone().build_typed_simulate_transaction()?;
        tx.try_into()
            .map_err(|_| ValueError::new_static(self, "Invalid transaction request"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Call, TempoTransaction};
    use alloy_primitives::{Bytes, Signature, TxKind, U256, address};
    use alloy_sol_types::SolCall;

    const PAYMENT_TKN: Address = address!("20c0000000000000000000000000000000000001");

    #[rustfmt::skip]
    /// Returns valid ABI-encoded calldata for every recognized TIP-20 payment selector.
    fn payment_calldatas() -> [Bytes; 9] {
        let (to, from, amount, memo) = (Address::random(), Address::random(), U256::random(), B256::random());
        [
            ITIP20::transferCall { to, amount }.abi_encode().into(),
            ITIP20::transferWithMemoCall { to, amount, memo }.abi_encode().into(),
            ITIP20::transferFromCall { from, to, amount }.abi_encode().into(),
            ITIP20::transferFromWithMemoCall { from, to, amount, memo }.abi_encode().into(),
            ITIP20::approveCall { spender: to, amount }.abi_encode().into(),
            ITIP20::mintCall { to, amount }.abi_encode().into(),
            ITIP20::mintWithMemoCall { to, amount, memo }.abi_encode().into(),
            ITIP20::burnCall { amount }.abi_encode().into(),
            ITIP20::burnWithMemoCall { amount, memo }.abi_encode().into(),
        ]
    }

    #[test]
    fn test_non_fee_token_access() {
        let legacy_tx = TxLegacy::default();
        let signature = Signature::new(
            alloy_primitives::U256::ZERO,
            alloy_primitives::U256::ZERO,
            false,
        );
        let signed = Signed::new_unhashed(legacy_tx, signature);
        let envelope = TempoTxEnvelope::Legacy(signed);

        assert!(!envelope.is_fee_token());
        assert_eq!(envelope.fee_token(), None);
        assert!(!envelope.is_aa());
        assert!(envelope.as_aa().is_none());
    }

    #[test]
    fn test_payment_classification_legacy_tx() {
        // Test with legacy transaction type
        let tx = TxLegacy {
            to: TxKind::Call(PAYMENT_TKN),
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);

        assert!(envelope.is_payment_v1());
    }

    #[test]
    fn test_payment_classification_non_payment() {
        let non_payment_addr = address!("1234567890123456789012345678901234567890");
        let tx = TxLegacy {
            to: TxKind::Call(non_payment_addr),
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);

        assert!(!envelope.is_payment_v1());
    }

    fn create_aa_envelope(call: Call) -> TempoTxEnvelope {
        let tx = TempoTransaction {
            fee_token: Some(PAYMENT_TKN),
            calls: vec![call],
            ..Default::default()
        };
        TempoTxEnvelope::AA(tx.into_signed(Signature::test_signature().into()))
    }

    #[test]
    fn test_payment_classification_aa_with_tip20_prefix() {
        let payment_addr = address!("20c0000000000000000000000000000000000001");
        let call = Call {
            to: TxKind::Call(payment_addr),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope = create_aa_envelope(call);
        assert!(envelope.is_payment_v1());
    }

    #[test]
    fn test_payment_classification_aa_without_tip20_prefix() {
        let non_payment_addr = address!("1234567890123456789012345678901234567890");
        let call = Call {
            to: TxKind::Call(non_payment_addr),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope = create_aa_envelope(call);
        assert!(!envelope.is_payment_v1());
    }

    #[test]
    fn test_payment_classification_aa_no_to_address() {
        let call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope = create_aa_envelope(call);
        assert!(!envelope.is_payment_v1());
    }

    #[test]
    fn test_payment_classification_aa_partial_match() {
        // First 12 bytes match TIP20_PAYMENT_PREFIX, remaining 8 bytes differ
        let payment_addr = address!("20c0000000000000000000001111111111111111");
        let call = Call {
            to: TxKind::Call(payment_addr),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope = create_aa_envelope(call);
        assert!(envelope.is_payment_v1());
    }

    #[test]
    fn test_payment_classification_aa_different_prefix() {
        // Different prefix (30c0 instead of 20c0)
        let non_payment_addr = address!("30c0000000000000000000000000000000000001");
        let call = Call {
            to: TxKind::Call(non_payment_addr),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope = create_aa_envelope(call);
        assert!(!envelope.is_payment_v1());
    }

    #[test]
    fn test_is_payment_eip2930_eip1559_eip7702() {
        use alloy_consensus::{TxEip1559, TxEip2930, TxEip7702};

        // Eip2930 payment
        let tx = TxEip2930 {
            to: TxKind::Call(PAYMENT_TKN),
            ..Default::default()
        };
        let envelope =
            TempoTxEnvelope::Eip2930(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(envelope.is_payment_v1());

        // Eip2930 non-payment
        let tx = TxEip2930 {
            to: TxKind::Call(address!("1234567890123456789012345678901234567890")),
            ..Default::default()
        };
        let envelope =
            TempoTxEnvelope::Eip2930(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(!envelope.is_payment_v1());

        // Eip1559 payment
        let tx = TxEip1559 {
            to: TxKind::Call(PAYMENT_TKN),
            ..Default::default()
        };
        let envelope =
            TempoTxEnvelope::Eip1559(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(envelope.is_payment_v1());

        // Eip1559 non-payment
        let tx = TxEip1559 {
            to: TxKind::Call(address!("1234567890123456789012345678901234567890")),
            ..Default::default()
        };
        let envelope =
            TempoTxEnvelope::Eip1559(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(!envelope.is_payment_v1());

        // Eip7702 payment (note: Eip7702 has direct `to` address, not TxKind)
        let tx = TxEip7702 {
            to: PAYMENT_TKN,
            ..Default::default()
        };
        let envelope =
            TempoTxEnvelope::Eip7702(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(envelope.is_payment_v1());

        // Eip7702 non-payment
        let tx = TxEip7702 {
            to: address!("1234567890123456789012345678901234567890"),
            ..Default::default()
        };
        let envelope =
            TempoTxEnvelope::Eip7702(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(!envelope.is_payment_v1());
    }

    #[test]
    fn test_strict_payment_accepts_valid_calldata() {
        for calldata in payment_calldatas() {
            let tx = TxLegacy {
                to: TxKind::Call(PAYMENT_TKN),
                gas_limit: 21000,
                input: calldata.clone(),
                ..Default::default()
            };
            let signed = Signed::new_unhashed(tx, Signature::test_signature());
            let envelope = TempoTxEnvelope::Legacy(signed);
            assert!(
                envelope.is_payment_v1(),
                "is_payment should accept valid calldata"
            );
            assert!(
                envelope.is_payment_v2(),
                "is_strict_payment should accept valid calldata: {calldata}"
            );
        }
    }

    #[test]
    fn test_strict_payment_rejects_empty_calldata() {
        let tx = TxLegacy {
            to: TxKind::Call(PAYMENT_TKN),
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);
        assert!(
            envelope.is_payment_v1(),
            "is_payment should accept (prefix-only)"
        );
        assert!(
            !envelope.is_payment_v2(),
            "is_strict_payment should reject empty calldata"
        );
    }

    #[test]
    fn test_strict_payment_rejects_excess_calldata() {
        for calldata in payment_calldatas() {
            let mut data = calldata.to_vec();
            data.extend_from_slice(&[0u8; 32]);
            let tx = TxLegacy {
                to: TxKind::Call(PAYMENT_TKN),
                gas_limit: 21000,
                input: Bytes::from(data),
                ..Default::default()
            };
            let signed = Signed::new_unhashed(tx, Signature::test_signature());
            let envelope = TempoTxEnvelope::Legacy(signed);
            assert!(envelope.is_payment_v1(), "v1 should accept (prefix-only)");
            assert!(
                !envelope.is_payment_v2(),
                "v2 should reject excess calldata: {calldata}"
            );
        }
    }

    #[test]
    fn test_strict_payment_rejects_unknown_selector() {
        for calldata in payment_calldatas() {
            let mut data = calldata.to_vec();
            data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            let tx = TxLegacy {
                to: TxKind::Call(PAYMENT_TKN),
                gas_limit: 21000,
                input: Bytes::from(data),
                ..Default::default()
            };
            let signed = Signed::new_unhashed(tx, Signature::test_signature());
            let envelope = TempoTxEnvelope::Legacy(signed);
            assert!(envelope.is_payment_v1(), "v1 should accept (prefix-only)");
            assert!(
                !envelope.is_payment_v2(),
                "v2 should reject unknown selector: {calldata}"
            );
        }
    }

    #[test]
    fn test_strict_payment_aa_empty_calls() {
        let tx = TempoTransaction {
            fee_token: Some(PAYMENT_TKN),
            calls: vec![],
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::AA(tx.into_signed(Signature::test_signature().into()));
        assert!(
            !envelope.is_payment_v2(),
            "AA with empty calls should not be strict payment"
        );
    }

    #[test]
    fn test_strict_payment_aa_valid_calldata() {
        for calldata in payment_calldatas() {
            let call = Call {
                to: TxKind::Call(PAYMENT_TKN),
                value: U256::ZERO,
                input: calldata,
            };
            let envelope = create_aa_envelope(call);
            assert!(envelope.is_payment_v2());
        }
    }

    #[test]
    fn test_system_tx_validation_and_recovery() {
        use alloy_consensus::transaction::SignerRecoverable;

        let chain_id = 1u64;

        // Valid system tx: all fields zero, correct chain_id, system signature
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 0,
            gas_price: 0,
            gas_limit: 0,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let system_tx =
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, TEMPO_SYSTEM_TX_SIGNATURE));

        assert!(system_tx.is_system_tx(), "Should detect system signature");
        assert!(
            system_tx.is_valid_system_tx(chain_id),
            "Should be valid system tx"
        );

        // recover_signer returns ZERO for system tx
        let signer = system_tx.recover_signer().unwrap();
        assert_eq!(
            signer,
            Address::ZERO,
            "System tx signer should be Address::ZERO"
        );

        // Invalid: wrong chain_id
        assert!(
            !system_tx.is_valid_system_tx(2),
            "Wrong chain_id should fail"
        );

        // Invalid: non-zero gas_limit
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            gas_limit: 1, // non-zero
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, TEMPO_SYSTEM_TX_SIGNATURE));
        assert!(
            !envelope.is_valid_system_tx(chain_id),
            "Non-zero gas_limit should fail"
        );

        // Invalid: non-zero value
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            value: U256::from(1),
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, TEMPO_SYSTEM_TX_SIGNATURE));
        assert!(
            !envelope.is_valid_system_tx(chain_id),
            "Non-zero value should fail"
        );

        // Invalid: non-zero nonce
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 1,
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, TEMPO_SYSTEM_TX_SIGNATURE));
        assert!(
            !envelope.is_valid_system_tx(chain_id),
            "Non-zero nonce should fail"
        );

        // Non-system tx with regular signature should recover normally
        let tx = TxLegacy::default();
        let regular_tx =
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(
            !regular_tx.is_system_tx(),
            "Regular tx should not be system tx"
        );

        // fee_payer() for non-AA returns sender
        let sender = Address::random();
        assert_eq!(system_tx.fee_payer(sender).unwrap(), sender);

        // calls() iterator for non-AA returns single item
        let calls: Vec<_> = system_tx.calls().collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, TxKind::Call(Address::ZERO));

        // subblock_proposer() returns None for non-subblock tx
        assert!(system_tx.subblock_proposer().is_none());

        // AA-specific methods
        let aa_envelope = create_aa_envelope(Call {
            to: TxKind::Call(PAYMENT_TKN),
            value: U256::ZERO,
            input: Bytes::new(),
        });
        assert!(aa_envelope.is_aa());
        assert!(aa_envelope.as_aa().is_some());
        assert_eq!(aa_envelope.fee_token(), Some(PAYMENT_TKN));

        // calls() for AA tx
        let aa_calls: Vec<_> = aa_envelope.calls().collect();
        assert_eq!(aa_calls.len(), 1);
    }

    #[test]
    fn test_try_from_ethereum_envelope_eip4844_rejected() {
        use alloy_consensus::TxEip4844;

        // EIP-4844 should be rejected
        let eip4844_tx = TxEip4844::default();
        let eth_envelope: EthereumTxEnvelope<TxEip4844> = EthereumTxEnvelope::Eip4844(
            Signed::new_unhashed(eip4844_tx, Signature::test_signature()),
        );

        let result = TempoTxEnvelope::try_from(eth_envelope);
        assert!(result.is_err(), "EIP-4844 should be rejected");

        // Other types should be accepted
        let legacy_tx = TxLegacy::default();
        let eth_envelope: EthereumTxEnvelope<TxEip4844> = EthereumTxEnvelope::Legacy(
            Signed::new_unhashed(legacy_tx, Signature::test_signature()),
        );
        assert!(TempoTxEnvelope::try_from(eth_envelope).is_ok());
    }

    #[test]
    fn test_tx_type_conversions() {
        // TxType -> TempoTxType: EIP-4844 rejected
        assert!(TempoTxType::try_from(TxType::Legacy).is_ok());
        assert!(TempoTxType::try_from(TxType::Eip2930).is_ok());
        assert!(TempoTxType::try_from(TxType::Eip1559).is_ok());
        assert!(TempoTxType::try_from(TxType::Eip7702).is_ok());
        assert!(TempoTxType::try_from(TxType::Eip4844).is_err());

        // TempoTxType -> TxType: AA rejected
        assert!(TxType::try_from(TempoTxType::Legacy).is_ok());
        assert!(TxType::try_from(TempoTxType::Eip2930).is_ok());
        assert!(TxType::try_from(TempoTxType::Eip1559).is_ok());
        assert!(TxType::try_from(TempoTxType::Eip7702).is_ok());
        assert!(TxType::try_from(TempoTxType::AA).is_err());
    }
}
