use super::{fee_token::TxFeeToken, tt_signed::AASigned};
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
use reth_primitives_traits::InMemorySize;

/// TIP20 payment address prefix (14 bytes for payment classification)
/// Same as TIP20_TOKEN_PREFIX but extended to 14 bytes for payment classification
pub const TIP20_PAYMENT_PREFIX: [u8; 14] = hex!("20C0000000000000000000000000");

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
/// - Tempo fee token transactions (0x77)
#[derive(Clone, Debug, alloy_consensus::TransactionEnvelope)]
#[envelope(
    tx_type_name = TempoTxType,
    typed = TempoTypedTransaction,
    arbitrary_cfg(any(test, feature = "arbitrary")),
    serde_cfg(feature = "serde")
)]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
#[expect(clippy::large_enum_variant)]
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

    /// Tempo fee token transaction (type 0x77)
    #[envelope(ty = 0x77)]
    FeeToken(Signed<TxFeeToken>),
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
            TempoTxType::FeeToken => {
                return Err(UnsupportedTransactionType::new(TempoTxType::FeeToken));
            }
            TempoTxType::AA => {
                return Err(UnsupportedTransactionType::new(TempoTxType::AA));
            }
        })
    }
}

impl TempoTxEnvelope {
    /// Returns the fee token preference if this is a fee token transaction
    pub fn fee_token(&self) -> Option<Address> {
        match self {
            Self::FeeToken(tx) => tx.tx().fee_token,
            Self::AA(tx) => tx.tx().fee_token,
            _ => None,
        }
    }

    /// Resolves fee payer for the transaction.
    pub fn fee_payer(&self, sender: Address) -> Result<Address, RecoveryError> {
        match self {
            Self::FeeToken(tx) => tx.tx().recover_fee_payer(sender),
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
            Self::FeeToken(_) => TempoTxType::FeeToken,
        }
    }

    /// Returns true if this is a fee token transaction
    pub fn is_fee_token(&self) -> bool {
        matches!(self, Self::FeeToken(_) | Self::AA(_))
    }

    /// Returns the authorization list if present (for EIP-7702 and FeeToken transactions)
    pub fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        match self {
            Self::Eip7702(tx) => Some(&tx.tx().authorization_list),
            Self::FeeToken(tx) => Some(&tx.tx().authorization_list),
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

    /// Classify a transaction as payment or non-payment.
    ///
    /// Currently uses classifier v1: transaction is a payment if the `to` address has the TIP20 prefix.
    pub fn is_payment(&self) -> bool {
        match self {
            Self::Legacy(tx) => tx
                .tx()
                .to
                .to()
                .is_some_and(|to| to.starts_with(&TIP20_PAYMENT_PREFIX)),
            Self::Eip2930(tx) => tx
                .tx()
                .to
                .to()
                .is_some_and(|to| to.starts_with(&TIP20_PAYMENT_PREFIX)),
            Self::Eip1559(tx) => tx
                .tx()
                .to
                .to()
                .is_some_and(|to| to.starts_with(&TIP20_PAYMENT_PREFIX)),
            Self::Eip7702(tx) => tx.tx().to.starts_with(&TIP20_PAYMENT_PREFIX),
            Self::FeeToken(tx) => tx
                .tx()
                .to
                .to()
                .is_some_and(|to| to.starts_with(&TIP20_PAYMENT_PREFIX)),
            Self::AA(tx) => tx.tx().calls.iter().all(|call| {
                call.to
                    .to()
                    .is_some_and(|to| to.starts_with(&TIP20_PAYMENT_PREFIX))
            }),
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
            Self::FeeToken(tx) => {
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
            Self::FeeToken(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
            Self::AA(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
        }
    }
}

impl reth_primitives_traits::InMemorySize for TempoTxEnvelope {
    fn size(&self) -> usize {
        match self {
            Self::Legacy(tx) => reth_primitives_traits::InMemorySize::size(tx),
            Self::Eip2930(tx) => reth_primitives_traits::InMemorySize::size(tx),
            Self::Eip1559(tx) => reth_primitives_traits::InMemorySize::size(tx),
            Self::Eip7702(tx) => reth_primitives_traits::InMemorySize::size(tx),
            Self::AA(tx) => reth_primitives_traits::InMemorySize::size(tx),
            Self::FeeToken(tx) => reth_primitives_traits::InMemorySize::size(tx),
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
            Self::FeeToken(tx) => tx.hash(),
        }
    }
}

impl reth_primitives_traits::SignedTransaction for TempoTxEnvelope {}

impl InMemorySize for TempoTxType {
    fn size(&self) -> usize {
        core::mem::size_of::<Self>()
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
            Self::FeeToken => write!(f, "FeeToken"),
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

impl From<Signed<TxFeeToken>> for TempoTxEnvelope {
    fn from(value: Signed<TxFeeToken>) -> Self {
        Self::FeeToken(value)
    }
}

impl From<AASigned> for TempoTxEnvelope {
    fn from(value: AASigned) -> Self {
        Self::AA(value)
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
            Self::FeeToken(tx) => tx.into_signed(sig).into(),
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
            Self::FeeToken(tx) => tx,
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
            TempoTxEnvelope::FeeToken(tx) => Self::FeeToken(tx.into_parts().0),
            TempoTxEnvelope::AA(tx) => Self::AA(tx.into_parts().0),
        }
    }
}

impl From<TxFeeToken> for TempoTypedTransaction {
    fn from(value: TxFeeToken) -> Self {
        Self::FeeToken(value)
    }
}

impl From<TempoTransaction> for TempoTypedTransaction {
    fn from(value: TempoTransaction) -> Self {
        Self::AA(value)
    }
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

#[cfg(feature = "serde-bincode-compat")]
impl reth_primitives_traits::serde_bincode_compat::RlpBincode for TempoTxEnvelope {}

#[cfg(feature = "reth-codec")]
mod codec {
    use crate::{TempoSignature, TempoTransaction};

    use super::*;
    use alloy_eips::eip2718::EIP7702_TX_TYPE_ID;
    use alloy_primitives::{
        Bytes, Signature,
        bytes::{self, BufMut},
    };
    use reth_codecs::{
        Compact,
        alloy::transaction::{CompactEnvelope, Envelope},
        txtype::{
            COMPACT_EXTENDED_IDENTIFIER_FLAG, COMPACT_IDENTIFIER_EIP1559,
            COMPACT_IDENTIFIER_EIP2930, COMPACT_IDENTIFIER_LEGACY,
        },
    };

    impl reth_codecs::alloy::transaction::FromTxCompact for TempoTxEnvelope {
        type TxType = TempoTxType;

        fn from_tx_compact(
            buf: &[u8],
            tx_type: Self::TxType,
            signature: Signature,
        ) -> (Self, &[u8]) {
            use alloy_consensus::Signed;
            use reth_codecs::Compact;

            match tx_type {
                TempoTxType::Legacy => {
                    let (tx, buf) = TxLegacy::from_compact(buf, buf.len());
                    let tx = Signed::new_unhashed(tx, signature);
                    (Self::Legacy(tx), buf)
                }
                TempoTxType::Eip2930 => {
                    let (tx, buf) = TxEip2930::from_compact(buf, buf.len());
                    let tx = Signed::new_unhashed(tx, signature);
                    (Self::Eip2930(tx), buf)
                }
                TempoTxType::Eip1559 => {
                    let (tx, buf) = TxEip1559::from_compact(buf, buf.len());
                    let tx = Signed::new_unhashed(tx, signature);
                    (Self::Eip1559(tx), buf)
                }
                TempoTxType::Eip7702 => {
                    let (tx, buf) = TxEip7702::from_compact(buf, buf.len());
                    let tx = Signed::new_unhashed(tx, signature);
                    (Self::Eip7702(tx), buf)
                }
                TempoTxType::AA => {
                    let (tx, buf) = TempoTransaction::from_compact(buf, buf.len());
                    // For Tempo transactions, we need to decode the signature bytes as TempoSignature
                    let (sig_bytes, buf) = Bytes::from_compact(buf, buf.len());
                    let aa_sig = TempoSignature::from_bytes(&sig_bytes)
                        .map_err(|e| panic!("Failed to decode AA signature: {e}"))
                        .unwrap();
                    let tx = AASigned::new_unhashed(tx, aa_sig);
                    (Self::AA(tx), buf)
                }
                TempoTxType::FeeToken => {
                    let (tx, buf) = TxFeeToken::from_compact(buf, buf.len());
                    let tx = Signed::new_unhashed(tx, signature);
                    (Self::FeeToken(tx), buf)
                }
            }
        }
    }

    impl reth_codecs::alloy::transaction::ToTxCompact for TempoTxEnvelope {
        fn to_tx_compact(&self, buf: &mut (impl BufMut + AsMut<[u8]>)) {
            match self {
                Self::Legacy(tx) => tx.tx().to_compact(buf),
                Self::Eip2930(tx) => tx.tx().to_compact(buf),
                Self::Eip1559(tx) => tx.tx().to_compact(buf),
                Self::Eip7702(tx) => tx.tx().to_compact(buf),
                Self::AA(tx) => {
                    let mut len = tx.tx().to_compact(buf);
                    // Also encode the TempoSignature as Bytes
                    len += tx.signature().to_bytes().to_compact(buf);
                    len
                }
                Self::FeeToken(tx) => tx.tx().to_compact(buf),
            };
        }
    }

    impl Envelope for TempoTxEnvelope {
        fn signature(&self) -> &Signature {
            match self {
                Self::Legacy(tx) => tx.signature(),
                Self::Eip2930(tx) => tx.signature(),
                Self::Eip1559(tx) => tx.signature(),
                Self::Eip7702(tx) => tx.signature(),
                Self::AA(_tx) => {
                    // TODO: Will this work?
                    &TEMPO_SYSTEM_TX_SIGNATURE
                }
                Self::FeeToken(tx) => tx.signature(),
            }
        }

        fn tx_type(&self) -> Self::TxType {
            Self::tx_type(self)
        }
    }

    impl Compact for TempoTxType {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: BufMut + AsMut<[u8]>,
        {
            match self {
                Self::Legacy => COMPACT_IDENTIFIER_LEGACY,
                Self::Eip2930 => COMPACT_IDENTIFIER_EIP2930,
                Self::Eip1559 => COMPACT_IDENTIFIER_EIP1559,
                Self::Eip7702 => {
                    buf.put_u8(EIP7702_TX_TYPE_ID);
                    COMPACT_EXTENDED_IDENTIFIER_FLAG
                }
                Self::AA => {
                    buf.put_u8(crate::transaction::TEMPO_TX_TYPE_ID);
                    COMPACT_EXTENDED_IDENTIFIER_FLAG
                }
                Self::FeeToken => {
                    buf.put_u8(crate::transaction::FEE_TOKEN_TX_TYPE_ID);
                    COMPACT_EXTENDED_IDENTIFIER_FLAG
                }
            }
        }

        // For backwards compatibility purposes only 2 bits of the type are encoded in the identifier
        // parameter. In the case of a [`COMPACT_EXTENDED_IDENTIFIER_FLAG`], the full transaction type
        // is read from the buffer as a single byte.
        fn from_compact(mut buf: &[u8], identifier: usize) -> (Self, &[u8]) {
            use bytes::Buf;
            (
                match identifier {
                    COMPACT_IDENTIFIER_LEGACY => Self::Legacy,
                    COMPACT_IDENTIFIER_EIP2930 => Self::Eip2930,
                    COMPACT_IDENTIFIER_EIP1559 => Self::Eip1559,
                    COMPACT_EXTENDED_IDENTIFIER_FLAG => {
                        let extended_identifier = buf.get_u8();
                        match extended_identifier {
                            EIP7702_TX_TYPE_ID => Self::Eip7702,
                            crate::transaction::TEMPO_TX_TYPE_ID => Self::AA,
                            crate::transaction::FEE_TOKEN_TX_TYPE_ID => Self::FeeToken,
                            _ => panic!("Unsupported TxType identifier: {extended_identifier}"),
                        }
                    }
                    _ => panic!("Unknown identifier for TxType: {identifier}"),
                },
                buf,
            )
        }
    }

    impl Compact for TempoTxEnvelope {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: BufMut + AsMut<[u8]>,
        {
            CompactEnvelope::to_compact(self, buf)
        }

        fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
            CompactEnvelope::from_compact(buf, len)
        }
    }

    impl reth_db_api::table::Compress for TempoTxEnvelope {
        type Compressed = Vec<u8>;

        fn compress_to_buf<B: alloy_primitives::bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
            let _ = Compact::to_compact(self, buf);
        }
    }

    impl reth_db_api::table::Decompress for TempoTxEnvelope {
        fn decompress(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
            let (obj, _) = Compact::from_compact(value, value.len());
            Ok(obj)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Signature, TxKind, address};

    #[test]
    fn test_fee_token_access() {
        let fee_token_tx = TxFeeToken {
            fee_token: Some(Address::ZERO),
            ..Default::default()
        };
        let signature = Signature::new(
            alloy_primitives::U256::ZERO,
            alloy_primitives::U256::ZERO,
            false,
        );
        let signed = Signed::new_unhashed(fee_token_tx, signature);
        let envelope = TempoTxEnvelope::FeeToken(signed);

        assert!(envelope.is_fee_token());
        assert_eq!(envelope.fee_token(), Some(Address::ZERO));
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
    }

    #[test]
    fn test_payment_classification_with_tip20_prefix() {
        // Create an address with TIP20 prefix
        let payment_addr = address!("20c0000000000000000000000000000000000001");
        let tx = TxFeeToken {
            to: TxKind::Call(payment_addr),
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::FeeToken(signed);

        assert!(envelope.is_payment());
    }

    #[test]
    fn test_payment_classification_without_tip20_prefix() {
        // Create an address without TIP20 prefix
        let non_payment_addr = address!("1234567890123456789012345678901234567890");
        let tx = TxFeeToken {
            to: TxKind::Call(non_payment_addr),
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::FeeToken(signed);

        assert!(!envelope.is_payment());
    }

    #[test]
    fn test_payment_classification_no_to_address() {
        // Create a transaction with no `to` address (contract creation)
        let tx = TxFeeToken {
            to: TxKind::Create,
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::FeeToken(signed);

        assert!(!envelope.is_payment());
    }

    #[test]
    fn test_payment_classification_partial_match() {
        // Create an address that partially matches but not completely
        let partial_match_addr = address!("20c0000000000000000000000000000100000000");
        let tx = TxFeeToken {
            to: TxKind::Call(partial_match_addr),
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::FeeToken(signed);

        // This should still be classified as payment since first 14 bytes match
        assert!(envelope.is_payment());
    }

    #[test]
    fn test_payment_classification_different_prefix() {
        // Create an address with a different prefix
        let different_prefix_addr = address!("30c0000000000000000000000000000000000001");
        let tx = TxFeeToken {
            to: TxKind::Call(different_prefix_addr),
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::FeeToken(signed);

        assert!(!envelope.is_payment());
    }

    #[test]
    fn test_payment_classification_legacy_tx() {
        // Test with legacy transaction type
        let payment_addr = address!("20c0000000000000000000000000000000000001");
        let tx = TxLegacy {
            to: TxKind::Call(payment_addr),
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);

        assert!(envelope.is_payment());
    }
}
