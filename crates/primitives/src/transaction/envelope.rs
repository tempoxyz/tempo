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

/// TIP20 payment address prefix (12 bytes for payment classification)
/// Same as TIP20_TOKEN_PREFIX
pub const TIP20_PAYMENT_PREFIX: [u8; 12] = hex!("20C000000000000000000000");

/// Valid TIP-20 payment selectors with their expected calldata lengths.
const PAYMENT_CALLDATA: &[([u8; 4], usize)] = &[
    (hex!("a9059cbb"), 68),  // transfer(address,uint256)
    (hex!("95777d59"), 100), // transferWithMemo(address,uint256,bytes32)
    (hex!("23b872dd"), 100), // transferFrom(address,address,uint256)
    (hex!("929c2539"), 132), // transferFromWithMemo(address,address,uint256,bytes32)
];

/// Returns `true` if `input` has a recognized TIP-20 payment selector and its length exactly
/// matches the expected ABI-encoded size for that function.
fn is_valid_payment_calldata(input: &[u8]) -> bool {
    input.first_chunk::<4>().is_some_and(|selector| {
        PAYMENT_CALLDATA
            .iter()
            .any(|(sel, len)| selector == sel && input.len() == *len)
    })
}

/// Returns `true` if `to` has the TIP-20 payment prefix and `input` is valid payment calldata.
fn is_tip20_payment(to: Option<&Address>, input: &[u8]) -> bool {
    to.is_some_and(|to| to.starts_with(&TIP20_PAYMENT_PREFIX)) && is_valid_payment_calldata(input)
}

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

    /// Classify a transaction as payment or non-payment.
    ///
    /// A transaction is a payment if:
    /// 1. The `to` address has the TIP20 prefix, AND
    /// 2. The calldata has a recognized payment selector with exact ABI-encoded length.
    pub fn is_payment(&self) -> bool {
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

#[cfg(feature = "reth")]
impl reth_primitives_traits::InMemorySize for TempoTxEnvelope {
    fn size(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.size(),
            Self::Eip2930(tx) => tx.size(),
            Self::Eip1559(tx) => tx.size(),
            Self::Eip7702(tx) => tx.size(),
            Self::AA(tx) => tx.size(),
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

#[cfg(feature = "reth")]
impl reth_primitives_traits::SignedTransaction for TempoTxEnvelope {}

#[cfg(feature = "reth")]
impl reth_primitives_traits::InMemorySize for TempoTxType {
    fn size(&self) -> usize {
        size_of::<Self>()
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

#[cfg(all(feature = "serde-bincode-compat", feature = "reth"))]
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
    use crate::transaction::{Call, TempoTransaction};
    use alloy_primitives::{Bytes, Signature, TxKind, U256, address};

    const PAYMENT_TKN: Address = address!("20c0000000000000000000000000000000000001");

    fn payment_calldata(index: usize) -> Bytes {
        let (selector, len) = PAYMENT_CALLDATA[index];
        let mut data = vec![0u8; len];
        data[..4].copy_from_slice(&selector);
        Bytes::from(data)
    }

    fn transfer_calldata() -> Bytes {
        payment_calldata(0)
    }

    fn transfer_with_memo_calldata() -> Bytes {
        payment_calldata(1)
    }

    fn transfer_from_calldata() -> Bytes {
        payment_calldata(2)
    }

    fn transfer_from_with_memo_calldata() -> Bytes {
        payment_calldata(3)
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
        let tx = TxLegacy {
            to: TxKind::Call(PAYMENT_TKN),
            gas_limit: 21000,
            input: transfer_calldata(),
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);
        assert!(envelope.is_payment());

        let tx = TxLegacy {
            to: TxKind::Call(PAYMENT_TKN),
            gas_limit: 21000,
            input: transfer_with_memo_calldata(),
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);
        assert!(envelope.is_payment());

        let tx = TxLegacy {
            to: TxKind::Call(PAYMENT_TKN),
            gas_limit: 21000,
            input: transfer_from_calldata(),
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);
        assert!(envelope.is_payment());

        let tx = TxLegacy {
            to: TxKind::Call(PAYMENT_TKN),
            gas_limit: 21000,
            input: transfer_from_with_memo_calldata(),
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);
        assert!(envelope.is_payment());
    }

    #[test]
    fn test_payment_rejects_empty_calldata() {
        let tx = TxLegacy {
            to: TxKind::Call(PAYMENT_TKN),
            gas_limit: 21000,
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);
        assert!(!envelope.is_payment());
    }

    #[test]
    fn test_payment_rejects_excess_calldata() {
        let mut data = transfer_calldata().to_vec();
        data.extend_from_slice(&[0u8; 32]);
        let tx = TxLegacy {
            to: TxKind::Call(PAYMENT_TKN),
            gas_limit: 21000,
            input: Bytes::from(data),
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);
        assert!(!envelope.is_payment());
    }

    #[test]
    fn test_payment_rejects_unknown_selector() {
        let mut data = transfer_calldata().to_vec();
        data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let tx = TxLegacy {
            to: TxKind::Call(PAYMENT_TKN),
            gas_limit: 21000,
            input: Bytes::from(data),
            ..Default::default()
        };
        let signed = Signed::new_unhashed(tx, Signature::test_signature());
        let envelope = TempoTxEnvelope::Legacy(signed);
        assert!(!envelope.is_payment());
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

        assert!(!envelope.is_payment());
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
    fn test_payment_classification_aa_empty_calls() {
        let tx = TempoTransaction {
            fee_token: Some(PAYMENT_TKN),
            calls: vec![],
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::AA(tx.into_signed(Signature::test_signature().into()));
        assert!(!envelope.is_payment());
    }

    #[test]
    fn test_payment_classification_aa_with_tip20_prefix() {
        let payment_addr = address!("20c0000000000000000000000000000000000001");
        for i in 0..PAYMENT_CALLDATA.len() {
            let call = Call {
                to: TxKind::Call(payment_addr),
                value: U256::ZERO,
                input: payment_calldata(i),
            };
            let envelope = create_aa_envelope(call);
            assert!(
                envelope.is_payment(),
                "PAYMENT_CALLDATA[{i}] should be classified as payment"
            );
        }
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
        assert!(!envelope.is_payment());
    }

    #[test]
    fn test_payment_classification_aa_no_to_address() {
        let call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope = create_aa_envelope(call);
        assert!(!envelope.is_payment());
    }

    #[test]
    fn test_payment_classification_aa_partial_match() {
        let payment_addr = address!("20c0000000000000000000001111111111111111");
        for i in 0..PAYMENT_CALLDATA.len() {
            let call = Call {
                to: TxKind::Call(payment_addr),
                value: U256::ZERO,
                input: payment_calldata(i),
            };
            let envelope = create_aa_envelope(call);
            assert!(
                envelope.is_payment(),
                "PAYMENT_CALLDATA[{i}] should match partial TIP20 prefix"
            );
        }
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
        assert!(!envelope.is_payment());
    }

    #[test]
    fn test_is_payment_eip2930_eip1559_eip7702() {
        use alloy_consensus::{TxEip1559, TxEip2930, TxEip7702};

        for i in 0..PAYMENT_CALLDATA.len() {
            let input = payment_calldata(i);

            // Eip2930 payment
            let tx = TxEip2930 {
                to: TxKind::Call(PAYMENT_TKN),
                input: input.clone(),
                ..Default::default()
            };
            let envelope =
                TempoTxEnvelope::Eip2930(Signed::new_unhashed(tx, Signature::test_signature()));
            assert!(envelope.is_payment(), "Eip2930 PAYMENT_CALLDATA[{i}]");

            // Eip1559 payment
            let tx = TxEip1559 {
                to: TxKind::Call(PAYMENT_TKN),
                input: input.clone(),
                ..Default::default()
            };
            let envelope =
                TempoTxEnvelope::Eip1559(Signed::new_unhashed(tx, Signature::test_signature()));
            assert!(envelope.is_payment(), "Eip1559 PAYMENT_CALLDATA[{i}]");

            // Eip7702 payment
            let tx = TxEip7702 {
                to: PAYMENT_TKN,
                input,
                ..Default::default()
            };
            let envelope =
                TempoTxEnvelope::Eip7702(Signed::new_unhashed(tx, Signature::test_signature()));
            assert!(envelope.is_payment(), "Eip7702 PAYMENT_CALLDATA[{i}]");
        }

        // Non-payment addresses
        let tx = TxEip2930 {
            to: TxKind::Call(address!("1234567890123456789012345678901234567890")),
            ..Default::default()
        };
        let envelope =
            TempoTxEnvelope::Eip2930(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(!envelope.is_payment());

        let tx = TxEip1559 {
            to: TxKind::Call(address!("1234567890123456789012345678901234567890")),
            ..Default::default()
        };
        let envelope =
            TempoTxEnvelope::Eip1559(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(!envelope.is_payment());

        let tx = TxEip7702 {
            to: address!("1234567890123456789012345678901234567890"),
            ..Default::default()
        };
        let envelope =
            TempoTxEnvelope::Eip7702(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(!envelope.is_payment());
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
