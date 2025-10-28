use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use alloy_rpc_types_eth::TransactionTrait;
use reth_primitives_traits::{Recovered, crypto::RecoveryError};
use tempo_primitives::TempoTxEnvelope;

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct SubBlock {
    /// Hash of the parent block. This subblock can only be included as
    /// part of the block building on top of the specified parent.
    pub parent_hash: B256,
    /// Transactions included in the subblock.
    pub transactions: Vec<TempoTxEnvelope>,
}

impl SubBlock {
    /// Returns the hash for the signature.
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::new();
        self.parent_hash.encode(&mut buf);
        self.transactions.encode(&mut buf);
        keccak256(&buf)
    }

    /// Returns the total gas occupied by the subblock.
    pub fn occupied_gas(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.gas_limit()).sum()
    }
}

/// A subblock with a signature.
#[derive(Debug, Clone, RlpEncodable, RlpDecodable, derive_more::Deref, derive_more::DerefMut)]
pub struct SignedSubBlock {
    /// The subblock.
    #[deref]
    #[deref_mut]
    pub inner: SubBlock,
    /// The signature of the subblock.
    pub signature: Bytes,
}

impl SignedSubBlock {
    /// Attempts to recover the senders and convert the subblock into a [`RecoveredSubBlock`].
    ///
    /// Note that the validator is assumed to be pre-validated to match the submitted signature.
    pub fn try_into_recovered(self, validator: B256) -> Result<RecoveredSubBlock, RecoveryError> {
        let senders =
            reth_primitives_traits::transaction::recover::recover_signers(&self.transactions)?;

        Ok(RecoveredSubBlock {
            inner: self,
            senders,
            validator,
        })
    }
}

/// A subblock with recovered senders.
#[derive(Debug, Clone, RlpEncodable, RlpDecodable, derive_more::Deref, derive_more::DerefMut)]
pub struct RecoveredSubBlock {
    /// Inner subblock.
    #[deref]
    #[deref_mut]
    inner: SignedSubBlock,

    /// The senders of the transactions.
    senders: Vec<Address>,

    /// The validator that submitted the subblock.
    validator: B256,
}

impl RecoveredSubBlock {
    /// Returns an iterator over `Recovered<&Transaction>`
    #[inline]
    pub fn transactions_recovered(&self) -> impl Iterator<Item = Recovered<&TempoTxEnvelope>> + '_ {
        self.senders
            .iter()
            .zip(self.inner.transactions.iter())
            .map(|(sender, tx)| Recovered::new_unchecked(tx, *sender))
    }

    /// Returns the validator that submitted the subblock.
    pub fn validator(&self) -> B256 {
        self.validator
    }
}
