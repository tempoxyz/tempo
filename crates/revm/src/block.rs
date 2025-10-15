use alloy_primitives::{Address, B256, U256};
use reth_evm::{
    env::BlockEnvironment,
    revm::{
        context::{Block, BlockEnv},
        context_interface::block::BlobExcessGasAndPrice,
    },
};

/// Tempo block environment.
#[derive(Debug, Clone, Default, derive_more::Deref, derive_more::DerefMut)]
pub struct TempoBlockEnv {
    /// Inner [`BlockEnv`].
    #[deref]
    #[deref_mut]
    pub inner: BlockEnv,

    /// Milliseconds portion of the timestamp.
    pub timestamp_millis_part: u64,
}

impl Block for TempoBlockEnv {
    #[inline]
    fn number(&self) -> U256 {
        self.inner.number()
    }

    #[inline]
    fn beneficiary(&self) -> Address {
        self.inner.beneficiary()
    }

    #[inline]
    fn timestamp(&self) -> U256 {
        self.inner.timestamp()
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    #[inline]
    fn basefee(&self) -> u64 {
        self.inner.basefee()
    }

    #[inline]
    fn difficulty(&self) -> U256 {
        self.inner.difficulty()
    }

    #[inline]
    fn prevrandao(&self) -> Option<B256> {
        self.inner.prevrandao()
    }

    #[inline]
    fn blob_excess_gas_and_price(&self) -> Option<BlobExcessGasAndPrice> {
        self.inner.blob_excess_gas_and_price()
    }
}

impl BlockEnvironment for TempoBlockEnv {
    fn inner_mut(&mut self) -> &mut BlockEnv {
        &mut self.inner
    }
}
