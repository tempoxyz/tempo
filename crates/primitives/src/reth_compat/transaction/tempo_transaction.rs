use crate::TempoTransaction;

impl reth_primitives_traits::InMemorySize for TempoTransaction {
    fn size(&self) -> usize {
        Self::size(self)
    }
}

#[cfg(feature = "serde-bincode-compat")]
impl reth_primitives_traits::serde_bincode_compat::RlpBincode for TempoTransaction {}
