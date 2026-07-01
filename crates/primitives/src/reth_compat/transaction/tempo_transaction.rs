use crate::TempoTransaction;

impl reth_primitives_traits::InMemorySize for TempoTransaction {
    fn size(&self) -> usize {
        Self::size(self)
    }
}
