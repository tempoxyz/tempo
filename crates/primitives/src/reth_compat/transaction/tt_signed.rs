use crate::transaction::tt_signed::AASigned;

impl reth_primitives_traits::InMemorySize for AASigned {
    fn size(&self) -> usize {
        size_of::<Self>() + self.tx().size() + self.signature().size()
    }
}
