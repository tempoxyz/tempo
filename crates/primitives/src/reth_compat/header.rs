use crate::TempoHeader;

impl reth_primitives_traits::InMemorySize for TempoHeader {
    fn size(&self) -> usize {
        let Self {
            inner,
            general_gas_limit,
            timestamp_millis_part,
            shared_gas_limit,
        } = self;
        inner.size()
            + general_gas_limit.size()
            + timestamp_millis_part.size()
            + shared_gas_limit.size()
    }
}
