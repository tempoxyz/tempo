/// Kind of Tempo EVM, which fixes the protocol rules that differ between Tempo L1 and its zones.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TempoEvmKind {
    /// Tempo L1, including its mainnet, testnets, and devnets.
    #[default]
    L1,
    /// A Tempo zone.
    Zone,
}

impl TempoEvmKind {
    /// Whether this is Tempo L1.
    pub fn is_l1(&self) -> bool {
        matches!(self, Self::L1)
    }
}
