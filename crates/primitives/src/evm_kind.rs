/// Kind of Tempo EVM, which fixes the protocol rules that differ between Tempo L1 and its zones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TempoEvmKind {
    /// Tempo L1, including its mainnet, testnets, and devnets.
    #[default]
    L1,
    /// A Tempo zone.
    Zone {
        /// Accounts whose Tempo commitment the current transaction already read (TIP-1154).
        l1_commitments: alloy_primitives::map::AddressSet,
    },
}

impl TempoEvmKind {
    /// A zone whose current transaction has read no Tempo commitment yet.
    pub fn zone() -> Self {
        Self::Zone {
            l1_commitments: Default::default(),
        }
    }

    /// Whether this is Tempo L1.
    pub fn is_l1(&self) -> bool {
        matches!(self, Self::L1)
    }
}
