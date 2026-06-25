use crate::TempoHardfork;

/// ABI selector lifecycle changes introduced at a hardfork boundary.
///
/// Selectors in [`Self::added`] are unavailable before [`Self::hardfork`] activates.
/// Selectors in [`Self::dropped`] are unavailable once [`Self::hardfork`] activates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelectorSchedule {
    pub hardfork: TempoHardfork,
    pub added: &'static [[u8; 4]],
    pub dropped: &'static [[u8; 4]],
}

impl SelectorSchedule {
    /// Creates an empty schedule for `hardfork`.
    pub const fn new(hardfork: TempoHardfork) -> Self {
        Self {
            hardfork,
            added: &[],
            dropped: &[],
        }
    }

    /// Registers selectors introduced at this hardfork boundary.
    pub const fn with_added(mut self, selectors: &'static [[u8; 4]]) -> Self {
        self.added = selectors;
        self
    }

    /// Registers selectors removed at this hardfork boundary.
    pub const fn with_dropped(mut self, selectors: &'static [[u8; 4]]) -> Self {
        self.dropped = selectors;
        self
    }

    /// Returns `true` if `schedule` gates out `selector` under the `active` hardfork.
    #[inline]
    pub fn rejects(&self, selector: [u8; 4], active: TempoHardfork) -> bool {
        if self.hardfork <= active {
            self.dropped
        } else {
            self.added
        }
        .contains(&selector)
    }
}

/// Tempo-specific ABI metadata generated for a Solidity interface.
pub trait SolCallWithSchedule {
    /// Selector lifecycle metadata used by precompile dispatchers for hardfork gating.
    const SELECTOR_SCHEDULE: &'static [SelectorSchedule];
}
