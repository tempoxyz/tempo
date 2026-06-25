use crate::TempoHardfork;
use paste as _;

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

#[macro_export]
macro_rules! schedule {
    // Entry: emit cleaned ABI and schedule impl.
    (@sol [$(#[$attr:meta])* $vis:vis interface $iface:ident] $($body:tt)*) => {
        $crate::schedule!(@strip [$(#[$attr])* $vis interface $iface] [] $($body)*);
        paste::paste! {
            impl $crate::SolCallWithSchedule for $iface::[<$iface Calls>] {
                const SELECTOR_SCHEDULE: &'static [$crate::SelectorSchedule] = $crate::schedule!(@scan $iface [] [] $($body)*);
            }
        }
    };

    // Strip pass: remove Tempo attrs before forwarding to Alloy.
    (@strip [$($head:tt)*] [$($out:tt)*]) => { $crate::sol!(@emit $($head)* { $($out)* }); };
    (@strip [$($head:tt)*] [$($out:tt)*] #[since($($args:tt)*)] $($rest:tt)*) => {
        $crate::schedule!(@strip [$($head)*] [$($out)*] $($rest)*);
    };
    (@strip [$($head:tt)*] [$($out:tt)*] #[until($($args:tt)*)] $($rest:tt)*) => {
        $crate::schedule!(@strip [$($head)*] [$($out)*] $($rest)*);
    };
    (@strip [$($head:tt)*] [$($out:tt)*] #[overload($($args:tt)*)] $($rest:tt)*) => {
        $crate::schedule!(@strip [$($head)*] [$($out)*] $($rest)*);
    };
    (@strip [$($head:tt)*] [$($out:tt)*] $tt:tt $($rest:tt)*) => {
        $crate::schedule!(@strip [$($head)*] [$($out)* $tt] $($rest)*);
    };

    // Scan pass: collect attrs immediately before each function.
    (@scan $iface:ident [$($out:tt)*] [$($attrs:tt)*]) => { &[$($out)*] };
    (@scan $iface:ident [$($out:tt)*] [$($attrs:tt)*] #[$attr:meta] $($rest:tt)*) => {
        $crate::schedule!(@scan $iface [$($out)*] [$($attrs)* #[$attr]] $($rest)*)
    };
    (@scan $iface:ident [$($out:tt)*] [] function $name:ident $($rest:tt)*) => {
        $crate::schedule!(@skip_fn $iface [$($out)*] $($rest)*)
    };
    (@scan $iface:ident [$($out:tt)*] [$($attrs:tt)*] function $name:ident $($rest:tt)*) => {
        $crate::schedule!(@overload $iface $name [$($out)*] [$($rest)*] [] [] $($attrs)*)
    };
    (@scan $iface:ident [$($out:tt)*] [$($attrs:tt)*] $tt:tt $($rest:tt)*) => {
        $crate::schedule!(@scan $iface [$($out)*] [] $($rest)*)
    };

    // Skip the function signature after its attrs have been processed.
    (@skip_fn $iface:ident [$($out:tt)*] ; $($rest:tt)*) => {
        $crate::schedule!(@scan $iface [$($out)*] [] $($rest)*)
    };
    (@skip_fn $iface:ident [$($out:tt)*] $tt:tt $($rest:tt)*) => {
        $crate::schedule!(@skip_fn $iface [$($out)*] $($rest)*)
    };

    // Overload pass: extract one optional overload index for all schedule attrs.
    (@overload $iface:ident $name:ident [$($out:tt)*] [$($fn_rest:tt)*] [$($idx:literal)?] [$($attrs:tt)*]) => {
        $crate::schedule!(@entries $iface $name [$($out)*] [$($fn_rest)*] [$($idx)?] $($attrs)*)
    };
    (@overload $iface:ident $name:ident [$($out:tt)*] [$($fn_rest:tt)*] [$($old:literal)?] [$($attrs:tt)*] #[overload($idx:literal)] $($rest:tt)*) => {
        $crate::schedule!(@overload $iface $name [$($out)*] [$($fn_rest)*] [$idx] [$($attrs)*] $($rest)*)
    };
    (@overload $iface:ident $name:ident [$($out:tt)*] [$($fn_rest:tt)*] [$($idx:literal)?] [$($attrs:tt)*] #[$attr:meta] $($rest:tt)*) => {
        $crate::schedule!(@overload $iface $name [$($out)*] [$($fn_rest)*] [$($idx)?] [$($attrs)* #[$attr]] $($rest)*)
    };

    // Entry pass: turn recognized attrs into schedule rows.
    (@entries $iface:ident $name:ident [$($out:tt)*] [$($fn_rest:tt)*] [$($idx:literal)?]) => {
        $crate::schedule!(@skip_fn $iface [$($out)*] $($fn_rest)*)
    };
    (@entries $iface:ident $name:ident [$($out:tt)*] [$($fn_rest:tt)*] [$($idx:literal)?] #[since($hardfork:path)] $($attrs:tt)*) => {
        $crate::schedule!(@push with_added $iface $name [$($out)*] [$($fn_rest)*] $hardfork [$($idx)?]; $($attrs)*)
    };
    (@entries $iface:ident $name:ident [$($out:tt)*] [$($fn_rest:tt)*] [$($idx:literal)?] #[until($hardfork:path)] $($attrs:tt)*) => {
        $crate::schedule!(@push with_dropped $iface $name [$($out)*] [$($fn_rest)*] $hardfork [$($idx)?]; $($attrs)*)
    };
    (@entries $iface:ident $name:ident [$($out:tt)*] [$($fn_rest:tt)*] [$($idx:literal)?] #[$attr:meta] $($attrs:tt)*) => {
        $crate::schedule!(@entries $iface $name [$($out)*] [$($fn_rest)*] [$($idx)?] $($attrs)*)
    };

    // Push one added/dropped selector, using `_i` for annotated overloads.
    (@push $method:ident $iface:ident $name:ident [$($out:tt)*] [$($fn_rest:tt)*] $hardfork:path [$($idx:literal)?]; $($attrs:tt)*) => {
        paste::paste! {
            $crate::schedule!(@entries $iface $name [$($out)* $crate::SelectorSchedule::new($hardfork).$method(&[$iface::[<$name $(_ $idx)? Call>]::SELECTOR]),] [$($fn_rest)*] $($attrs)*)
        }
    };
}
