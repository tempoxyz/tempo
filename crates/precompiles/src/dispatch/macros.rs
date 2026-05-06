//! Declarative `dispatch!` macro for precompile ABI dispatch. Co-located with
//! [`crate::dispatch_call`].
//!
//! # Syntax
//!
//! ```ignore
//! // Single-interface (decoder is `InterfaceCalls::abi_decode`):
//! dispatch!(calldata => {
//!     Interface::variant(args) => body,
//!     #[since = HF] Interface::variant(args) => body,
//!     #[since = HF, selector = <override>] Interface::variant(args) => body,
//!     ...
//! })
//!
//! // Multi-interface, dispatched through a wrapper enum (decoder is `Outer::abi_decode`):
//! dispatch!(@call = Outer, calldata => {
//!     Interface::variant(args) => body,
//!     ...
//! })
//! ```
//!
//! `calldata` is the user's `&[u8]` binding. It must be passed explicitly because
//! `macro_rules!` cannot resolve free identifiers at the call site.
//!
//! `Interface` is the bare ABI interface module (e.g. `IValidatorConfig`, `ITIP20`); the macro
//! appends `Calls` automatically. Trailing commas after every arm body are required.
//!
//! In `@call` mode, each arm `Interface::variant(args)` is rewritten to
//! `Outer::Interface(InterfaceCalls::variant(args))`, so the outer enum's variants must be named
//! exactly after their inner interface:
//! ```rs
//! enum TIP20Call {
//!    ITIP20(ITIP20Calls),
//!    IRolesAuth(IRolesAuthCalls)
//! }
//! ```
//!
//! # Hardfork-gated selectors
//!
//! Arms accept `[since, until)` attributes describing a selector's validity window:
//!
//! - `#[since = HF]` rejects the arm's selector before `HF` activates.
//! - `#[until = HF]` rejects it once `HF` activates.
//!
//! `HF` is a bare ident on `tempo_chainspec::hardfork::TempoHardfork` (e.g. `T2`). The
//! selector is inferred by appending `Call` to the variant ident
//! (`Interface::variant` → `Interface::variantCall::SELECTOR`); override with `selector = <expr>`
//! when the call type doesn't follow that convention:
//!
//! ```ignore
//! #[since = T3, selector = authorizeKeyCall::SELECTOR]
//! IAccountKeychain::authorizeKey_1(call) => ...,
//! ```
//!
//! Gated selectors are rejected by `dispatch_call` before the body runs, so they behave
//! identically to nonexistent selectors at runtime.

/// See module docs.
#[macro_export]
macro_rules! dispatch {
    () => { ::core::compile_error!("dispatch! requires at least one arm") };

    // Single-interface entry. Decoder is `<first arm's Interface>Calls::abi_decode`; we peek
    // at the first arm to extract `Interface` without consuming it.
    ($cd:ident => { $( #[ $($_m0:tt)* ] )* $iface:ident :: $($rest:tt)+ }) => {
        $crate::__dispatch_arms! {
            [calldata: $cd] [decoder: [< $iface Calls >] ::] [outer: ]
            [schedules: ] [arms: ]
            $iface :: $($rest)+
        }
    };

    // Multi-interface entry: outer enum is implicit. Each arm's `Interface::variant(..)` is
    // rewritten to `Outer::Interface(InterfaceCalls::variant(..))`; decoder is `Outer::abi_decode`.
    (@call = $outer:ident, $cd:ident => { $($input:tt)+ }) => {
        $crate::__dispatch_arms! {
            [calldata: $cd] [decoder: $outer ::] [outer: $outer]
            [schedules: ] [arms: ]
            $($input)+
        }
    };
}

// Arm dispatcher.
// Each step consumes one arm, appends to `[schedules: ...]` and `[arms: ...]`, then
// recurses; the terminal emits `dispatch_call(...)`. Gated arms detour through
// `__dispatch_meta_kv!`, which forwards (calldata, decoder, outer) opaquely as
// `[ctx: ...]` so its kv rules don't repeat them on each step.
// `Calls` is injected via `paste!` markers (`[< I Calls >]`).
#[macro_export]
#[doc(hidden)]
macro_rules! __dispatch_arms {
    // Emit the dispatch_call invocation. `paste!` wraps each component on its own so $cd keeps its
    // call-site binding.
    (
        [calldata: $cd:ident] [decoder: $($decoder:tt)*] [outer: $($_outer:tt)*]
        [schedules: $($schedules:tt)*] [arms: $($arms:tt)*]
    ) => {
        $crate::dispatch_call(
            $cd,
            &[$($schedules)*],
            ::paste::paste! { $($decoder)* abi_decode },
            |call| ::paste::paste! { match call { $($arms)* } },
        )
    };

    // @call mode, gated.
    (
        [calldata: $cd:ident] [decoder: $($d:tt)*] [outer: $outer:ident]
        [schedules: $($s:tt)*] [arms: $($a:tt)*]
        $( #[ $($meta:tt)* ] )+
        $iface:ident :: $variant:ident ( $($args:tt)* ) => $body:expr ,
        $($rest:tt)*
    ) => {
        $crate::__dispatch_meta_kv! {
            [since: ] [until: ] [selector: ]
            [ctx: [calldata: $cd] [decoder: $($d)*] [outer: $outer]]
            [schedules: $($s)*]
            [arms: $($a)*
                $outer :: $iface ( [< $iface Calls >] :: $variant ( $($args)* ) ) => $body, ]
            [default_selector: $iface :: [< $variant Call >] :: SELECTOR]
            [rest: $($rest)*]
            $( $($meta)* ),+
        }
    };

    // @call mode, plain.
    (
        [calldata: $cd:ident] [decoder: $($d:tt)*] [outer: $outer:ident]
        [schedules: $($s:tt)*] [arms: $($a:tt)*]
        $iface:ident :: $variant:ident ( $($args:tt)* ) => $body:expr ,
        $($rest:tt)*
    ) => {
        $crate::__dispatch_arms! {
            [calldata: $cd] [decoder: $($d)*] [outer: $outer]
            [schedules: $($s)*]
            [arms: $($a)*
                $outer :: $iface ( [< $iface Calls >] :: $variant ( $($args)* ) ) => $body, ]
            $($rest)*
        }
    };

    // Single-interface mode, gated.
    (
        [calldata: $cd:ident] [decoder: $($d:tt)*] [outer: ]
        [schedules: $($s:tt)*] [arms: $($a:tt)*]
        $( #[ $($meta:tt)* ] )+
        $iface:ident :: $variant:ident ( $($args:tt)* ) => $body:expr ,
        $($rest:tt)*
    ) => {
        $crate::__dispatch_meta_kv! {
            [since: ] [until: ] [selector: ]
            [ctx: [calldata: $cd] [decoder: $($d)*] [outer: ]]
            [schedules: $($s)*]
            [arms: $($a)*
                [< $iface Calls >] :: $variant ( $($args)* ) => $body, ]
            [default_selector: $iface :: [< $variant Call >] :: SELECTOR]
            [rest: $($rest)*]
            $( $($meta)* ),+
        }
    };

    // Single-interface mode, plain.
    (
        [calldata: $cd:ident] [decoder: $($d:tt)*] [outer: ]
        [schedules: $($s:tt)*] [arms: $($a:tt)*]
        $iface:ident :: $variant:ident ( $($args:tt)* ) => $body:expr ,
        $($rest:tt)*
    ) => {
        $crate::__dispatch_arms! {
            [calldata: $cd] [decoder: $($d)*] [outer: ]
            [schedules: $($s)*]
            [arms: $($a)*
                [< $iface Calls >] :: $variant ( $($args)* ) => $body, ]
            $($rest)*
        }
    };
}

// Metadata processor.
// Walks a flat `key = value,` stream that the arm dispatcher already flattened from attrib groups.
// Recognized keys: `since` (ident), `until` (ident), `selector` (expr).
#[macro_export]
#[doc(hidden)]
macro_rules! __dispatch_meta_kv {
    // Stream exhausted. Pick override-vs-default selector, then resume with the new schedule.
    (
        [since: $($since:ident)?] [until: $($until:ident)?] [selector: $($override:tt)*]
        [ctx: $($ctx:tt)*]
        [schedules: $($s:tt)*] [arms: $($a:tt)*]
        [default_selector: $($ds:tt)*]
        [rest: $($r:tt)*]
    ) => {
        $crate::__dispatch_arms! {
            $($ctx)*
            [schedules: $($s)*
                $crate::__dispatch_emit_schedules!(
                    [$($since)?] [$($until)?]
                    $crate::__dispatch_pick_selector!([$($override)*] $($ds)*)
                ),
            ]
            [arms: $($a)*]
            $($r)*
        }
    };

    // since = HF
    (
        [since: ] [until: $($until:tt)*] [selector: $($sel:tt)*]
        [ctx: $($ctx:tt)*] [schedules: $($s:tt)*] [arms: $($a:tt)*]
        [default_selector: $($ds:tt)*] [rest: $($r:tt)*]
        since = $hf:ident $(, $($kv:tt)*)?
    ) => {
        $crate::__dispatch_meta_kv! {
            [since: $hf] [until: $($until)*] [selector: $($sel)*]
            [ctx: $($ctx)*] [schedules: $($s)*] [arms: $($a)*]
            [default_selector: $($ds)*] [rest: $($r)*]
            $($($kv)*)?
        }
    };

    // until = HF
    (
        [since: $($since:tt)*] [until: ] [selector: $($sel:tt)*]
        [ctx: $($ctx:tt)*] [schedules: $($s:tt)*] [arms: $($a:tt)*]
        [default_selector: $($ds:tt)*] [rest: $($r:tt)*]
        until = $hf:ident $(, $($kv:tt)*)?
    ) => {
        $crate::__dispatch_meta_kv! {
            [since: $($since)*] [until: $hf] [selector: $($sel)*]
            [ctx: $($ctx)*] [schedules: $($s)*] [arms: $($a)*]
            [default_selector: $($ds)*] [rest: $($r)*]
            $($($kv)*)?
        }
    };

    // selector = <expr>.
    (
        [since: $($since:tt)*] [until: $($until:tt)*] [selector: ]
        [ctx: $($ctx:tt)*] [schedules: $($s:tt)*] [arms: $($a:tt)*]
        [default_selector: $($ds:tt)*] [rest: $($r:tt)*]
        selector = $sel:expr $(, $($kv:tt)*)?
    ) => {
        $crate::__dispatch_meta_kv! {
            [since: $($since)*] [until: $($until)*] [selector: ($sel)]
            [ctx: $($ctx)*] [schedules: $($s)*] [arms: $($a)*]
            [default_selector: $($ds)*] [rest: $($r)*]
            $($($kv)*)?
        }
    };
}

// Returns the override expression when called as `[($expr)]` and the default-selector when called as `[]`.
#[macro_export]
#[doc(hidden)]
macro_rules! __dispatch_pick_selector {
    ([] $($ds:tt)*) => { $($ds)* };
    ([($($sel:tt)*)] $($_ds:tt)*) => { $($sel)* };
}

// Emits the (since-bound, until-bound) schedule pair for one gated arm.
// Each rule wraps its body in `paste!` because selectors may carry `[< $variant Call >]` markers.
#[macro_export]
#[doc(hidden)]
macro_rules! __dispatch_emit_schedules {
    ([] [] $($_sel:tt)*) => {
        ::core::compile_error!(
            "dispatch! arm has attributes but neither `since` nor `until`; \
             only `since`/`until`/`selector` are recognized"
        )
    };
    ([$sh:ident] [] $($sel:tt)*) => {
        ::paste::paste! {
            $crate::SelectorSchedule::new(::tempo_chainspec::hardfork::TempoHardfork::$sh)
                .with_added(&[$($sel)*])
        }
    };
    ([] [$uh:ident] $($sel:tt)*) => {
        ::paste::paste! {
            $crate::SelectorSchedule::new(::tempo_chainspec::hardfork::TempoHardfork::$uh)
                .with_dropped(&[$($sel)*])
        }
    };
    ([$sh:ident] [$uh:ident] $($sel:tt)*) => {
        ::paste::paste! {
            $crate::SelectorSchedule::new(::tempo_chainspec::hardfork::TempoHardfork::$sh)
                .with_added(&[$($sel)*])
        },
        ::paste::paste! {
            $crate::SelectorSchedule::new(::tempo_chainspec::hardfork::TempoHardfork::$uh)
                .with_dropped(&[$($sel)*])
        }
    };
}
