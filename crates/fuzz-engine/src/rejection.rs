//! Why an input, or part of it, did not execute.

use std::fmt::{self, Debug, Display};

use tempo_chainspec::hardfork::TempoHardfork;
use tempo_fuzz_types::{ErrorClass, HarnessInputKind};

/// The [`ErrorClass`] an input stopped short with, and which check stopped it, such as the
/// validation error of the transaction that failed its block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rejection {
    class: ErrorClass,
    reason: String,
}

impl Rejection {
    /// A rejection of class `class` because of `why`. Its reason reads `kind: message`, the kind
    /// being `class` then the enum variants `why`'s Debug form starts with, such as
    /// `Rejected/CollectFeePreTx/InsufficientFeeTokenBalance`.
    pub fn new(class: ErrorClass, why: impl Debug + Display) -> Self {
        let debug = format!("{why:?}");
        let mut kind = format!("{class:?}");
        let mut rest = debug.as_str();
        while rest.starts_with(|c: char| c.is_ascii_uppercase()) {
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            kind.push('/');
            kind.push_str(&rest[..end]);
            let Some(inner) = rest[end..].strip_prefix('(') else {
                break;
            };
            rest = inner;
        }
        Self {
            class,
            reason: format!("{kind}: {why}"),
        }
    }

    /// The class the outcome reports.
    pub const fn class(&self) -> ErrorClass {
        self.class
    }

    /// The reason, as [`Self::new`] describes it.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// A harness check that rejects an input with no error value of its own.
#[derive(Debug)]
pub(crate) enum Check {
    Null,
    HarnessInput,
    OutcomeEncoding,
    UnsupportedInput { kind: HarnessInputKind },
    HardforkSchedule,
    UnsupportedHardfork { hardfork: TempoHardfork },
    TimestampOrder,
    PreState,
    PreStateInvariants,
    Header,
    SenderCount,
    IncompletePreState,
    AnchoredChain,
}

impl Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null input"),
            Self::AnchoredChain => {
                f.write_str("an anchored chain needs a genesis pre-state and context headers")
            }
            Self::HarnessInput => f.write_str("harness input does not decode"),
            Self::OutcomeEncoding => f.write_str("outcome does not encode"),
            Self::UnsupportedInput { kind } => write!(f, "{kind:?} inputs are not supported"),
            Self::HardforkSchedule => f.write_str("hardfork schedule out of order"),
            Self::UnsupportedHardfork { hardfork } => {
                write!(f, "a block executes at unsupported hardfork {hardfork:?}")
            }
            Self::TimestampOrder => f.write_str("blocks out of timestamp order"),
            Self::PreState => f.write_str("pre-state does not load"),
            Self::PreStateInvariants => f.write_str("pre-state breaks invariants"),
            Self::Header => f.write_str("header does not resolve"),
            Self::SenderCount => f.write_str("sender count differs from the transaction count"),
            Self::IncompletePreState => f.write_str("pre-state could not answer a read"),
        }
    }
}
