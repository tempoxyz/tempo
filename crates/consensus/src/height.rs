//! Blockchain height type for Malachite consensus.
//!
//! This module provides a height type that represents the current blockchain height
//! and implements the Malachite `Height` trait. Heights are zero-indexed internally
//! but the initial height for consensus is 1.

use core::fmt;
use malachitebft_core_types::Height as MalachiteHeight;
use serde::{Deserialize, Serialize};

/// A blockchain height
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Height(pub u64);

impl MalachiteHeight for Height {
    const ZERO: Self = Height(0);
    const INITIAL: Self = Height(1);

    fn as_u64(&self) -> u64 {
        self.0
    }

    fn increment(&self) -> Self {
        Self(self.0 + 1)
    }

    fn decrement(&self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    fn increment_by(&self, n: u64) -> Self {
        Self(self.0 + n)
    }

    fn decrement_by(&self, n: u64) -> Option<Self> {
        self.0.checked_sub(n).map(Self)
    }
}

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Height({})", self.0)
    }
}
