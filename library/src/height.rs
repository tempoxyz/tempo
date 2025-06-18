use core::fmt;
use serde::{Deserialize, Serialize};
use malachitebft_core_types::Height as MalachiteHeight;

/// A blockchain height
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Height(u64);

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

impl Height {
    pub const fn new(height: u64) -> Self {
        Self(height)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
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
