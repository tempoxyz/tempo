//! Native version of the public-mix zone portal deposit and the settlement fixture's settle.

use super::NativeFrame;
use crate::error::{Result, TempoPrecompileError};
use alloy::primitives::Bytes;

pub const DEPOSIT_EXTRA_GAS: u64 = 0;
pub const SETTLE_EXTRA_GAS: u64 = 0;

pub(super) fn select(_selector: [u8; 4], _code: &[u8]) -> Option<super::Entry> {
    None
}

pub(super) fn deposit(_frame: &NativeFrame<'_>) -> Result<Bytes> {
    Err(TempoPrecompileError::Fatal(
        "native portal deposit not implemented".into(),
    ))
}

pub(super) fn settle(_frame: &NativeFrame<'_>) -> Result<Bytes> {
    Err(TempoPrecompileError::Fatal(
        "native settle not implemented".into(),
    ))
}
