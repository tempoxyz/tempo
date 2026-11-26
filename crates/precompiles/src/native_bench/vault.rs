//! Native version of the public-mix Earn vault's deposit and redeem.

use super::NativeFrame;
use crate::error::{Result, TempoPrecompileError};
use alloy::primitives::{Address, Bytes, address};

/// The UserVault proxy every public-mix vault template calls.
pub const USER_VAULT: Address = address!("0x7ab1b8f13760b57021ad9baff0be170259245992");

/// deposit(uint256,address,uint256)
pub const DEPOSIT_SELECTOR: [u8; 4] = [0xbc, 0x15, 0x7a, 0xc1];
/// redeem(uint256,address,uint256)
pub const REDEEM_SELECTOR: [u8; 4] = [0xd8, 0x78, 0x01, 0x61];

pub const DEPOSIT_EXTRA_GAS: u64 = 0;
pub const REDEEM_EXTRA_GAS: u64 = 0;

pub(super) fn select(destination: Address, selector: [u8; 4]) -> Option<super::Entry> {
    if destination != USER_VAULT {
        return None;
    }
    match selector {
        DEPOSIT_SELECTOR => Some(super::Entry::VaultDeposit),
        REDEEM_SELECTOR => Some(super::Entry::VaultRedeem),
        _ => None,
    }
}

pub(super) fn deposit(_frame: &NativeFrame<'_>) -> Result<Bytes> {
    Err(TempoPrecompileError::Fatal(
        "native vault deposit not implemented".into(),
    ))
}

pub(super) fn redeem(_frame: &NativeFrame<'_>) -> Result<Bytes> {
    Err(TempoPrecompileError::Fatal(
        "native vault redeem not implemented".into(),
    ))
}
