//! Shared account-scoped read authorization for Zone precompiles.

use alloy_primitives::Address;
use alloy_sol_types::SolError;
use tempo_contracts::zones::Unauthorized;
use tempo_precompiles::storage::StorageCtx;

use crate::{execution::CallCheck, zone_identity::ZoneIdentity};

/// Allows a read by an account the getter names or, from T15, one that may read the first.
pub(crate) fn check_caller(caller: Address, accounts: &[Address]) -> CallCheck {
    if accounts.contains(&caller) {
        return CallCheck::Continue;
    }
    if StorageCtx::default().spec().is_t15()
        && let Some(&subject) = accounts.first()
    {
        match ZoneIdentity::new().can_read(caller, subject) {
            Ok(true) => return CallCheck::Continue,
            Ok(false) => {}
            Err(error) => return CallCheck::Error(error),
        }
    }
    CallCheck::Revert(Unauthorized {}.abi_encode().into())
}
