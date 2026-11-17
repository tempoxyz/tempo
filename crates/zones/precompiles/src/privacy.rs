//! Shared account-scoped read authorization for Zone precompiles.

use alloy_primitives::Address;
use alloy_sol_types::SolError;
use tempo_contracts::zones::Unauthorized;
use tempo_precompiles::storage::StorageCtx;

use crate::{ZonePrecompileError, execution::CallCheck, zone_identity::ZoneIdentity};

/// Allow a read only when the immediate EVM caller owns an account named by the getter, or, from
/// T15, may read one of them through `ZoneIdentity` as its org's admin or a reader.
pub(crate) fn check_caller(caller: Address, accounts: &[Address]) -> CallCheck {
    if accounts.contains(&caller) {
        return CallCheck::Continue;
    }
    if StorageCtx::default().spec().is_t15() {
        let identity = ZoneIdentity::new();
        for &account in accounts {
            match identity.can_read(caller, account) {
                Ok(true) => return CallCheck::Continue,
                Ok(false) => {}
                Err(ZonePrecompileError::Tempo(error)) => return CallCheck::Error(error),
                Err(error) => {
                    return CallCheck::Error(
                        tempo_precompiles::error::TempoPrecompileError::Fatal(error.to_string()),
                    );
                }
            }
        }
    }
    CallCheck::Revert(Unauthorized {}.abi_encode().into())
}
