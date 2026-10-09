//! Portal storage-layout conformance tests.

use alloy_primitives::U256;
use tempo_precompiles::zone_factory::portal;

/// Pins the Rust portal storage-slot constants to the ZonePortal storage layout.
#[test]
fn zone_portal_storage_slot_constants_match_solidity() {
    assert_eq!(portal::slots::ADMIN, U256::ZERO, "admin is slot 0");
    assert_eq!(
        portal::slots::CURRENT_DEPOSIT_QUEUE_HASH,
        U256::from(3),
        "currentDepositQueueHash is slot 3"
    );
    assert_eq!(
        portal::slots::ENCRYPTION_KEYS,
        U256::from(5),
        "_encryptionKeys is slot 5"
    );
    assert_eq!(portal::slots::ROLE, U256::from(20), "role is slot 20");
    assert_eq!(
        portal::slots::MAX_TEMPO_GAS_RATE,
        U256::from(22),
        "maxTempoGasRate is slot 22"
    );
    assert_eq!(
        portal::slots::TOKEN_ENABLEMENT_HASH,
        U256::from(26),
        "tokenEnablementHash is slot 26"
    );
}
