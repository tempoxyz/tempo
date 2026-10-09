//! Both crate names expose the same types, so callers never need ABI conversions.

use std::any::TypeId;
use tempo_contracts::precompiles::{IZoneFactory, IZoneVerifier};
use tempo_zone_contracts::{
    BlockTransition, DepositQueueTransition, TokenEnablementTransition, ZoneFactory,
};

#[test]
fn compatibility_exports_share_native_binding_types() {
    assert_eq!(
        TypeId::of::<ZoneFactory::CreateZoneParams>(),
        TypeId::of::<IZoneFactory::CreateZoneParams>()
    );
    assert_eq!(
        TypeId::of::<ZoneFactory::ZoneInfo>(),
        TypeId::of::<tempo_contracts::precompiles::ZoneInfo>()
    );
    assert_eq!(
        TypeId::of::<BlockTransition>(),
        TypeId::of::<IZoneVerifier::BlockTransition>()
    );
    assert_eq!(
        TypeId::of::<DepositQueueTransition>(),
        TypeId::of::<IZoneVerifier::DepositQueueTransition>()
    );
    assert_eq!(
        TypeId::of::<TokenEnablementTransition>(),
        TypeId::of::<IZoneVerifier::TokenEnablementTransition>()
    );
}
