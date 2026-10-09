//! Native TIP-1091 ZoneFactory bindings shared with Tempo.

pub use crate::precompiles::zone_factory::{
    IZoneFactory, MAX_SEQUENCERS, ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS,
    ZONE_PORTAL_IMPL_ADDRESS, ZONE_PORTAL_PREFIX, ZONE_VERIFIER_ADDRESS, ZoneInfo,
};

/// Compatibility path for existing ZoneFactory clients.
#[allow(non_snake_case)]
pub mod ZoneFactory {
    #[cfg(feature = "rpc")]
    pub use crate::precompiles::zone_factory::IZoneFactory::IZoneFactoryInstance as ZoneFactoryInstance;
    pub use crate::precompiles::zone_factory::{
        IZoneFactory::{
            IZoneFactoryCalls as ZoneFactoryCalls, IZoneFactoryErrors as ZoneFactoryErrors,
            IZoneFactoryEvents as ZoneFactoryEvents, *,
        },
        ZoneInfo,
    };
}
