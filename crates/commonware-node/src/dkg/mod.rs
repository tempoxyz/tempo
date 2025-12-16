use commonware_codec::{EncodeSize, Read, Write};

pub mod ceremony;
pub mod manager;

#[derive(Debug, Clone, Copy)]
pub enum HardforkRegime {
    PreAllegretto,
    PostAllegretto,
}

/// Trait for epoch state types that are associated with a specific hardfork regime.
pub trait RegimeEpochState:
    Read<Cfg = ()> + Write + EncodeSize + Clone + Send + Sync + 'static
{
    const REGIME: HardforkRegime;
}
