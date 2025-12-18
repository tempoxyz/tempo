use commonware_codec::{EncodeSize, Read, Write};

mod ceremony;
pub(crate) mod manager;

#[derive(Debug, Clone, Copy)]
enum HardforkRegime {
    PreAllegretto,
    PostAllegretto,
}

/// Trait for epoch state types that are associated with a specific hardfork regime.
trait RegimeEpochState: Read<Cfg = ()> + Write + EncodeSize + Clone + Send + Sync + 'static {
    const REGIME: HardforkRegime;
}
