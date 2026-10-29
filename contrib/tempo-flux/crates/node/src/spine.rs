use flux::{communication::ShmemData, spine::SpineQueue, tile::TileInfo};
use spine_derive::from_spine;
use tempo_flux_primitives::{
    Block, BuildRequest, Executed, Finalized, Persisted, RawTx, StateDiff, ValidTx,
};

/// Every queue in the node. Dataflow:
///
/// ingress -> RawTx -> txpool -> ValidTx -> builder
/// consensus -> BuildRequest -> builder -> Block -> executor, storage
/// executor -> StateDiff -> merkle -> Executed -> consensus -> Finalized -> builder, storage
/// storage -> Persisted -> consensus
#[from_spine("tempo-flux")]
#[derive(Debug)]
pub struct NodeSpine {
    pub tile_info: ShmemData<TileInfo>,
    #[queue(size(2usize.pow(20)), mtu(2usize.pow(12)))]
    pub raw_tx: SpineQueue<RawTx>,
    #[queue(size(2usize.pow(20)), mtu(2usize.pow(12)))]
    pub valid_tx: SpineQueue<ValidTx>,
    #[queue(size(2usize.pow(10)))]
    pub build_request: SpineQueue<BuildRequest>,
    #[queue(size(2usize.pow(10)), mtu(2usize.pow(25)))]
    pub block: SpineQueue<Block>,
    #[queue(size(2usize.pow(10)), mtu(2usize.pow(26)))]
    pub state_diff: SpineQueue<StateDiff>,
    #[queue(size(2usize.pow(10)))]
    pub executed: SpineQueue<Executed>,
    #[queue(size(2usize.pow(10)))]
    pub finalized: SpineQueue<Finalized>,
    #[queue(size(2usize.pow(10)))]
    pub persisted: SpineQueue<Persisted>,
}
