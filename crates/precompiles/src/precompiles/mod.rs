use alloy::primitives::Address;
use reth::revm::precompile::PrecompileResult;

mod dispatch;
pub mod tip20_factory_precompile;
pub mod tip20_precompile;
pub mod tip403_registry_precompile;

pub trait Precompile {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult;
}
