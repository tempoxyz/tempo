use alloy::primitives::{Address, B256};
use tempo_precompiles::stablecoin_dex::StablecoinDEX;

pub(crate) struct InvariantContext<'a> {
    pub(crate) exchange: &'a StablecoinDEX,
    pub(crate) created_order_ids: &'a [u128],
    pub(crate) users: &'a [Address],
    pub(crate) base_token: Address,
    pub(crate) quote_token: Address,
    pub(crate) book_key: B256,
    pub(crate) control_book_key: B256,
    pub(crate) swap_count: u64,
}
