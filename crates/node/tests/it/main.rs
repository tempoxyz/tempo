#![allow(clippy::cast_lossless)]

mod backfill;
mod base_fee;
mod block_building;
mod createx;
mod eth_call;
mod eth_transactions;
mod fork_schedule;
mod gas;
mod key_authorization;
mod liquidity;
mod max_gas_limit;
mod operator;
mod payment_lane;
mod pool;
mod simulate;
mod stablecoin_dex;
mod stablecoin_dex_gas;
mod tempo_transaction;
mod tip20;
mod tip20_factory;
mod tip20_gas_fees;
mod tip_fee_amm;
mod tip_fee_manager;
mod utils;

use tempo_node as _;

fn main() {}
