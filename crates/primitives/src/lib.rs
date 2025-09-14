#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

// reth-ethereum-primitives is used for serde-bincode-compat and arbitrary features
#[cfg(all(
    any(feature = "serde-bincode-compat", feature = "arbitrary"),
    not(test)
))]
use reth_ethereum_primitives as _;

pub mod transaction;

pub use transaction::{FEE_TOKEN_TX_TYPE_ID, TempoTxEnvelope, TempoTxType, TxFeeToken};
