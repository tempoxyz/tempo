//! Tempo chainspec implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod spec;
pub use spec::{PAYMENT_CLASSIFIER_ID, TIP20_PAYMENT_PREFIX, TempoChainSpec};
