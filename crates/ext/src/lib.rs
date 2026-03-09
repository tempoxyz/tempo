//! Extension dispatch and management for the Tempo CLI.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod installer;
mod launcher;
mod state;

pub use launcher::Launcher;
