//! Historical execution corpus for Tempo: capture a finite archive range once into an
//! object store, then replay it without the source database.

pub mod code;
pub mod store;
pub mod types;
