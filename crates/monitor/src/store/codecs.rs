//! Codec strategy for durable monitor rows.
//!
//! The concrete MDBX codecs stay out of the store trait, but the durable
//! format must be deterministic and versioned. Foundational tables
//! should encode monitor-owned row types with an explicit codec version from
//! [`TableMetadata`](super::TableMetadata); schema changes must bump either the
//! table schema version or the row codec version. Reth table codecs may be used
//! as backend plumbing, but foundational row payloads must remain monitor-owned
//! types rather than Reth table rows.
