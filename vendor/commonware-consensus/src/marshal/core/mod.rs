//! Unified marshal core implementation.
//!
//! # Overview
//!
//! This module provides the core marshal actor and mailbox that work with both
//! the [`crate::marshal::standard`] and [`crate::marshal::coding`] variants through
//! the [`Variant`] and [`Buffer`] trait abstractions.
//!
//! # Components
//!
//! - [`Actor`]: The main marshal actor that orders finalized blocks, manages caching,
//!   handles backfill requests, and reports blocks to the application.
//! - [`Mailbox`]: A clonable handle for interacting with the actor from other subsystems.
//! - [`Variant`]: A marker trait describing the types used by different marshal variants
//!   (block types, commitment types, etc.).
//! - [`Buffer`]: An abstraction over block dissemination strategies (whole blocks
//!   vs erasure-coded shards).
//!
//! # Usage
//!
//! The actor is initialized with storage archives and started with an optional buffer:
//!
//! ```rust,ignore
//! // Initialize with storage
//! let (actor, mailbox, last_height) = Actor::<S, Standard<B>>::init(
//!     context,
//!     finalizations_archive,
//!     blocks_archive,
//!     config,
//! ).await;
//! // `last_height` is `None` until the application acknowledges a block.
//!
//! // Start with application and buffer
//! actor.start(application, buffer, resolver);
//!
//! // Or omit broadcast buffering for follower-only chain tracking
//! actor.start_unbuffered(application, resolver);
//! ```
//!
//! For standard mode, use [`crate::marshal::standard::Standard`] as the variant and
//! [`commonware_broadcast::buffered::Mailbox`] as the buffer. For coding mode, use
//! [`crate::marshal::coding::Coding`] as the variant and
//! [`crate::marshal::coding::shards::Mailbox`] as the buffer.

mod actor;
pub use actor::Actor;

mod acks;
pub(crate) mod cache;
mod delivery;
pub(crate) mod durability;
mod floor;
mod stream;

mod mailbox;
pub use mailbox::{CommitmentFallback, DigestFallback, Mailbox};

mod subscriptions;
mod variant;
pub use variant::{Buffer, Variant};
