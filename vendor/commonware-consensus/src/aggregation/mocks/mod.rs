//! Mock implementations for testing.

mod application;
pub use application::{Application, Strategy};
mod monitor;
pub use monitor::Monitor;
mod reporter;
pub use reporter::{Mailbox as ReporterMailbox, Reporter};
mod provider;
pub use provider::Provider;
pub mod scheme;
