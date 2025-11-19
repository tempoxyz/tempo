//! WeakDatabase implementation for test-utils feature.
//!
//! This module provides a database wrapper that uses Weak references instead of Arc,
//! allowing tests to force panic/shutdown node threads.

use reth_db::{Database, DatabaseError, database_metrics::DatabaseMetrics, mdbx::DatabaseEnv};
use reth_metrics::metrics::Label;
use std::sync::Weak;

/// Wrapper type over Weak<DatabaseEnv> that implements [`Database`] and [`DatabaseMetrics`].
///
/// This type is used by TempoFullNode when the test-utils feature is enabled.
#[derive(Clone, Debug)]
pub struct WeakDatabase(pub Weak<DatabaseEnv>);

impl Database for WeakDatabase {
    type TX = <DatabaseEnv as Database>::TX;
    type TXMut = <DatabaseEnv as Database>::TXMut;

    fn tx(&self) -> Result<Self::TX, DatabaseError> {
        let arc = self.0.upgrade().ok_or_else(|| {
            DatabaseError::Other("Database has been dropped (Weak reference is dead)".into())
        })?;
        arc.tx()
    }

    fn tx_mut(&self) -> Result<Self::TXMut, DatabaseError> {
        let arc = self.0.upgrade().ok_or_else(|| {
            DatabaseError::Other("Database has been dropped (Weak reference is dead)".into())
        })?;
        arc.tx_mut()
    }
}

impl DatabaseMetrics for WeakDatabase {
    fn report_metrics(&self) {
        if let Some(arc) = self.0.upgrade() {
            arc.report_metrics();
        }
    }

    fn gauge_metrics(&self) -> Vec<(&'static str, f64, Vec<Label>)> {
        self.0
            .upgrade()
            .map(|arc| arc.gauge_metrics())
            .unwrap_or_default()
    }

    fn counter_metrics(&self) -> Vec<(&'static str, u64, Vec<Label>)> {
        self.0
            .upgrade()
            .map(|arc| arc.counter_metrics())
            .unwrap_or_default()
    }

    fn histogram_metrics(&self) -> Vec<(&'static str, f64, Vec<Label>)> {
        self.0
            .upgrade()
            .map(|arc| arc.histogram_metrics())
            .unwrap_or_default()
    }
}
