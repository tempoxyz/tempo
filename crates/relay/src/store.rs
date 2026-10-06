//! Atomic expiring storage shared by configuration, approval and submission records.

use crate::RpcError;
use async_trait::async_trait;
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

/// Returns Unix milliseconds, the timestamp representation used by viem.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// Storage with atomic compare-and-set across all instances sharing the database.
#[async_trait]
pub trait Store: Send + Sync {
    /// Reads an unexpired value.
    async fn get(&self, key: &str) -> Result<Option<String>, RpcError>;
    /// Writes only if the unexpired current value equals `expected`.
    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&str>,
        value: Option<&str>,
        expires_at: Option<u64>,
    ) -> Result<bool, RpcError>;
}

/// Ephemeral atomic store for tests and explicitly ephemeral embedded relays.
#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, (String, Option<u64>)>>);

#[async_trait]
impl Store for MemoryStore {
    async fn get(&self, key: &str) -> Result<Option<String>, RpcError> {
        let mut values = self.0.lock().await;
        if values
            .get(key)
            .is_some_and(|(_, expiration)| expiration.is_some_and(|expiration| expiration <= now()))
        {
            values.remove(key);
        }
        Ok(values.get(key).map(|(value, _)| value.clone()))
    }

    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&str>,
        value: Option<&str>,
        expires_at: Option<u64>,
    ) -> Result<bool, RpcError> {
        let mut values = self.0.lock().await;
        if values
            .get(key)
            .is_some_and(|(_, expiration)| expiration.is_some_and(|expiration| expiration <= now()))
        {
            values.remove(key);
        }
        if values.get(key).map(|(value, _)| value.as_str()) != expected {
            return Ok(false);
        }
        if let Some(value) = value {
            values.insert(key.into(), (value.into(), expires_at));
        } else {
            values.remove(key);
        }
        Ok(true)
    }
}

/// SQLite and Postgres adapters using database transactions, never process-local locks.
#[cfg(feature = "storage")]
pub mod sql {
    use super::*;
    use sqlx::{PgPool, Row, SqlitePool};

    /// SQLite WAL-backed store. Clones and separate relay processes share CAS semantics.
    pub struct SqliteStore(SqlitePool);

    impl SqliteStore {
        /// Opens or creates a SQLite database.
        pub async fn connect(url: &str) -> Result<Self, RpcError> {
            let options = url
                .parse::<sqlx::sqlite::SqliteConnectOptions>()
                .map_err(error)?
                .create_if_missing(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .busy_timeout(std::time::Duration::from_secs(5));
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(8)
                .connect_with(options)
                .await
                .map_err(error)?;
            sqlx::query("CREATE TABLE IF NOT EXISTS tempo_relay_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at BIGINT)").execute(&pool).await.map_err(error)?;
            Ok(Self(pool))
        }
    }

    #[async_trait]
    impl Store for SqliteStore {
        async fn get(&self, key: &str) -> Result<Option<String>, RpcError> {
            sqlx::query_scalar("SELECT value FROM tempo_relay_kv WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)")
                .bind(key).bind(now() as i64).fetch_optional(&self.0).await.map_err(error)
        }

        async fn compare_and_set(
            &self,
            key: &str,
            expected: Option<&str>,
            value: Option<&str>,
            expires_at: Option<u64>,
        ) -> Result<bool, RpcError> {
            // BEGIN IMMEDIATE obtains the writer lock before reading, including absent rows.
            let mut tx = self.0.begin_with("BEGIN IMMEDIATE").await.map_err(error)?;
            sqlx::query("DELETE FROM tempo_relay_kv WHERE key = ? AND expires_at <= ?")
                .bind(key)
                .bind(now() as i64)
                .execute(&mut *tx)
                .await
                .map_err(error)?;
            let current: Option<String> =
                sqlx::query_scalar("SELECT value FROM tempo_relay_kv WHERE key = ?")
                    .bind(key)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(error)?;
            if current.as_deref() != expected {
                tx.rollback().await.map_err(error)?;
                return Ok(false);
            }
            if let Some(value) = value {
                sqlx::query("INSERT INTO tempo_relay_kv (key, value, expires_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at")
                    .bind(key).bind(value).bind(expires_at.map(|v| v.min(i64::MAX as u64) as i64)).execute(&mut *tx).await.map_err(error)?;
            } else {
                sqlx::query("DELETE FROM tempo_relay_kv WHERE key = ?")
                    .bind(key)
                    .execute(&mut *tx)
                    .await
                    .map_err(error)?;
            }
            tx.commit().await.map_err(error)?;
            Ok(true)
        }
    }

    /// Postgres-backed shared store, using transaction-scoped per-key advisory locks.
    pub struct PostgresStore(PgPool);

    impl PostgresStore {
        /// Connects and creates the isolated relay key-value table if needed.
        pub async fn connect(url: &str) -> Result<Self, RpcError> {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .connect(url)
                .await
                .map_err(error)?;
            sqlx::query("CREATE TABLE IF NOT EXISTS tempo_relay_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at BIGINT)").execute(&pool).await.map_err(error)?;
            Ok(Self(pool))
        }
    }

    #[async_trait]
    impl Store for PostgresStore {
        async fn get(&self, key: &str) -> Result<Option<String>, RpcError> {
            sqlx::query_scalar("SELECT value FROM tempo_relay_kv WHERE key = $1 AND (expires_at IS NULL OR expires_at > $2)")
                .bind(key).bind(now() as i64).fetch_optional(&self.0).await.map_err(error)
        }

        async fn compare_and_set(
            &self,
            key: &str,
            expected: Option<&str>,
            value: Option<&str>,
            expires_at: Option<u64>,
        ) -> Result<bool, RpcError> {
            let mut tx = self.0.begin().await.map_err(error)?;
            // A row lock alone cannot serialize two writers that both observe an absent key.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(key)
                .execute(&mut *tx)
                .await
                .map_err(error)?;
            sqlx::query("DELETE FROM tempo_relay_kv WHERE key = $1 AND expires_at <= $2")
                .bind(key)
                .bind(now() as i64)
                .execute(&mut *tx)
                .await
                .map_err(error)?;
            let current = sqlx::query("SELECT value FROM tempo_relay_kv WHERE key = $1 FOR UPDATE")
                .bind(key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(error)?;
            let current = current.map(|row| row.get::<String, _>(0));
            if current.as_deref() != expected {
                tx.rollback().await.map_err(error)?;
                return Ok(false);
            }
            if let Some(value) = value {
                sqlx::query("INSERT INTO tempo_relay_kv (key, value, expires_at) VALUES ($1, $2, $3) ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at")
                    .bind(key).bind(value).bind(expires_at.map(|v| v.min(i64::MAX as u64) as i64)).execute(&mut *tx).await.map_err(error)?;
            } else {
                sqlx::query("DELETE FROM tempo_relay_kv WHERE key = $1")
                    .bind(key)
                    .execute(&mut *tx)
                    .await
                    .map_err(error)?;
            }
            tx.commit().await.map_err(error)?;
            Ok(true)
        }
    }

    fn error(error: impl std::fmt::Display) -> RpcError {
        RpcError::new(-32603, format!("Relay storage error: {error}"))
    }
}
