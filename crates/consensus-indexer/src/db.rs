use eyre::WrapErr;
use std::str::FromStr;

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use tempo_node::rpc::consensus::{
    CertifiedBlock, ConsensusState, IdentityTransition, IdentityTransitionResponse, Query,
    TransitionProofData,
};

#[derive(Clone, Debug)]
pub struct ConsensusDb {
    pool: SqlitePool,
}

impl ConsensusDb {
    pub async fn connect(database_url: &str) -> eyre::Result<Self> {
        let options = SqliteConnectOptions::from_str(database_url)
            .wrap_err("parse sqlite url")?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .wrap_err("connect sqlite")?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn migrate(&self) -> eyre::Result<()> {
        sqlx::query(
            r#"
            PRAGMA journal_mode = WAL;
            "#,
        )
        .execute(&self.pool)
        .await
        .wrap_err("set journal_mode")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS certified_blocks (
                kind TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                view INTEGER NOT NULL,
                height INTEGER,
                digest BLOB NOT NULL,
                certificate TEXT NOT NULL,
                seen INTEGER NOT NULL,
                PRIMARY KEY (kind, epoch, view, digest)
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .wrap_err("create certified_blocks")?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS certified_blocks_height_idx
                ON certified_blocks(kind, height);
            "#,
        )
        .execute(&self.pool)
        .await
        .wrap_err("create certified_blocks_height_idx")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS nullifications (
                epoch INTEGER NOT NULL,
                view INTEGER NOT NULL,
                seen INTEGER NOT NULL,
                PRIMARY KEY (epoch, view)
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .wrap_err("create nullifications")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS identity_transitions (
                transition_epoch INTEGER NOT NULL PRIMARY KEY,
                old_identity TEXT NOT NULL,
                new_identity TEXT NOT NULL,
                header_json TEXT,
                finalization_certificate TEXT
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .wrap_err("create identity_transitions")?;

        Ok(())
    }

    pub async fn upsert_finalized_block(
        &self,
        block: &CertifiedBlock,
        seen: u64,
    ) -> eyre::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO certified_blocks (kind, epoch, view, height, digest, certificate, seen)
            VALUES ('finalized', ?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(kind, epoch, view, digest) DO UPDATE SET
                height = excluded.height,
                certificate = excluded.certificate,
                seen = MAX(certified_blocks.seen, excluded.seen);
            "#,
        )
        .bind(block.epoch as i64)
        .bind(block.view as i64)
        .bind(block.height.map(|h| h as i64))
        .bind(block.digest.as_slice())
        .bind(&block.certificate)
        .bind(seen as i64)
        .execute(&self.pool)
        .await
        .wrap_err("upsert certified block")?;
        Ok(())
    }

    pub async fn insert_nullification(&self, epoch: u64, view: u64, seen: u64) -> eyre::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO nullifications (epoch, view, seen)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(epoch, view) DO UPDATE SET seen = MAX(seen, excluded.seen);
            "#,
        )
        .bind(epoch as i64)
        .bind(view as i64)
        .bind(seen as i64)
        .execute(&self.pool)
        .await
        .wrap_err("insert nullification")?;
        Ok(())
    }

    pub async fn upsert_identity_transition(
        &self,
        transition: &IdentityTransition,
    ) -> eyre::Result<()> {
        let (header_json, finalization_certificate) = if let Some(proof) = transition.proof.as_ref()
        {
            (
                Some(serde_json::to_string(&proof.header)?),
                Some(proof.finalization_certificate.clone()),
            )
        } else {
            (None, None)
        };

        sqlx::query(
            r#"
            INSERT INTO identity_transitions (
                transition_epoch,
                old_identity,
                new_identity,
                header_json,
                finalization_certificate
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(transition_epoch) DO UPDATE SET
                old_identity = excluded.old_identity,
                new_identity = excluded.new_identity,
                header_json = excluded.header_json,
                finalization_certificate = excluded.finalization_certificate;
            "#,
        )
        .bind(transition.transition_epoch as i64)
        .bind(&transition.old_identity)
        .bind(&transition.new_identity)
        .bind(header_json)
        .bind(finalization_certificate)
        .execute(&self.pool)
        .await
        .wrap_err("upsert identity transition")?;
        Ok(())
    }

    pub async fn latest_finalized(&self) -> eyre::Result<Option<CertifiedBlock>> {
        let row = sqlx::query_as::<_, CertifiedBlockRow>(
            r#"
            SELECT epoch, view, height, digest, certificate
            FROM certified_blocks
            WHERE kind = 'finalized'
            ORDER BY COALESCE(height, 0) DESC, view DESC
            LIMIT 1;
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .wrap_err("fetch latest certified block")?;
        Ok(row.map(|r| r.into()))
    }

    pub async fn latest_finalized_height(&self) -> eyre::Result<Option<u64>> {
        let row = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT height
            FROM certified_blocks
            WHERE kind = 'finalized' AND height IS NOT NULL
            ORDER BY height DESC
            LIMIT 1;
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .wrap_err("fetch latest finalized height")?;
        Ok(row.flatten().map(|h| h as u64))
    }

    pub async fn get_finalization(&self, query: Query) -> eyre::Result<Option<CertifiedBlock>> {
        match query {
            Query::Latest => self.latest_finalized().await,
            Query::Height(height) => {
                let row = sqlx::query_as::<_, CertifiedBlockRow>(
                    r#"
                    SELECT epoch, view, height, digest, certificate
                    FROM certified_blocks
                    WHERE kind = 'finalized' AND height = ?1
                    LIMIT 1;
                    "#,
                )
                .bind(height as i64)
                .fetch_optional(&self.pool)
                .await
                .wrap_err("fetch finalization by height")?;
                Ok(row.map(|r| r.into()))
            }
        }
    }

    pub async fn get_latest(&self) -> eyre::Result<ConsensusState> {
        let finalized = self.latest_finalized().await?;
        Ok(ConsensusState {
            finalized,
            notarized: None,
        })
    }

    pub async fn get_identity_transition_proof(
        &self,
        from_epoch: Option<u64>,
        full: bool,
    ) -> eyre::Result<IdentityTransitionResponse> {
        let latest_epoch = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT MAX(transition_epoch) FROM identity_transitions;
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .wrap_err("fetch latest transition epoch")?
        .unwrap_or(0);

        let latest_finalized_epoch = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT epoch
            FROM certified_blocks
            WHERE kind = 'finalized'
            ORDER BY COALESCE(height, 0) DESC, view DESC
            LIMIT 1;
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .wrap_err("fetch latest finalized epoch")?
        .map(|epoch| epoch as u64);

        let start_epoch = from_epoch
            .or(latest_finalized_epoch)
            .unwrap_or(latest_epoch as u64);
        let rows = if full {
            sqlx::query_as::<_, TransitionRow>(
                r#"
                SELECT transition_epoch, old_identity, new_identity, header_json, finalization_certificate
                FROM identity_transitions
                WHERE transition_epoch <= ?1
                ORDER BY transition_epoch DESC;
                "#,
            )
            .bind(start_epoch as i64)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as::<_, TransitionRow>(
                r#"
                SELECT transition_epoch, old_identity, new_identity, header_json, finalization_certificate
                FROM identity_transitions
                WHERE transition_epoch <= ?1
                ORDER BY transition_epoch DESC
                LIMIT 1;
                "#,
            )
            .bind(start_epoch as i64)
            .fetch_all(&self.pool)
            .await
        }
        .wrap_err("fetch identity transitions")?;

        let mut transitions: Vec<IdentityTransition> = rows
            .into_iter()
            .map(IdentityTransition::try_from)
            .collect::<eyre::Result<_>>()?;

        let identity = crate::identity::derive_identity(start_epoch, &transitions);

        if !full && transitions.len() > 1 {
            transitions.truncate(1);
        }

        Ok(IdentityTransitionResponse {
            identity,
            transitions,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct CertifiedBlockRow {
    epoch: i64,
    view: i64,
    height: Option<i64>,
    digest: Vec<u8>,
    certificate: String,
}

impl From<CertifiedBlockRow> for CertifiedBlock {
    fn from(row: CertifiedBlockRow) -> Self {
        let digest = alloy_primitives::B256::from_slice(&row.digest);
        Self {
            epoch: row.epoch as u64,
            view: row.view as u64,
            height: row.height.map(|h| h as u64),
            digest,
            certificate: row.certificate,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct TransitionRow {
    transition_epoch: i64,
    old_identity: String,
    new_identity: String,
    header_json: Option<String>,
    finalization_certificate: Option<String>,
}

impl TryFrom<TransitionRow> for IdentityTransition {
    type Error = eyre::Error;

    fn try_from(row: TransitionRow) -> Result<Self, Self::Error> {
        let proof = match (row.header_json, row.finalization_certificate) {
            (Some(header_json), Some(finalization_certificate)) => {
                let header = serde_json::from_str(&header_json)?;
                Some(TransitionProofData {
                    header,
                    finalization_certificate,
                })
            }
            _ => None,
        };
        Ok(Self {
            transition_epoch: row.transition_epoch as u64,
            old_identity: row.old_identity,
            new_identity: row.new_identity,
            proof,
        })
    }
}
