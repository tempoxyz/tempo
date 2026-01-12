use clickhouse::{Client, Row};
use eyre::Context;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub user: Option<String>,
    pub password: Option<String>,
}

impl ClickHouseConfig {
    pub fn new(url: String) -> Self {
        Self {
            url,
            database: "default".to_string(),
            user: None,
            password: None,
        }
    }

    pub fn with_database(mut self, database: String) -> Self {
        self.database = database;
        self
    }

    pub fn with_credentials(mut self, user: String, password: String) -> Self {
        self.user = Some(user);
        self.password = Some(password);
        self
    }
}

#[derive(Debug, Row, Serialize)]
pub struct TempoBenchRun {
    pub run_id: Uuid,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub created_at: OffsetDateTime,
    pub chain_id: u64,
    pub start_block: u64,
    pub end_block: u64,
    pub target_tps: u64,
    pub run_duration_secs: u64,
    pub accounts: u64,
    pub total_connections: u32,
    pub total_blocks: u32,
    pub total_transactions: u64,
    pub total_successful: u64,
    pub total_failed: u64,
    pub total_gas_used: u64,
    pub avg_block_time_ms: f64,
    pub avg_tps: f64,
    pub tip20_weight: f64,
    pub place_order_weight: f64,
    pub swap_weight: f64,
    pub erc20_weight: f64,
    pub node_commit_sha: String,
    pub build_profile: String,
    pub benchmark_mode: String,
    pub argo_workflow_name: String,
    pub k8s_namespace: String,
}

#[derive(Debug, Row, Serialize)]
pub struct TempoBenchBlock {
    pub run_id: Uuid,
    pub block_number: u64,
    pub timestamp_ms: u64,
    pub tx_count: u32,
    pub ok_count: u32,
    pub err_count: u32,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub latency_ms: u64,
}

#[derive(Debug, Row, Serialize)]
pub struct TempoBenchTransaction {
    pub run_id: Uuid,
    pub block_number: u64,
    pub tx_index: u32,
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub status: bool,
    pub gas_used: u64,
    pub effective_gas_price: u64,
    pub cumulative_gas_used: u64,
    pub fee_token: String,
    pub fee_payer: String,
    pub logs_count: u32,
}

pub struct ClickHouseReporter {
    client: Client,
}

impl ClickHouseReporter {
    pub fn new(config: &ClickHouseConfig) -> Self {
        let mut client = Client::default()
            .with_url(&config.url)
            .with_database(&config.database);

        if let Some(ref user) = config.user {
            client = client.with_user(user);
        }
        if let Some(ref password) = config.password {
            client = client.with_password(password);
        }

        Self { client }
    }

    pub async fn ensure_tables(&self) -> eyre::Result<()> {
        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS tempo_bench_runs (
                    run_id UUID,
                    created_at DateTime64(3),
                    chain_id UInt64,
                    start_block UInt64,
                    end_block UInt64,
                    target_tps UInt64,
                    run_duration_secs UInt64,
                    accounts UInt64,
                    total_connections UInt32,
                    total_blocks UInt32,
                    total_transactions UInt64,
                    total_successful UInt64,
                    total_failed UInt64,
                    total_gas_used UInt64,
                    avg_block_time_ms Float64,
                    avg_tps Float64,
                    tip20_weight Float64,
                    place_order_weight Float64,
                    swap_weight Float64,
                    erc20_weight Float64,
                    node_commit_sha String,
                    build_profile String,
                    benchmark_mode String,
                    argo_workflow_name String,
                    k8s_namespace String
                ) ENGINE = MergeTree()
                ORDER BY (created_at, run_id)
                "#,
            )
            .execute()
            .await
            .context("Failed to create tempo_bench_runs table")?;

        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS tempo_bench_blocks (
                    run_id UUID,
                    block_number UInt64,
                    timestamp_ms UInt64,
                    tx_count UInt32,
                    ok_count UInt32,
                    err_count UInt32,
                    gas_used UInt64,
                    gas_limit UInt64,
                    latency_ms UInt64
                ) ENGINE = MergeTree()
                ORDER BY (run_id, block_number)
                "#,
            )
            .execute()
            .await
            .context("Failed to create tempo_bench_blocks table")?;

        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS tempo_bench_transactions (
                    run_id UUID,
                    block_number UInt64,
                    tx_index UInt32,
                    tx_hash String,
                    from_address String,
                    to_address String,
                    status Bool,
                    gas_used UInt64,
                    effective_gas_price UInt64,
                    cumulative_gas_used UInt64,
                    fee_token String,
                    fee_payer String,
                    logs_count UInt32
                ) ENGINE = MergeTree()
                ORDER BY (run_id, block_number, tx_index)
                "#,
            )
            .execute()
            .await
            .context("Failed to create tempo_bench_transactions table")?;

        Ok(())
    }

    pub async fn insert_run(&self, run: &TempoBenchRun) -> eyre::Result<()> {
        let mut insert = self.client.insert("tempo_bench_runs")?;
        insert.write(run).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_blocks(&self, blocks: &[TempoBenchBlock]) -> eyre::Result<()> {
        let mut insert = self.client.insert("tempo_bench_blocks")?;
        for block in blocks {
            insert.write(block).await?;
        }
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_transactions(&self, transactions: &[TempoBenchTransaction]) -> eyre::Result<()> {
        if transactions.is_empty() {
            return Ok(());
        }
        let mut insert = self.client.insert("tempo_bench_transactions")?;
        for tx in transactions {
            insert.write(tx).await?;
        }
        insert.end().await?;
        Ok(())
    }

    pub async fn report(
        &self,
        run: TempoBenchRun,
        blocks: Vec<TempoBenchBlock>,
        transactions: Vec<TempoBenchTransaction>,
    ) -> eyre::Result<()> {
        self.ensure_tables().await?;
        self.insert_run(&run).await?;
        self.insert_blocks(&blocks).await?;
        self.insert_transactions(&transactions).await?;
        Ok(())
    }
}

pub fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}
