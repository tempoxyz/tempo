//! Consensus indexer binary entrypoint.

use clap::Parser;
use consensus_indexer::{
    db::ConsensusDb, feed::ConsensusFeed, indexer::ConsensusIndexer, state::ConsensusCache,
    store::ConsensusStore,
};
use jsonrpsee::server::{ServerBuilder, ServerConfigBuilder};
use std::net::SocketAddr;
use tempo_node::rpc::consensus::{TempoConsensusApiServer, TempoConsensusRpc};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "sqlite://consensus-indexer.db")]
    db_url: String,

    #[arg(long, default_value = "ws://moderato-stable-rpc-service:8546")]
    upstream_ws_url: String,

    #[arg(long, default_value = "http://moderato-stable-rpc-service:8545")]
    upstream_http_url: String,

    #[arg(long, default_value = "0.0.0.0:8545")]
    http_listen: SocketAddr,

    #[arg(long, default_value = "0.0.0.0:8546")]
    ws_listen: SocketAddr,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,consensus_indexer=debug,tempo_consensus_indexer=debug")
    });
    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .init();

    let args = Args::parse();
    tracing::info!(
        db_url = %args.db_url,
        upstream_ws_url = %args.upstream_ws_url,
        upstream_http_url = %args.upstream_http_url,
        http_listen = %args.http_listen,
        ws_listen = %args.ws_listen,
        "starting consensus indexer"
    );

    let db = ConsensusDb::connect(&args.db_url).await?;

    let feed = ConsensusFeed::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let feed_task = {
        let feed = feed.clone();
        let shutdown_rx = shutdown_rx.clone();
        let ws_url = args.upstream_ws_url.clone();
        tokio::spawn(async move { feed.run(ws_url, shutdown_rx).await })
    };

    let cache = ConsensusCache::new();
    let indexer = ConsensusIndexer::new(db.clone(), args.upstream_http_url.clone(), cache.clone());
    indexer.seed_cache().await?;
    indexer.fill_gaps().await?;
    let indexer_task = {
        let events = feed.subscribe();
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move { indexer.run(events, shutdown_rx).await })
    };

    let http_server = ServerBuilder::new()
        .set_config(ServerConfigBuilder::default().http_only().build())
        .build(args.http_listen)
        .await?;
    let ws_server = ServerBuilder::new()
        .set_config(ServerConfigBuilder::default().ws_only().build())
        .build(args.ws_listen)
        .await?;

    let store = ConsensusStore::new(db.clone(), feed.events_tx(), cache);
    let http_rpc = TempoConsensusRpc::new(store.clone());
    let ws_rpc = TempoConsensusRpc::new(store.clone());
    let http_handle = http_server.start(http_rpc.into_rpc());
    let ws_handle = ws_server.start(ws_rpc.into_rpc());
    tracing::info!("consensus RPC servers started");
    let http_handle_wait = http_handle.clone();
    let ws_handle_wait = ws_handle.clone();

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
        _ = sigint.recv() => tracing::info!("Received SIGINT, shutting down"),
        _ = http_handle_wait.stopped() => tracing::info!("HTTP RPC server stopped"),
        _ = ws_handle_wait.stopped() => tracing::info!("WS RPC server stopped"),
    }

    let _ = shutdown_tx.send(true);
    http_handle.stop().ok();
    ws_handle.stop().ok();
    feed_task.abort();
    indexer_task.abort();

    Ok(())
}
