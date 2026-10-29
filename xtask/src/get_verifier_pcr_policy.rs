//! Query the serving node's expected verifier policy, independently of batch submissions.

use std::{sync::Arc, time::Duration};

use alloy::providers::ProviderBuilder;
use eyre::{Context, OptionExt, ensure};
use tempo_alloy::{TempoNetwork, provider::TempoProviderExt, rpc::VerifierPcrPolicy};
use tempo_chainspec::TempoChainSpec;

#[derive(Debug, clap::Args)]
pub(crate) struct GetVerifierPcrPolicy {
    /// Chain used for the default RPC URL and chain ID check, or a custom genesis JSON path.
    #[arg(long, short, value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// Endpoint supporting tempo_getVerifierPcrPolicy. No local-policy fallback is used.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Activated hardfork to inspect. Defaults to the serving node's active fork.
    #[arg(long)]
    hardfork: Option<String>,
}

impl GetVerifierPcrPolicy {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let policy = self.query().await?;
        println!("{}", serde_json::to_string_pretty(&policy)?);
        Ok(())
    }

    async fn query(self) -> eyre::Result<VerifierPcrPolicy> {
        let rpc_url = self
            .rpc_url
            .or_else(|| self.chain.default_follow_url().map(str::to_owned))
            .ok_or_eyre("selected chain has no default RPC URL; pass --rpc-url")?;
        tokio::time::timeout(Duration::from_secs(30), async {
            let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect(&rpc_url).await.wrap_err("failed to connect to RPC")?;
            let policy = provider.get_verifier_pcr_policy(self.hardfork.as_deref())
                .await.wrap_err("failed to query tempo_getVerifierPcrPolicy; an upgraded Tempo L1 node is required")?;
            ensure!(policy.chain_id == self.chain.inner.chain.id(),
                "RPC chain ID {} does not match selected chain {}",
                policy.chain_id, self.chain.inner.chain.id());
            Ok(policy)
        }).await.wrap_err("verifier policy query timed out after 30 seconds")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
    };

    fn args(extra: &[&str]) -> GetVerifierPcrPolicy {
        let parsed = crate::Args::try_parse_from(
            ["xtask", "get-verifier-pcr-policy", "--chain", "mainnet"]
                .into_iter()
                .chain(extra.iter().copied()),
        )
        .unwrap();
        let crate::Action::GetVerifierPcrPolicy(args) = parsed.action else {
            panic!("expected get-verifier-pcr-policy");
        };
        args
    }

    #[test]
    fn verifier_policy_cli_arguments() {
        let current = args(&[]);
        assert_eq!(current.hardfork, None);
        assert_eq!(current.rpc_url, None);
        let historical = args(&["--hardfork", "T13", "--rpc-url", "http://localhost:8545"]);
        assert_eq!(historical.hardfork.as_deref(), Some("T13"));
        assert_eq!(historical.rpc_url.as_deref(), Some("http://localhost:8545"));
    }

    async fn serve(response: Value) -> (String, tokio::task::JoinHandle<Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut content_length = 0;
                loop {
                    let mut line = String::new();
                    assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" { break; }
                    if let Some(length) = line.to_lowercase().strip_prefix("content-length:") {
                        content_length = length.trim().parse::<usize>().unwrap();
                    }
                }
                let mut body = vec![0; content_length];
                stream.read_exact(&mut body).await.unwrap();
                let request: Value = serde_json::from_slice(&body).unwrap();
                let mut response = response;
                response["id"] = request["id"].clone();
                response["jsonrpc"] = json!("2.0");
                let body = serde_json::to_string(&response).unwrap();
                stream.write_all(format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body
                ).as_bytes()).await.unwrap();
                request
            }).await.unwrap()
        });
        (url, task)
    }

    #[tokio::test]
    async fn verifier_policy_query_preserves_remote_values_and_rejects_wrong_network() {
        let chain_id = args(&[]).chain.inner.chain.id();
        for (hardfork, response_chain_id) in [(None, chain_id), (Some("T13"), chain_id), (None, 1)]
        {
            let response = json!({
                "chainId": response_chain_id, "blockNumber": 123, "blockHash": format!("0x{}", "ab".repeat(32)),
                "blockTimestamp": 456, "activeHardfork": "T14",
                "selected": { "hardfork": hardfork.unwrap_or("T14"), "activationTime": 0,
                    "pcrs": [format!("0x{}", "11".repeat(48)), format!("0x{}", "22".repeat(48)), format!("0x{}", "33".repeat(48))] },
                "history": [{ "hardfork": "T12", "activationTime": 0, "pcrs": null }]
            });
            let (url, server) = serve(json!({ "result": response })).await;
            let mut query = args(&[]);
            query.rpc_url = Some(url);
            query.hardfork = hardfork.map(str::to_owned);
            let result = query.query().await;
            if response_chain_id == chain_id {
                assert_eq!(serde_json::to_value(result.unwrap()).unwrap(), response);
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    format!("RPC chain ID 1 does not match selected chain {chain_id}")
                );
            }
            let request = server.await.unwrap();
            assert_eq!(request["method"], "tempo_getVerifierPcrPolicy");
            assert_eq!(request["params"], json!([hardfork]));
        }
    }

    #[tokio::test]
    async fn verifier_policy_query_does_not_fall_back_when_rpc_is_unavailable() {
        let (url, server) =
            serve(json!({ "error": { "code": -32601, "message": "Method not found" } })).await;
        let mut query = args(&[]);
        query.rpc_url = Some(url);
        let error = query.query().await.unwrap_err();
        assert!(format!("{error:#}").contains("Method not found"));
        assert_eq!(
            server.await.unwrap()["method"],
            "tempo_getVerifierPcrPolicy"
        );
    }
}
