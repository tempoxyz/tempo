//! Helper functions for the Tempo node entrypoint.

use eyre::WrapErr as _;
use std::time::Duration;

/// Force-install the default crypto provider.
///
/// This is necessary in case there are more than one available backends enabled in rustls (ring,
/// aws-lc-rs).
///
/// This should be called high in the main fn.
///
/// See also:
///   <https://github.com/snapview/tokio-tungstenite/issues/353#issuecomment-2455100010>
///   <https://github.com/awslabs/aws-sdk-rust/discussions/1257>
pub(crate) fn install_crypto_provider() {
    // https://github.com/snapview/tokio-tungstenite/issues/353
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default rustls crypto provider");
}

pub(crate) fn block_on_consensus_public_key(
    args: &tempo_consensus::Args,
) -> eyre::Result<Option<commonware_cryptography::ed25519::PublicKey>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .wrap_err("failed building runtime for consensus key parsing")?
        .block_on(args.public_key())
}

/// Print installed extensions as a footer after root help output.
/// Skips printing when help is for a subcommand (e.g. `tempo node --help`).
pub(crate) fn print_extensions_footer() {
    let is_subcommand_help = std::env::args()
        .skip(1)
        .any(|a| !a.starts_with('-') && a != "help");
    if is_subcommand_help {
        return;
    }

    let extensions = match tempo_ext::installed_extensions() {
        Ok(e) => e,
        Err(_) => return,
    };
    if extensions.is_empty() {
        return;
    }
    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let (b, bu, r) = if use_color {
        ("\x1b[1m", "\x1b[1m\x1b[4m", "\x1b[0m")
    } else {
        ("", "", "")
    };
    println!("\n{bu}Extensions:{r}");
    for (name, desc) in &extensions {
        if desc.is_empty() {
            println!("  {b}{name}{r}");
        } else {
            println!("  {b}{name:<22}{r} {desc}");
        }
    }
}

/// Fetches bootnodes from the given endpoint for the specified chain ID.
///
/// The endpoint must return JSON in the format:
/// `{ "<chain_id>": ["enode://...", ...] }`
pub(crate) async fn fetch_bootnodes(
    endpoint: &str,
    chain_id: u64,
) -> eyre::Result<Vec<reth_network_peers::NodeRecord>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .wrap_err("failed to build HTTP client")?;

    let resp: std::collections::HashMap<String, Vec<String>> = client
        .get(endpoint)
        .send()
        .await
        .wrap_err("request failed")?
        .error_for_status()
        .wrap_err("endpoint returned error status")?
        .json()
        .await
        .wrap_err("failed to parse response as JSON")?;

    // Skip malformed entries instead of panicking, so one bad record does not drop the rest.
    Ok(resp
        .get(&chain_id.to_string())
        .into_iter()
        .flatten()
        .filter_map(|node| match node.parse() {
            Ok(node) => Some(node),
            Err(err) => {
                tracing::warn!(node, %err, "skipping malformed bootnode");
                None
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const VALID_ENODE: &str = "enode://6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0@10.3.58.6:30303";

    /// Serves `body` as a JSON response to a single HTTP request.
    async fn serve_once(body: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn fetch_bootnodes_skips_malformed_entries() {
        let body = format!(r#"{{"4217": ["{VALID_ENODE}", "enode://not-a-node"]}}"#);
        let endpoint = serve_once(body).await;
        let nodes = tokio::spawn(async move { fetch_bootnodes(&endpoint, 4217).await })
            .await
            .expect("fetching bootnodes must not panic on a malformed entry")
            .unwrap();
        assert_eq!(nodes, vec![VALID_ENODE.parse().unwrap()]);
    }
}
