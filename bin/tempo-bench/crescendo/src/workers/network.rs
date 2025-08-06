use std::time::{Duration, Instant};

use alloy::primitives::{Bytes, hex};
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use thousands::Separable;

use crate::{config, network_stats::NETWORK_STATS, tx_queue::TX_QUEUE};

pub async fn network_worker(worker_id: usize) {
    let config = &config::get().network_worker;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(100)
        .retry_canceled_requests(true)
        .build({
            let mut connector = HttpConnector::new();
            connector.set_nodelay(true);
            connector.set_keepalive(Some(Duration::from_secs(60)));
            connector
        });

    loop {
        if let Some(txs) = TX_QUEUE.pop_at_most(config.batch_factor).await {
            let json_body = format!(
                "[{}]",
                txs.iter()
                    .enumerate()
                    .map(|(i, tx)| {
                        format!(
                            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x{}"],"id":{}}}"#,
                            hex::encode(tx),
                            i + 1
                        )
                    })
                    .collect::<Vec<String>>()
                    .join(",")
            );

            // For hitting multiple RPCs, randomly select a target URL from the array.
            let target_url = &config.target_urls[fastrand::usize(..config.target_urls.len())];

            let req = Request::builder()
                .method("POST")
                .uri(target_url)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(json_body.into_bytes())))
                .unwrap();

            let start_time = Instant::now();
            match client.request(req).await {
                Ok(res) => {
                    // Note: May be better to print for random workers, or a range, or the median + last + first.
                    if worker_id == 0 {
                        let duration = start_time.elapsed();
                        let implied_total_rps = (txs.len() as f64 / duration.as_secs_f64())
                            * (config.total_connections as f64);
                        println!(
                            "[~] Worker {} request duration: {:.1?} ({} implied total RPS)",
                            worker_id,
                            duration,
                            (implied_total_rps as u64).separate_with_commas()
                        );
                    }

                    if res.status() == StatusCode::OK {
                        match res.into_body().collect().await {
                            Ok(collected) => {
                                let body_bytes = collected.to_bytes();
                                let body_str = std::str::from_utf8(&body_bytes).unwrap();

                                let error_count = body_str.matches("\"error\":").count();
                                if error_count > 0 {
                                    println!(
                                        "[!] RPC response ({}/{} errored): {}",
                                        error_count,
                                        txs.len(),
                                        body_str
                                    );
                                    NETWORK_STATS.inc_errors_by(error_count);
                                }

                                NETWORK_STATS.inc_requests_by(txs.len() - error_count);
                            }
                            Err(e) => {
                                eprintln!("[!] Failed to read response body: {e:?}");
                                NETWORK_STATS.inc_errors_by(txs.len());
                                tokio::time::sleep(Duration::from_millis(config.error_sleep_ms))
                                    .await;
                            }
                        }
                    } else {
                        println!("[!] Request did not have OK status: {res:?}");
                        NETWORK_STATS.inc_errors_by(txs.len());
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
                Err(e) => {
                    eprintln!("[!] Request failed: {e:?}");
                    NETWORK_STATS.inc_errors_by(txs.len());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        } else {
            // Sleep for a bit while the tx queue repopulates.
            tokio::time::sleep(Duration::from_millis(config.tx_queue_empty_sleep_ms)).await;
        }
    }
}
