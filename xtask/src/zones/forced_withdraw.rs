//! Submit an encrypted full-balance forced exit using only Tempo L1 RPC.
use alloy::{
    consensus::BlockHeader as _,
    network::{EthereumWallet, primitives::ReceiptResponse},
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolEvent,
};
use eyre::{WrapErr as _, ensure, eyre};
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use std::{num::NonZeroU64, time::Duration};
use tempo_alloy::{TempoNetwork, rpc::TempoCallBuilderExt};
use tempo_contracts::{
    precompiles::ITIP20,
    zones::{ForcedExitAuthorization, ZONE_FACTORY_ADDRESS, ZoneFactory, ZonePortal},
};
use zone_precompiles::ecies::{EncryptionContext, encrypt_request};
use zone_primitives::constants::zone_chain_id;

/// Request withdrawal of the account's full liquid token balance, without an L2 transaction.
/// Admission charges compensation even if Zone execution later rejects the request.
#[derive(clap::Parser)]
#[command(
    after_help = "Example (PRIVATE_KEY contains the account root key):\n  cargo zone-xtask forced-withdraw --l1-rpc-url http://localhost:8545 --portal <PORTAL> --to <RECIPIENT> --approve --wait-for-processing\n\nOnly L1 RPC is required. The amount is the full liquid balance at execution time.\n--wait-for-processing observes inbox settlement, not successful L1 delivery."
)]
pub(crate) struct ForcedWithdraw {
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,
    #[arg(long, env = "L1_PORTAL_ADDRESS")]
    portal: Address,
    /// Account root secp256k1 key; access keys cannot authorize forced withdrawals.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,
    /// Optional separate L1 signer/payer. Defaults to the authorizing account, exposing
    /// its address as the public L1 payer. A separate payer reduces this linkage;
    /// the recipient also defaults to the authorizing account.
    #[arg(long, env = "FEE_PAYER_PRIVATE_KEY", hide_env_values = true)]
    fee_payer_private_key: Option<String>,
    #[arg(long, default_value_t = tempo_precompiles::PATH_USD_ADDRESS)]
    token: Address,
    /// L1 recipient. Defaults to the signing account.
    #[arg(long)]
    to: Option<Address>,
    /// Private authorization nonce (not an Ethereum transaction nonce). Defaults to random 256 bits.
    #[arg(long)]
    nonce: Option<U256>,
    /// Exclusive L1 admission deadline, in Unix seconds. Defaults to latest L1 timestamp + 600.
    #[arg(long)]
    admit_before: Option<u64>,
    /// Approve exactly the compensation amount if the payer's allowance is insufficient.
    #[arg(long)]
    approve: bool,
    /// Wait for the L1 settled inbox cursor; this does NOT establish payout or rejection reason.
    #[arg(long)]
    wait_for_processing: bool,
    /// Maximum seconds to wait for inbox settlement after admission.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    timeout_secs: u64,
}

// The top-level CLI derives Debug; never expose either signing key through it.
impl std::fmt::Debug for ForcedWithdraw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForcedWithdraw").finish_non_exhaustive()
    }
}

fn authorization(
    signer: &PrivateKeySigner,
    recipient: Address,
    token: Address,
    chain_id: u64,
    nonce: U256,
    deadline: Option<u64>,
    now: u64,
) -> eyre::Result<ForcedExitAuthorization> {
    ensure!(!recipient.is_zero(), "recipient must not be zero");
    let admit_before = match deadline {
        Some(value) => value,
        None => now
            .checked_add(600)
            .ok_or_else(|| eyre!("deadline overflow"))?,
    };
    ensure!(
        admit_before > now,
        "admission deadline must be later than the latest L1 timestamp"
    );
    Ok(ForcedExitAuthorization {
        account: signer.address(),
        zoneChainId: U256::from(chain_id),
        token,
        recipient,
        nonce,
        admitBefore: admit_before,
    })
}

impl ForcedWithdraw {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let signer: PrivateKeySigner = self
            .private_key
            .parse()
            .wrap_err("invalid account root key")?;
        let payer: PrivateKeySigner = match &self.fee_payer_private_key {
            Some(key) => key.parse().wrap_err("invalid fee payer key")?,
            None => signer.clone(),
        };
        let payer_address = payer.address();
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(EthereumWallet::from(payer))
            .connect(&self.l1_rpc_url)
            .await?;
        let header = provider
            .get_header_by_number(alloy_eips::BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| eyre!("latest L1 header unavailable"))?;
        let block = alloy_eips::BlockId::hash_canonical(header.hash);
        let factory = ZoneFactory::new(ZONE_FACTORY_ADDRESS, &provider);
        // Authenticate the spender against protocol state, not the supplied portal's getters.
        // Pin all identity/format checks to one block before signing or sending any transaction.
        ensure!(
            factory
                .isZonePortal(self.portal)
                .block(block)
                .call()
                .await?,
            "portal is not registered in the canonical ZoneFactory"
        );
        let portal = ZonePortal::new(self.portal, &provider);
        let zone_id = portal.zoneId().block(block).call().await?;
        let registration = factory.zones(zone_id).block(block).call().await?;
        ensure!(
            registration.portal == self.portal && registration.zoneId == zone_id,
            "portal does not match ZoneFactory registration for zone {zone_id}"
        );
        ensure!(
            portal.forcedExitVersion().block(block).call().await? == 1,
            "unsupported forced-exit format (expected version 1)"
        );
        ensure!(
            portal
                .FORCED_EXIT_COMPENSATION()
                .block(block)
                .call()
                .await?
                == exithatch::FORCED_EXIT_COMPENSATION,
            "unexpected compensation for forced-exit v1"
        );
        // The approved amount comes from the protocol constant, never from an RPC getter.
        let compensation = U256::from(exithatch::FORCED_EXIT_COMPENSATION);
        ensure!(
            !portal.paused().block(block).call().await?,
            "portal is paused"
        );
        ensure!(
            portal
                .tokenConfig(self.token)
                .block(block)
                .call()
                .await?
                .enabled,
            "token is not enabled on portal"
        );
        let l1_chain_id = provider.get_chain_id().await?;
        let chain_id = zone_chain_id(l1_chain_id, zone_id)?;
        let mut random_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut random_nonce);
        let auth = authorization(
            &signer,
            self.to.unwrap_or(signer.address()),
            self.token,
            chain_id,
            self.nonce
                .unwrap_or_else(|| U256::from_be_bytes(random_nonce)),
            self.admit_before,
            header.timestamp(),
        )?;
        let token = ITIP20::new(self.token, &provider);
        ensure!(
            token.balanceOf(payer_address).call().await? >= compensation,
            "fee payer lacks {compensation} token base units for compensation (transaction gas is additional)"
        );
        let allowance = token.allowance(payer_address, self.portal).call().await?;
        if allowance < compensation {
            ensure!(
                self.approve,
                "insufficient compensation allowance; approve {compensation} for portal {} or pass --approve",
                self.portal
            );
            let receipt = token
                .approve(self.portal, compensation)
                .send_sync()
                .await
                .wrap_err("compensation approval failed")?;
            ensure!(
                receipt.status(),
                "compensation approval reverted: {}",
                receipt.transaction_hash
            );
            println!("Compensation approval: {}", receipt.transaction_hash);
        }
        // Fetch after approval to minimize key-rotation races. All encryption context binds to
        // the actual L1 payer, which may differ from the authorized account.
        let (key, key_index) = portal
            .encryption_key()
            .await
            .wrap_err("no usable portal encryption key")?;
        let signature = signer.sign_hash_sync(&exithatch::authorization_digest(
            &auth,
            U256::from(l1_chain_id),
            self.portal,
        ))?;
        let encrypted = encrypt_request(
            &key.x,
            key.normalized_y_parity()
                .ok_or_else(|| eyre!("invalid encryption key parity"))?,
            &auth,
            &signature.as_bytes(),
            EncryptionContext {
                portal: self.portal,
                sender: payer_address,
                key_index,
            },
            &mut OsRng,
        )
        .ok_or_else(|| eyre!("forced-exit encryption failed"))?;
        // Refuse a stale authorization before spending the non-refundable admission fee.
        let header = provider
            .get_header_by_number(alloy_eips::BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| eyre!("latest L1 header unavailable"))?;
        ensure!(
            header.timestamp() < auth.admitBefore,
            "admission deadline elapsed before submission"
        );
        println!(
            "Requesting full liquid balance withdrawal; compensation: {compensation} token base units."
        );
        println!(
            "Authorization nonce: {}; admit before: {}",
            auth.nonce, auth.admitBefore
        );
        let pending = portal
            .requestForcedExit(self.token, key_index, encrypted)
            .valid_before(
                NonZeroU64::new(auth.admitBefore)
                    .ok_or_else(|| eyre!("invalid admission deadline"))?,
            )
            .send()
            .await
            .wrap_err("failed to submit forced withdrawal")?;
        println!("Admission transaction: {}", pending.tx_hash());
        let receipt = pending.get_receipt().await.wrap_err(
            "failed to confirm admission; inspect the printed transaction before retrying",
        )?;
        ensure!(
            receipt.status(),
            "forced withdrawal admission reverted: {}",
            receipt.transaction_hash
        );
        let event = receipt
            .inner
            .logs()
            .iter()
            .filter(|log| log.address() == self.portal)
            .find_map(|log| ZonePortal::ForcedExitRequested::decode_log(&log.inner).ok())
            .ok_or_else(|| eyre!("successful receipt is missing ForcedExitRequested"))?;
        println!(
            "Admitted request {}; inbox deposit number {}.",
            event.entry.requestId, event.depositNumber
        );
        println!(
            "Admission is not payout confirmation; rejected and empty requests also consume inbox entries."
        );
        if self.wait_for_processing {
            tokio::time::timeout(Duration::from_secs(self.timeout_secs), async {
                loop {
                    if portal.lastProcessedDepositNumber().call().await? >= event.depositNumber {
                        return Ok::<_, eyre::Report>(());
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }).await.map_err(|_| eyre!("timed out waiting for inbox settlement; request {} remains admitted, do not blindly resubmit", event.entry.requestId))??;
            println!(
                "Inbox processing settled on L1. Payout, rejection, or bounce-back must be verified separately."
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn signer() -> PrivateKeySigner {
        PrivateKeySigner::from_slice(&[7; 32]).unwrap()
    }

    #[test]
    fn authorization_is_accepted_by_execution_and_binds_domain() {
        let signer = signer();
        let portal = Address::repeat_byte(3);
        let token = tempo_precompiles::PATH_USD_ADDRESS;
        let chain = zone_chain_id(1337, 42).unwrap();
        let auth = authorization(
            &signer,
            Address::repeat_byte(4),
            token,
            chain,
            U256::from(99),
            None,
            100,
        )
        .unwrap();
        assert_eq!(auth.admitBefore, 700);
        let sig = signer
            .sign_hash_sync(&exithatch::authorization_digest(
                &auth,
                U256::from(1337),
                portal,
            ))
            .unwrap()
            .as_bytes();
        let payload = exithatch::encode_payload(&auth, &sig);
        let (decoded, decoded_sig) = exithatch::decode_payload(&payload).unwrap();
        assert!(
            exithatch::authorize(
                &decoded,
                &decoded_sig,
                U256::from(1337),
                portal,
                U256::from(chain),
                token,
                699
            )
            .is_ok()
        );
        for (parent, target, timestamp) in [
            (1338, portal, 699),
            (1337, Address::ZERO, 699),
            (1337, portal, 700),
        ] {
            assert!(
                exithatch::authorize(
                    &decoded,
                    &decoded_sig,
                    U256::from(parent),
                    target,
                    U256::from(chain),
                    token,
                    timestamp
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_invalid_recipient_and_deadlines_before_submission() {
        let signer = signer();
        for (to, deadline, now) in [
            (Address::ZERO, Some(101), 100),
            (signer.address(), Some(100), 100),
            (signer.address(), Some(99), 100),
            (signer.address(), None, u64::MAX),
        ] {
            assert!(
                authorization(
                    &signer,
                    to,
                    tempo_precompiles::PATH_USD_ADDRESS,
                    123,
                    U256::ZERO,
                    deadline,
                    now
                )
                .is_err()
            );
        }
    }

    #[test]
    fn cli_needs_no_zone_rpc_and_redacts_both_keys() {
        let root = "07".repeat(32);
        let payer = "08".repeat(32);
        let args = [
            "forced-withdraw",
            "--l1-rpc-url",
            "http://localhost:8545",
            "--portal",
            "0x1111111111111111111111111111111111111111",
            "--private-key",
            &root,
            "--fee-payer-private-key",
            &payer,
            "--nonce",
            "42",
            "--approve",
            "--wait-for-processing",
        ];
        let command = ForcedWithdraw::try_parse_from(args).unwrap();
        assert_eq!(command.nonce, Some(U256::from(42)));
        assert!(command.approve && command.wait_for_processing);
        let debug = format!("{command:?}");
        assert!(!debug.contains(&root) && !debug.contains(&payer));
        assert!(
            ForcedWithdraw::try_parse_from(args.into_iter().chain(["--timeout-secs", "0"]))
                .is_err()
        );
        assert!(ForcedWithdraw::try_parse_from(args.into_iter().chain(["--amount", "1"])).is_err());
    }
}

#[cfg(test)]
mod rpc_tests {
    use super::*;
    use alloy::{
        consensus::Transaction,
        primitives::Bytes,
        sol_types::{SolCall, SolValue},
    };
    use alloy_eips::eip2718::Decodable2718;
    use jsonrpsee::{RpcModule, server::ServerBuilder, types::ErrorObjectOwned};
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use tempo_contracts::zones::ZoneInfo;

    const PORTAL: Address = Address::repeat_byte(0x11);
    const ZONE_ID: u32 = 42;

    struct Scenario {
        registered: bool,
        registry_portal: Address,
        registry_zone_id: u32,
        version: u64,
        compensation: u128,
        allowance: U256,
    }

    impl Default for Scenario {
        fn default() -> Self {
            Self {
                registered: true,
                registry_portal: PORTAL,
                registry_zone_id: ZONE_ID,
                version: 1,
                compensation: exithatch::FORCED_EXIT_COMPENSATION,
                allowance: U256::ZERO,
            }
        }
    }

    #[derive(Default)]
    struct Observed {
        calls: Vec<Value>,
        transactions: Vec<Bytes>,
    }

    // Exercise the actual CLI, including its wallet and signed approval transaction.
    // Stop at transaction submission: the mock must never execute a token transfer.
    async fn run(scenario: Scenario, approve: bool) -> (String, Observed) {
        let observed = Arc::new(Mutex::new(Observed::default()));
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut rpc = RpcModule::new(());
        let mut header = tempo_primitives::TempoHeader::default();
        header.inner.number = 100;
        header.inner.timestamp = 1000;
        header.inner.base_fee_per_gas = Some(1);
        let header = tempo_alloy::rpc::TempoHeaderResponse {
            inner: alloy_rpc_types_eth::Header::new(header),
            timestamp_millis: 1_000_000,
        };
        let block = alloy_eips::BlockId::hash_canonical(header.hash);
        rpc.register_method("eth_getBlockByNumber", move |_, _, _| {
            serde_json::to_value(&header).unwrap()
        })
        .unwrap();
        let calls = observed.clone();
        rpc.register_method("eth_call", move |params, _, _| {
            let params: Vec<Value> = params.parse()?;
            calls.lock().unwrap().calls.push(json!(params));
            let to: Address = serde_json::from_value(params[0]["to"].clone()).unwrap();
            let input: Bytes = serde_json::from_value(
                params[0]
                    .get("input")
                    .or_else(|| params[0].get("data"))
                    .unwrap()
                    .clone(),
            )
            .unwrap();
            let selector = &input[..4];
            let output = if to == ZONE_FACTORY_ADDRESS {
                assert_eq!(params[1], serde_json::to_value(block).unwrap());
                if selector == ZoneFactory::isZonePortalCall::SELECTOR {
                    assert_eq!(
                        ZoneFactory::isZonePortalCall::abi_decode(&input)
                            .unwrap()
                            .portal,
                        PORTAL
                    );
                    scenario.registered.abi_encode()
                } else {
                    assert_eq!(
                        ZoneFactory::zonesCall::abi_decode(&input).unwrap().id,
                        ZONE_ID
                    );
                    (ZoneInfo {
                        zoneId: scenario.registry_zone_id,
                        portal: scenario.registry_portal,
                        accessMode: false,
                        gatewayMode: false,
                        admin: Address::ZERO,
                        sequencers: vec![],
                        threshold: 0,
                        verifier: Address::ZERO,
                        rpcUrl: String::new(),
                    },)
                        .abi_encode_params()
                }
            } else if to == PORTAL {
                if selector == ZonePortal::encryptionKeyAtBlockCall::SELECTOR {
                    let secret = k256::SecretKey::from_slice(&[3; 32]).unwrap();
                    let (x, parity) = zone_precompiles::ecies::compressed_x_and_parity(
                        secret.public_key().as_affine(),
                    );
                    return Ok(Bytes::from(
                        ZonePortal::encryptionKeyAtBlockCall::abi_encode_returns(
                            &ZonePortal::encryptionKeyAtBlockReturn {
                                x,
                                yParity: parity,
                                keyIndex: U256::ZERO,
                            },
                        ),
                    ));
                }
                assert_eq!(params[1], serde_json::to_value(block).unwrap());
                if selector == ZonePortal::zoneIdCall::SELECTOR {
                    ZONE_ID.abi_encode()
                } else if selector == ZonePortal::forcedExitVersionCall::SELECTOR {
                    scenario.version.abi_encode()
                } else if selector == ZonePortal::FORCED_EXIT_COMPENSATIONCall::SELECTOR {
                    scenario.compensation.abi_encode()
                } else if selector == ZonePortal::pausedCall::SELECTOR {
                    false.abi_encode()
                } else if selector == ZonePortal::tokenConfigCall::SELECTOR {
                    (true, true).abi_encode_params()
                } else {
                    return Err(ErrorObjectOwned::owned(
                        -32000,
                        "unexpected portal call",
                        None::<()>,
                    ));
                }
            } else {
                assert_eq!(to, tempo_precompiles::PATH_USD_ADDRESS);
                if selector == ITIP20::balanceOfCall::SELECTOR {
                    U256::from(1_000_000_000u64).abi_encode()
                } else {
                    assert_eq!(selector, ITIP20::allowanceCall::SELECTOR);
                    scenario.allowance.abi_encode()
                }
            };
            Ok::<_, ErrorObjectOwned>(Bytes::from(output))
        })
        .unwrap();
        for (method, value) in [
            ("eth_blockNumber", json!("0x64")),
            ("eth_chainId", json!("0x539")),
            ("eth_getTransactionCount", json!("0x0")),
            ("eth_estimateGas", json!("0x100000")),
            ("eth_gasPrice", json!("0x1")),
            ("eth_maxPriorityFeePerGas", json!("0x1")),
            (
                "eth_feeHistory",
                json!({
                    "oldestBlock": "0x63", "baseFeePerGas": ["0x1", "0x1"],
                    "gasUsedRatio": [0.5], "reward": [["0x1"]]
                }),
            ),
        ] {
            rpc.register_method(method, move |_, _, _| value.clone())
                .unwrap();
        }
        for method in ["eth_sendRawTransactionSync", "eth_sendRawTransaction"] {
            let transactions = observed.clone();
            rpc.register_method(method, move |params, _, _| {
                let params: Vec<Value> = params.parse()?;
                let raw: Bytes = serde_json::from_value(params[0].clone()).unwrap();
                transactions.lock().unwrap().transactions.push(raw);
                Err::<Value, _>(ErrorObjectOwned::owned(
                    -32000,
                    "stop after recording transaction",
                    None::<()>,
                ))
            })
            .unwrap();
        }
        let handle = server.start(rpc);
        let command = ForcedWithdraw {
            l1_rpc_url: format!("http://{address}"),
            portal: PORTAL,
            private_key: "07".repeat(32),
            fee_payer_private_key: Some("08".repeat(32)),
            token: tempo_precompiles::PATH_USD_ADDRESS,
            to: None,
            nonce: Some(U256::ONE),
            admit_before: Some(1600),
            approve,
            wait_for_processing: false,
            timeout_secs: 1,
        };
        let error = tokio::time::timeout(Duration::from_secs(10), command.run())
            .await
            .unwrap()
            .unwrap_err();
        handle.stop().unwrap();
        handle.stopped().await;
        let observed = std::mem::take(&mut *observed.lock().unwrap());
        (format!("{error:#}"), observed)
    }

    #[tokio::test]
    async fn rejects_spoofed_portal_before_any_transaction_or_portal_getter() {
        for approve in [false, true] {
            let (error, observed) = run(
                Scenario {
                    registered: false,
                    compensation: 1_000_000_000,
                    ..Default::default()
                },
                approve,
            )
            .await;
            assert!(error.contains("not registered"), "{error}");
            assert!(observed.transactions.is_empty());
            assert_eq!(observed.calls.len(), 1);
        }
    }

    #[tokio::test]
    async fn rejects_registry_mismatches_and_unexpected_format_or_fee_without_transactions() {
        for (scenario, expected) in [
            (
                Scenario {
                    registry_portal: Address::repeat_byte(2),
                    ..Default::default()
                },
                "does not match",
            ),
            (
                Scenario {
                    registry_zone_id: 43,
                    ..Default::default()
                },
                "does not match",
            ),
            (
                Scenario {
                    version: 2,
                    ..Default::default()
                },
                "unsupported forced-exit format",
            ),
            (
                Scenario {
                    compensation: 1_000_000_000,
                    ..Default::default()
                },
                "unexpected compensation",
            ),
            (
                Scenario {
                    compensation: 0,
                    ..Default::default()
                },
                "unexpected compensation",
            ),
        ] {
            let (error, observed) = run(scenario, true).await;
            assert!(error.contains(expected), "{error}");
            assert!(observed.transactions.is_empty());
        }
    }

    #[tokio::test]
    async fn admission_transaction_expires_at_authorization_deadline() {
        let (error, observed) = run(
            Scenario {
                allowance: U256::MAX,
                ..Default::default()
            },
            false,
        )
        .await;
        assert!(
            error.contains("stop after recording transaction"),
            "{error}"
        );
        assert_eq!(observed.transactions.len(), 1);
        let tx =
            tempo_primitives::TempoTxEnvelope::decode_2718(&mut observed.transactions[0].as_ref())
                .unwrap();
        assert_eq!(tx.valid_before(), Some(1600));
    }

    #[tokio::test]
    async fn authenticated_portal_approval_is_exactly_the_protocol_fee() {
        let (error, observed) = run(Scenario::default(), true).await;
        assert!(
            error.contains("stop after recording transaction"),
            "{error}"
        );
        assert_eq!(observed.transactions.len(), 1);
        let tx =
            tempo_primitives::TempoTxEnvelope::decode_2718(&mut observed.transactions[0].as_ref())
                .unwrap();
        assert_eq!(tx.to(), Some(tempo_precompiles::PATH_USD_ADDRESS));
        let approval = ITIP20::approveCall::abi_decode(tx.input()).unwrap();
        assert_eq!(approval.spender, PORTAL);
        assert_eq!(
            approval.amount,
            U256::from(exithatch::FORCED_EXIT_COMPENSATION)
        );
    }
}
