//! Live end-to-end test of a Tempo Zone running against real `hankie` and `cloakroom` binaries.

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use eyre::WrapErr as _;
use tempo_alloy::TempoNetwork;
use tempo_contracts::{
    precompiles::{ITIP20, ITIP403Registry, PATH_USD_ADDRESS},
    zones::{IZoneOutbox, ZONE_OUTBOX_ADDRESS, ZoneFactory, ZonePortal},
};
use tempo_precompiles::{TIP403_REGISTRY_ADDRESS, zone_factory::portal_address};
use zone_precompiles::{L1StorageReader as _, ecies};

use crate::utils::{
    L1_TIMEOUT, TIP20_TX_GAS, WITHDRAWAL_TX_GAS, ZoneCreationConfig, ZoneGenesis, ZoneL1,
    ZoneLaunch, ZoneTestNode, create_zone_request, l1_dev_signer, poll_until, portal_admin_signer,
    signer_at,
};

struct ChildGuard(Vec<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires hankie and cloakroom binaries in HANKIE_BIN and CLOAKROOM_BIN"]
async fn live_zone_against_hankie_e2e() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let hankie_bin = PathBuf::from(std::env::var("HANKIE_BIN").wrap_err("set HANKIE_BIN")?);
    let cloakroom_bin =
        PathBuf::from(std::env::var("CLOAKROOM_BIN").wrap_err("set CLOAKROOM_BIN")?);
    eyre::ensure!(
        hankie_bin.exists(),
        "missing hankie binary at {}",
        hankie_bin.display()
    );
    eyre::ensure!(
        cloakroom_bin.exists(),
        "missing cloakroom binary at {}",
        cloakroom_bin.display()
    );

    // Kept after the test, so the logs of a failed run can be read.
    let dir = tempfile::Builder::new()
        .prefix("hankie-e2e")
        .tempdir()?
        .keep();
    eprintln!("[hankie-e2e] logs in {}", dir.display());
    // The L1 genesis must carry the Zone runtimes this checkout builds against: hankie keeps the
    // runtimes of a genesis that starts at T15, and Tempo's dev genesis does. Hankie's default
    // genesis comes from its own tempo pin, whose runtimes can differ.
    let genesis_path = dir.join("genesis.json");
    std::fs::write(
        &genesis_path,
        serde_json::to_vec_pretty(&tempo_chainspec::spec::DEV.inner.genesis)?,
    )?;

    let store_port = free_port();
    let upload_port = free_port();
    let rpc_port = free_port();
    let node_port = free_port();
    let p2p_port = free_port();
    let log = |name: &str| -> eyre::Result<(Stdio, Stdio)> {
        let file = std::fs::File::create(dir.join(name))?;
        Ok((Stdio::from(file.try_clone()?), Stdio::from(file)))
    };

    // Cloakroom runs the store in process, ingests what the validator uploads, executes it in its
    // replica, serves RPC from the store, and forwards transactions to the validator's RPC.
    let mut children = ChildGuard(Vec::new());
    let (stdout, stderr) = log("cloakroom.log")?;
    children.0.push(
        Command::new(&cloakroom_bin)
            .args([
                "--embedded-store",
                dir.join("store").to_str().unwrap(),
                "--embedded-store-listen",
                &format!("127.0.0.1:{store_port}"),
                "--listen",
                &format!("127.0.0.1:{rpc_port}"),
                "--storage-dir",
                dir.join("cloakroom").to_str().unwrap(),
                "--upload-listen",
                &format!("127.0.0.1:{upload_port}"),
                "--seed",
                "0",
                "--validators",
                "1",
                "--genesis",
                genesis_path.to_str().unwrap(),
                "--producer",
                &format!("http://127.0.0.1:{node_port}"),
            ])
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?,
    );

    let (stdout, stderr) = log("hankie.log")?;
    children.0.push(
        Command::new(&hankie_bin)
            .args([
                "node",
                "--index",
                "0",
                "--peers",
                &format!("127.0.0.1:{p2p_port}"),
                "--seed",
                "0",
                "--rpc",
                &format!("127.0.0.1:{node_port}"),
                "--storage-dir",
                dir.join("node").to_str().unwrap(),
                "--genesis",
                genesis_path.to_str().unwrap(),
                "--indexer",
                &format!("http://127.0.0.1:{upload_port}"),
            ])
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?,
    );

    let http_url: url::Url = format!("http://127.0.0.1:{rpc_port}").parse()?;
    let ws_url = format!("ws://127.0.0.1:{rpc_port}");

    let l1_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(http_url.clone())
        .erased();

    // 1. Wait for hankie to produce blocks and cloakroom to publish them.
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(200),
        "cloakroom block >= 2",
        || {
            let provider = l1_provider.clone();
            async move {
                Ok(provider
                    .get_block_number()
                    .await
                    .ok()
                    .filter(|&number| number >= 2))
            }
        },
    )
    .await?;
    eprintln!(
        "[hankie-e2e] cloakroom up at block {}",
        l1_provider.get_block_number().await?
    );

    // 2. Deploy a Zone portal on hankie through cloakroom.
    let dev_signer = l1_dev_signer();
    let admin_signer = portal_admin_signer();
    let user_signer = signer_at(1);
    let dev_provider = ProviderBuilder::new()
        .wallet(dev_signer.clone())
        .connect_http(http_url.clone())
        .erased();

    let factory_address = zone_node::dev::native_zone_factory(
        http_url.as_str(),
        alloy_network::EthereumWallet::from(dev_signer.clone()),
    )
    .await?;
    let portal = portal_address(
        ZoneFactory::new(factory_address, &dev_provider)
            .nextZoneId()
            .call()
            .await?,
    );

    // Tempo's dev genesis binds no token to a TIP-403 transfer policy, and createZone requires
    // one for its initial token. `zone-xtask create-zone` migrates the binding the same way.
    let migrate_receipt = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &dev_provider)
        .migrateTransferPolicyIds(vec![PATH_USD_ADDRESS])
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(
        migrate_receipt.status(),
        "migrateTransferPolicyIds reverted on hankie"
    );

    let nonce = dev_provider
        .get_transaction_count(dev_signer.address())
        .pending()
        .await?;
    let config = ZoneCreationConfig::closed(vec![admin_signer.address(), user_signer.address()]);
    let create_tx = dev_provider
        .send_transaction(
            create_zone_request(
                factory_address,
                admin_signer.address(),
                vec![dev_signer.address()],
                1,
                config,
            )
            .nonce(nonce),
        )
        .await?;
    let fund_admin_tx = ITIP20::new(PATH_USD_ADDRESS, &dev_provider)
        .transfer(admin_signer.address(), U256::from(10_000_000))
        .nonce(nonce + 1)
        .gas(TIP20_TX_GAS)
        .send()
        .await?;
    let fund_user_tx = ITIP20::new(PATH_USD_ADDRESS, &dev_provider)
        .transfer(user_signer.address(), U256::from(10_000_000))
        .nonce(nonce + 2)
        .gas(TIP20_TX_GAS)
        .send()
        .await?;
    let proof = zone_sequencer::prove_encryption_key_possession(portal, &dev_signer)?;
    let register_key_tx = ZonePortal::new(portal, &dev_provider)
        .setSequencerEncryptionKey(
            proof.x,
            proof.y_parity,
            proof.pop_v,
            proof.pop_r,
            proof.pop_s,
        )
        .nonce(nonce + 3)
        .gas(2_000_000)
        .send()
        .await?;

    for (name, pending) in [
        ("createZone", create_tx),
        ("fundAdmin", fund_admin_tx),
        ("fundUser", fund_user_tx),
        ("registerKey", register_key_tx),
    ] {
        let receipt = pending.get_receipt().await?;
        eyre::ensure!(receipt.status(), "{name} reverted on hankie");
    }
    eprintln!("[hankie-e2e] deployed ZonePortal at {portal}");

    // 3. Start a real ZoneTestNode connected to cloakroom over WS + HTTP.
    let zone = ZoneTestNode::launch(ZoneLaunch {
        l1: ZoneL1::Portal {
            url: ws_url,
            portal_address: portal,
        },
        genesis: ZoneGenesis::L1(BlockNumberOrTag::Latest),
        sequencer_signer: dev_signer.clone(),
        ..Default::default()
    })
    .await?;

    let l1_tip = l1_provider.get_block_number().await?;
    zone.wait_for_l2_tempo_finalized(l1_tip, L1_TIMEOUT).await?;
    eprintln!("[hankie-e2e] Zone synced L1 tip {l1_tip}");

    let _sequencer = zone
        .spawn_sequencer(
            zone_sequencer::ZoneSequencerConfig {
                chain_spec: std::sync::Arc::new(zone_chainspec::ZoneChainSpec {
                    inner: tempo_chainspec::spec::DEV.clone(),
                }),
                portal_address: portal,
                l1_rpc_url: http_url.to_string(),
                retry_connection_interval: Duration::from_millis(100),
                zone_poll_interval: Duration::from_secs(1),
                withdrawal_poll_interval: Duration::from_millis(500),
                withdrawal_batch_limits: zone_sequencer::WithdrawalBatchLimits::default(),
                outbox_address: zone_primitives::constants::ZONE_OUTBOX_ADDRESS,
                inbox_address: zone_primitives::constants::ZONE_INBOX_ADDRESS,
                batch_anchor_config: zone_sequencer::BatchAnchorConfig::default()
                    .with_blockhash_lag(2)?,
            },
            dev_signer.clone(),
        )
        .await;

    // 4. Send a real encrypted L1 deposit on hankie and verify L2 mints pathUSD.
    let user_provider = ProviderBuilder::new()
        .wallet(user_signer.clone())
        .connect_http(http_url.clone())
        .erased();
    let deposit_amount: u128 = 1_000_000;
    let approve_receipt = ITIP20::new(PATH_USD_ADDRESS, &user_provider)
        .approve(portal, U256::from(deposit_amount))
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(approve_receipt.status(), "approve reverted on hankie");
    eprintln!(
        "[hankie-e2e] approve mined in L1 block {:?}",
        approve_receipt.block_number
    );

    let portal_reader = ZonePortal::new(portal, &l1_provider);
    let key_result = portal_reader.sequencerEncryptionKey().call().await?;
    let key_index = portal_reader.encryptionKeyCount().call().await? - U256::ONE;
    let enc = ecies::encrypt_deposit(
        &key_result.x,
        key_result.yParity,
        user_signer.address(),
        B256::ZERO,
        user_signer.address(),
        portal,
        key_index,
    )
    .ok_or_else(|| eyre::eyre!("ECIES encryption failed"))?;
    let payload = tempo_contracts::zones::DepositPayload {
        ephemeralPubkeyX: enc.eph_pub_x,
        ephemeralPubkeyYParity: enc.eph_pub_y_parity,
        ciphertext: enc.ciphertext.into(),
        nonce: alloy_primitives::FixedBytes(enc.nonce),
        tag: alloy_primitives::FixedBytes(enc.tag),
    };
    let deposit_receipt = ZonePortal::new(portal, &user_provider)
        .deposit_0(
            PATH_USD_ADDRESS,
            deposit_amount,
            key_index,
            payload,
            user_signer.address(),
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(deposit_receipt.status(), "deposit reverted on hankie");
    eprintln!(
        "[hankie-e2e] deposit mined in L1 block {:?} (logs={})",
        deposit_receipt.block_number,
        deposit_receipt.logs().len()
    );

    let zone_ref = &zone;
    let zone_addr = user_signer.address();
    poll_until(
        Duration::from_secs(20),
        Duration::from_millis(250),
        "L2 deposit minted",
        || async move {
            let bal = zone_ref.balance_of(PATH_USD_ADDRESS, zone_addr).await?;
            Ok((bal >= U256::from(deposit_amount)).then_some(bal))
        },
    )
    .await?;
    eprintln!("[hankie-e2e] L2 minted deposit of {deposit_amount} pathUSD");

    // 5. Wait for Zone sequencer to settle a batch back to hankie (key-0 nonces + lag k=2).
    let settled_hash = poll_until(
        Duration::from_secs(25),
        Duration::from_millis(250),
        "Zone batch settled on hankie",
        || {
            let portal_reader = portal_reader.clone();
            async move {
                let latest = portal_reader.blockHash().call().await?;
                Ok((latest != B256::ZERO).then_some(latest))
            }
        },
    )
    .await?;
    eprintln!("[hankie-e2e] Zone settled batch on hankie: blockHash={settled_hash}");

    // 6. Fetch a real eth_getMultiProof from cloakroom and verify it with zone-spf QMDB mode.
    let proof_block = l1_provider.get_block_number().await?;
    let block = l1_provider
        .get_block_by_number(proof_block.into())
        .await?
        .ok_or_else(|| eyre::eyre!("missing L1 block {proof_block}"))?;
    let header_rlp = alloy_primitives::Bytes::from(alloy_rlp::encode(&*block.header.inner));
    let targets = vec![(portal, vec![B256::ZERO])];
    let proofs: Vec<alloy_rpc_types_eth::EIP1186AccountProofResponse> = l1_provider
        .raw_request(
            "eth_getMultiProof".into(),
            (targets, format!("0x{proof_block:x}")),
        )
        .await?;
    let mut node_pool = Vec::new();
    for account_proof in &proofs {
        node_pool.extend(account_proof.account_proof.iter().cloned());
        for slot_proof in &account_proof.storage_proof {
            node_pool.extend(slot_proof.proof.iter().cloned());
        }
    }
    let witness = zone_spf::TempoStateWitness {
        initial_tempo_header_rlp: header_rlp,
        node_pool,
    };
    let db = zone_spf::TempoWitnessDatabase::from_tempo_state_witness_with_format(
        witness,
        zone_spf::L1ProofFormat::Qmdb,
    )?;
    let proved_slot = db.read_l1_storage(portal, B256::ZERO, proof_block)?;
    let rpc_slot = l1_provider
        .get_storage_at(portal, U256::ZERO)
        .block_id(proof_block.into())
        .await?;
    assert_eq!(proved_slot, B256::from(rpc_slot));
    eprintln!(
        "[hankie-e2e] zone-spf QMDB verified real cloakroom proof at block {proof_block}: slot0={proved_slot:#x}"
    );

    // 7. Withdraw back to hankie. The sequencer settles the batch with the withdrawal, then
    // processes it with processWithdrawals, both from the sequencer's one L1 account.
    let withdrawal_amount: u128 = 250_000;
    let l2_provider = ProviderBuilder::new()
        .wallet(user_signer.clone())
        .connect_http(zone.http_url().clone())
        .erased();
    let approve_receipt = ITIP20::new(PATH_USD_ADDRESS, &l2_provider)
        .approve(ZONE_OUTBOX_ADDRESS, U256::MAX)
        .gas(TIP20_TX_GAS)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(
        approve_receipt.status(),
        "outbox approval reverted on the zone"
    );
    let l1_token = ITIP20::new(PATH_USD_ADDRESS, &l1_provider);
    let l1_before = l1_token.balanceOf(user_signer.address()).call().await?;
    let request_receipt = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &l2_provider)
        .requestWithdrawal_0(
            PATH_USD_ADDRESS,
            user_signer.address(),
            withdrawal_amount,
            B256::ZERO,
            0,
            user_signer.address(),
            alloy_primitives::Bytes::new(),
            alloy_primitives::Bytes::new(),
        )
        .gas(WITHDRAWAL_TX_GAS)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(
        request_receipt.status(),
        "withdrawal request reverted on the zone"
    );
    eprintln!("[hankie-e2e] withdrawal of {withdrawal_amount} pathUSD requested on the zone");

    let l1_token = &l1_token;
    let user = user_signer.address();
    let l1_after = poll_until(
        Duration::from_secs(60),
        Duration::from_millis(250),
        "withdrawal paid out on hankie",
        || async move {
            let balance = l1_token.balanceOf(user).call().await?;
            Ok((balance > l1_before).then_some(balance))
        },
    )
    .await?;
    assert_eq!(l1_after - l1_before, U256::from(withdrawal_amount));
    eprintln!("[hankie-e2e] withdrawal of {withdrawal_amount} pathUSD paid out on hankie");

    Ok(())
}
