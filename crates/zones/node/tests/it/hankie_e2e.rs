//! Live end-to-end test of a Tempo Zone running against real `hankie` and `hankie-rpc` binaries.

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use tempo_alloy::TempoNetwork;
use tempo_contracts::{
    precompiles::{ITIP20, PATH_USD_ADDRESS},
    zones::{ZoneFactory, ZonePortal},
};
use tempo_precompiles::zone_factory::portal_address;
use zone_precompiles::{L1StorageReader as _, ecies};

use crate::utils::{
    L1_TIMEOUT, TIP20_TX_GAS, ZoneCreationConfig, ZoneGenesis, ZoneL1, ZoneLaunch, ZoneTestNode,
    create_zone_request, l1_dev_signer, poll_until, portal_admin_signer, signer_at,
    t15_hankie_test_genesis,
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
#[ignore = "requires local hankie and hankie-rpc binaries"]
async fn live_zone_against_hankie_e2e() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let hankie_bin = PathBuf::from(
        std::env::var("HANKIE_BIN")
            .unwrap_or_else(|_| "/home/user/workspace/repo/target/debug/hankie".into()),
    );
    let hankie_rpc_bin = PathBuf::from(
        std::env::var("HANKIE_RPC_BIN")
            .unwrap_or_else(|_| "/home/user/workspace/repo/target/debug/hankie-rpc".into()),
    );
    eyre::ensure!(
        hankie_bin.exists(),
        "missing hankie binary at {}",
        hankie_bin.display()
    );
    eyre::ensure!(
        hankie_rpc_bin.exists(),
        "missing hankie-rpc binary at {}",
        hankie_rpc_bin.display()
    );

    let dir = tempfile::tempdir()?;
    let genesis = t15_hankie_test_genesis()?;
    let genesis_path = dir.path().join("genesis.json");
    std::fs::write(&genesis_path, serde_json::to_vec_pretty(&genesis)?)?;

    let store_port = free_port();
    let rpc_port = free_port();
    let node_port = free_port();
    let p2p_port = free_port();

    let rpc_log = std::fs::File::create(dir.path().join("hankie-rpc.log"))?;
    let rpc_log_err = rpc_log.try_clone()?;
    let node_log = std::fs::File::create(dir.path().join("hankie.log"))?;
    let node_log_err = node_log.try_clone()?;

    let mut children = ChildGuard(Vec::new());
    children.0.push(
        Command::new(&hankie_rpc_bin)
            .args([
                "--store",
                dir.path().join("store").to_str().unwrap(),
                "--store-listen",
                &format!("127.0.0.1:{store_port}"),
                "--listen",
                &format!("127.0.0.1:{rpc_port}"),
                "--validator",
                &format!("http://127.0.0.1:{node_port}"),
                "--chain-id",
                "1337",
            ])
            .stdout(Stdio::from(rpc_log))
            .stderr(Stdio::from(rpc_log_err))
            .spawn()?,
    );

    children.0.push(
        Command::new(&hankie_bin)
            .args([
                "--index",
                "0",
                "--peers",
                &format!("127.0.0.1:{p2p_port}"),
                "--rpc",
                &format!("127.0.0.1:{node_port}"),
                "--storage-dir",
                dir.path().join("node").to_str().unwrap(),
                "--genesis",
                genesis_path.to_str().unwrap(),
                "--indexer",
                &format!("http://127.0.0.1:{store_port}"),
            ])
            .stdout(Stdio::from(node_log))
            .stderr(Stdio::from(node_log_err))
            .spawn()?,
    );

    let http_url: url::Url = format!("http://127.0.0.1:{rpc_port}").parse()?;
    let ws_url = format!("ws://127.0.0.1:{rpc_port}");

    let l1_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(http_url.clone())
        .erased();

    // 1. Wait for hankie + hankie-rpc to produce and index blocks.
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(200),
        "hankie-rpc block >= 2",
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
        "[hankie-e2e] hankie-rpc up at block {}",
        l1_provider.get_block_number().await?
    );

    // 2. Deploy a Zone portal on hankie through hankie-rpc.
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

    // 3. Start a real ZoneTestNode connected to hankie-rpc over WS + HTTP.
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
                batch_anchor_config: zone_sequencer::BatchAnchorConfig::default(),
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

    // 6. Fetch a real eth_getMultiProof from hankie-rpc and verify it with zone-spf QMDB mode.
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
        "[hankie-e2e] zone-spf QMDB verified real hankie-rpc proof at block {proof_block}: slot0={proved_slot:#x}"
    );

    Ok(())
}
