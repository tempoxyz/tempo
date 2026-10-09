//! Upgrade an existing portal and prove the first T13 recovery batch before settling its output.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use alloy::genesis::Genesis;
use alloy_consensus::{BlockHeader, Transaction};
use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rlp::Decodable;
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag};
use alloy_sol_types::{SolCall, SolError};
use reth_chainspec::EthChainSpec;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::{hardfork::TempoHardfork, spec::TempoChainSpec};
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    storage::{
        Handler, PrecompileStorageProvider, StorageCtx, StorageKey, hashmap::HashMapStorageProvider,
    },
};
use tempo_primitives::TempoHeader;
use tempo_contracts::zones::{
    IZoneInbox, IZoneOutbox, TEMPO_STATE_ADDRESS, TempoState, ZONE_INBOX_ADDRESS,
    ZONE_OUTBOX_ADDRESS, ZonePortal,
};
use zone_chainspec::test_utils::set_tempo_fork;
use zone_rpc::types::ZoneExecutionWitness;
use zone_sequencer::{BatchData, BatchSubmitter};
use zone_spf::{
    BatchOutput, BatchWitness, PublicInputs, SpfConfig, TempoImport, TempoStateWitness, ZoneBlock,
    ZoneStateWitness, prove_zone_batch,
};

use crate::utils::{
    DEFAULT_TIMEOUT, L1TestNode, TcpChaosProxy, ZoneAccount, ZoneTestNode, now_secs, poll_until,
    signer_at,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_t13_migrates_and_settles_existing_portal() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let activation = now_secs() + 60;
    let mut portal_address = Address::ZERO;
    let l1 = L1TestNode::start_with(|cfg| {
        let mut genesis = cfg.chain.genesis().clone();
        portal_address =
            init_migration_portal(&mut genesis, activation).expect("valid T12 migration genesis");
        cfg.chain = Arc::new(TempoChainSpec::from_genesis(genesis));
        cfg.dev.block_time = None;
    })
    .await?;
    l1.fund_user(l1.admin_address(), 10_000_000).await?;
    let encryption_key = k256::SecretKey::from(l1.dev_signer().credential());
    l1.set_sequencer_encryption_key(portal_address, &encryption_key)
        .await?;
    let portal = ZonePortal::new(portal_address, l1.provider());
    // Create metadata before the zone starts; only alpha is processed before the upgrade.
    let alpha = l1
        .create_tip20("Alpha", "ALP", B256::with_last_byte(1))
        .await?;
    let beta = l1
        .create_tip20("Beta", "BET", B256::with_last_byte(2))
        .await?;
    let gamma = l1
        .create_tip20("Gamma", "GAM", B256::with_last_byte(3))
        .await?;
    // HTTP polling retains pending block-filter changes while responses are paused, without
    // WebSocket keepalive timeouts obscuring the hardfork coordination under test.
    let proxy = TcpChaosProxy::start(TcpChaosProxy::upstream_addr(l1.http_url())?).await?;
    let (zone, spec) = ZoneTestNode::start_from_l1_with_t13(
        l1.http_url(),
        &proxy.proxy_url(l1.http_url())?,
        portal_address,
        activation,
    )
    .await?;
    let provider = zone.provider();
    let inbox = IZoneInbox::new(ZONE_INBOX_ADDRESS, &provider);
    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    l1.enable_token_on_portal(portal_address, alpha).await?;
    l1.fund_user(account.address(), 1_000_000).await?;
    account.deposit(100, DEFAULT_TIMEOUT, &zone).await?;
    zone.wait_for_tempo_block_number(l1.provider().get_block_number().await?, DEFAULT_TIMEOUT)
        .await?;
    let deposit_block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .unwrap();
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &provider);
    assert_eq!(outbox.lastBatch().call().await?.withdrawalBatchIndex, 1);
    // The deposit finalizes the first batch; block eight finalizes the second T12 batch.
    assert!(deposit_block.header.number() < 8);
    while provider.get_block_number().await? < 8 {
        l1.fund_user(l1.admin_address(), 1).await?;
        zone.wait_for_tempo_block_number(l1.provider().get_block_number().await?, DEFAULT_TIMEOUT)
            .await?;
    }
    assert_eq!(provider.get_block_number().await?, 8);
    assert_eq!(outbox.lastBatch().call().await?.withdrawalBatchIndex, 2);
    let parent = provider.get_block_by_number(8.into()).await?.unwrap();
    assert!(
        parent.header.timestamp() < activation,
        "T12 setup crossed activation"
    );
    assert_eq!(portal.enabledTokenCount().call().await?, U256::from(2));
    assert_eq!(ITIP20::new(alpha, &provider).name().call().await?, "Alpha");
    assert_eq!(inbox.processedDepositNumber().call().await?, 1);
    let migrated_hash = inbox.processedTokenEnablementHash().call().await?;
    assert_eq!(migrated_hash, portal.tokenEnablementHash().call().await?);
    assert_eq!(
        provider
            .get_storage_at(
                ZONE_INBOX_ADDRESS,
                zone_precompiles::inbox::slots::PROCESSED_ENABLED_TOKEN_COUNT
            )
            .await?,
        U256::ZERO
    );

    // Limit the pause so outstanding HTTP requests remain within their normal timeout.
    tokio::time::sleep(Duration::from_secs(
        activation.saturating_sub(now_secs() + 20),
    ))
    .await;
    proxy.pause_upstream_to_client(true);
    let l1_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(l1.dev_signer())
        .connect_http(l1.http_url().clone())
        .erased();
    let submitter = BatchSubmitter::with_signer_and_anchor_config(
        portal_address,
        l1_provider.clone(),
        spec.clone(),
        l1.dev_signer(),
        Default::default(),
    );
    let deposit_batch = BatchData {
        zone_height: deposit_block.header.number(),
        tempo_block_number: TempoState::new(TEMPO_STATE_ADDRESS, &provider)
            .tempoBlockNumber()
            .block(BlockId::number(deposit_block.header.number()))
            .call()
            .await?,
        prev_block_hash: B256::ZERO,
        next_block_hash: deposit_block.header.hash,
        prev_processed_deposit_hash: B256::ZERO,
        next_processed_deposit_hash: inbox.processedDepositQueueHash().call().await?,
        prev_deposit_number: 0,
        next_deposit_number: 1,
        prev_processed_token_count: 0,
        next_processed_token_count: 0,
        withdrawal_queue_hash: B256::ZERO,
        withdrawal_batch_index: 1,
    };
    let interval_batch = BatchData {
        zone_height: 8,
        tempo_block_number: zone.tempo_block_number().await?,
        prev_block_hash: deposit_batch.next_block_hash,
        next_block_hash: parent.header.hash,
        prev_processed_deposit_hash: deposit_batch.next_processed_deposit_hash,
        prev_deposit_number: deposit_batch.next_deposit_number,
        withdrawal_batch_index: 2,
        ..deposit_batch.clone()
    };
    for legacy in [deposit_batch, interval_batch] {
        submitter
            .submit_batch(
                &submitter.prepare_batch(legacy).await?,
                None,
                None,
                zone_prover::VerifierMode::NitroV1,
            )
            .await
            .map_err(|err| eyre::eyre!("legacy settlement: {err:?}"))?;
    }
    assert_eq!(portal.blockHash().call().await?, parent.header.hash);
    assert_eq!(portal.withdrawalBatchIndex().call().await?, 2);

    // Leave one enablement and one deposit outstanding on T12 while the zone cannot receive L1.
    l1.enable_token_on_portal(portal_address, beta).await?;
    account.submit_deposit(200).await?;
    let last_t12 = l1_provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .unwrap();
    assert!(last_t12.header.timestamp() < activation);
    tokio::time::sleep(Duration::from_secs(activation.saturating_sub(now_secs()))).await;
    proxy.pause_upstream_to_client(false);
    poll_until(
        DEFAULT_TIMEOUT,
        Duration::from_millis(100),
        "T12 backlog visible",
        || async {
            Ok(zone
                .deposit_queue()
                .last_enqueued()
                .filter(|anchor| anchor.number >= last_t12.header.number())
                .map(|_| ()))
        },
    )
    .await?;
    // Wall-clock T13 alone must not execute the queued T12 work.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(provider.get_block_number().await?, 8);
    assert_eq!(
        inbox.processedTokenEnablementHash().call().await?,
        migrated_hash
    );

    // This transaction mines the first actual T13 L1 block and installs the new runtimes.
    l1.fund_user(l1.admin_address(), 1).await?;
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        account.address(),
        U256::from(300),
        DEFAULT_TIMEOUT,
    )
    .await?;
    let end = zone.stop_engine().await?;
    assert!(
        end >= 10,
        "recovery must contain a checkpoint prefix and a full block"
    );
    for number in 9..end {
        let block = BlockId::number(number);
        assert_eq!(
            inbox
                .processedEnabledTokenCount()
                .block(block)
                .call()
                .await?,
            0,
            "checkpoint {number} must not migrate the token cursor"
        );
        assert_eq!(
            inbox
                .processedTokenEnablementHash()
                .block(block)
                .call()
                .await?,
            migrated_hash,
            "checkpoint {number} must preserve the legacy token prefix"
        );
        assert_eq!(
            inbox.processedDepositNumber().block(block).call().await?,
            1,
            "checkpoint {number} must leave the pending deposit untouched"
        );
    }
    assert_eq!(inbox.processedEnabledTokenCount().call().await?, 3);
    assert_eq!(inbox.processedDepositNumber().call().await?, 2);
    assert_eq!(ITIP20::new(alpha, &provider).name().call().await?, "Alpha");
    assert_eq!(ITIP20::new(beta, &provider).name().call().await?, "Beta");
    assert!(!portal.tokenEnablementCursorInitialized().call().await?);
    assert_eq!(portal.lastProcessedEnabledTokenCount().call().await?, 0);
    let blocked = ZonePortal::new(portal_address, l1.admin_provider())
        .enableToken(gamma)
        .call()
        .await
        .expect_err("enablement must wait for migration settlement");
    assert_eq!(
        blocked.as_revert_data().unwrap(),
        ZonePortal::TokenEnablementCursorNotInitialized {}.abi_encode()
    );

    let witness = recovery_witness(&l1, &zone, portal_address, 9, end).await?;
    let config = SpfConfig::new(spec);
    let output = prove_zone_batch(&config, witness.clone())?;
    let head = provider.get_block_by_number(end.into()).await?.unwrap();
    assert_eq!(output.block_transition.prevBlockHash, parent.header.hash);
    assert_eq!(
        output.block_transition.nextBlockHash, head.header.hash,
        "SPF and production execution must produce the same state and block hash"
    );
    assert_eq!(
        output.token_enablement_transition.prevProcessedTokenCount,
        0
    );
    assert_eq!(
        output.token_enablement_transition.nextProcessedTokenCount,
        3
    );
    assert_eq!(output.deposit_queue_transition.prevDepositNumber, 1);
    assert_eq!(output.deposit_queue_transition.nextDepositNumber, 2);
    assert_eq!(output.last_batch_commitment.withdrawal_batch_index, 3);
    assert_eq!(
        output.deposit_queue_transition.nextProcessedHash,
        inbox.processedDepositQueueHash().call().await?
    );

    let mut checkpoint_only = witness.clone();
    checkpoint_only.zone_blocks.pop();
    assert!(matches!(
        prove_zone_batch(&config, checkpoint_only),
        Err(zone_spf::Error::InvalidBatchShape)
    ));
    let mut omitted = witness;
    if let TempoImport::Full { enabled_tokens, .. } =
        &mut omitted.zone_blocks.last_mut().unwrap().tempo_import
    {
        enabled_tokens.clear();
    }
    assert!(
        prove_zone_batch(&config, omitted).is_err(),
        "the full token suffix is mandatory"
    );

    let batch = batch_from_output(end, zone.tempo_block_number().await?, &output);
    let prepared = submitter.prepare_batch(batch).await?;
    // This harness has no Nitro attestation service. Use `NoProof` explicitly.
    let settled = submitter
        .submit_batch(&prepared, None, None, zone_prover::VerifierMode::NoProof)
        .await
        .map_err(|err| eyre::eyre!("T13 settlement: {err:?}"))?;
    assert_eq!(settled.lastProcessedEnabledTokenCount, 3);
    assert_eq!(settled.withdrawalBatchIndex, 3);
    assert_eq!(
        settled.withdrawalQueueIndex,
        U256::MAX,
        "empty batch must not create a withdrawal queue"
    );
    assert!(portal.tokenEnablementCursorInitialized().call().await?);
    assert_eq!(portal.lastProcessedEnabledTokenCount().call().await?, 3);
    assert_eq!(portal.lastProcessedDepositNumber().call().await?, 2);
    assert_eq!(
        portal.blockHash().call().await?,
        output.block_transition.nextBlockHash
    );
    assert!(
        submitter
            .submit_batch(&prepared, None, None, zone_prover::VerifierMode::NoProof)
            .await
            .is_err(),
        "settlement cannot replay"
    );
    assert_eq!(portal.withdrawalBatchIndex().call().await?, 3);
    l1.enable_token_on_portal(portal_address, gamma).await?;
    assert_eq!(portal.enabledTokenCount().call().await?, U256::from(4));
    Ok(())
}

/// Predeploy a T12 portal whose mock verifier storage survives the canonical T13 runtime upgrade.
fn init_migration_portal(genesis: &mut Genesis, activation: u64) -> eyre::Result<Address> {
    use revm::state::Bytecode;
    use tempo_contracts::precompiles::{IZoneFactory, initial_zone_factory_state};
    use tempo_precompiles::zone_factory::{
        ZoneFactory, ZoneInfoStorageHandler, ZonePortalStorage, slots,
    };

    let signer = signer_at(0);
    let admin = signer_at(2).address();
    let user = signer_at(1).address();
    set_tempo_fork(genesis, TempoHardfork::T13, activation);
    for account in initial_zone_factory_state(signer.address()) {
        genesis.alloc.get_mut(&account.address).unwrap().code = Some(account.code);
    }

    // Return ABI-encoded true for both verifier ABIs, regardless of calldata.
    // PUSH1 1; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN.
    let verifier = address!("000000000000000000000000000000000000beef");
    genesis.alloc.entry(verifier).or_default().code =
        Some(alloy_primitives::bytes!("600160005260206000f3"));

    // Run the real factory against the genesis state under T12, before the node starts.
    // Genesis allocations do not consume storage credits or emit on-chain creation logs.
    let mut storage =
        HashMapStorageProvider::new_with_spec(genesis.config.chain_id, TempoHardfork::T12);
    storage.set_tip1060_storage_credits(false);
    storage.set_block_number(0);
    storage.set_timestamp(U256::from(genesis.timestamp));
    for (&address, account) in &genesis.alloc {
        if let Some(code) = &account.code {
            storage.set_code(address, Bytecode::new_legacy(code.clone()))?;
        }
        if let Some(slots) = &account.storage {
            for (&slot, &value) in slots {
                storage.sstore(address, slot.into(), value.into())?;
            }
        }
    }
    let portal_address = StorageCtx::enter(&mut storage, || -> eyre::Result<Address> {
        let mut factory = ZoneFactory::new();
        let created = factory.create_zone(
            signer.address(),
            IZoneFactory::createZoneCall {
                params: IZoneFactory::CreateZoneParams {
                    admin,
                    initialToken: PATH_USD_ADDRESS,
                    accessMode: true,
                    gatewayMode: true,
                    allowedAccounts: vec![admin, user],
                    zoneGateways: Vec::new(),
                    sequencers: vec![signer.address()],
                    threshold: 1,
                    rpcUrl: String::new(),
                },
            },
        )?;
        // The typed slot write preserves the other fields packed alongside the verifier.
        // Unlike the default proof-call bytecode patch, this survives runtime replacement.
        ZonePortalStorage::new(created.portal)
            .verifier
            .write(verifier)?;
        ZoneInfoStorageHandler::new(
            created.zoneId.mapping_slot(slots::ZONES),
            tempo_precompiles::ZONE_FACTORY_ADDRESS,
        )
        .verifier
        .write(verifier)?;
        Ok(created.portal)
    })?;
    let (_, code) = storage.account_code(portal_address)?;
    genesis.alloc.entry(portal_address).or_default().code = Some(code.original_bytes());
    for (address, slot, value) in storage.into_storage() {
        genesis
            .alloc
            .entry(address)
            .or_default()
            .storage
            .get_or_insert_default()
            .insert(slot.into(), value.into());
    }
    Ok(portal_address)
}

fn batch_from_output(height: u64, tempo_number: u64, output: &BatchOutput) -> BatchData {
    BatchData {
        zone_height: height,
        tempo_block_number: tempo_number,
        prev_block_hash: output.block_transition.prevBlockHash,
        next_block_hash: output.block_transition.nextBlockHash,
        prev_processed_deposit_hash: output.deposit_queue_transition.prevProcessedHash,
        next_processed_deposit_hash: output.deposit_queue_transition.nextProcessedHash,
        prev_deposit_number: output.deposit_queue_transition.prevDepositNumber,
        next_deposit_number: output.deposit_queue_transition.nextDepositNumber,
        prev_processed_token_count: output.token_enablement_transition.prevProcessedTokenCount,
        next_processed_token_count: output.token_enablement_transition.nextProcessedTokenCount,
        withdrawal_queue_hash: output.withdrawal_queue_hash,
        withdrawal_batch_index: output.last_batch_commitment.withdrawal_batch_index,
    }
}

/// Build a witness from actual execution and L1 Merkle proofs, without substituting synthetic state.
async fn recovery_witness(
    l1: &L1TestNode,
    zone: &ZoneTestNode,
    portal: Address,
    from: u64,
    to: u64,
) -> eyre::Result<BatchWitness> {
    let provider = zone.provider();
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(l1.http_url().clone());
    let parent = provider
        .get_block_by_number((from - 1).into())
        .await?
        .unwrap();
    let initial_number = TempoState::new(TEMPO_STATE_ADDRESS, &provider)
        .tempoBlockNumber()
        .block(BlockId::number(from - 1))
        .call()
        .await?;
    let initial = l1_provider
        .get_block_by_number(initial_number.into())
        .await?
        .unwrap();
    let mut zone_nodes = BTreeMap::new();
    let mut codes = BTreeMap::new();
    let mut tempo_nodes = BTreeMap::new();
    let mut blocks = Vec::new();
    let mut final_header = TempoHeader::default();
    for number in from..=to {
        let block = provider
            .get_block_by_number(number.into())
            .full()
            .await?
            .unwrap();
        let txs = block.transactions.as_transactions().unwrap();
        let generated: ZoneExecutionWitness = provider
            .raw_request(
                "debug_zoneExecutionWitness".into(),
                (BlockNumberOrTag::Number(number),),
            )
            .await?;
        for node in generated.execution_witness.state {
            zone_nodes.insert(keccak256(&node), node);
        }
        for code in generated.execution_witness.codes {
            codes.insert(keccak256(&code), code);
        }
        let is_full = txs[0]
            .input()
            .starts_with(&IZoneInbox::advanceTempoCall::SELECTOR);
        let (import, header, finalization) = if is_full {
            assert_eq!(number, to);
            assert_eq!(txs.len(), 2);
            let call = IZoneInbox::advanceTempoCall::abi_decode(txs[0].input())?;
            let header = TempoHeader::decode(&mut call.header.as_ref())?;
            let finalize = IZoneOutbox::finalizeWithdrawalBatchCall::abi_decode(txs[1].input())?;
            (
                TempoImport::Full {
                    header_rlp: call.header,
                    deposits: call.deposits,
                    decryptions: call.decryptions,
                    enabled_tokens: call.enabledTokens,
                },
                header,
                Some(finalize.count),
            )
        } else {
            assert_eq!(txs.len(), 1);
            assert!(
                generated.tempo_state.is_empty(),
                "checkpoint must not read L1 state"
            );
            let call = IZoneInbox::advanceTempoHeadersCall::abi_decode(txs[0].input())?;
            let header = TempoHeader::decode(&mut call.headers.last().unwrap().as_ref())?;
            (
                TempoImport::CheckpointOnly {
                    headers_rlp: call.headers,
                },
                header,
                None,
            )
        };
        for node in generated.tempo_state {
            tempo_nodes.insert(keccak256(&node), node);
        }
        blocks.push(ZoneBlock {
            number,
            parent_hash: block.header.parent_hash(),
            timestamp: block.header.timestamp(),
            timestamp_millis_part: block.header.timestamp_millis_part,
            beneficiary: block.header.beneficiary(),
            tempo_import: import,
            finalize_withdrawal_batch_count: finalization,
            finalize_withdrawal_batch_encrypted_senders: vec![],
            transactions: vec![],
        });
        final_header = header;
    }
    let zone_id = ZonePortal::new(portal, l1.provider())
        .zoneId()
        .call()
        .await?;
    Ok(BatchWitness {
        public_inputs: PublicInputs {
            parent_chain_id: 1_337,
            zone_id,
            tempo_block_number: final_header.number(),
            anchor_block_number: final_header.number(),
            anchor_block_hash: alloy_consensus::Sealable::hash_slow(&final_header),
            expected_withdrawal_batch_index: 3,
        },
        parent_header: parent.header.inner.into_consensus(),
        zone_blocks: blocks,
        zone_state_witness: ZoneStateWitness {
            node_pool: zone_nodes.into_values().collect(),
            bytecodes: codes.into_values().collect(),
        },
        tempo_state_witness: TempoStateWitness {
            initial_tempo_header_rlp: Bytes::from(alloy_rlp::encode(initial.header.as_ref())),
            node_pool: tempo_nodes.into_values().collect(),
        },
        tempo_ancestry_headers: vec![],
    })
}
