use alloy::genesis::{Genesis, GenesisAccount};
use alloy_consensus::{Header, Sealable as _};
use alloy_eips::NumHash;
use alloy_network::ReceiptResponse;
use alloy_primitives::{Address, B256, U256, address, keccak256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder, bindings::IMulticall3};
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag, Filter, TransactionRequest};
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use commonware_codec::Encode as _;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey as Ed25519PrivateKey};
use eyre::WrapErr;
use k256::SecretKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use reth_node_api::FullNodeComponents;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle, rpc::RethRpcAddOns};
use reth_node_core::{args::RpcServerArgs, exit::NodeExitFuture};
use reth_primitives_traits::SealedHeader;
use reth_provider::{BlockNumReader, ChainSpecProvider, HeaderProvider};
use reth_rpc_builder::RpcModuleSelection;
use reth_tasks::Runtime;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::{SocketAddr, TcpListener},
    num::NonZeroU32,
    ops::Deref,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tempo_alloy::{
    TempoNetwork,
    rpc::{TempoCallBuilderExt, TempoHeaderResponse},
};
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{TEMPO_T0_BASE_FEE, TempoChainSpec},
};
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, IStablecoinDEX, ITIP20, ITIP403Registry, TIP403_REGISTRY_ADDRESS,
    ZONE_PORTAL_IMPL_ADDRESS, ZONE_VERIFIER_ADDRESS,
    account_keychain::IAccountKeychain::{
        IAccountKeychainInstance, KeyRestrictions, SignatureType as KeyInfoSignatureType,
    },
    t13_zone_factory_state,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    storage::{
        Handler, PrecompileStorageProvider, StorageCtx, StorageKey, hashmap::HashMapStorageProvider,
    },
    tip403_registry::{
        ALLOW_ALL_POLICY_ID, AuthRole, CompoundPolicyData as RawCompoundPolicyData, PolicyData,
        PolicyType, TIP403Registry, tip403_registry_slots,
    },
    zone_factory::portal,
};
use tempo_primitives::{TempoHeader, transaction::tt_signature::TempoSignature};
use tempo_zone_contracts::{
    ZONE_OUTBOX_ADDRESS,
    ZonePortal::{self, Role as PortalRole},
    submitBatchCall,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;
use zone_chainspec::{ZoneChainSpec, test_utils::set_tempo_fork};
use zone_l1::{
    Deposit, DepositQueue, EnabledToken, EncryptionKeyRotation, L1BlockTracker, L1Deposit,
    L1PortalEvents, L1StateCache, encryption_key_address, state::EnabledTokenRegistry,
};
use zone_node::{ZoneNode, ZoneProverConfig, ZoneRedactedRpcConfig, ZoneSequencerAddOnsConfig};
use zone_p2p::{LeadershipSchedule, LeadershipState, P2pConfig, P2pPeerId, Role};
use zone_precompiles::{ZONE_FEE_MANAGER_ADDRESS, ecies::compressed_x_and_parity};
use zone_primitives::constants::{ZONE_INBOX_ADDRESS, zone_chain_id};

#[path = "../../../rpc/test-utils/auth_tokens.rs"]
mod auth_tokens;
mod network;

pub(crate) use auth_tokens::{
    build_signed_token_blob, now_secs, sign_keychain_signature, sign_p256_signature,
    sign_webauthn_signature,
};
pub(crate) use network::{P2pChaosNetwork, TcpChaosProxy};

/// Atomic counter for unique zone IDs across concurrent tests.
static NEXT_ZONE_ID: AtomicU64 = AtomicU64::new(71_000);

fn next_unique_chain_id() -> u64 {
    zone_chain_id(1_337, NEXT_ZONE_ID.fetch_add(1, Ordering::Relaxed) as u32)
        .expect("test zone ID fits in u32")
}

/// Returns a signer derived from [`TEST_MNEMONIC`] at the given BIP-44 index.
pub(crate) fn signer_at(index: u32) -> alloy_signer_local::PrivateKeySigner {
    MnemonicBuilder::<English>::default()
        .phrase(TEST_MNEMONIC)
        .index(index)
        .expect("valid derivation index")
        .build()
        .expect("valid test mnemonic")
}

pub(crate) fn l1_dev_signer() -> alloy_signer_local::PrivateKeySigner {
    signer_at(0)
}

/// Default timeout for polling loops in e2e tests.
pub(crate) const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Default poll interval for e2e tests.
pub(crate) const DEFAULT_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// Gas limit for ordinary TIP-20 calls under the current Tempo fork schedule.
pub(crate) const TIP20_TX_GAS: u64 = 500_000;

/// Gas limit for `ZoneOutbox.requestWithdrawal` test transactions.
///
/// The current Tempo fork schedule needs enough headroom for `transferFrom`, the subsequent
/// `burn`, and storage writes for the callback payloads exercised by router-based
/// withdrawals.
pub(crate) const WITHDRAWAL_TX_GAS: u64 = 10_000_000;

pub(crate) const TEST_MNEMONIC: &str =
    "test test test test test test test test test test test junk";

pub(crate) use tempo_contracts::precompiles::STABLECOIN_DEX_ADDRESS;

pub(crate) fn local_dev_zone_account(zone: &ZoneTestNode) -> eyre::Result<(DynProvider, Address)> {
    let dev_signer = l1_dev_signer();
    let dev_address = dev_signer.address();
    let provider = ProviderBuilder::new()
        .wallet(dev_signer)
        .connect_http(zone.http_url().clone())
        .erased();
    Ok((provider, dev_address))
}

pub(crate) fn local_dev_tempo_zone_account(
    zone: &ZoneTestNode,
) -> eyre::Result<(DynProvider<TempoNetwork>, Address)> {
    let dev_signer = l1_dev_signer();
    let dev_address = dev_signer.address();
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(dev_signer)
        .connect_http(zone.http_url().clone())
        .erased();
    Ok((provider, dev_address))
}

pub(crate) async fn approve_outbox<P>(
    fixture: &mut L1Fixture,
    zone: &ZoneTestNode,
    provider: P,
) -> eyre::Result<()>
where
    P: Provider + Clone,
{
    let zone_token = ITIP20::new(PATH_USD_ADDRESS, provider);
    let approve_pending = zone_token
        .approve(ZONE_OUTBOX_ADDRESS, U256::MAX)
        .gas_price(TEMPO_T0_BASE_FEE as u128)
        .gas(TIP20_TX_GAS)
        .send()
        .await?;
    fixture.inject_empty_block(zone.deposit_queue());
    let approve_receipt = approve_pending.get_receipt().await?;
    assert!(approve_receipt.status(), "approve should succeed");
    Ok(())
}

fn enabled_deposits_active_token_config() -> B256 {
    let mut value = [0u8; 32];
    value[30] = 1; // TokenConfig.depositsActive
    value[31] = 1; // TokenConfig.enabled
    B256::new(value)
}

/// Read a Foundry artifact from `crates/zones/contracts/out` and return its deployment bytecode.
///
/// Requires `forge build` to have been run in `crates/zones/contracts`.
pub(crate) fn forge_bytecode(contract: &str) -> eyre::Result<alloy_primitives::Bytes> {
    let specs_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../contracts/out");
    let path = specs_dir.join(format!("{contract}.sol/{contract}.json"));
    let json = std::fs::read_to_string(&path).wrap_err_with(|| {
        format!("{contract} artifact not found – run `forge build` in crates/zones/contracts")
    })?;
    let artifact: serde_json::Value = serde_json::from_str(&json)?;
    let hex_str = artifact["bytecode"]["object"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing bytecode in {contract} artifact"))?;
    Ok(alloy_primitives::Bytes::from(
        alloy_primitives::hex::decode(hex_str)?,
    ))
}

fn install_native_zone_factory(genesis: &mut Genesis, owner: Address) -> eyre::Result<()> {
    for account in t13_zone_factory_state(owner) {
        let storage = account
            .storage
            .map(|(slot, value)| BTreeMap::from([(slot.into(), value.into())]));
        genesis.alloc.insert(
            account.address,
            GenesisAccount::default()
                .with_nonce(Some(1))
                .with_code(Some(account.code))
                .with_storage(storage),
        );
    }

    // The T13 native verifier shadows its Solidity stub. Run that same stub at an ordinary
    // address and redirect only submitBatch's proof call; certificate domains stay canonical.
    let mock_verifier = genesis.alloc[&ZONE_VERIFIER_ADDRESS].clone();
    genesis.alloc.insert(
        address!("000000000000000000000000000000000000beef"),
        mock_verifier,
    );
    let portal = genesis.alloc.get_mut(&ZONE_PORTAL_IMPL_ADDRESS).unwrap();
    let mut code = portal.code.as_ref().unwrap().to_vec();
    // (2**160 - 1) & sload(16): this unique sequence loads the proof-call target.
    // Replace PUSH1 0x10; SLOAD with PUSH2 0xBEEF, preserving all jump offsets.
    const VERIFIER_LOAD: [u8; 13] = alloy_primitives::hex!("600160a01b6001900360105416");
    let mut matches = code
        .windows(VERIFIER_LOAD.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == VERIFIER_LOAD).then_some(offset));
    let offset = matches
        .next()
        .ok_or_else(|| eyre::eyre!("portal verifier load changed"))?;
    eyre::ensure!(matches.next().is_none(), "ambiguous portal verifier load");
    code[offset + 9..offset + 12].copy_from_slice(&[0x61, 0xbe, 0xef]);
    portal.code = Some(code.into());

    // The native factory requires the initial token's TIP-403 policy binding to exist.
    let token_policy_slot =
        PATH_USD_ADDRESS.mapping_slot(tip403_registry_slots::TOKEN_TRANSFER_POLICIES);
    let packed_policy = U256::from(ALLOW_ALL_POLICY_ID) | (U256::ONE << u64::BITS);
    genesis
        .alloc
        .entry(TIP403_REGISTRY_ADDRESS)
        .or_default()
        .storage
        .get_or_insert_default()
        .insert(token_policy_slot.into(), packed_policy.into());

    Ok(())
}

/// Dummy L1 URL used when no real L1 is needed.
///
/// The launch helper recognizes this sentinel and replaces it with a local RPC
/// server that exposes the enabled-token snapshot required during node startup.
const DUMMY_L1_URL: &str = "http://127.0.0.1:1";

async fn spawn_test_l1_rpc(chain_id: u64) -> eyre::Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let enabled_tokens = Arc::new(vec![PATH_USD_ADDRESS]);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let enabled_tokens = enabled_tokens.clone();
            tokio::spawn(handle_test_l1_rpc_request(stream, enabled_tokens, chain_id));
        }
    });
    Ok(format!("http://{address}"))
}

async fn handle_test_l1_rpc_request(
    mut stream: tokio::net::TcpStream,
    enabled_tokens: Arc<Vec<Address>>,
    chain_id: u64,
) {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    let mut headers_end = None;
    let mut content_length = 0usize;

    loop {
        let Ok(read) = stream.read(&mut buf).await else {
            return;
        };
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buf[..read]);

        if headers_end.is_none()
            && let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n")
        {
            headers_end = Some(end + 4);
            let headers = String::from_utf8_lossy(&request[..end]);
            content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().ok())
                        .flatten()
                })
                .unwrap_or(0);
        }

        if let Some(end) = headers_end
            && request.len() >= end + content_length
        {
            break;
        }
    }

    let request = headers_end
        .and_then(|end| request.get(end..end + content_length))
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let id = request
        .get("id")
        .cloned()
        .unwrap_or_else(|| serde_json::json!(1));
    let method = request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let result = match method {
        "eth_chainId" => serde_json::json!(format!("0x{chain_id:x}")),
        "eth_blockNumber" => serde_json::json!("0x0"),
        "eth_getCode" => serde_json::json!("0x01"),
        // Synthetic SPF fixtures supply their own Tempo trie nodes; only the initial header
        // and a successful proof RPC are needed when generating their Zone witness.
        "eth_getMultiProof" => serde_json::json!([]),
        "eth_getBlockByNumber" => {
            let mut block = serde_json::to_value(TempoHeaderResponse {
                inner: alloy_rpc_types_eth::Header::new(TempoHeader::default()),
                timestamp_millis: 0,
            })
            .expect("test L1 header should serialize");
            block["transactions"] = serde_json::json!([]);
            block["uncles"] = serde_json::json!([]);
            block
        }
        "eth_newBlockFilter" => serde_json::json!("0x1"),
        "eth_getFilterChanges" => serde_json::json!([]),
        "eth_uninstallFilter" => serde_json::json!(true),
        "eth_getHeaderByNumber" => serde_json::to_value(TempoHeaderResponse {
            inner: alloy_rpc_types_eth::Header::new(TempoHeader::default()),
            timestamp_millis: 0,
        })
        .expect("test L1 header should serialize"),
        "eth_call" => {
            let input = request
                .pointer("/params/0/input")
                .or_else(|| request.pointer("/params/0/data"))
                .and_then(serde_json::Value::as_str)
                .and_then(|input| const_hex::decode(input.trim_start_matches("0x")).ok())
                .unwrap_or_default();

            if input.starts_with(&IMulticall3::aggregateCall::SELECTOR) {
                IMulticall3::aggregateCall::abi_decode(&input)
                    .ok()
                    .and_then(|aggregate| {
                        aggregate
                            .calls
                            .iter()
                            .map(|call| {
                                answer_portal_call(&call.callData, &enabled_tokens)
                                    .map(alloy_primitives::Bytes::from)
                            })
                            .collect::<Option<Vec<_>>>()
                    })
                    .map(|return_data| {
                        serde_json::json!(const_hex::encode_prefixed(
                            IMulticall3::aggregateCall::abi_encode_returns(
                                &IMulticall3::aggregateReturn {
                                    blockNumber: U256::ZERO,
                                    returnData: return_data,
                                }
                            )
                        ))
                    })
                    .unwrap_or(serde_json::Value::Null)
            } else {
                answer_portal_call(&input, &enabled_tokens)
                    .map(|data| serde_json::json!(const_hex::encode_prefixed(data)))
                    .unwrap_or(serde_json::Value::Null)
            }
        }
        _ => serde_json::Value::Null,
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
    .to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

/// Answers a [`ZonePortal`] view call against the mock registry and genesis checkpoint, either
/// issued directly or as an inner call of a Multicall3 `aggregate` batch.
fn answer_portal_call(input: &[u8], enabled_tokens: &[Address]) -> Option<Vec<u8>> {
    if input.starts_with(&ZonePortal::blockHashCall::SELECTOR) {
        Some(B256::ZERO.abi_encode())
    } else if input.starts_with(&ZonePortal::zoneHeightCall::SELECTOR) {
        Some(U256::ZERO.abi_encode())
    } else if input.starts_with(&ZonePortal::enabledTokenCountCall::SELECTOR) {
        Some(U256::from(enabled_tokens.len()).abi_encode())
    } else if input.starts_with(&ZonePortal::enabledTokenAtCall::SELECTOR) {
        let index = input.get(4..36).map(U256::from_be_slice)?.to::<u64>() as usize;
        enabled_tokens.get(index).map(|token| token.abi_encode())
    } else {
        None
    }
}

/// Helper to check TIP-403 authorization through the trusted operator RPC.
pub(crate) struct Check403Registry {
    pub(crate) provider: DynProvider<TempoNetwork>,
    pub(crate) token: Address,
}

impl Check403Registry {
    pub(crate) async fn is_auth_as(&self, account: Address, role: AuthRole) -> bool {
        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &self.provider);
        let Ok(policy) = registry
            .tokenTransferPolicyId(self.token)
            .from(Address::ZERO)
            .call()
            .await
        else {
            return false;
        };
        if !policy.isSet {
            return false;
        }
        let mut data = match role {
            AuthRole::Transfer => ITIP403Registry::isAuthorizedCall::SELECTOR,
            AuthRole::Sender => ITIP403Registry::isAuthorizedSenderCall::SELECTOR,
            AuthRole::Recipient => ITIP403Registry::isAuthorizedRecipientCall::SELECTOR,
            AuthRole::MintRecipient => ITIP403Registry::isAuthorizedMintRecipientCall::SELECTOR,
        }
        .to_vec();
        data.extend((policy.policyId, account).abi_encode());
        self.provider
            .call(
                TransactionRequest::default()
                    .to(TIP403_REGISTRY_ADDRESS)
                    .from(Address::ZERO)
                    .input(data.into())
                    .into(),
            )
            .await
            .ok()
            .and_then(|output| bool::abi_decode(&output).ok())
            .unwrap_or(false)
    }
}

/// Seed a TIP-1092 token-policy binding in the TIP-403 registry's raw L1 storage.
pub(crate) fn seed_raw_tip403_token_policy(
    cache: &mut zone_l1::state::L1StateCacheInner,
    block_number: u64,
    token: Address,
    policy_id: u64,
) {
    let slot: B256 = token
        .mapping_slot(tip403_registry_slots::TOKEN_TRANSFER_POLICIES)
        .into();
    let packed: U256 = U256::from(policy_id) | (U256::ONE << 64);
    cache.set(TIP403_REGISTRY_ADDRESS, slot, block_number, packed.into());
}

/// A TIP-403 policy write for [`seed_raw_tip403_policy`].
pub(crate) struct PolicySeed<'a> {
    pub(crate) id: u64,
    pub(crate) ty: PolicyType,
    pub(crate) members: &'a [(Address, bool)],
    pub(crate) compound: Option<(u64, u64, u64)>,
}

impl<'a> PolicySeed<'a> {
    pub(crate) fn simple(id: u64, ty: PolicyType, members: &'a [(Address, bool)]) -> Self {
        Self {
            id,
            ty,
            members,
            compound: None,
        }
    }

    pub(crate) fn compound(id: u64, sender: u64, recipient: u64, mint_recipient: u64) -> Self {
        Self {
            id,
            ty: PolicyType::COMPOUND,
            members: &[],
            compound: Some((sender, recipient, mint_recipient)),
        }
    }
}

/// Materialize one or more TIP-403 policy writes into the raw L1 cache.
/// A batch shares a single storage snapshot, so multiple policy writes can reference each other.
pub(crate) fn seed_raw_tip403_policy(
    cache: &L1StateCache,
    block_number: u64,
    policies: &[PolicySeed<'_>],
) -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
    let registry = TIP403Registry::new();
    let counter_slot = registry.policy_id_counter.slot();
    let existing_next_policy_id = cache
        .lock()
        .get(TIP403_REGISTRY_ADDRESS, counter_slot.into(), block_number)
        .and_then(|value| U256::from_be_bytes(value.0).try_into().ok())
        .unwrap_or(2u64);
    let mut slots = vec![counter_slot];
    for policy in policies {
        slots.push(registry.policy_records[policy.id].base.base_slot());
        if policy.compound.is_some() {
            slots.push(registry.policy_records[policy.id].compound.base_slot());
        }
        slots.extend(
            policy
                .members
                .iter()
                .map(|(account, _)| registry.policy_set[policy.id][*account].slot()),
        );
    }

    StorageCtx::enter(&mut storage, || -> tempo_precompiles::Result<()> {
        let mut registry = TIP403Registry::new();
        let next_policy_id = policies
            .iter()
            .map(|policy| policy.id + 1)
            .max()
            .unwrap_or(2)
            .max(existing_next_policy_id);
        registry.policy_id_counter.write(next_policy_id)?;
        for policy in policies {
            registry.policy_records[policy.id].base.write(PolicyData {
                policy_type: policy.ty as u8,
                admin: Address::ZERO,
            })?;
            if let Some((sender, recipient, mint_recipient)) = policy.compound {
                registry.policy_records[policy.id]
                    .compound
                    .write(RawCompoundPolicyData {
                        sender_policy_id: sender,
                        recipient_policy_id: recipient,
                        mint_recipient_policy_id: mint_recipient,
                    })?;
            }
            for &(account, in_set) in policy.members {
                registry.policy_set[policy.id][account].write(in_set)?;
            }
        }
        Ok(())
    })?;

    let mut cache = cache.lock();
    for slot in slots {
        let value = storage.sload(TIP403_REGISTRY_ADDRESS, slot)?;
        cache.set(
            TIP403_REGISTRY_ADDRESS,
            slot.into(),
            block_number,
            value.into(),
        );
    }
    Ok(())
}

pub(crate) trait TestNodeHandle: Send {
    fn proof_directory(&self) -> std::path::PathBuf;
    fn subscribe_to_canonical_state(
        &self,
    ) -> reth_provider::CanonStateNotifications<tempo_primitives::TempoPrimitives>;

    fn node_exit_future_mut(&mut self) -> &mut NodeExitFuture;

    fn spawn_sequencer(
        &self,
        config: zone_sequencer::ZoneSequencerConfig,
        signer: alloy_signer_local::PrivateKeySigner,
    ) -> Pin<Box<dyn Future<Output = zone_sequencer::ZoneSequencerHandle> + Send + '_>>;
}

impl<Node, AddOns> TestNodeHandle for NodeHandle<Node, AddOns>
where
    Node: FullNodeComponents<
        Types: reth_node_api::NodeTypes<Primitives = tempo_primitives::TempoPrimitives>,
    >,
    AddOns: RethRpcAddOns<Node>,
{
    fn proof_directory(&self) -> std::path::PathBuf {
        self.node.data_dir.data_dir().join("proofs")
    }

    fn subscribe_to_canonical_state(
        &self,
    ) -> reth_provider::CanonStateNotifications<tempo_primitives::TempoPrimitives> {
        use reth_provider::CanonStateSubscriptions;
        self.node.provider().subscribe_to_canonical_state()
    }

    fn node_exit_future_mut(&mut self) -> &mut NodeExitFuture {
        &mut self.node_exit_future
    }

    fn spawn_sequencer(
        &self,
        config: zone_sequencer::ZoneSequencerConfig,
        signer: alloy_signer_local::PrivateKeySigner,
    ) -> Pin<Box<dyn Future<Output = zone_sequencer::ZoneSequencerHandle> + Send + '_>> {
        let provider = self.node.provider().clone();
        Box::pin(async move {
            zone_sequencer::spawn_zone_sequencer(
                config,
                signer,
                provider,
                None,
                None,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
        })
    }
}

/// A self-contained Tempo Zone L2 node for integration testing.
///
/// Wraps an in-process reth node configured as a Zone, providing:
/// - An HTTP RPC endpoint for provider connections
/// - A [`DepositQueue`] handle for injecting synthetic L1 blocks
/// - A [`L1StateCache`] for seeding TempoState storage-read data
///
/// # Construction
///
/// Use one of the static constructors depending on your test scenario:
///
/// - [`start_local()`](Self::start_local) — standalone node, no real L1, fastest for unit-style e2e
/// - [`start_local_with_chain_id()`](Self::start_local_with_chain_id) — standalone with custom chain ID (multi-zone tests)
/// - [`start_from_l1()`](Self::start_from_l1) — connected to a real [`L1TestNode`], genesis patched from L1 header
/// - [`start()`](Self::start) — connected to an external L1 via WebSocket URL
type RpcApiFuture =
    Pin<Box<dyn Future<Output = eyre::Result<Arc<dyn zone_node::rpc::ZoneRpcApi>>>>>;
type RpcApiFactory = dyn Fn(zone_node::rpc::RedactedRpcConfig) -> RpcApiFuture + Send + Sync;

pub(crate) struct ZoneTestNode {
    http_url: url::Url,
    l1_provider: DynProvider<TempoNetwork>,
    portal_address: Address,
    deposit_queue: DepositQueue,
    enabled_tokens: EnabledTokenRegistry,
    l1_state_cache: L1StateCache,
    l1_block_tracker: L1BlockTracker,
    rpc_api_factory: Arc<RpcApiFactory>,
    node_handle: Box<dyn TestNodeHandle>,
    /// Cancels the `ZoneEngine`, when this node runs one.
    ///
    /// Exercises the graceful-stop path used by the leadership role controller.
    engine_stop: Option<CancellationToken>,
    /// The shared leadership schedule
    leadership: Option<LeadershipSchedule>,
    _tasks: Runtime,
}

impl ZoneTestNode {
    pub(crate) fn proof_directory(&self) -> std::path::PathBuf {
        self.node_handle.proof_directory()
    }

    /// Returns the HTTP RPC URL for connecting providers to this node.
    pub(crate) fn http_url(&self) -> &url::Url {
        &self.http_url
    }

    /// Stop this node's task runtime while retaining its storage handles for the test lifetime.
    pub(crate) fn crash(&self) {
        let _ = self
            ._tasks
            .graceful_shutdown_with_timeout(Duration::from_secs(5));
    }

    async fn spawn_sequencer(
        &self,
        config: zone_sequencer::ZoneSequencerConfig,
        signer: alloy_signer_local::PrivateKeySigner,
    ) -> zone_sequencer::ZoneSequencerHandle {
        self.node_handle.spawn_sequencer(config, signer).await
    }

    /// Stops the `ZoneEngine` at a block boundary and waits until block production has
    /// actually ceased.
    ///
    /// Returns the head the engine stopped at.
    pub(crate) async fn stop_engine(&self) -> eyre::Result<u64> {
        let stop = self
            .engine_stop
            .as_ref()
            .ok_or_else(|| eyre::eyre!("this test node does not run a ZoneEngine"))?;
        stop.cancel();

        // The engine finishes the block in flight before returning, so poll until the head
        // holds still rather than assuming it stops instantly.
        let provider = self.provider();
        let mut previous = provider.get_block_number().await?;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let current = provider.get_block_number().await?;
            if current == previous {
                return Ok(current);
            }
            previous = current;
        }
        eyre::bail!("ZoneEngine kept producing blocks after cancellation");
    }

    /// Returns an HTTP provider connected to this zone node.
    pub(crate) fn provider(&self) -> alloy_provider::DynProvider<TempoNetwork> {
        ProviderBuilder::new_with_network()
            .connect_http(self.http_url.clone())
            .erased()
    }

    /// Assert gateway registration on the L1 portal.
    pub(crate) async fn assert_zone_gateway(
        &self,
        gateway: Address,
        expected: bool,
    ) -> eyre::Result<()> {
        use tempo_zone_contracts::{ZonePortal, ZonePortal::Role};
        let portal = ZonePortal::new(self.portal_address, &self.l1_provider);
        eyre::ensure!(
            portal
                .hasRole(gateway, Role::CallbackGateway)
                .call()
                .await?
                == expected,
            "portal gateway state for {gateway} did not equal {expected}"
        );
        Ok(())
    }

    /// Assert whether account enforcement is enabled on the L1 portal.
    pub(crate) async fn assert_access_enforced(&self, expected: bool) -> eyre::Result<()> {
        use tempo_zone_contracts::ZonePortal;
        let actual = ZonePortal::new(self.portal_address, &self.l1_provider)
            .isAccessEnforced()
            .call()
            .await?;
        eyre::ensure!(
            actual == expected,
            "portal access enforcement {actual} did not equal {expected}"
        );
        Ok(())
    }

    /// Assert whether gateway registration is open on the L1 portal.
    pub(crate) async fn assert_gateway_open(&self, expected: bool) -> eyre::Result<()> {
        use tempo_zone_contracts::ZonePortal;
        let actual = ZonePortal::new(self.portal_address, &self.l1_provider)
            .isGatewayOpen()
            .call()
            .await?;
        eyre::ensure!(
            actual == expected,
            "portal gateway openness {actual} did not equal {expected}"
        );
        Ok(())
    }

    /// Assert mode-aware account authorization on the L1 portal.
    pub(crate) async fn assert_allowed_account(
        &self,
        account: Address,
        expected: bool,
    ) -> eyre::Result<()> {
        use tempo_zone_contracts::{ZonePortal, ZonePortal::Role};
        let portal = ZonePortal::new(self.portal_address, &self.l1_provider);
        let actual = !portal.isAccessEnforced().call().await?
            || portal.hasRole(account, Role::Account).call().await?;
        eyre::ensure!(
            actual == expected,
            "portal account state for {account} did not equal {expected}"
        );
        Ok(())
    }

    /// Returns a handle to the deposit queue for injecting synthetic L1 blocks.
    pub(crate) fn deposit_queue(&self) -> &DepositQueue {
        &self.deposit_queue
    }

    /// Returns the enabled-token registry used by pool admission.
    pub(crate) fn enabled_tokens(&self) -> &EnabledTokenRegistry {
        &self.enabled_tokens
    }

    /// Returns a handle to the L1 state cache for seeding precompile data.
    pub(crate) fn l1_state_cache(&self) -> &L1StateCache {
        &self.l1_state_cache
    }

    /// Returns the L1 anchors observed by this node.
    pub(crate) fn l1_block_tracker(&self) -> &L1BlockTracker {
        &self.l1_block_tracker
    }

    /// Returns this node's leadership schedule (multi-sequencer nodes only).
    pub(crate) fn leadership(&self) -> &LeadershipSchedule {
        self.leadership
            .as_ref()
            .expect("this test node was not started in multi-sequencer mode")
    }

    /// Builds the real redacted RPC API backed by the node's EthHandlers.
    pub(crate) async fn rpc_api(
        &self,
        config: zone_node::rpc::RedactedRpcConfig,
    ) -> eyre::Result<Arc<dyn zone_node::rpc::ZoneRpcApi>> {
        (self.rpc_api_factory)(config).await
    }

    /// Subscribe to canonical state notifications.
    pub(crate) fn subscribe_to_canonical_state(
        &self,
    ) -> reth_provider::CanonStateNotifications<tempo_primitives::TempoPrimitives> {
        self.node_handle.subscribe_to_canonical_state()
    }

    pub(crate) async fn wait_for_node_exit(&mut self) -> eyre::Result<()> {
        self.node_handle.node_exit_future_mut().await
    }

    /// Wait for a TIP-20 token balance to reach at least `min_balance` on this zone.
    ///
    /// Polls the token's `balanceOf` until `balance >= min_balance`, then
    /// returns the observed balance. Useful for verifying deposit mints.
    ///
    /// **Important:** passing `U256::ZERO` returns immediately (any balance satisfies `>= 0`).
    /// Use the expected post-deposit balance as `min_balance` to actually wait.
    pub(crate) async fn wait_for_balance(
        &self,
        token: Address,
        account: Address,
        min_balance: U256,
        timeout: Duration,
    ) -> eyre::Result<U256> {
        use tempo_contracts::precompiles::ITIP20;

        let tip20 = ITIP20::new(token, self.provider());
        poll_until(timeout, DEFAULT_POLL, "token balance", || {
            let tip20 = &tip20;
            async move {
                // balanceOf may revert with Uninitialized() if the token hasn't
                // been created yet (e.g. waiting for a TokenEnabled event to be
                // processed). Treat reverts as "not ready" rather than fatal.
                let balance = match tip20.balanceOf(account).from(account).call().await {
                    Ok(b) => b,
                    Err(_) => return Ok(None),
                };
                if balance >= min_balance {
                    Ok(Some(balance))
                } else {
                    Ok(None)
                }
            }
        })
        .await
    }

    /// Reads `tempoBlockNumber` from the L2 `TempoState` predeploy right now.
    pub(crate) async fn tempo_block_number(&self) -> eyre::Result<u64> {
        use tempo_zone_contracts::{TEMPO_STATE_ADDRESS, TempoState};

        Ok(TempoState::new(TEMPO_STATE_ADDRESS, self.provider())
            .tempoBlockNumber()
            .call()
            .await?)
    }

    /// Wait for `tempoBlockNumber` on this zone to reach at least `target`.
    ///
    /// Returns the observed block number once it reaches the target.
    pub(crate) async fn wait_for_tempo_block_number(
        &self,
        target: u64,
        timeout: Duration,
    ) -> eyre::Result<u64> {
        use tempo_zone_contracts::{TEMPO_STATE_ADDRESS, TempoState};

        let tempo_state = TempoState::new(TEMPO_STATE_ADDRESS, self.provider());
        poll_until(
            timeout,
            DEFAULT_POLL,
            &format!("tempoBlockNumber >= {target}"),
            || {
                let tempo_state = &tempo_state;
                async move {
                    // During a pre-creation replay the zone can advance before the initial
                    // TokenEnabled event has initialized the default fee token on L2. Treat the
                    // resulting transient eth_call failure as "not ready" and keep polling.
                    let n = match tempo_state.tempoBlockNumber().call().await {
                        Ok(n) => n,
                        Err(err) if err.to_string().contains("InvalidToken") => return Ok(None),
                        Err(err) => return Err(err.into()),
                    };
                    if n >= target { Ok(Some(n)) } else { Ok(None) }
                }
            },
        )
        .await
    }

    /// Wait for the zone L2 RPC head to reach at least `target`.
    ///
    /// This polls `eth_blockNumber`, which is useful when a test needs to assert
    /// that a follower imported leader-produced zone blocks over P2P.
    pub(crate) async fn wait_for_block_number(
        &self,
        target: u64,
        timeout: Duration,
    ) -> eyre::Result<u64> {
        let provider = self.provider();
        poll_until(
            timeout,
            DEFAULT_POLL,
            &format!("eth_blockNumber >= {target}"),
            || {
                let provider = &provider;
                async move {
                    let n = provider.get_block_number().await?;
                    if n >= target { Ok(Some(n)) } else { Ok(None) }
                }
            },
        )
        .await
    }

    /// Read a TIP-20 token balance on this zone (single-shot, no polling).
    pub(crate) async fn balance_of(&self, token: Address, account: Address) -> eyre::Result<U256> {
        use tempo_contracts::precompiles::ITIP20;
        Ok(ITIP20::new(token, self.provider())
            .balanceOf(account)
            .from(account)
            .call()
            .await?)
    }

    /// Wait for the zone L2 to finalize an L1 block beyond `after_block`.
    ///
    /// Polls for [`TempoState::TempoBlockFinalized`] logs on the zone L2 until
    /// one appears with a `blockNumber > after_block`, then confirms the on-chain
    /// `tempoBlockNumber` matches. Returns the finalized block number.
    ///
    /// Use this instead of manually polling `tempoBlockNumber()` — it's both
    /// event-driven (checks logs each iteration) and verifies consistency.
    pub(crate) async fn wait_for_l2_tempo_finalized(
        &self,
        after_block: u64,
        timeout: Duration,
    ) -> eyre::Result<u64> {
        use tempo_zone_contracts::{TEMPO_STATE_ADDRESS, TempoState};

        let provider = self.provider();
        let tempo_state = TempoState::new(TEMPO_STATE_ADDRESS, &provider);

        let filter = Filter::new()
            .address(TEMPO_STATE_ADDRESS)
            .event_signature(TempoState::TempoBlockFinalized::SIGNATURE_HASH);

        poll_until(
            timeout,
            DEFAULT_POLL,
            "TempoBlockFinalized past target",
            || {
                let provider = &provider;
                let tempo_state = &tempo_state;
                let filter = &filter;
                async move {
                    // Check logs first — fast path when events already emitted
                    let logs = provider.get_logs(filter).await?;
                    for log in logs.iter().rev() {
                        if let Ok(ev) = TempoState::TempoBlockFinalized::decode_log(&log.inner)
                            && ev.blockNumber > after_block
                        {
                            // Confirm on-chain state matches
                            let on_chain = match tempo_state.tempoBlockNumber().call().await {
                                Ok(n) => n,
                                Err(err) if err.to_string().contains("InvalidToken") => {
                                    return Ok(None);
                                }
                                Err(err) => return Err(err.into()),
                            };
                            if on_chain >= ev.blockNumber {
                                return Ok(Some(on_chain));
                            }
                        }
                    }
                    Ok(None)
                }
            },
        )
        .await
    }

    /// Start a zone node pointing at a real L1 WebSocket URL.
    pub(crate) async fn start(l1_ws_url: String, portal_address: Address) -> eyre::Result<Self> {
        Self::launch(l1_ws_url, portal_address, next_unique_chain_id()).await
    }

    /// Start a zone node connected to a real L1, generating genesis from the L1's
    /// current block header.
    ///
    /// See [`build_l1_anchored_genesis`] for details on how the genesis is patched.
    pub(crate) async fn start_from_l1(
        l1_http_url: &url::Url,
        l1_ws_url: &url::Url,
        portal_address: Address,
    ) -> eyre::Result<Self> {
        let (genesis, _) = build_l1_anchored_genesis(l1_http_url, portal_address).await?;

        let signer = l1_dev_signer();
        Self::launch_with_genesis(
            l1_ws_url.to_string(),
            portal_address,
            next_unique_chain_id(),
            Some(genesis),
            signer,
        )
        .await
    }

    /// Run the scheduled T12 -> T13 transition against a real L1 and return the proof chain spec.
    pub(crate) async fn start_from_l1_with_t13(
        l1_http_url: &url::Url,
        l1_rpc_url: &url::Url,
        portal_address: Address,
        activation: u64,
    ) -> eyre::Result<(Self, Arc<ZoneChainSpec>)> {
        let (mut genesis, _) = build_l1_anchored_genesis(l1_http_url, portal_address).await?;
        let provider = ProviderBuilder::new().connect_http(l1_http_url.clone());
        let zone_id = ZonePortal::new(portal_address, provider)
            .zoneId()
            .call()
            .await?;
        let chain_id = zone_chain_id(1_337, zone_id)?;
        genesis.config.chain_id = chain_id;
        set_tempo_fork(&mut genesis, TempoHardfork::T13, activation);
        let spec = Arc::new(ZoneChainSpec::from_genesis(genesis.clone())?);
        let node = Self::launch_with_genesis(
            l1_rpc_url.to_string(),
            portal_address,
            chain_id,
            Some(genesis),
            l1_dev_signer(),
        )
        .await?;
        Ok((node, spec))
    }

    /// Start a zone node with additional private keys for historical encrypted deposits.
    pub(crate) async fn start_from_l1_with_decryption_keys(
        l1_http_url: &url::Url,
        l1_ws_url: &url::Url,
        portal_address: Address,
        additional_decryption_keys: Vec<SecretKey>,
    ) -> eyre::Result<Self> {
        let (genesis, _) = build_l1_anchored_genesis(l1_http_url, portal_address).await?;

        let signer = l1_dev_signer();
        Self::launch_with_genesis_and_withdrawal_batch_interval_and_decryption_keys(
            l1_ws_url.to_string(),
            portal_address,
            next_unique_chain_id(),
            Some(genesis),
            signer,
            8,
            None,
            true,
            additional_decryption_keys,
            None,
        )
        .await
    }

    /// Start a zone node connected to a real L1, anchoring genesis to a specific L1 block.
    pub(crate) async fn start_from_l1_at_block(
        l1_http_url: &url::Url,
        l1_ws_url: &url::Url,
        portal_address: Address,
        block_number: u64,
    ) -> eyre::Result<Self> {
        let (genesis, _) =
            build_l1_anchored_genesis_at_block(l1_http_url, portal_address, block_number).await?;

        let signer = l1_dev_signer();
        Self::launch_with_genesis_and_withdrawal_batch_interval(
            l1_ws_url.to_string(),
            portal_address,
            next_unique_chain_id(),
            Some(genesis),
            signer,
            8,
            None,
            true,
        )
        .await
    }

    pub(crate) async fn start_from_l1_with_withdrawal_batch_interval(
        l1_http_url: &url::Url,
        l1_ws_url: &url::Url,
        portal_address: Address,
        withdrawal_batch_interval_blocks: u64,
    ) -> eyre::Result<Self> {
        let (genesis, _) = build_l1_anchored_genesis(l1_http_url, portal_address).await?;

        let signer = l1_dev_signer();
        Self::launch_with_genesis_and_withdrawal_batch_interval(
            l1_ws_url.to_string(),
            portal_address,
            next_unique_chain_id(),
            Some(genesis),
            signer,
            withdrawal_batch_interval_blocks,
            None,
            true,
        )
        .await
    }

    /// Start a zone node connected to a real L1 at an explicit genesis block.
    ///
    /// Unlike [`start_from_l1`], this preserves the full replay gap between the
    /// portal genesis and the current L1 tip, which is useful for long-downtime
    /// catch-up tests.
    pub(crate) async fn start_from_l1_genesis_block(
        l1_http_url: &url::Url,
        l1_ws_url: &url::Url,
        portal_address: Address,
        genesis_block_number: u64,
    ) -> eyre::Result<Self> {
        let (genesis, _) =
            build_l1_anchored_genesis_at_block(l1_http_url, portal_address, genesis_block_number)
                .await?;

        let signer = l1_dev_signer();
        Self::launch_with_genesis(
            l1_ws_url.to_string(),
            portal_address,
            next_unique_chain_id(),
            Some(genesis),
            signer,
        )
        .await
    }

    /// Start a self-contained zone node with no real L1 connection.
    ///
    /// The L1Subscriber retries a dummy URL in the background, but the
    /// ZoneEngine is fully functional. Deposits and L1 headers are injected
    /// directly into the `deposit_queue`; the L1 state cache must be seeded
    /// via [`L1Fixture::seed_l1_cache`] for TempoState storage reads.
    pub(crate) async fn start_local() -> eyre::Result<Self> {
        Self::launch(
            DUMMY_L1_URL.to_string(),
            Address::ZERO,
            next_unique_chain_id(),
        )
        .await
    }

    /// Start a self-contained zone node with a custom chain ID.
    ///
    /// Useful for running multiple zone nodes in a single test — each needs
    /// a unique chain ID to avoid datadir collisions.
    pub(crate) async fn start_local_with_chain_id(chain_id: u64) -> eyre::Result<Self> {
        Self::launch(DUMMY_L1_URL.to_string(), Address::ZERO, chain_id).await
    }

    pub(crate) async fn start_local_with_p2p(
        l1_rpc_url: String,
        p2p_config: P2pConfig,
    ) -> eyre::Result<Self> {
        let throwaway_key = k256::SecretKey::from_slice(&[0x01; 32])?;
        let signer = alloy_signer_local::PrivateKeySigner::from(throwaway_key);
        Self::launch_with_genesis_and_withdrawal_batch_interval(
            l1_rpc_url,
            Address::ZERO,
            next_unique_chain_id(),
            None,
            signer,
            8,
            Some(p2p_config),
            true,
        )
        .await
    }

    async fn launch(
        l1_ws_url: String,
        portal_address: Address,
        chain_id: u64,
    ) -> eyre::Result<Self> {
        // Generate a throwaway signer for tests that don't use encrypted deposits.
        let throwaway_key = k256::SecretKey::from_slice(&[0x01; 32]).expect("valid throwaway key");
        let signer = alloy_signer_local::PrivateKeySigner::from(throwaway_key);
        Self::launch_with_genesis_and_withdrawal_batch_interval(
            l1_ws_url,
            portal_address,
            chain_id,
            None,
            signer,
            8,
            None,
            true,
        )
        .await
    }

    async fn launch_with_genesis(
        l1_ws_url: String,
        portal_address: Address,
        chain_id: u64,
        custom_genesis: Option<Genesis>,
        sequencer_signer: alloy_signer_local::PrivateKeySigner,
    ) -> eyre::Result<Self> {
        Self::launch_with_genesis_and_withdrawal_batch_interval(
            l1_ws_url,
            portal_address,
            chain_id,
            custom_genesis,
            sequencer_signer,
            8,
            None,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn launch_with_genesis_and_withdrawal_batch_interval(
        l1_ws_url: String,
        portal_address: Address,
        chain_id: u64,
        custom_genesis: Option<Genesis>,
        sequencer_signer: alloy_signer_local::PrivateKeySigner,
        withdrawal_batch_interval_blocks: u64,
        p2p_config: Option<P2pConfig>,
        spawn_engine: bool,
    ) -> eyre::Result<Self> {
        Self::launch_with_genesis_and_withdrawal_batch_interval_and_decryption_keys(
            l1_ws_url,
            portal_address,
            chain_id,
            custom_genesis,
            sequencer_signer,
            withdrawal_batch_interval_blocks,
            p2p_config,
            spawn_engine,
            Vec::new(),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn launch_with_genesis_and_withdrawal_batch_interval_and_decryption_keys(
        l1_ws_url: String,
        portal_address: Address,
        chain_id: u64,
        custom_genesis: Option<Genesis>,
        sequencer_signer: alloy_signer_local::PrivateKeySigner,
        withdrawal_batch_interval_blocks: u64,
        p2p_config: Option<P2pConfig>,
        spawn_engine: bool,
        additional_decryption_keys: Vec<SecretKey>,
        prover_config: Option<ZoneProverConfig>,
    ) -> eyre::Result<Self> {
        let tasks = Runtime::test();
        let is_local_dummy_l1 = l1_ws_url == DUMMY_L1_URL;
        let l1_ws_url = if is_local_dummy_l1 {
            spawn_test_l1_rpc(1337).await?
        } else {
            l1_ws_url
        };
        let mut l1_http_url = url::Url::parse(&l1_ws_url)?;
        match l1_http_url.scheme() {
            "ws" => l1_http_url.set_scheme("http").expect("valid HTTP scheme"),
            "wss" => l1_http_url.set_scheme("https").expect("valid HTTPS scheme"),
            _ => {}
        }
        let l1_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http(l1_http_url.clone())
            .erased();
        let redacted_l1_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http(l1_http_url)
            .erased();

        let (chain_id, zone_id) = if portal_address.is_zero() {
            (chain_id, 0)
        } else {
            let parent_chain_id = l1_provider.get_chain_id().await?;
            let zone_id = ZonePortal::new(portal_address, &l1_provider)
                .zoneId()
                .call()
                .await?;
            (zone_chain_id(parent_chain_id, zone_id)?, zone_id)
        };

        let mut genesis = custom_genesis.unwrap_or_else(|| {
            zone_node::genesis::genesis_template().expect("valid zone genesis template")
        });
        genesis.config.chain_id = chain_id;
        let chain_spec = ZoneChainSpec::from_genesis(genesis)?;

        let mut zone_node = ZoneNode::new(
            l1_ws_url,
            portal_address,
            4,
            std::time::Duration::from_millis(100),
        )
        .with_withdrawal_batch_interval_blocks(withdrawal_batch_interval_blocks)
        .with_redacted_rpc(ZoneRedactedRpcConfig {
            zone_id,
            ..Default::default()
        })
        .with_deposit_decryption_keys(
            std::iter::once(SecretKey::from(sequencer_signer.credential()))
                .chain(additional_decryption_keys),
        );
        if portal_address.is_zero() {
            zone_node = zone_node
                .with_deposit_decryption_keys(std::iter::once(L1Fixture::encryption_key()));
        }
        if is_local_dummy_l1 {
            zone_node = zone_node
                .with_l1_chain_id(1337)
                .with_l1_state_provider_retry_limits(0, NonZeroU32::MIN);
        }
        let p2p_enabled = p2p_config.is_some();
        if p2p_enabled && !is_local_dummy_l1 && portal_address.is_zero() {
            // Synthetic multi-sequencer harness nodes run against an RPC that cannot serve
            // storage reads: every read must come from the seeded cache. A real Portal must
            // retain normal L1 retry behavior for its independent attestation reconstruction.
            zone_node = zone_node.with_l1_state_provider_retry_limits(0, NonZeroU32::MIN);
        }
        let mut leadership = None;
        if let Some(p2p_config) = p2p_config {
            // The finalized L1 subscriber never observes a portal in this harness, so seed
            // the manifest's initial record unless the test pre-published a schedule.
            let schedule = p2p_config.leadership();
            if !schedule.is_initialized() {
                schedule.publish(p2p_config.manifest().bootstrap_leadership())?;
            }
            leadership = Some(schedule);
            let l1_transaction_signer = p2p_config.block_attestation_signer();
            let zone_id = p2p_config.zone_id();
            // Every multi-sequencer node holds complete sequencer resources; the role
            // controller decides at runtime whether this node's engine and sequencer
            // background tasks are active.
            zone_node = zone_node
                .with_p2p(p2p_config)
                .with_sequencer(ZoneSequencerAddOnsConfig {
                    sequencer_signer: sequencer_signer.clone(),
                    l1_transaction_signer,
                    zone_id,
                    zone_poll_interval: Duration::from_secs(1),
                    batch_anchor_config: Default::default(),
                    withdrawal_poll_interval: Duration::from_secs(5),
                    withdrawal_batch_limits: Default::default(),
                });
        }
        if let Some(config) = prover_config {
            zone_node = zone_node.with_prover(config);
        }
        // Multi-sequencer nodes run the real role controller, which owns the engine; the
        // harness must not drive a second head writer against the same queue.
        let spawn_engine = spawn_engine && !p2p_enabled;
        if spawn_engine {
            // The harness drives its own ZoneEngine against the shared queue below, so the
            // node must keep enqueueing deposits even without a sequencer or P2P config.
            zone_node = zone_node.with_external_deposit_consumer();
        }

        // Don't use .dev() — it spawns a LocalMiner that conflicts with ZoneEngine.
        // The ZoneEngine is the sole block producer; it advances the chain when L1
        // blocks arrive in the deposit queue.
        let node_config = NodeConfig::new(Arc::new(chain_spec))
            .with_unused_ports()
            .with_rpc(
                RpcServerArgs::default()
                    .with_unused_ports()
                    .with_http()
                    .with_http_api(RpcModuleSelection::All),
            )
            .apply(|mut c| {
                c.network.discovery.disable_discovery = true;
                // A node attached to a real portal may have the standalone sequencer started
                // after launch. Match production by making every settleable block durable
                // immediately. Synthetic P2P nodes need the same policy for replication.
                if p2p_enabled || !portal_address.is_zero() {
                    c.engine.persistence_threshold = 0;
                    c.engine.memory_block_buffer_target = Some(0);
                }
                c
            });

        let deposit_queue = zone_node.deposit_queue();
        let enabled_tokens = zone_node.enabled_tokens();
        let l1_state_cache = zone_node.l1_state_cache();
        let l1_block_tracker = zone_node.l1_block_tracker();
        let deposit_decryption_keys = zone_node
            .deposit_decryption_keys()
            .expect("test sequencer configures deposit decryption keys");
        if portal_address.is_zero() {
            // Synthetic fixtures expose this key as Portal index 0 in the seeded L1 cache.
            // Direct queue injection bypasses the subscriber that normally observes and binds
            // SequencerEncryptionKeyUpdated, so mirror that binding before starting the engine.
            let fixture_key = L1Fixture::encryption_key();
            let (x, y_parity) = compressed_x_and_parity(fixture_key.public_key().as_affine());
            deposit_decryption_keys.apply_rotation(&EncryptionKeyRotation {
                x,
                y_parity,
                pubkey: encryption_key_address(x, y_parity)?,
                key_index: U256::ZERO,
                activation_block: 0,
            })?;
        }
        if is_local_dummy_l1 {
            let mut cache = l1_state_cache.lock();
            seed_raw_tip403_token_policy(&mut cache, 0, PATH_USD_ADDRESS, ALLOW_ALL_POLICY_ID);
        }

        let node_handle = NodeBuilder::new(node_config)
            .testing_node(tasks.clone())
            .node(zone_node)
            .launch_with_debug_capabilities()
            .await?;

        let mut engine_stop = None;
        if spawn_engine {
            let provider = node_handle.node.provider();
            let last_header = provider
                .sealed_header(provider.best_block_number()?)?
                .ok_or_else(|| eyre::eyre!("no latest block header"))?;
            let stop = CancellationToken::new();
            engine_stop = Some(stop.clone());
            let engine = zone_node::ZoneEngine::new(
                provider.chain_spec(),
                node_handle.node.add_ons_handle.beacon_engine_handle.clone(),
                node_handle.node.payload_builder_handle.clone(),
                deposit_queue.clone(),
                l1_block_tracker.clone(),
                last_header,
                sequencer_signer.address(),
                deposit_decryption_keys,
                portal_address,
                None,
            );
            node_handle
                .node
                .task_executor
                .spawn_critical_task("zone-engine", async move {
                    engine.run_until(stop).await;
                });
        }

        let http_url: url::Url = node_handle
            .node
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        // Build the real redacted RPC API while the handle is still concrete,
        // before type-erasing it into Box<dyn TestNodeHandle>.
        let eth_handlers = node_handle.node.eth_handlers().clone();
        let rpc_enabled_tokens = enabled_tokens.clone();
        let rpc_l1_provider = redacted_l1_provider;
        let rpc_api_factory = Arc::new(move |config: zone_node::rpc::RedactedRpcConfig| {
            let eth_handlers = eth_handlers.clone();
            let enabled_tokens = rpc_enabled_tokens.clone();
            let l1_provider = rpc_l1_provider.clone();
            Box::pin(async move {
                Ok(Arc::new(zone_node::rpc::ZoneRpc::new(
                    eth_handlers,
                    config,
                    enabled_tokens,
                    l1_provider,
                )) as Arc<dyn zone_node::rpc::ZoneRpcApi>)
            })
                as Pin<Box<dyn Future<Output = eyre::Result<Arc<dyn zone_node::rpc::ZoneRpcApi>>>>>
        });

        Ok(Self {
            deposit_queue,
            enabled_tokens,
            http_url,
            l1_provider,
            portal_address,
            l1_state_cache,
            l1_block_tracker,
            rpc_api_factory,
            node_handle: Box::new(node_handle),
            engine_stop,
            leadership,
            _tasks: tasks,
        })
    }
}

/// A Tempo L1 node running in dev mode for integration testing.
///
/// Starts an in-process Tempo node that produces blocks automatically
/// (500ms block time), providing both HTTP and WebSocket endpoints.
///
/// # Usage
///
/// ```ignore
/// let l1 = L1TestNode::start().await?;
/// let provider = ProviderBuilder::new().connect_http(l1.http_url().clone());
/// let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), Address::ZERO).await?;
/// ```
pub(crate) struct L1TestNode {
    http_url: url::Url,
    ws_url: url::Url,
    _node_handle: Box<dyn TestNodeHandle>,
    _tasks: Runtime,
}

/// Explicit account-access and callback-gateway configuration for a test zone.
#[derive(Clone, Debug)]
pub(crate) struct ZoneCreationConfig {
    pub(crate) access_mode: bool,
    pub(crate) gateway_mode: bool,
    pub(crate) allowed_accounts: Vec<Address>,
    pub(crate) zone_gateways: Vec<Address>,
}

impl ZoneCreationConfig {
    pub(crate) fn closed(mut allowed_accounts: Vec<Address>) -> Self {
        allowed_accounts.sort_unstable();
        allowed_accounts.dedup();
        Self {
            access_mode: true,
            gateway_mode: true,
            allowed_accounts,
            zone_gateways: Vec::new(),
        }
    }

    pub(crate) fn open() -> Self {
        Self {
            access_mode: false,
            gateway_mode: false,
            allowed_accounts: Vec::new(),
            zone_gateways: Vec::new(),
        }
    }

    pub(crate) fn open_with_enforced_gateways() -> Self {
        Self {
            gateway_mode: true,
            ..Self::open()
        }
    }
}

impl L1TestNode {
    /// Returns the HTTP RPC URL for this L1 node.
    pub(crate) fn http_url(&self) -> &url::Url {
        &self.http_url
    }

    /// Returns the WebSocket RPC URL for this L1 node.
    pub(crate) fn ws_url(&self) -> &url::Url {
        &self.ws_url
    }

    /// Returns an unsigned HTTP provider connected to this L1 node.
    pub(crate) fn provider(&self) -> alloy_provider::DynProvider {
        ProviderBuilder::new()
            .connect_http(self.http_url.clone())
            .erased()
    }

    /// Returns a signer for the pre-funded dev account.
    ///
    /// This is the first key derived from [`TEST_MNEMONIC`] (`test test … junk`),
    /// corresponding to address `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`.
    /// The account is pre-funded with pathUSD in `test-genesis.json`.
    pub(crate) fn dev_signer(&self) -> alloy_signer_local::PrivateKeySigner {
        l1_dev_signer()
    }

    /// Returns the address of the pre-funded dev account.
    pub(crate) fn dev_address(&self) -> Address {
        self.dev_signer().address()
    }

    /// Returns the signer used as the ZonePortal admin (mnemonic index 2).
    ///
    /// Distinct from the dev account (which acts as the sequencer) so the test
    /// suite exercises the admin/sequencer role separation. This account is NOT
    /// pre-funded; [`create_zone`](Self::create_zone) funds it with pathUSD for
    /// gas so it can make admin-only portal calls.
    pub(crate) fn admin_signer(&self) -> alloy_signer_local::PrivateKeySigner {
        self.signer_at(2)
    }

    /// Returns the address of the ZonePortal admin account.
    pub(crate) fn admin_address(&self) -> Address {
        self.admin_signer().address()
    }

    /// Returns a signer for the second test account (mnemonic index 1).
    ///
    /// This account is NOT pre-funded — use [`fund_user`](Self::fund_user) to
    /// transfer pathUSD from the dev account before depositing.
    pub(crate) fn user_signer(&self) -> alloy_signer_local::PrivateKeySigner {
        self.signer_at(1)
    }

    /// Returns a signer derived from [`TEST_MNEMONIC`] at the given BIP-44 index.
    pub(crate) fn signer_at(&self, index: u32) -> alloy_signer_local::PrivateKeySigner {
        signer_at(index)
    }

    /// Transfer pathUSD from the dev account to a recipient on L1.
    pub(crate) async fn fund_user(&self, to: Address, amount: u128) -> eyre::Result<()> {
        use tempo_contracts::precompiles::ITIP20;
        use tempo_precompiles::PATH_USD_ADDRESS;

        let provider = self.dev_provider();
        let receipt = ITIP20::new(PATH_USD_ADDRESS, &provider)
            .transfer(to, U256::from(amount))
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "fund_user transfer failed");
        Ok(())
    }

    /// Read a TIP-20 token balance on L1 (single-shot, no polling).
    pub(crate) async fn balance_of(&self, token: Address, account: Address) -> eyre::Result<U256> {
        use tempo_contracts::precompiles::ITIP20;
        Ok(ITIP20::new(token, self.provider())
            .balanceOf(account)
            .call()
            .await?)
    }

    /// Wait for a TIP-20 token balance to reach at least `min_balance` on L1.
    pub(crate) async fn wait_for_balance(
        &self,
        token: Address,
        account: Address,
        min_balance: U256,
        timeout: Duration,
    ) -> eyre::Result<U256> {
        use tempo_contracts::precompiles::ITIP20;

        let tip20 = ITIP20::new(token, self.provider());
        poll_until(timeout, DEFAULT_POLL, "L1 token balance", || {
            let tip20 = &tip20;
            async move {
                let balance = tip20.balanceOf(account).call().await?;
                if balance >= min_balance {
                    Ok(Some(balance))
                } else {
                    Ok(None)
                }
            }
        })
        .await
    }

    /// Assert that a `BatchSubmitted` event exists on the portal.
    pub(crate) async fn assert_batch_submitted(&self, portal_address: Address) -> eyre::Result<()> {
        use tempo_zone_contracts::ZonePortal;
        let portal = ZonePortal::new(portal_address, self.provider());
        let events = portal
            .BatchSubmitted_1_filter()
            .from_block(0)
            .query()
            .await?;
        eyre::ensure!(
            !events.is_empty(),
            "expected at least one BatchSubmitted event on L1"
        );
        Ok(())
    }

    /// Assert that a `WithdrawalProcessed` event exists on the portal matching `to` and `amount`.
    pub(crate) async fn assert_withdrawal_processed(
        &self,
        portal_address: Address,
        to: Address,
        amount: u128,
    ) -> eyre::Result<()> {
        use tempo_zone_contracts::ZonePortal;
        let portal = ZonePortal::new(portal_address, self.provider());
        let events = portal
            .WithdrawalProcessed_filter()
            .from_block(0)
            .query()
            .await?;
        let found = events.iter().any(|(e, _)| e.to == to && e.amount == amount);
        eyre::ensure!(
            found,
            "expected WithdrawalProcessed event for {to} with amount {amount}"
        );
        Ok(())
    }

    /// Assert that a `WithdrawalProcessed` event exists with the expected callback result.
    pub(crate) async fn assert_withdrawal_processed_with_status(
        &self,
        portal_address: Address,
        to: Address,
        token: Address,
        amount: u128,
        callback_success: bool,
    ) -> eyre::Result<()> {
        use tempo_zone_contracts::ZonePortal;
        let portal = ZonePortal::new(portal_address, self.provider());
        let events = portal
            .WithdrawalProcessed_filter()
            .from_block(0)
            .query()
            .await?;
        let found = events.iter().any(|(e, _)| {
            e.to == to
                && e.token == token
                && e.amount == amount
                && e.callbackSuccess == callback_success
        });
        eyre::ensure!(
            found,
            "expected WithdrawalProcessed event for {to} with token {token} amount {amount} and callbackSuccess={callback_success}"
        );
        Ok(())
    }

    /// Wait for a matching withdrawal result and return its callback status.
    pub(crate) async fn wait_for_withdrawal_processed_status(
        &self,
        portal_address: Address,
        to: Address,
        token: Address,
        amount: u128,
        timeout: Duration,
    ) -> eyre::Result<bool> {
        use tempo_zone_contracts::ZonePortal;
        let portal = ZonePortal::new(portal_address, self.provider());
        poll_until(timeout, DEFAULT_POLL, "WithdrawalProcessed event", || {
            let portal = &portal;
            async move {
                let events = portal
                    .WithdrawalProcessed_filter()
                    .from_block(0)
                    .query()
                    .await?;
                Ok(events
                    .iter()
                    .find(|(event, _)| {
                        event.to == to && event.token == token && event.amount == amount
                    })
                    .map(|(event, _)| event.callbackSuccess))
            }
        })
        .await
    }

    /// Assert that matching withdrawal results were emitted in FIFO order.
    pub(crate) async fn assert_withdrawals_processed_in_order(
        &self,
        portal_address: Address,
        expected: &[(Address, Address, u128, bool)],
    ) -> eyre::Result<()> {
        use tempo_zone_contracts::ZonePortal;
        let portal = ZonePortal::new(portal_address, self.provider());
        let events = portal
            .WithdrawalProcessed_filter()
            .from_block(0)
            .query()
            .await?;
        let mut expected_index = 0;
        for (event, _) in events {
            if let Some((to, token, amount, success)) = expected.get(expected_index)
                && event.to == *to
                && event.token == *token
                && event.amount == *amount
                && event.callbackSuccess == *success
            {
                expected_index += 1;
            }
        }
        eyre::ensure!(
            expected_index == expected.len(),
            "expected ordered withdrawal results {expected:?}, matched only {expected_index}"
        );
        Ok(())
    }

    /// Returns an HTTP provider with the dev account wallet attached.
    pub(crate) fn dev_provider(&self) -> alloy_provider::DynProvider {
        self.provider_with_signer(self.dev_signer())
    }

    /// Returns an HTTP provider with the admin account wallet attached.
    ///
    /// Used for `onlyAdmin` portal calls so they are signed by the admin key
    /// rather than the dev (sequencer) key.
    pub(crate) fn admin_provider(&self) -> alloy_provider::DynProvider {
        self.provider_with_signer(self.admin_signer())
    }

    /// Returns an HTTP provider with an explicit signer attached.
    pub(crate) fn provider_with_signer(
        &self,
        signer: alloy_signer_local::PrivateKeySigner,
    ) -> alloy_provider::DynProvider {
        ProviderBuilder::new()
            .wallet(signer)
            .connect_http(self.http_url.clone())
            .erased()
    }

    /// Create a zone through the native ZoneFactory.
    ///
    /// Combines [`native_zone_factory`](Self::native_zone_factory) and
    /// [`create_zone`](Self::create_zone). Returns the portal address.
    pub(crate) async fn deploy_zone(&self) -> eyre::Result<Address> {
        let factory = self.native_zone_factory().await?;
        self.create_zone(factory).await
    }

    /// Wait for a withdrawal to be fully processed on L1 (pathUSD).
    ///
    /// Polls the account's L1 token balance until it increases by at least
    /// `amount` from the caller-provided pre-withdrawal balance, then asserts
    /// both `BatchSubmitted` and `WithdrawalProcessed` events exist on the portal.
    pub(crate) async fn wait_for_withdrawal_on_l1(
        &self,
        portal_address: Address,
        account: Address,
        balance_before: U256,
        amount: u128,
        timeout: Duration,
    ) -> eyre::Result<()> {
        use tempo_precompiles::PATH_USD_ADDRESS;
        self.wait_for_withdrawal_on_l1_token(
            portal_address,
            PATH_USD_ADDRESS,
            account,
            balance_before,
            amount,
            timeout,
        )
        .await
    }

    /// Wait for a withdrawal of a specific token to be fully processed on L1.
    ///
    /// `balance_before` must be captured before submitting the withdrawal request.
    pub(crate) async fn wait_for_withdrawal_on_l1_token(
        &self,
        portal_address: Address,
        token: Address,
        account: Address,
        balance_before: U256,
        amount: u128,
        timeout: Duration,
    ) -> eyre::Result<()> {
        let expected = balance_before + U256::from(amount);
        self.wait_for_balance(token, account, expected, timeout)
            .await?;
        self.assert_batch_submitted(portal_address).await?;
        self.assert_withdrawal_processed(portal_address, account, amount)
            .await
    }

    /// Create a StablecoinDEX pair for a base token.
    pub(crate) async fn create_dex_pair(&self, base_token: Address) -> eyre::Result<()> {
        let provider = self.dev_provider();
        let dex = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, &provider);
        let receipt = dex
            .createPair(base_token)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "createPair failed for {base_token}");
        Ok(())
    }

    /// Place a bid order on the StablecoinDEX using the dev account.
    pub(crate) async fn place_dex_bid_order(
        &self,
        base_token: Address,
        amount: u128,
        tick: i16,
    ) -> eyre::Result<()> {
        use tempo_contracts::precompiles::ITIP20;

        let provider = self.dev_provider();
        let quote_token = ITIP20::new(base_token, &provider)
            .quoteToken()
            .call()
            .await?;

        ITIP20::new(quote_token, &provider)
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?
            .get_receipt()
            .await?;

        let dex = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, &provider);
        let receipt = dex
            .place(base_token, amount, true, tick)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(
            receipt.status(),
            "place bid order failed for {base_token} amount {amount} at tick {tick}"
        );
        Ok(())
    }

    /// Place an ask order on the StablecoinDEX using the dev account.
    pub(crate) async fn place_dex_ask_order(
        &self,
        base_token: Address,
        amount: u128,
        tick: i16,
    ) -> eyre::Result<()> {
        use tempo_contracts::precompiles::ITIP20;

        let provider = self.dev_provider();
        ITIP20::new(base_token, &provider)
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?
            .get_receipt()
            .await?;

        let dex = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, &provider);
        let receipt = dex
            .place(base_token, amount, false, tick)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(
            receipt.status(),
            "place ask order failed for {base_token} amount {amount} at tick {tick}"
        );
        Ok(())
    }

    /// Quote a StablecoinDEX swap without executing it.
    pub(crate) async fn quote_dex_swap_exact_amount_in(
        &self,
        token_in: Address,
        token_out: Address,
        amount_in: u128,
    ) -> eyre::Result<u128> {
        let provider = self.provider();
        let dex = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, &provider);
        Ok(dex
            .quoteSwapExactAmountIn(token_in, token_out, amount_in)
            .call()
            .await?)
    }

    /// Verify and return the native ZoneFactory at TIP-1091's fixed address.
    pub(crate) async fn native_zone_factory(&self) -> eyre::Result<Address> {
        zone_node::dev::native_zone_factory(
            self.http_url.as_str(),
            alloy_network::EthereumWallet::from(self.dev_signer()),
        )
        .await
    }

    /// Create a zone on an existing ZoneFactory and return the portal address.
    ///
    /// Captures the current L1 header as the genesis anchor, then calls
    /// `createZone()` with pathUSD as the token, a distinct [`admin_address`] as
    /// the portal admin, and the dev account as the sequencer. This exercises the
    /// common deployment pattern of distinct admin and sequencer keys. The admin account is funded with pathUSD
    /// for gas so admin-only portal calls (e.g. `enableToken`) can be made, and the dev
    /// sequencer's encryption key is registered so the portal can accept deposits immediately.
    ///
    /// [`admin_address`]: Self::admin_address
    pub(crate) async fn create_zone(&self, factory_address: Address) -> eyre::Result<Address> {
        let config =
            ZoneCreationConfig::closed(vec![self.admin_address(), self.user_signer().address()]);
        let portal = self
            .create_zone_with_admin_sequencer_and_config(
                factory_address,
                self.admin_address(),
                self.dev_address(),
                config,
            )
            .await?;
        // The admin is not pre-funded; give it pathUSD to pay for gas on
        // admin-only portal calls.
        self.fund_user(self.admin_address(), 10_000_000).await?;
        let encryption_key = k256::SecretKey::from(self.dev_signer().credential());
        self.set_sequencer_encryption_key(portal, &encryption_key)
            .await?;
        Ok(portal)
    }

    /// Create a zone with an exact access-mode, membership, and gateway configuration.
    pub(crate) async fn create_zone_with_admin_sequencer_and_config(
        &self,
        factory_address: Address,
        admin: Address,
        sequencer: Address,
        config: ZoneCreationConfig,
    ) -> eyre::Result<Address> {
        self.create_zone_with_admin_sequencers_and_config(
            factory_address,
            admin,
            vec![sequencer],
            1,
            config,
        )
        .await
    }

    /// Create a zone with an explicit on-chain settlement signer set and threshold.
    pub(crate) async fn create_zone_with_admin_sequencers_and_config(
        &self,
        factory_address: Address,
        admin: Address,
        sequencers: Vec<Address>,
        threshold: u8,
        config: ZoneCreationConfig,
    ) -> eyre::Result<Address> {
        use tempo_precompiles::PATH_USD_ADDRESS;
        use tempo_zone_contracts::ZoneFactory;

        let l1_provider = self.dev_provider();
        let create_zone = ZoneFactory::createZoneCall {
            params: ZoneFactory::CreateZoneParams {
                admin,
                initialToken: PATH_USD_ADDRESS,
                accessMode: config.access_mode,
                gatewayMode: config.gateway_mode,
                allowedAccounts: config.allowed_accounts,
                zoneGateways: config.zone_gateways,
                sequencers,
                threshold,
                rpcUrl: String::new(),
            },
        };
        let receipt = l1_provider
            .send_transaction(
                TransactionRequest::default()
                    .to(factory_address)
                    .input(create_zone.abi_encode().into()),
            )
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "createZone failed");

        let zone_created = receipt
            .decoded_log::<ZoneFactory::ZoneCreated>()
            .ok_or_else(|| eyre::eyre!("ZoneCreated event not found"))?;

        Ok(zone_created.portal)
    }

    /// Deploy the SwapAndDepositRouter contract on L1 from the Foundry artifact.
    ///
    /// The constructor takes `(address stablecoinDEX, address zoneFactory)`.
    /// We pass `Address::ZERO` for the DEX since both zones use the same token.
    pub(crate) async fn deploy_router(&self, factory_address: Address) -> eyre::Result<Address> {
        self.deploy_router_with_dex(factory_address, Address::ZERO)
            .await
    }

    /// Deploy the SwapAndDepositRouter with a specific DEX address.
    ///
    /// Use this when the test requires actual token swaps via the StablecoinDEX.
    pub(crate) async fn deploy_router_with_dex(
        &self,
        factory_address: Address,
        dex_address: Address,
    ) -> eyre::Result<Address> {
        use alloy_network::TransactionBuilder as _;
        use alloy_rpc_types_eth::TransactionRequest;
        use alloy_sol_types::SolValue;

        let l1_provider = self.dev_provider();

        // Constructor: constructor(address _stablecoinDEX, address _zoneFactory)
        let mut deploy_bytes = forge_bytecode("SwapAndDepositRouter")?.to_vec();
        deploy_bytes.extend_from_slice(&(dex_address, factory_address).abi_encode());

        let deploy_tx = TransactionRequest::default().with_deploy_code(deploy_bytes);
        let receipt = l1_provider
            .send_transaction(deploy_tx)
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "SwapAndDepositRouter deployment failed");

        receipt
            .contract_address
            .ok_or_else(|| eyre::eyre!("SwapAndDepositRouter deployment missing contract address"))
    }

    /// Deploy two open zones for cross-zone routing, with separate sequencers.
    pub(crate) async fn deploy_two_open_zones_with_sequencers(
        &self,
        sequencer_a: alloy_signer_local::PrivateKeySigner,
        sequencer_b: alloy_signer_local::PrivateKeySigner,
    ) -> eyre::Result<(Address, Address, Address)> {
        let factory = self.native_zone_factory().await?;
        let portal_a = self
            .create_zone_with_admin_sequencer_and_config(
                factory,
                self.dev_address(),
                sequencer_a.address(),
                ZoneCreationConfig::open(),
            )
            .await?;
        let portal_b = self
            .create_zone_with_admin_sequencer_and_config(
                factory,
                self.dev_address(),
                sequencer_b.address(),
                ZoneCreationConfig::open(),
            )
            .await?;
        let encryption_key_a = k256::SecretKey::from(sequencer_a.credential());
        self.set_sequencer_encryption_key_with_signer(portal_a, &encryption_key_a, sequencer_a)
            .await?;
        let encryption_key_b = k256::SecretKey::from(sequencer_b.credential());
        self.set_sequencer_encryption_key_with_signer(portal_b, &encryption_key_b, sequencer_b)
            .await?;
        let router = self.deploy_router(factory).await?;

        Ok((portal_a, portal_b, router))
    }

    /// Create a new TIP-20 token on L1 via the factory precompile.
    ///
    /// Returns the new token's address.
    pub(crate) async fn create_tip20(
        &self,
        name: &str,
        symbol: &str,
        salt: B256,
    ) -> eyre::Result<Address> {
        use tempo_contracts::precompiles::ITIP20Factory;
        use tempo_precompiles::{PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS};

        let provider = self.dev_provider();
        let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, &provider);
        let receipt = factory
            .createToken_0(
                name.to_string(),
                symbol.to_string(),
                "USD".to_string(),
                PATH_USD_ADDRESS,
                self.dev_address(),
                salt,
            )
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "createToken failed");

        let event = receipt
            .decoded_log::<ITIP20Factory::TokenCreated>()
            .ok_or_else(|| eyre::eyre!("TokenCreated event not found"))?;

        Ok(event.token)
    }

    /// Enable a token on a ZonePortal (must be called by the admin).
    pub(crate) async fn enable_token_on_portal(
        &self,
        portal_address: Address,
        token: Address,
    ) -> eyre::Result<()> {
        use tempo_zone_contracts::ZonePortal;
        let provider = self.admin_provider();
        let portal = ZonePortal::new(portal_address, &provider);
        let receipt = portal
            .enableToken(token)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "enableToken failed");
        Ok(())
    }

    /// Update a portal callback gateway with the default distinct admin signer.
    pub(crate) async fn set_zone_gateway_on_portal(
        &self,
        portal_address: Address,
        gateway: Address,
        enabled: bool,
    ) -> eyre::Result<u64> {
        self.set_zone_gateway_on_portal_with_signer(
            portal_address,
            gateway,
            enabled,
            self.admin_signer(),
        )
        .await
    }

    /// Update account allowlist enforcement with the default portal admin.
    pub(crate) async fn set_access_mode_on_portal(
        &self,
        portal_address: Address,
        mode: bool,
    ) -> eyre::Result<u64> {
        use tempo_zone_contracts::ZonePortal;
        let provider = self.admin_provider();
        let portal = ZonePortal::new(portal_address, &provider);
        let receipt = portal
            .setAccessMode(mode)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "setAccessMode failed");
        eyre::ensure!(
            portal.isAccessEnforced().call().await? == mode,
            "L1 ZonePortal access mode did not update"
        );
        Ok(provider.get_block_number().await?)
    }

    /// Update callback gateway registration enforcement with the default portal admin.
    pub(crate) async fn set_gateway_mode_on_portal(
        &self,
        portal_address: Address,
        mode: bool,
    ) -> eyre::Result<u64> {
        use tempo_zone_contracts::ZonePortal;
        let provider = self.admin_provider();
        let portal = ZonePortal::new(portal_address, &provider);
        let receipt = portal
            .setGatewayMode(mode)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "setGatewayMode failed");
        eyre::ensure!(
            portal.isGatewayOpen().call().await? != mode,
            "L1 ZonePortal gateway mode did not update"
        );
        Ok(provider.get_block_number().await?)
    }

    /// Update a portal callback gateway with the signer that owns that portal's admin role.
    pub(crate) async fn set_zone_gateway_on_portal_with_signer(
        &self,
        portal_address: Address,
        gateway: Address,
        enabled: bool,
        admin_signer: alloy_signer_local::PrivateKeySigner,
    ) -> eyre::Result<u64> {
        use tempo_zone_contracts::ZonePortal;
        let provider = self.provider_with_signer(admin_signer);
        let portal = ZonePortal::new(portal_address, &provider);
        let receipt = portal
            .setGateway(gateway, enabled)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "setGateway failed");
        let expected_role = if enabled {
            PortalRole::CallbackGateway
        } else {
            PortalRole::None
        };
        eyre::ensure!(
            portal.hasRole(gateway, expected_role).call().await?,
            "L1 ZonePortal gateway role for {gateway} did not equal {expected_role:?}"
        );
        Ok(provider.get_block_number().await?)
    }

    /// Update closed-mode account membership with the default distinct admin signer.
    pub(crate) async fn set_allowed_account_on_portal(
        &self,
        portal_address: Address,
        account: Address,
        enabled: bool,
    ) -> eyre::Result<u64> {
        self.set_allowed_account_on_portal_with_signer(
            portal_address,
            account,
            enabled,
            self.admin_signer(),
        )
        .await
    }

    /// Update closed-mode account membership with an explicit portal admin signer.
    pub(crate) async fn set_allowed_account_on_portal_with_signer(
        &self,
        portal_address: Address,
        account: Address,
        enabled: bool,
        admin_signer: alloy_signer_local::PrivateKeySigner,
    ) -> eyre::Result<u64> {
        use tempo_zone_contracts::ZonePortal;
        let provider = self.provider_with_signer(admin_signer);
        let portal = ZonePortal::new(portal_address, &provider);
        let receipt = portal
            .setAllowedAccount(account, enabled)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "setAllowedAccount failed");
        let expected_role = if enabled {
            PortalRole::Account
        } else {
            PortalRole::None
        };
        eyre::ensure!(
            portal.hasRole(account, expected_role).call().await?,
            "L1 ZonePortal account role for {account} did not equal {expected_role:?}"
        );
        Ok(provider.get_block_number().await?)
    }

    /// Pause deposits for a token on the ZonePortal.
    pub(crate) async fn pause_deposits_on_portal(
        &self,
        portal_address: Address,
        token: Address,
    ) -> eyre::Result<()> {
        let provider = self.admin_provider();
        let portal = ZonePortal::new(portal_address, &provider);
        let receipt = portal
            .pauseDeposits(token)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "pauseDeposits failed");
        eyre::ensure!(
            !portal.areDepositsActive(token).call().await?,
            "deposits should be paused for {token}"
        );
        Ok(())
    }

    /// Set the sequencer encryption key on the ZonePortal.
    ///
    /// The sequencer must sign a proof-of-possession with the encryption key's
    /// private key. The POP message is `keccak256(abi.encode(portalAddress, x, yParity))`.
    pub(crate) async fn set_sequencer_encryption_key(
        &self,
        portal_address: Address,
        encryption_key: &k256::SecretKey,
    ) -> eyre::Result<()> {
        self.set_sequencer_encryption_key_with_signer(
            portal_address,
            encryption_key,
            self.dev_signer(),
        )
        .await
    }

    /// Set the sequencer encryption key using an explicit portal sequencer signer.
    pub(crate) async fn set_sequencer_encryption_key_with_signer(
        &self,
        portal_address: Address,
        encryption_key: &k256::SecretKey,
        sequencer_signer: alloy_signer_local::PrivateKeySigner,
    ) -> eyre::Result<()> {
        // Sign with the encryption key (not the sequencer's Ethereum key)
        let pop_signer = alloy_signer_local::PrivateKeySigner::from(encryption_key);

        let sequencer_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(sequencer_signer)
            .connect_http(self.http_url.clone());
        zone_sequencer::register_encryption_key(&sequencer_provider, portal_address, &pop_signer)
            .await?;
        Ok(())
    }

    /// Build a valid encrypted deposit payload for the current portal key.
    pub(crate) async fn encrypt_deposit_for_portal(
        &self,
        portal_address: Address,
        sender: Address,
        recipient: Address,
        memo: B256,
    ) -> eyre::Result<(U256, tempo_zone_contracts::DepositPayload)> {
        use tempo_zone_contracts::ZonePortal;
        use zone_precompiles::ecies;

        let portal = ZonePortal::new(portal_address, self.provider());
        let key_result = portal.sequencerEncryptionKey().call().await?;
        let key_count = portal.encryptionKeyCount().call().await?;
        eyre::ensure!(
            key_count > U256::ZERO,
            "no encryption key registered on portal"
        );
        let key_index = key_count - U256::ONE;

        let enc = ecies::encrypt_deposit(
            &key_result.x,
            key_result.yParity,
            recipient,
            memo,
            sender,
            portal_address,
            key_index,
        )
        .ok_or_else(|| eyre::eyre!("ECIES encryption failed"))?;

        Ok((
            key_index,
            tempo_zone_contracts::DepositPayload {
                ephemeralPubkeyX: enc.eph_pub_x,
                ephemeralPubkeyYParity: enc.eph_pub_y_parity,
                ciphertext: enc.ciphertext.into(),
                nonce: alloy_primitives::FixedBytes(enc.nonce),
                tag: alloy_primitives::FixedBytes(enc.tag),
            },
        ))
    }

    /// Transfer a specific TIP-20 token from the dev account to a recipient on L1.
    pub(crate) async fn fund_user_token(
        &self,
        token: Address,
        to: Address,
        amount: u128,
    ) -> eyre::Result<()> {
        use tempo_contracts::precompiles::ITIP20;
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(self.dev_signer())
            .connect_http(self.http_url.clone());
        let receipt = ITIP20::new(token, &provider)
            .transfer(to, U256::from(amount))
            // A transfer call would otherwise infer `token` as its L1 fee token. Newly created
            // test tokens intentionally have no FeeAMM pool, so pay gas explicitly in pathUSD.
            .fee_token(PATH_USD_ADDRESS)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "fund_user_token transfer failed");
        Ok(())
    }

    /// Mint tokens on L1.
    ///
    /// The dev account must be the admin of the token (set during `createToken`).
    /// Grants `ISSUER_ROLE` to self first (admin can grant roles), then mints.
    pub(crate) async fn mint_tip20(
        &self,
        token: Address,
        to: Address,
        amount: u128,
    ) -> eyre::Result<()> {
        use tempo_contracts::precompiles::{IRolesAuth, ITIP20};
        use tempo_precompiles::tip20::ISSUER_ROLE;

        let provider = self.dev_provider();

        // Admin can grant ISSUER_ROLE to self
        let receipt = IRolesAuth::new(token, &provider)
            .grantRole(ISSUER_ROLE, self.dev_address())
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "grantRole ISSUER failed on L1");

        let receipt = ITIP20::new(token, &provider)
            .mint(to, U256::from(amount))
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "mint_tip20 failed");
        Ok(())
    }

    /// Create a new BLACKLIST policy on L1. Returns the policy ID.
    pub(crate) async fn create_blacklist_policy(&self) -> eyre::Result<u64> {
        use tempo_contracts::precompiles::ITIP403Registry;
        use tempo_precompiles::TIP403_REGISTRY_ADDRESS;

        let provider = self.dev_provider();
        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &provider);
        let receipt = registry
            .createPolicy(self.dev_address(), ITIP403Registry::PolicyType::BLACKLIST)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "createPolicy (BLACKLIST) failed");

        let event = receipt
            .decoded_log::<ITIP403Registry::PolicyCreated>()
            .ok_or_else(|| eyre::eyre!("PolicyCreated event not found"))?;

        Ok(event.policyId)
    }

    /// Create a new WHITELIST policy on L1. Returns the policy ID.
    #[allow(dead_code)]
    pub(crate) async fn create_whitelist_policy(&self) -> eyre::Result<u64> {
        use tempo_contracts::precompiles::ITIP403Registry;
        use tempo_precompiles::TIP403_REGISTRY_ADDRESS;

        let provider = self.dev_provider();
        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &provider);
        let receipt = registry
            .createPolicy(self.dev_address(), ITIP403Registry::PolicyType::WHITELIST)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "createPolicy (WHITELIST) failed");

        let event = receipt
            .decoded_log::<ITIP403Registry::PolicyCreated>()
            .ok_or_else(|| eyre::eyre!("PolicyCreated event not found"))?;

        Ok(event.policyId)
    }

    /// Add an address to a blacklist policy.
    pub(crate) async fn blacklist_address(
        &self,
        policy_id: u64,
        account: Address,
    ) -> eyre::Result<()> {
        use tempo_contracts::precompiles::ITIP403Registry;
        use tempo_precompiles::TIP403_REGISTRY_ADDRESS;

        let provider = self.dev_provider();
        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &provider);
        let receipt = registry
            .modifyPolicyBlacklist(policy_id, account, true)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "modifyPolicyBlacklist failed");
        Ok(())
    }

    /// Add an address to a whitelist policy.
    #[allow(dead_code)]
    pub(crate) async fn whitelist_address(
        &self,
        policy_id: u64,
        account: Address,
    ) -> eyre::Result<()> {
        use tempo_contracts::precompiles::ITIP403Registry;
        use tempo_precompiles::TIP403_REGISTRY_ADDRESS;

        let provider = self.dev_provider();
        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &provider);
        let receipt = registry
            .modifyPolicyWhitelist(policy_id, account, true)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "modifyPolicyWhitelist failed");
        Ok(())
    }

    /// Change a token's transfer policy on L1.
    ///
    /// The dev account must hold `DEFAULT_ADMIN_ROLE` on the token.
    pub(crate) async fn change_transfer_policy_id(
        &self,
        token: Address,
        policy_id: u64,
    ) -> eyre::Result<()> {
        use tempo_contracts::precompiles::ITIP20;

        let provider = self.dev_provider();
        let receipt = ITIP20::new(token, &provider)
            .changeTransferPolicyId(policy_id)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "changeTransferPolicyId failed");
        Ok(())
    }

    /// Create a COMPOUND policy on L1 that delegates to sub-policies by role.
    ///
    /// Returns the compound policy ID.
    pub(crate) async fn create_compound_policy(
        &self,
        sender_policy_id: u64,
        recipient_policy_id: u64,
        mint_recipient_policy_id: u64,
    ) -> eyre::Result<u64> {
        use tempo_contracts::precompiles::ITIP403Registry;
        use tempo_precompiles::TIP403_REGISTRY_ADDRESS;

        let provider = self.dev_provider();
        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &provider);
        let receipt = registry
            .createCompoundPolicy(
                sender_policy_id,
                recipient_policy_id,
                mint_recipient_policy_id,
            )
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "createCompoundPolicy failed");

        let event = receipt
            .decoded_log::<ITIP403Registry::CompoundPolicyCreated>()
            .ok_or_else(|| eyre::eyre!("CompoundPolicyCreated event not found"))?;

        Ok(event.policyId)
    }

    /// Check if a user is authorized under a policy on L1.
    pub(crate) async fn is_authorized(&self, policy_id: u64, user: Address) -> eyre::Result<bool> {
        use tempo_contracts::precompiles::ITIP403Registry;
        use tempo_precompiles::TIP403_REGISTRY_ADDRESS;

        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, self.provider());
        Ok(registry.isAuthorized(policy_id, user).call().await?)
    }

    /// Start an L1 dev node with the default configuration (500ms block time).
    pub(crate) async fn start() -> eyre::Result<Self> {
        Self::start_with(|_| {}).await
    }

    /// Start an L1 dev node, applying a closure to customise the [`NodeConfig`]
    /// before launch.
    ///
    /// The base config already has dev mode enabled, random ports, and full
    /// HTTP + WS RPC. The closure receives a `&mut NodeConfig` for last-mile
    /// tweaks (e.g. changing block time):
    ///
    /// ```ignore
    /// let l1 = L1TestNode::start_with(|cfg| {
    ///     cfg.dev.block_time = Some(Duration::from_secs(1));
    /// }).await?;
    /// ```
    pub(crate) async fn start_with(
        f: impl FnOnce(&mut NodeConfig<TempoChainSpec>),
    ) -> eyre::Result<Self> {
        let tasks = Runtime::test();

        let genesis: serde_json::Value =
            serde_json::from_str(include_str!("../assets/test-genesis.json"))?;
        let mut genesis = serde_json::from_value(genesis)?;
        install_native_zone_factory(&mut genesis, l1_dev_signer().address())?;
        let chain_spec = TempoChainSpec::from_genesis(genesis);

        let mut node_config = NodeConfig::new(Arc::new(chain_spec))
            .with_unused_ports()
            .dev()
            .with_rpc(
                RpcServerArgs::default()
                    .with_unused_ports()
                    .with_http()
                    .with_http_api(RpcModuleSelection::All)
                    .with_ws()
                    .with_ws_api(RpcModuleSelection::All),
            )
            .apply(|mut c| {
                c.dev.block_time = Some(Duration::from_millis(500));
                c.dev.finality_depth = std::num::NonZeroUsize::MIN;
                // Witness collection must prove older L1 checkpoints during catch-up.
                c.rpc.rpc_eth_proof_window = 100_000;
                c
            });

        f(&mut node_config);

        let node_handle = NodeBuilder::new(node_config)
            .testing_node(tasks.clone())
            .node(tempo_node::node::TempoNode::default())
            .launch_with_debug_capabilities()
            .await?;

        let http_url = node_handle
            .node
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();
        let ws_url = node_handle
            .node
            .rpc_server_handle()
            .ws_url()
            .unwrap()
            .parse()
            .unwrap();

        Ok(Self {
            http_url,
            ws_url,
            _node_handle: Box::new(node_handle),
            _tasks: tasks,
        })
    }
}

/// Patch a controlled post-creation test snapshot with the portal's token commitment.
///
/// This is intentionally test-only. It is sound for the shared integration fixture because the
/// fixture has exactly its genesis token and no queued deposits. Tests that exercise portal
/// creation replay pass a pre-portal block explicitly and leave the commitment empty.
async fn patch_clean_portal_snapshot<P: Provider<TempoNetwork>>(
    provider: &P,
    genesis: &mut Genesis,
    portal_address: Address,
    block_number: u64,
) -> eyre::Result<()> {
    let block_id = BlockId::number(block_number);
    let portal = ZonePortal::new(portal_address, provider);
    eyre::ensure!(
        portal.enabledTokenCount().block(block_id).call().await? == U256::ONE
            && portal
                .currentDepositQueueHash()
                .block(block_id)
                .call()
                .await?
                .is_zero(),
        "test snapshot at L1 block {block_number} is not a clean initial-token snapshot"
    );
    let token_enablement_hash = portal.tokenEnablementHash().block(block_id).call().await?;
    eyre::ensure!(
        !token_enablement_hash.is_zero(),
        "test snapshot at L1 block {block_number} has no initial-token commitment"
    );

    genesis
        .alloc
        .get_mut(&ZONE_INBOX_ADDRESS)
        .ok_or_else(|| eyre::eyre!("ZoneInbox not found in test genesis alloc"))?
        .storage
        .get_or_insert_with(Default::default)
        .insert(
            zone_precompiles::inbox::slots::PROCESSED_TOKEN_ENABLEMENT_HASH.into(),
            token_enablement_hash,
        );
    Ok(())
}

/// Build a zone test genesis anchored to a real L1 block.
///
/// Returns `(genesis, genesis_block_number)`.
async fn build_l1_anchored_genesis(
    l1_http_url: &url::Url,
    portal_address: Address,
) -> eyre::Result<(Genesis, u64)> {
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(l1_http_url.clone());

    let block = l1_provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .ok_or_else(|| eyre::eyre!("L1 latest block not found"))?;
    let l1_header: &TempoHeader = block.header.as_ref();
    let default_fee_token = if portal_address.is_zero() {
        PATH_USD_ADDRESS
    } else {
        ZonePortal::new(portal_address, &l1_provider)
            .enabledTokenAt(U256::ZERO)
            .call()
            .await?
    };
    let (mut genesis, genesis_block_number) =
        zone_node::genesis::l1_anchored_genesis(l1_header, default_fee_token)?;
    if !portal_address.is_zero() {
        patch_clean_portal_snapshot(
            &l1_provider,
            &mut genesis,
            portal_address,
            l1_header.inner.number,
        )
        .await?;
    }
    Ok((genesis, genesis_block_number))
}

/// Build a zone test genesis anchored to a specific L1 block number.
async fn build_l1_anchored_genesis_at_block(
    l1_http_url: &url::Url,
    portal_address: Address,
    block_number: u64,
) -> eyre::Result<(Genesis, u64)> {
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(l1_http_url.clone());

    let block = l1_provider
        .get_block_by_number(block_number.into())
        .await?
        .ok_or_else(|| eyre::eyre!("L1 block {block_number} not found"))?;
    let l1_header: &TempoHeader = block.header.as_ref();
    let default_fee_token = if portal_address.is_zero() {
        PATH_USD_ADDRESS
    } else {
        ZonePortal::new(portal_address, &l1_provider)
            .enabledTokenAt(U256::ZERO)
            .call()
            .await?
    };
    let (mut genesis, genesis_block_number) =
        zone_node::genesis::l1_anchored_genesis(l1_header, default_fee_token)?;
    if !portal_address.is_zero()
        && !l1_provider
            .get_code_at(portal_address)
            .number(block_number)
            .await?
            .is_empty()
    {
        patch_clean_portal_snapshot(&l1_provider, &mut genesis, portal_address, block_number)
            .await?;
    }
    Ok((genesis, genesis_block_number))
}

pub(crate) async fn batch_count(
    portal: &ZonePortal::ZonePortalInstance<alloy::providers::DynProvider>,
) -> eyre::Result<usize> {
    Ok(portal
        .BatchSubmitted_1_filter()
        .from_block(0)
        .query()
        .await?
        .len())
}

/// Poll an async condition until it returns `Some(T)` or the timeout expires.
pub(crate) async fn poll_until<T, Fut, F>(
    timeout: std::time::Duration,
    interval: std::time::Duration,
    description: &str,
    mut f: F,
) -> eyre::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = eyre::Result<Option<T>>>,
{
    let start = std::time::Instant::now();
    loop {
        if let Some(v) = f().await.wrap_err("poll iteration failed")? {
            return Ok(v);
        }
        if start.elapsed() > timeout {
            eyre::bail!("timed out after {timeout:?}: {description}");
        }
        tokio::time::sleep(interval).await;
    }
}

/// Arguments for [`ZoneAccount::withdraw_with`].
///
/// Use [`WithdrawalArgs::new`] for the common case (amount only, self-withdrawal),
/// then override individual fields as needed.
#[derive(Clone)]
pub(crate) struct WithdrawalArgs {
    pub amount: u128,
    pub to: Option<Address>,
    pub memo: B256,
    pub gas_limit: u64,
    pub zone_fallback_recipient: Option<Address>,
    pub data: alloy_primitives::Bytes,
    pub reveal_to: alloy_primitives::Bytes,
}

pub(crate) struct RouterDepositArgs {
    pub amount: u128,
    pub router: Address,
    pub token_out: Address,
    pub target_portal: Address,
    pub recipient: Address,
    pub tempo_refund_recipient: Address,
    pub memo: B256,
    pub min_amount_out: u128,
}

pub(crate) struct RouterCallbackArgs {
    pub amount: u128,
    pub router: Address,
    pub token_out: Address,
    pub target_portal: Address,
    pub key_index: U256,
    pub encrypted: tempo_zone_contracts::DepositPayload,
    pub tempo_refund_recipient: Address,
    pub min_amount_out: u128,
}

impl WithdrawalArgs {
    /// Simple withdrawal: send `amount` back to self with no callback.
    pub(crate) fn new(amount: u128) -> Self {
        Self {
            amount,
            to: None,
            memo: B256::ZERO,
            gas_limit: 0,
            zone_fallback_recipient: None,
            data: alloy_primitives::Bytes::new(),
            reveal_to: alloy_primitives::Bytes::new(),
        }
    }

    /// Encrypt a router callback for the target portal.
    pub(crate) async fn swap_and_deposit_via_router(
        l1: &L1TestNode,
        args: RouterDepositArgs,
    ) -> eyre::Result<Self> {
        let (key_index, encrypted) = l1
            .encrypt_deposit_for_portal(args.target_portal, args.router, args.recipient, args.memo)
            .await?;
        Ok(Self::swap_and_deposit_via_router_callback(
            RouterCallbackArgs {
                amount: args.amount,
                router: args.router,
                token_out: args.token_out,
                target_portal: args.target_portal,
                key_index,
                encrypted,
                tempo_refund_recipient: args.tempo_refund_recipient,
                min_amount_out: args.min_amount_out,
            },
        ))
    }

    /// Prepared router callback: optionally swap, then deposit into `target_portal`.
    pub(crate) fn swap_and_deposit_via_router_callback(args: RouterCallbackArgs) -> Self {
        let callback_data = tempo_zone_contracts::SwapAndDepositRouterCallback {
            token_out: args.token_out,
            target_portal: args.target_portal,
            key_index: args.key_index,
            encrypted: args.encrypted,
            tempo_refund_recipient: args.tempo_refund_recipient,
            min_amount_out: args.min_amount_out,
        }
        .abi_encode();

        Self {
            amount: args.amount,
            to: Some(args.router),
            memo: B256::ZERO,
            gas_limit: 2_000_000,
            zone_fallback_recipient: None, // defaults to self
            data: alloy_primitives::Bytes::from(callback_data),
            reveal_to: alloy_primitives::Bytes::new(),
        }
    }

    /// Cross-zone withdrawal via the [`SwapAndDepositRouter`].
    ///
    /// The withdrawal callback sends tokens to the router, which deposits them
    /// into `target_portal` for `recipient`. Both zones must use the same token
    /// (no swap needed — `tokenOut == tokenIn`).
    pub(crate) async fn cross_zone_via_router(
        l1: &L1TestNode,
        amount: u128,
        router: Address,
        target_portal: Address,
        token: Address,
        recipient: Address,
        tempo_refund_recipient: Address,
    ) -> eyre::Result<Self> {
        Self::swap_and_deposit_via_router(
            l1,
            RouterDepositArgs {
                amount,
                router,
                token_out: token,
                target_portal,
                recipient,
                tempo_refund_recipient,
                memo: B256::ZERO,
                min_amount_out: 0,
            },
        )
        .await
    }
}

/// A test account that can interact with both L1 and L2 (zone) nodes.
///
/// Wraps a signing key and provides high-level helpers for the common
/// deposit/withdrawal flow, tracking approvals to avoid redundant transactions.
pub(crate) struct ZoneAccount {
    /// The account's on-chain address (derived from `signer`).
    address: Address,
    /// Wallet-attached provider for Tempo L1 (deposits, approvals).
    l1_provider: alloy_provider::DynProvider,
    /// Wallet-attached provider for the Zone L2 (withdrawals, approvals).
    l2_provider: alloy_provider::DynProvider,
    /// The ZonePortal contract address on L1 for this zone.
    portal_address: Address,
    /// Whether we've already approved the portal to spend pathUSD on L1.
    l1_portal_approved: bool,
    /// Tokens already approved for the ZoneOutbox on L2.
    l2_outbox_approved_tokens: BTreeSet<Address>,
}

impl ZoneAccount {
    /// Create a new `ZoneAccount` from an [`L1TestNode`] and [`ZoneTestNode`].
    ///
    /// Uses the L1's **user** signer (mnemonic index 1) as the account key,
    /// separate from the dev/sequencer account (index 0). The same key signs
    /// both L1 and L2 transactions.
    ///
    /// The user account must be funded on L1 before depositing — call
    /// [`L1TestNode::fund_user`] first.
    pub(crate) fn from_l1_and_zone(
        l1: &L1TestNode,
        zone: &ZoneTestNode,
        portal_address: Address,
    ) -> Self {
        Self::with_signer(l1.user_signer(), l1, zone, portal_address)
    }

    /// Create a `ZoneAccount` with a custom signer.
    ///
    /// Unlike [`from_l1_and_zone`](Self::from_l1_and_zone) which uses the L1's
    /// user signer, this allows creating an account with any private key —
    /// useful when the account was funded via encrypted deposit to a specific
    /// recipient.
    pub(crate) fn with_signer(
        signer: alloy_signer_local::PrivateKeySigner,
        l1: &L1TestNode,
        zone: &ZoneTestNode,
        portal_address: Address,
    ) -> Self {
        let address = signer.address();

        let l1_provider = l1.provider_with_signer(signer.clone());

        let l2_provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(zone.http_url().clone())
            .erased();

        Self {
            address,
            l1_provider,
            l2_provider,
            portal_address,
            l1_portal_approved: false,
            l2_outbox_approved_tokens: BTreeSet::new(),
        }
    }

    /// The account's address.
    pub(crate) fn address(&self) -> Address {
        self.address
    }

    /// The account's L1 provider.
    pub(crate) fn l1_provider(&self) -> &alloy_provider::DynProvider {
        &self.l1_provider
    }

    /// Approve the ZonePortal to spend pathUSD on L1, then deposit.
    ///
    /// Skips approval if already approved in this session.
    /// Waits for the expected post-deposit balance on L2 and returns it.
    pub(crate) async fn deposit(
        &mut self,
        amount: u128,
        timeout: Duration,
        zone: &ZoneTestNode,
    ) -> eyre::Result<U256> {
        self.deposit_to(self.address, amount, timeout, zone).await
    }

    /// Submit a pathUSD deposit on L1 without waiting for the zone to process it.
    ///
    /// Returns the L1 block containing the deposit. This is useful for tests that deliberately
    /// prevent a zone node from observing L1 and need to restore connectivity before awaiting the
    /// corresponding mint.
    pub(crate) async fn submit_deposit(&mut self, amount: u128) -> eyre::Result<u64> {
        self.submit_deposit_with_memo(amount, self.address, B256::ZERO)
            .await
    }

    /// Simulate an encrypted deposit without submitting a transaction.
    pub(crate) async fn simulate_deposit(
        &self,
        amount: u128,
        recipient: Address,
        tempo_refund_recipient: Address,
    ) -> eyre::Result<()> {
        use tempo_precompiles::PATH_USD_ADDRESS;
        use tempo_zone_contracts::ZonePortal;

        let (key_index, encrypted) = self.prepare_deposit(recipient, B256::ZERO).await?;

        ZonePortal::new(self.portal_address, &self.l1_provider)
            .deposit(
                PATH_USD_ADDRESS,
                amount,
                key_index,
                encrypted,
                tempo_refund_recipient,
            )
            .call()
            .await?;
        Ok(())
    }

    /// Approve the ZonePortal to spend pathUSD on L1, then deposit to a specific recipient.
    ///
    /// Waits for the expected post-deposit balance on L2 and returns it.
    pub(crate) async fn deposit_to(
        &mut self,
        recipient: Address,
        amount: u128,
        timeout: Duration,
        zone: &ZoneTestNode,
    ) -> eyre::Result<U256> {
        Ok(self
            .deposit_to_with_block(recipient, amount, timeout, zone)
            .await?
            .1)
    }

    /// Same as [`deposit_to`](Self::deposit_to), but also returns the L1 block number
    /// that included the deposit transaction.
    pub(crate) async fn deposit_to_with_block(
        &mut self,
        recipient: Address,
        amount: u128,
        timeout: Duration,
        zone: &ZoneTestNode,
    ) -> eyre::Result<(u64, U256)> {
        self.deposit_with_memo_and_block(amount, recipient, B256::ZERO, timeout, zone)
            .await
    }

    /// Approve the ZonePortal to spend `amount` of a specific `token` on L1, then deposit.
    ///
    /// Unlike [`deposit`](Self::deposit), this allows depositing any enabled token.
    /// The caller must ensure:
    /// - The token is enabled on the portal (`enableToken`)
    /// - The account has sufficient balance of `token` on L1
    ///
    /// Waits for the expected post-deposit balance on L2 and returns it.
    pub(crate) async fn deposit_token(
        &mut self,
        token: Address,
        l2_token: Address,
        amount: u128,
        timeout: Duration,
        zone: &ZoneTestNode,
    ) -> eyre::Result<U256> {
        use tempo_contracts::precompiles::ITIP20;
        use tempo_zone_contracts::ZonePortal;

        // Approve portal for this specific token
        ITIP20::new(token, &self.l1_provider)
            .approve(self.portal_address, U256::MAX)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Snapshot balance before deposit so we wait for the expected increase
        let balance_before = zone.balance_of(l2_token, self.address).await?;
        let (key_index, encrypted) = self.prepare_deposit(self.address, B256::ZERO).await?;

        let portal = ZonePortal::new(self.portal_address, &self.l1_provider);
        let receipt = portal
            .deposit(token, amount, key_index, encrypted, self.address)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "L1 deposit tx failed");

        zone.wait_for_balance(
            l2_token,
            self.address,
            balance_before + U256::from(amount),
            timeout,
        )
        .await
    }

    /// Approve portal + call `deposit` on L1 with properly ECIES-encrypted payload.
    ///
    /// Performs ECIES encryption client-side (matching what a real depositor would do):
    /// 1. Read the sequencer's encryption key from the portal
    /// 2. Generate an ephemeral key pair
    /// 3. ECDH → HKDF → AES-256-GCM encrypt (to, memo)
    /// 4. Call `deposit` on the portal
    /// 5. Wait for the zone to mint tokens to the decrypted recipient
    pub(crate) async fn deposit_with_memo(
        &mut self,
        amount: u128,
        recipient: Address,
        memo: B256,
        timeout: Duration,
        zone: &ZoneTestNode,
    ) -> eyre::Result<U256> {
        Ok(self
            .deposit_with_memo_and_block(amount, recipient, memo, timeout, zone)
            .await?
            .1)
    }

    /// Same as [`deposit_with_memo`](Self::deposit_with_memo), but also returns the
    /// L1 block number that included the encrypted deposit transaction.
    pub(crate) async fn deposit_with_memo_and_block(
        &mut self,
        amount: u128,
        recipient: Address,
        memo: B256,
        timeout: Duration,
        zone: &ZoneTestNode,
    ) -> eyre::Result<(u64, U256)> {
        use tempo_zone_contracts::ZONE_TOKEN_ADDRESS;

        // Snapshot balance before deposit
        let balance_before = zone.balance_of(ZONE_TOKEN_ADDRESS, recipient).await?;
        let block_number = self
            .submit_deposit_with_memo(amount, recipient, memo)
            .await?;

        // Wait for the zone to process the encrypted deposit and mint to recipient
        let balance = zone
            .wait_for_balance(
                ZONE_TOKEN_ADDRESS,
                recipient,
                balance_before + U256::from(amount),
                timeout,
            )
            .await?;

        Ok((block_number, balance))
    }

    async fn submit_deposit_with_memo(
        &mut self,
        amount: u128,
        recipient: Address,
        memo: B256,
    ) -> eyre::Result<u64> {
        use tempo_contracts::precompiles::ITIP20;
        use tempo_precompiles::PATH_USD_ADDRESS;
        use tempo_zone_contracts::ZonePortal;

        let portal_address = self.portal_address;
        if !self.l1_portal_approved {
            let receipt = ITIP20::new(PATH_USD_ADDRESS, &self.l1_provider)
                .approve(portal_address, U256::MAX)
                .send()
                .await?
                .get_receipt()
                .await?;
            eyre::ensure!(receipt.status(), "L1 portal approval failed");
            self.l1_portal_approved = true;
        }

        let (key_index, encrypted) = self.prepare_deposit(recipient, memo).await?;
        let receipt = ZonePortal::new(portal_address, &self.l1_provider)
            .deposit(PATH_USD_ADDRESS, amount, key_index, encrypted, self.address)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "L1 deposit tx failed");
        receipt
            .block_number
            .ok_or_else(|| eyre::eyre!("deposit receipt missing block number"))
    }

    async fn prepare_deposit(
        &self,
        recipient: Address,
        memo: B256,
    ) -> eyre::Result<(U256, tempo_zone_contracts::DepositPayload)> {
        use tempo_zone_contracts::{DepositPayload, ZonePortal};
        use zone_precompiles::ecies;

        let portal = ZonePortal::new(self.portal_address, &self.l1_provider);
        let key_result = portal.sequencerEncryptionKey().call().await?;
        let key_count = portal.encryptionKeyCount().call().await?;
        eyre::ensure!(
            key_count > U256::ZERO,
            "no encryption key registered on portal"
        );
        let key_index = key_count - U256::ONE;
        let enc = ecies::encrypt_deposit(
            &key_result.x,
            key_result.yParity,
            recipient,
            memo,
            self.address,
            self.portal_address,
            key_index,
        )
        .ok_or_else(|| eyre::eyre!("ECIES encryption failed"))?;

        Ok((
            key_index,
            DepositPayload {
                ephemeralPubkeyX: enc.eph_pub_x,
                ephemeralPubkeyYParity: enc.eph_pub_y_parity,
                ciphertext: enc.ciphertext.into(),
                nonce: alloy_primitives::FixedBytes(enc.nonce),
                tag: alloy_primitives::FixedBytes(enc.tag),
            },
        ))
    }

    /// Approve the ZoneOutbox, then request a withdrawal on L2.
    ///
    /// Skips approval if already approved in this session.
    pub(crate) async fn withdraw(&mut self, amount: u128) -> eyre::Result<()> {
        self.withdraw_with(WithdrawalArgs::new(amount)).await
    }

    /// Submit a simple withdrawal to the L2 transaction pool without waiting for inclusion.
    ///
    /// The outbox must already be approved with [`Self::approve_outbox`]. Keeping approval
    /// separate makes it possible to submit this transaction while block production is paused.
    pub(crate) async fn submit_withdrawal(&self, amount: u128) -> eyre::Result<B256> {
        use tempo_zone_contracts::{IZoneOutbox, ZONE_OUTBOX_ADDRESS, ZONE_TOKEN_ADDRESS};

        eyre::ensure!(
            self.l2_outbox_approved_tokens.contains(&ZONE_TOKEN_ADDRESS),
            "zone outbox must be approved before submitting a non-blocking withdrawal"
        );
        let args = WithdrawalArgs::new(amount);
        let pending = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &self.l2_provider)
            .requestWithdrawal(
                ZONE_TOKEN_ADDRESS,
                self.address,
                args.amount,
                args.memo,
                args.gas_limit,
                self.address,
                args.data,
                args.reveal_to,
            )
            .gas(WITHDRAWAL_TX_GAS)
            .send()
            .await?;
        Ok(*pending.tx_hash())
    }

    /// Approve the ZoneOutbox, then request a withdrawal on L2 with custom args.
    ///
    /// Skips approval if already approved in this session.
    /// Uses the default zone token (pathUSD / `ZONE_TOKEN_ADDRESS`).
    pub(crate) async fn withdraw_with(&mut self, args: WithdrawalArgs) -> eyre::Result<()> {
        use tempo_zone_contracts::ZONE_TOKEN_ADDRESS;
        self.withdraw_token_with(ZONE_TOKEN_ADDRESS, args).await
    }

    /// Simulate a withdrawal request without submitting it to the transaction pool.
    /// Useful for asserting deterministic validation reverts.
    pub(crate) async fn simulate_withdraw_with(&self, args: WithdrawalArgs) -> eyre::Result<()> {
        use tempo_zone_contracts::{IZoneOutbox, ZONE_OUTBOX_ADDRESS, ZONE_TOKEN_ADDRESS};

        let to = args.to.unwrap_or(self.address);
        let zone_fallback_recipient = args.zone_fallback_recipient.unwrap_or(self.address);
        IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &self.l2_provider)
            .requestWithdrawal(
                ZONE_TOKEN_ADDRESS,
                to,
                args.amount,
                args.memo,
                args.gas_limit,
                zone_fallback_recipient,
                args.data,
                args.reveal_to,
            )
            .from(self.address)
            .call()
            .await?;
        Ok(())
    }

    /// Approve the ZoneOutbox, then simulate a token withdrawal without submitting it.
    pub(crate) async fn simulate_withdraw_token_with(
        &mut self,
        token: Address,
        args: WithdrawalArgs,
    ) -> eyre::Result<()> {
        use tempo_zone_contracts::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};

        self.approve_outbox(token).await?;

        let to = args.to.unwrap_or(self.address);
        let zone_fallback_recipient = args.zone_fallback_recipient.unwrap_or(self.address);
        IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &self.l2_provider)
            .requestWithdrawal(
                token,
                to,
                args.amount,
                args.memo,
                args.gas_limit,
                zone_fallback_recipient,
                args.data,
                args.reveal_to,
            )
            .from(self.address)
            .call()
            .await?;
        Ok(())
    }

    /// Approve the ZoneOutbox for a specific token, then request a withdrawal on L2.
    pub(crate) async fn withdraw_token(
        &mut self,
        token: Address,
        amount: u128,
    ) -> eyre::Result<()> {
        self.withdraw_token_with(token, WithdrawalArgs::new(amount))
            .await
    }

    /// Approve the ZoneOutbox for a specific token, then request a withdrawal on L2 with custom args.
    pub(crate) async fn withdraw_token_with(
        &mut self,
        token: Address,
        args: WithdrawalArgs,
    ) -> eyre::Result<()> {
        use tempo_zone_contracts::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};

        self.approve_outbox(token).await?;

        let to = args.to.unwrap_or(self.address);
        let zone_fallback_recipient = args.zone_fallback_recipient.unwrap_or(self.address);

        let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &self.l2_provider);
        let receipt = outbox
            .requestWithdrawal(
                token,
                to,
                args.amount,
                args.memo,
                args.gas_limit,
                zone_fallback_recipient,
                args.data,
                args.reveal_to,
            )
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(
            receipt.status(),
            "L2 withdrawal request failed (gas used: {})",
            receipt.gas_used
        );

        Ok(())
    }

    /// Approve the ZoneOutbox for a token without submitting a withdrawal.
    ///
    /// Reuses a successful max approval for subsequent withdrawals of the same token.
    pub(crate) async fn approve_outbox(&mut self, token: Address) -> eyre::Result<()> {
        use tempo_contracts::precompiles::ITIP20;
        use tempo_zone_contracts::ZONE_OUTBOX_ADDRESS;

        if self.l2_outbox_approved_tokens.contains(&token) {
            return Ok(());
        }

        let receipt = ITIP20::new(token, &self.l2_provider)
            .approve(ZONE_OUTBOX_ADDRESS, U256::MAX)
            .gas(TIP20_TX_GAS)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "L2 outbox approval failed");
        self.l2_outbox_approved_tokens.insert(token);
        Ok(())
    }
}

pub(crate) async fn fetch_submit_batch_call(
    l1: &L1TestNode,
    tx_hash: B256,
) -> eyre::Result<(submitBatchCall, u64)> {
    let tx = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(l1.http_url().clone())
        .get_transaction_by_hash(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("submitBatch tx {tx_hash} not found"))?;
    let input = tx
        .inner
        .calls()
        .map(|(_, input)| input)
        .find(|input| !input.is_empty())
        .ok_or_else(|| eyre::eyre!("submitBatch tx {tx_hash} has no calldata input"))?;
    let call = submitBatchCall::abi_decode(input)
        .map_err(|err| eyre::eyre!("failed to decode submitBatch calldata: {err}"))?;
    let block_number = tx
        .block_number
        .ok_or_else(|| eyre::eyre!("submitBatch tx {tx_hash} is missing blockNumber"))?;

    Ok((call, block_number))
}

/// Spawn the zone sequencer background tasks (batch submitter + withdrawal processor).
pub(crate) async fn spawn_sequencer(
    l1: &L1TestNode,
    zone: &ZoneTestNode,
    portal_address: Address,
    sequencer_signer: alloy_signer_local::PrivateKeySigner,
) -> zone_sequencer::ZoneSequencerHandle {
    spawn_sequencer_with_config(
        l1,
        zone,
        portal_address,
        sequencer_signer,
        zone_sequencer::BatchAnchorConfig::default(),
        zone_sequencer::WithdrawalBatchLimits::default(),
    )
    .await
}

/// Spawn the zone sequencer background tasks with custom limits.
pub(crate) async fn spawn_sequencer_with_config(
    l1: &L1TestNode,
    zone: &ZoneTestNode,
    portal_address: Address,
    sequencer_signer: alloy_signer_local::PrivateKeySigner,
    batch_anchor_config: zone_sequencer::BatchAnchorConfig,
    withdrawal_batch_limits: zone_sequencer::WithdrawalBatchLimits,
) -> zone_sequencer::ZoneSequencerHandle {
    use tempo_zone_contracts::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS};

    let config = zone_sequencer::ZoneSequencerConfig {
        chain_spec: std::sync::Arc::new(zone_chainspec::ZoneChainSpec {
            inner: tempo_chainspec::spec::DEV.clone(),
        }),
        portal_address,
        l1_rpc_url: l1.http_url().to_string(),
        retry_connection_interval: Duration::from_millis(100),
        zone_poll_interval: Duration::from_secs(1),
        withdrawal_poll_interval: Duration::from_millis(500),
        withdrawal_batch_limits,
        outbox_address: ZONE_OUTBOX_ADDRESS,
        inbox_address: ZONE_INBOX_ADDRESS,
        batch_anchor_config,
    };

    zone.spawn_sequencer(config, sequencer_signer).await
}

/// Start a local zone node with an L1Fixture already seeded for `seed_blocks` blocks.
pub(crate) async fn start_local_zone_with_fixture(
    seed_blocks: u64,
) -> eyre::Result<(ZoneTestNode, L1Fixture)> {
    let zone = ZoneTestNode::start_local().await?;
    let fixture = L1Fixture::new();

    fixture.seed_l1_cache(
        zone.l1_state_cache(),
        zone.enabled_tokens(),
        Address::ZERO,
        Address::ZERO,
        seed_blocks,
    );
    Ok((zone, fixture))
}

/// Start a local Zone whose production payload builder finalizes at the requested cadence.
///
/// SPF tests choose the cadence so finalization occurs only in the final block of the proof batch.
pub(crate) async fn start_local_zone_with_fixture_and_withdrawal_batch_interval(
    zone_id: u32,
    seed_blocks: u64,
    withdrawal_batch_interval_blocks: u64,
    genesis: Genesis,
) -> eyre::Result<(ZoneTestNode, L1Fixture)> {
    let throwaway_key = k256::SecretKey::from_slice(&[0x01; 32])?;
    let signer = alloy_signer_local::PrivateKeySigner::from(throwaway_key);
    let zone = ZoneTestNode::launch_with_genesis_and_withdrawal_batch_interval(
        DUMMY_L1_URL.to_string(),
        Address::ZERO,
        zone_primitives::constants::zone_chain_id(1_337, zone_id)?,
        Some(genesis),
        signer,
        withdrawal_batch_interval_blocks,
        None,
        true,
    )
    .await?;
    let fixture = L1Fixture::new();

    fixture.seed_l1_cache(
        zone.l1_state_cache(),
        zone.enabled_tokens(),
        Address::ZERO,
        Address::ZERO,
        seed_blocks,
    );
    Ok((zone, fixture))
}

/// A three-node multi-sequencer cluster driven by the real role controller.
///
/// Node 0 is the manifest bootstrap leader. Each node runs the complete dynamic role
/// machinery: the leader generation (engine with the per-anchor production permit,
/// broadcast, settlement, sequencer background tasks) and the follower generation (import,
/// transaction forwarding), switched by finalized leadership observations that tests publish
/// directly into each node's [`LeadershipSchedule`].
///
/// Every node uses a distinct sequencer signer, so a block's beneficiary identifies its
/// producer.
pub(crate) struct P2pCluster {
    pub(crate) nodes: Vec<ZoneTestNode>,
    pub(crate) p2p_public_keys: Vec<P2pPeerId>,
    pub(crate) sequencer_signers: Vec<PrivateKeySigner>,
    pub(crate) fixture: L1Fixture,
}

impl P2pCluster {
    /// The next Tempo anchor number the fixture will inject.
    pub(crate) fn next_anchor_number(&self) -> u64 {
        self.fixture.next_anchor_number()
    }

    /// Inject one L1 block into every node, simulating each node's finalized subscriber:
    /// the anchor is recorded in every tracker and the block enqueued in every deposit
    /// queue. Returns the anchor.
    pub(crate) fn inject_block(&mut self, deposits: Vec<DepositFixture>) -> eyre::Result<NumHash> {
        let all: Vec<usize> = (0..self.nodes.len()).collect();
        self.inject_block_observed_by(deposits, &all)
    }

    /// Inject one L1 block into every deposit queue, but record the anchor observation only
    /// on the given nodes. A node without the observation cannot import the corresponding
    /// zone block (or produce it) until [`Self::record_anchor`] delivers it.
    pub(crate) fn inject_block_observed_by(
        &mut self,
        deposits: Vec<DepositFixture>,
        observers: &[usize],
    ) -> eyre::Result<NumHash> {
        let block = self.fixture.next_block();
        let anchor = SealedHeader::seal_slow(block.header.clone()).num_hash();
        let events = self.fixture.portal_events_from_deposits(&deposits);
        for node in &self.nodes {
            self.fixture
                .enqueue(&block, node.deposit_queue(), deposits.clone());
        }
        for index in observers {
            self.nodes[*index]
                .l1_block_tracker()
                .record_with_portal_events(anchor, events.clone())?;
        }
        Ok(anchor)
    }

    /// Deliver a previously withheld anchor observation to one node.
    pub(crate) fn record_anchor(
        &self,
        index: usize,
        anchor: NumHash,
        deposits: Vec<DepositFixture>,
    ) -> eyre::Result<()> {
        let events = self.fixture.portal_events_from_deposits(&deposits);
        self.nodes[index]
            .l1_block_tracker()
            .record_with_portal_events(anchor, events)?;
        Ok(())
    }

    /// Publish a finalized leadership transition into every node's schedule, standing in
    /// for each node's receipt-authenticated `LeaderUpdated` observation.
    pub(crate) fn publish_transition(
        &self,
        epoch: u64,
        leader_index: usize,
        activation_tempo_block: u64,
    ) -> eyre::Result<()> {
        for node in &self.nodes {
            node.leadership().publish(LeadershipState::new(
                epoch,
                self.p2p_public_keys[leader_index].clone(),
                activation_tempo_block,
            ))?;
        }
        Ok(())
    }

    /// Wait until every node's canonical head reaches `height`.
    pub(crate) async fn wait_all_at(&self, height: u64, timeout: Duration) -> eyre::Result<()> {
        for node in &self.nodes {
            node.wait_for_block_number(height, timeout).await?;
        }
        Ok(())
    }

    /// Assert every node holds the same block at `height` and return its header.
    pub(crate) async fn assert_same_block(&self, height: u64) -> eyre::Result<TempoHeaderResponse> {
        let mut reference: Option<TempoHeaderResponse> = None;
        for (index, node) in self.nodes.iter().enumerate() {
            let block = node
                .provider()
                .get_block_by_number(BlockNumberOrTag::Number(height))
                .await?
                .ok_or_else(|| eyre::eyre!("node {index} is missing block {height}"))?;
            match &reference {
                None => reference = Some(block.header),
                Some(reference) => eyre::ensure!(
                    block.header.hash == reference.hash,
                    "node {index} diverges at height {height}: {} != {}",
                    block.header.hash,
                    reference.hash,
                ),
            }
        }
        reference.ok_or_else(|| eyre::eyre!("cluster is empty"))
    }
}

/// A real Tempo L1 and Portal paired with three P2P quorum nodes. Unlike [`P2pCluster`], this
/// fixture exercises settlement against the actual `ZonePortal` contract rather than synthetic
/// L1 cache injection.
pub(crate) struct RealP2pCluster {
    pub(crate) l1: L1TestNode,
    pub(crate) portal_address: Address,
    pub(crate) nodes: Vec<ZoneTestNode>,
    pub(crate) attestation_signers: Vec<PrivateKeySigner>,
}

impl RealP2pCluster {
    /// Wait for every node to independently execute through `height`.
    pub(crate) async fn wait_all_at(&self, height: u64, timeout: Duration) -> eyre::Result<()> {
        for node in &self.nodes {
            node.wait_for_block_number(height, timeout).await?;
        }
        Ok(())
    }

    /// Assert all nodes have the same canonical block at `height`.
    pub(crate) async fn assert_same_block(&self, height: u64) -> eyre::Result<TempoHeaderResponse> {
        let mut reference: Option<TempoHeaderResponse> = None;
        for (index, node) in self.nodes.iter().enumerate() {
            let block = node
                .provider()
                .get_block_by_number(BlockNumberOrTag::Number(height))
                .await?
                .ok_or_else(|| eyre::eyre!("node {index} is missing block {height}"))?;
            match &reference {
                None => reference = Some(block.header),
                Some(reference) => eyre::ensure!(
                    block.header.hash == reference.hash,
                    "node {index} diverges at height {height}: {} != {}",
                    block.header.hash,
                    reference.hash,
                ),
            }
        }
        reference.ok_or_else(|| eyre::eyre!("cluster is empty"))
    }
}

/// Start a three-member P2P quorum against a real Tempo L1 and a Portal registered with the
/// exact per-node attestation keys. The short interval bounds how long the tests wait for an
/// empty batch boundary. A full import following checkpoint-only blocks may close a batch sooner.
pub(crate) async fn start_real_p2p_cluster(
    withdrawal_batch_interval_blocks: u64,
) -> eyre::Result<RealP2pCluster> {
    start_real_p2p_cluster_with_active_nodes(withdrawal_batch_interval_blocks, 3).await
}

/// Start a three-member P2P quorum against a real Tempo L1, launching only `active_nodes` of
/// its configured members. This lets an integration test prove that a reachable 2-of-3 quorum
/// settles without waiting for the offline third member.
pub(crate) async fn start_real_p2p_cluster_with_active_nodes(
    withdrawal_batch_interval_blocks: u64,
    active_nodes: usize,
) -> eyre::Result<RealP2pCluster> {
    Ok(start_real_p2p_cluster_inner(
        withdrawal_batch_interval_blocks,
        active_nodes,
        L1ProxyMode::Direct,
        None,
        false,
        None,
    )
    .await?
    .cluster)
}

/// Start a real-L1 cluster whose nodes run settlement proving, so every node persists witnesses
/// before canonicalization.
///
/// No prover listens on the routed endpoint: every proof fails fast and settlement falls back to
/// the `NoProof` verifier.
pub(crate) async fn start_real_p2p_cluster_with_settlement_proving(
    withdrawal_batch_interval_blocks: u64,
    active_nodes: usize,
) -> eyre::Result<RealP2pCluster> {
    let unreachable = TempoHardfork::VARIANTS
        .iter()
        .map(|&hardfork| zone_sequencer::HardforkProverAddress {
            hardfork,
            address: "127.0.0.1:1".to_owned(),
        })
        .collect();
    // Use a synthetic transport policy even for forks without approved enclave measurements.
    // These endpoints never serve a proof; the tests exercise NoProof fallback.
    let pcr = "11".repeat(48);
    let policy = serde_json::to_vec(&serde_json::json!({
        "pcrs": { "0": [&pcr], "1": [&pcr], "2": [&pcr] }
    }))?;
    let prover_addresses = zone_sequencer::ProverAddresses::new(unreachable, Some(&policy))?
        .expect("hardforks are non-empty");
    Ok(start_real_p2p_cluster_inner(
        withdrawal_batch_interval_blocks,
        active_nodes,
        L1ProxyMode::Direct,
        None,
        false,
        Some(ZoneProverConfig::Settlement(prover_addresses)),
    )
    .await?
    .cluster)
}

/// Start the full three-member real-L1 cluster with one shared, controllable L1 proxy. Existing
/// cluster constructors intentionally retain their direct-connect behavior.
pub(crate) async fn start_real_p2p_cluster_with_l1_proxy(
    withdrawal_batch_interval_blocks: u64,
    l1_block_time: Duration,
) -> eyre::Result<(RealP2pCluster, TcpChaosProxy)> {
    let mut parts = start_real_p2p_cluster_inner(
        withdrawal_batch_interval_blocks,
        3,
        L1ProxyMode::All,
        Some(l1_block_time),
        false,
        None,
    )
    .await?;
    Ok((
        parts.cluster,
        parts
            .l1_proxies
            .pop()
            .expect("proxied cluster constructor must return its L1 proxy"),
    ))
}

/// Start the full three-member cluster with one independently controllable L1 proxy per node.
pub(crate) async fn start_real_p2p_cluster_with_per_node_l1_proxies(
    withdrawal_batch_interval_blocks: u64,
    l1_block_time: Duration,
) -> eyre::Result<(RealP2pCluster, [TcpChaosProxy; 3])> {
    let parts = start_real_p2p_cluster_inner(
        withdrawal_batch_interval_blocks,
        3,
        L1ProxyMode::PerNode,
        Some(l1_block_time),
        false,
        None,
    )
    .await?;
    let proxies: [TcpChaosProxy; 3] = parts
        .l1_proxies
        .try_into()
        .map_err(|_| eyre::eyre!("per-node proxy constructor must return three L1 proxies"))?;
    Ok((parts.cluster, proxies))
}

/// Start a full three-member cluster with independently controllable P2P links and one
/// controllable L1 proxy per node.
pub(crate) async fn start_real_p2p_network_chaos_cluster(
    withdrawal_batch_interval_blocks: u64,
    l1_block_time: Duration,
) -> eyre::Result<(RealP2pCluster, P2pChaosNetwork, [TcpChaosProxy; 3])> {
    let parts = start_real_p2p_cluster_inner(
        withdrawal_batch_interval_blocks,
        3,
        L1ProxyMode::PerNode,
        Some(l1_block_time),
        true,
        None,
    )
    .await?;
    let proxies = parts
        .l1_proxies
        .try_into()
        .map_err(|_| eyre::eyre!("network-chaos cluster must return three L1 proxies"))?;
    Ok((
        parts.cluster,
        parts
            .p2p_network
            .expect("network-chaos cluster must return its P2P proxy mesh"),
        proxies,
    ))
}

#[derive(Clone, Copy)]
enum L1ProxyMode {
    Direct,
    All,
    PerNode,
}

struct RealP2pClusterParts {
    cluster: RealP2pCluster,
    l1_proxies: Vec<TcpChaosProxy>,
    p2p_network: Option<P2pChaosNetwork>,
}

async fn start_real_p2p_cluster_inner(
    withdrawal_batch_interval_blocks: u64,
    active_nodes: usize,
    proxy_mode: L1ProxyMode,
    l1_block_time: Option<Duration>,
    proxy_p2p: bool,
    prover_config: Option<ZoneProverConfig>,
) -> eyre::Result<RealP2pClusterParts> {
    eyre::ensure!(
        (2..=3).contains(&active_nodes),
        "real P2P test cluster requires two or three active nodes, got {active_nodes}"
    );

    fn available_address() -> eyre::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?)
    }

    let l1 = match l1_block_time {
        Some(block_time) => {
            L1TestNode::start_with(|config| config.dev.block_time = Some(block_time)).await?
        }
        None => L1TestNode::start().await?,
    };
    let direct_url = l1.ws_url().to_string();
    let (l1_proxies, l1_rpc_urls) = match proxy_mode {
        L1ProxyMode::Direct => (Vec::new(), vec![direct_url; active_nodes]),
        L1ProxyMode::All => {
            let upstream = TcpChaosProxy::upstream_addr(l1.ws_url())?;
            let proxy = TcpChaosProxy::start(upstream).await?;
            let proxy_url = proxy.proxy_url(l1.ws_url())?.to_string();
            (vec![proxy], vec![proxy_url; active_nodes])
        }
        L1ProxyMode::PerNode => {
            let upstream = TcpChaosProxy::upstream_addr(l1.ws_url())?;
            let mut proxies = Vec::with_capacity(active_nodes);
            let mut urls = Vec::with_capacity(active_nodes);
            for _ in 0..active_nodes {
                let proxy = TcpChaosProxy::start(upstream).await?;
                urls.push(proxy.proxy_url(l1.ws_url())?.to_string());
                proxies.push(proxy);
            }
            (proxies, urls)
        }
    };
    let addresses = [
        available_address()?,
        available_address()?,
        available_address()?,
    ];
    let (p2p_network, manifest_addresses) = if proxy_p2p {
        let (network, manifest_addresses) = P2pChaosNetwork::start(addresses).await?;
        (Some(network), manifest_addresses)
    } else {
        (None, [addresses; 3])
    };
    let identities = [
        Ed25519PrivateKey::from_seed(301),
        Ed25519PrivateKey::from_seed(302),
        Ed25519PrivateKey::from_seed(303),
    ];
    let public_keys = identities.each_ref().map(|key| key.public_key());
    let attestation_keys = [301_u64, 302, 303].map(|key| format!("0x{key:064x}"));
    let attestation_signers = attestation_keys
        .each_ref()
        .map(|key| key.parse::<PrivateKeySigner>().expect("valid test signer"));

    let factory = l1.native_zone_factory().await?;
    let portal_address = l1
        .create_zone_with_admin_sequencers_and_config(
            factory,
            l1.admin_address(),
            attestation_signers
                .iter()
                .map(PrivateKeySigner::address)
                .collect(),
            2,
            ZoneCreationConfig::open(),
        )
        .await?;
    for signer in &attestation_signers {
        // Tempo's test genesis funds only the dev key. Settlement is submitted from the
        // individual registered quorum key, so each member needs a gas balance of its own.
        l1.fund_user(signer.address(), 10_000_000).await?;
    }
    let encryption_key = SecretKey::from(attestation_signers[0].credential());
    l1.set_sequencer_encryption_key_with_signer(
        portal_address,
        &encryption_key,
        attestation_signers[0].clone(),
    )
    .await?;

    let portal = ZonePortal::new(portal_address, l1.provider());
    let zone_id = portal.zoneId().call().await?;
    let (genesis, _) = build_l1_anchored_genesis(l1.http_url(), portal_address).await?;
    let chain_id = next_unique_chain_id();

    let config_dir = std::env::temp_dir().join(format!(
        "tempo-zone-real-p2p-test-{}-{}",
        std::process::id(),
        next_unique_chain_id()
    ));
    std::fs::create_dir_all(&config_dir)?;
    let mut configs = Vec::with_capacity(3);
    for (index, role) in [(0, Role::Leader), (1, Role::Follower), (2, Role::Follower)] {
        let manifest_path = config_dir.join(format!("manifest-{index}.toml"));
        let mut manifest = format!(
            "zone_id = {zone_id}\nsequencer_set_version = 0\nleader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(public_keys[0].as_ref())
        );
        for (peer_index, (public_key, signer)) in
            public_keys.iter().zip(&attestation_signers).enumerate()
        {
            let address = manifest_addresses[index][peer_index];
            manifest.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{peer_index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
                const_hex::encode_prefixed(public_key.as_ref()),
                signer.address(),
            ));
        }
        std::fs::write(&manifest_path, manifest)?;
        let key_path = config_dir.join(format!("node-{index}.key"));
        std::fs::write(
            &key_path,
            const_hex::encode_prefixed(identities[index].encode().as_ref()),
        )?;
        let secp256k1_key_path = config_dir.join(format!("node-{index}-secp256k1.key"));
        std::fs::write(&secp256k1_key_path, &attestation_keys[index])?;
        configs.push(P2pConfig::load(
            &manifest_path,
            &key_path,
            Some(&secp256k1_key_path),
            addresses[index],
            false,
            zone_id,
            Some(role),
        )?);
    }
    let _ = std::fs::remove_dir_all(&config_dir);

    let mut nodes = Vec::with_capacity(active_nodes);
    for (index, config) in configs.into_iter().take(active_nodes).enumerate() {
        let additional_decryption_keys = if index == 0 {
            Vec::new()
        } else {
            vec![SecretKey::from(attestation_signers[0].credential())]
        };
        nodes.push(
            ZoneTestNode::launch_with_genesis_and_withdrawal_batch_interval_and_decryption_keys(
                l1_rpc_urls[index].clone(),
                portal_address,
                chain_id,
                Some(genesis.clone()),
                attestation_signers[index].clone(),
                withdrawal_batch_interval_blocks,
                Some(config),
                false,
                additional_decryption_keys,
                prover_config.clone(),
            )
            .await?,
        );
    }

    Ok(RealP2pClusterParts {
        cluster: RealP2pCluster {
            l1,
            portal_address,
            nodes,
            attestation_signers: attestation_signers.to_vec(),
        },
        l1_proxies,
        p2p_network,
    })
}

/// Start a three-node multi-sequencer cluster with identical genesis state and authenticated
/// P2P identities. Node 0 bootstraps as the leader.
pub(crate) async fn start_local_p2p_cluster(seed_blocks: u64) -> eyre::Result<P2pCluster> {
    fn available_address() -> eyre::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?)
    }

    let addresses = [
        available_address()?,
        available_address()?,
        available_address()?,
    ];
    let identities = [
        Ed25519PrivateKey::from_seed(101),
        Ed25519PrivateKey::from_seed(102),
        Ed25519PrivateKey::from_seed(103),
    ];
    let public_keys = identities.each_ref().map(|key| key.public_key());
    let secp256k1_keys = [101_u64, 102, 103].map(|key| format!("0x{key:064x}"));
    let secp256k1_signers = secp256k1_keys
        .each_ref()
        .map(|key| key.parse::<PrivateKeySigner>().unwrap());
    // Distinct shared-sequencer signers per node: the block beneficiary then identifies the
    // producer, which handoff tests assert on.
    let sequencer_signers: Vec<PrivateKeySigner> = (0x51u8..0x54)
        .map(|byte| {
            PrivateKeySigner::from_bytes(&B256::with_last_byte(byte))
                .expect("valid test sequencer key")
        })
        .collect();

    let unique = NEXT_ZONE_ID.fetch_add(1, Ordering::Relaxed);
    let config_dir = std::env::temp_dir().join(format!(
        "tempo-zone-p2p-test-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&config_dir)?;
    let manifest_path = config_dir.join("manifest.toml");
    let mut manifest = format!(
        "zone_id = 0\nleader_ed25519_public_key = \"{}\"\n",
        const_hex::encode_prefixed(public_keys[0].as_ref())
    );
    for (index, ((public_key, secp256k1_signer), address)) in public_keys
        .iter()
        .zip(&secp256k1_signers)
        .zip(addresses)
        .enumerate()
    {
        manifest.push_str(&format!(
            "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
            const_hex::encode_prefixed(public_key.as_ref()),
            secp256k1_signer.address(),
        ));
    }
    std::fs::write(&manifest_path, manifest)?;
    let mut configs = Vec::with_capacity(3);
    for (index, role) in [(0, Role::Leader), (1, Role::Follower), (2, Role::Follower)] {
        let key_path = config_dir.join(format!("node-{index}.key"));
        std::fs::write(
            &key_path,
            const_hex::encode_prefixed(identities[index].encode().as_ref()),
        )?;
        let secp256k1_key_path = config_dir.join(format!("node-{index}-secp256k1.key"));
        std::fs::write(&secp256k1_key_path, &secp256k1_keys[index])?;
        configs.push(P2pConfig::load(
            &manifest_path,
            &key_path,
            Some(&secp256k1_key_path),
            addresses[index],
            false,
            0,
            Some(role),
        )?);
    }
    let _ = std::fs::remove_dir_all(&config_dir);

    let chain_id = next_unique_chain_id();
    let l1_rpc_url = spawn_test_l1_rpc(1337).await?;
    let genesis = zone_node::genesis::genesis_template()?;
    let mut nodes = Vec::with_capacity(3);
    for (index, config) in configs.into_iter().enumerate() {
        nodes.push(
            ZoneTestNode::launch_with_genesis_and_withdrawal_batch_interval(
                l1_rpc_url.clone(),
                Address::ZERO,
                chain_id,
                Some(genesis.clone()),
                sequencer_signers[index].clone(),
                8,
                Some(config),
                false,
            )
            .await?,
        );
    }

    let fixture = L1Fixture::new();
    for zone in &nodes {
        fixture.seed_l1_cache(
            zone.l1_state_cache(),
            zone.enabled_tokens(),
            Address::ZERO,
            Address::ZERO,
            seed_blocks,
        );
    }
    Ok(P2pCluster {
        nodes,
        p2p_public_keys: public_keys.to_vec(),
        sequencer_signers,
        fixture,
    })
}

pub(crate) fn leader_p2p_config(listen: SocketAddr) -> eyre::Result<P2pConfig> {
    fn available_address() -> eyre::Result<SocketAddr> {
        Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?)
    }

    let identities = [
        Ed25519PrivateKey::from_seed(201),
        Ed25519PrivateKey::from_seed(202),
        Ed25519PrivateKey::from_seed(203),
    ];
    let public_keys = identities.each_ref().map(|key| key.public_key());
    let secp256k1_keys = [201_u64, 202, 203].map(|key| format!("0x{key:064x}"));
    let secp256k1_signers = secp256k1_keys
        .each_ref()
        .map(|key| key.parse::<PrivateKeySigner>().unwrap());
    let addresses = [listen, available_address()?, available_address()?];
    let config_dir = std::env::temp_dir().join(format!(
        "tempo-zone-p2p-config-{}-{}",
        std::process::id(),
        next_unique_chain_id()
    ));
    std::fs::create_dir_all(&config_dir)?;
    let manifest_path = config_dir.join("manifest.toml");
    let key_path = config_dir.join("leader.key");
    let mut manifest = format!(
        "zone_id = 0\nleader_ed25519_public_key = \"{}\"\n",
        const_hex::encode_prefixed(public_keys[0].as_ref())
    );
    for (index, ((public_key, secp256k1_signer), address)) in public_keys
        .iter()
        .zip(&secp256k1_signers)
        .zip(addresses)
        .enumerate()
    {
        manifest.push_str(&format!(
            "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
            const_hex::encode_prefixed(public_key.as_ref()),
            secp256k1_signer.address(),
        ));
    }
    std::fs::write(&manifest_path, manifest)?;
    std::fs::write(
        &key_path,
        const_hex::encode_prefixed(identities[0].encode().as_ref()),
    )?;
    let secp256k1_key_path = config_dir.join("leader-secp256k1.key");
    std::fs::write(&secp256k1_key_path, &secp256k1_keys[0])?;
    let config = P2pConfig::load(
        &manifest_path,
        &key_path,
        Some(&secp256k1_key_path),
        listen,
        false,
        0,
        Some(Role::Leader),
    )?;
    let _ = std::fs::remove_dir_all(config_dir);
    Ok(config)
}

pub(crate) async fn start_chain_id_rpc(chain_id: u64) -> eyre::Result<url::Url> {
    Ok(spawn_test_l1_rpc(chain_id).await?.parse()?)
}

/// Seed an existing L1Fixture's cache into a zone node's L1 state cache.
///
/// Use when multiple zones share the same fixture timeline — call once per zone.
pub(crate) fn seed_fixture_for_zone(fixture: &L1Fixture, zone: &ZoneTestNode, seed_blocks: u64) {
    fixture.seed_l1_cache(
        zone.l1_state_cache(),
        zone.enabled_tokens(),
        Address::ZERO,
        Address::ZERO,
        seed_blocks,
    );
}

// ============ Redacted RPC Test Utilities ============

/// Build a hex-encoded authorization token for the redacted zone RPC.
///
/// Signs the token with the given signer and returns the hex string (no `0x` prefix)
/// suitable for the `X-Authorization-Token` header.
fn build_auth_token(
    signer: &alloy_signer_local::PrivateKeySigner,
    zone_id: u32,
    chain_id: u64,
) -> String {
    use alloy_signer::SignerSync;
    use zone_node::rpc::auth::build_token_fields;

    let now = now_secs();
    let expires_at = now + 600;

    let (fields, digest) = build_token_fields(zone_id, chain_id, now, expires_at);
    let sig = signer.sign_hash_sync(&digest).expect("signing failed");

    alloy_primitives::hex::encode([sig.as_rsy().as_slice(), &fields].concat())
}

fn build_auth_token_with_signature(
    signature: TempoSignature,
    zone_id: u32,
    chain_id: u64,
) -> String {
    use zone_node::rpc::auth::build_token_fields;

    let now = now_secs();
    let expires_at = now + 600;

    let (fields, _) = build_token_fields(zone_id, chain_id, now, expires_at);
    auth_tokens::build_token_with_signature(signature, &fields)
}

fn build_p256_auth_token(signing_key: &P256SigningKey, zone_id: u32, chain_id: u64) -> String {
    let now = now_secs();
    let expires_at = now + 600;
    let (_, digest) = zone_node::rpc::auth::build_token_fields(zone_id, chain_id, now, expires_at);
    build_auth_token_with_signature(
        sign_p256_signature(digest, signing_key).expect("p256 signing failed"),
        zone_id,
        chain_id,
    )
}

fn build_webauthn_auth_token(
    signing_key: &P256SigningKey,
    zone_id: u32,
    chain_id: u64,
    challenge_digest: Option<B256>,
) -> String {
    let now = now_secs();
    let expires_at = now + 600;
    let (_, digest) = zone_node::rpc::auth::build_token_fields(zone_id, chain_id, now, expires_at);
    build_auth_token_with_signature(
        sign_webauthn_signature(signing_key, challenge_digest.unwrap_or(digest))
            .expect("webauthn signing failed"),
        zone_id,
        chain_id,
    )
}

fn build_keychain_auth_token(
    signing_key: &P256SigningKey,
    root_account: Address,
    version: u8,
    zone_id: u32,
    chain_id: u64,
) -> (String, Address) {
    let now = now_secs();
    let expires_at = now + 600;
    let (_, digest) = zone_node::rpc::auth::build_token_fields(zone_id, chain_id, now, expires_at);
    let (signature, key_id) = sign_keychain_signature(digest, signing_key, root_account, version)
        .expect("keychain signing failed");

    (
        build_auth_token_with_signature(signature, zone_id, chain_id),
        key_id,
    )
}

/// Send a JSON-RPC request to the redacted zone RPC and return the parsed response.
///
/// Returns the full JSON response body (including `jsonrpc`, `id`, `result`/`error`).
async fn redacted_rpc_call(
    url: &url::Url,
    method: &str,
    params: serde_json::Value,
    auth_token: &str,
) -> eyre::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let resp = reqwest::Client::new()
        .post(url.as_str())
        .header("x-authorization-token", auth_token)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;

    if !status.is_success() && text.is_empty() {
        eyre::bail!("HTTP {status}");
    }

    Ok(serde_json::from_str(&text)?)
}

/// Send a JSON-RPC request to the redacted zone RPC and return the HTTP status + body.
///
/// Useful for testing authentication failures (401/403).
async fn redacted_rpc_call_raw(
    url: &url::Url,
    method: &str,
    params: serde_json::Value,
    auth_token: &str,
) -> eyre::Result<(reqwest::StatusCode, String)> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let resp = reqwest::Client::new()
        .post(url.as_str())
        .header("x-authorization-token", auth_token)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;
    Ok((status, text))
}

/// Send a JSON-RPC request WITHOUT any auth header.
async fn redacted_rpc_call_no_auth(
    url: &url::Url,
    method: &str,
    params: serde_json::Value,
) -> eyre::Result<(reqwest::StatusCode, String)> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let resp = reqwest::Client::new()
        .post(url.as_str())
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;
    Ok((status, text))
}

/// Context for redacted RPC e2e tests.
///
/// Wraps a zone node with a running redacted RPC server in front, providing
/// helpers for authenticated and unauthenticated request testing.
pub(crate) struct RedactedRpcTestCtx {
    /// The underlying zone test node.
    pub zone: ZoneTestNode,
    /// URL of the redacted RPC server (not the zone's direct HTTP endpoint).
    pub redacted_rpc_url: url::Url,
    /// The sequencer signer (gets full access on the redacted RPC).
    pub sequencer_signer: alloy_signer_local::PrivateKeySigner,
    /// Redacted RPC server configuration.
    pub config: zone_node::rpc::RedactedRpcConfig,
    /// L1 fixture for injecting deposits.
    pub fixture: L1Fixture,
}

/// Redacted RPC e2e context backed by a real L1 node and deployed ZonePortal.
pub(crate) struct RedactedRpcL1TestCtx {
    ctx: RedactedRpcTestCtx,
    l1: L1TestNode,
    portal_address: Address,
}

impl Deref for RedactedRpcL1TestCtx {
    type Target = RedactedRpcTestCtx;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

impl RedactedRpcL1TestCtx {
    /// Returns the real L1 node for tests that require one.
    pub(crate) fn l1(&self) -> &L1TestNode {
        &self.l1
    }

    /// Returns the real portal address for tests that require one.
    pub(crate) fn portal_address(&self) -> Address {
        self.portal_address
    }
}

impl RedactedRpcTestCtx {
    /// Build an auth token for the sequencer.
    pub(crate) fn sequencer_token(&self) -> String {
        build_auth_token(
            &self.sequencer_signer,
            self.config.zone_id,
            self.config.chain_id,
        )
    }

    /// Build an auth token for a regular (non-sequencer) user.
    pub(crate) fn user_token(&self, signer: &alloy_signer_local::PrivateKeySigner) -> String {
        build_auth_token(signer, self.config.zone_id, self.config.chain_id)
    }

    /// Build a P256 auth token for a non-sequencer caller.
    pub(crate) fn p256_token(&self, signing_key: &P256SigningKey) -> String {
        build_p256_auth_token(signing_key, self.config.zone_id, self.config.chain_id)
    }

    /// Build a WebAuthn auth token for a non-sequencer caller.
    pub(crate) fn webauthn_token(&self, signing_key: &P256SigningKey) -> String {
        build_webauthn_auth_token(signing_key, self.config.zone_id, self.config.chain_id, None)
    }

    /// Build a WebAuthn auth token with an overridden challenge digest.
    pub(crate) fn webauthn_token_with_challenge(
        &self,
        signing_key: &P256SigningKey,
        challenge_digest: B256,
    ) -> String {
        build_webauthn_auth_token(
            signing_key,
            self.config.zone_id,
            self.config.chain_id,
            Some(challenge_digest),
        )
    }

    /// Build a Keychain auth token signed by a P256 access key.
    pub(crate) fn keychain_p256_token(
        &self,
        root_account: Address,
        signing_key: &P256SigningKey,
        version: u8,
    ) -> (String, Address) {
        build_keychain_auth_token(
            signing_key,
            root_account,
            version,
            self.config.zone_id,
            self.config.chain_id,
        )
    }

    /// Send an authenticated JSON-RPC call to the redacted RPC server.
    pub(crate) async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
        auth_token: &str,
    ) -> eyre::Result<serde_json::Value> {
        redacted_rpc_call(&self.redacted_rpc_url, method, params, auth_token).await
    }

    /// Send a JSON-RPC call authenticated as the sequencer.
    pub(crate) async fn call_as_sequencer(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> eyre::Result<serde_json::Value> {
        let token = self.sequencer_token();
        self.call(method, params, &token).await
    }

    /// Send a JSON-RPC call authenticated as a regular user.
    pub(crate) async fn call_as_user(
        &self,
        method: &str,
        params: serde_json::Value,
        signer: &alloy_signer_local::PrivateKeySigner,
    ) -> eyre::Result<serde_json::Value> {
        let token = self.user_token(signer);
        self.call(method, params, &token).await
    }

    /// Send a JSON-RPC call with a raw auth token string, returning HTTP status + body.
    pub(crate) async fn call_raw(
        &self,
        method: &str,
        params: serde_json::Value,
        auth_token: &str,
    ) -> eyre::Result<(reqwest::StatusCode, String)> {
        redacted_rpc_call_raw(&self.redacted_rpc_url, method, params, auth_token).await
    }

    /// Send a JSON-RPC call with no auth header, returning HTTP status + body.
    pub(crate) async fn call_no_auth(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> eyre::Result<(reqwest::StatusCode, String)> {
        redacted_rpc_call_no_auth(&self.redacted_rpc_url, method, params).await
    }

    /// Build an auth token with custom zone_id and chain_id (for negative testing).
    pub(crate) fn build_bad_token(
        &self,
        signer: &alloy_signer_local::PrivateKeySigner,
        zone_id: u32,
        chain_id: u64,
    ) -> String {
        build_auth_token(signer, zone_id, chain_id)
    }

    /// Inject an empty L1 block and wait for it to be processed.
    pub(crate) async fn inject_empty_block(&mut self) -> eyre::Result<()> {
        let dq = self.zone.deposit_queue().clone();
        self.fixture.inject_empty_block(&dq);
        self.zone
            .wait_for_tempo_block_number(1, DEFAULT_TIMEOUT)
            .await?;
        Ok(())
    }

    /// Inject a deposit and wait for the balance to appear.
    pub(crate) async fn inject_deposit(
        &mut self,
        token: Address,
        depositor: Address,
        recipient: Address,
        amount: u128,
    ) -> eyre::Result<()> {
        let deposit = self
            .fixture
            .make_deposit(token, depositor, recipient, amount);
        let dq = self.zone.deposit_queue().clone();
        self.fixture.inject_deposits(&dq, vec![deposit]);
        self.zone
            .wait_for_balance(token, recipient, U256::from(amount), DEFAULT_TIMEOUT)
            .await?;
        Ok(())
    }

    /// Query `eth_getBalance` via the redacted RPC as a specific user.
    pub(crate) async fn get_balance_as_user(
        &self,
        address: Address,
        signer: &alloy_signer_local::PrivateKeySigner,
    ) -> eyre::Result<serde_json::Value> {
        self.call_as_user(
            "eth_getBalance",
            serde_json::json!([format!("{address:#x}"), "latest"]),
            signer,
        )
        .await
    }

    /// Query `eth_getBalance` via the redacted RPC as the sequencer.
    pub(crate) async fn get_balance_as_sequencer(
        &self,
        address: Address,
    ) -> eyre::Result<serde_json::Value> {
        self.call_as_sequencer(
            "eth_getBalance",
            serde_json::json!([format!("{address:#x}"), "latest"]),
        )
        .await
    }

    /// Query `eth_getTransactionCount` via the redacted RPC as a specific user.
    pub(crate) async fn get_tx_count_as_user(
        &self,
        address: Address,
        signer: &alloy_signer_local::PrivateKeySigner,
    ) -> eyre::Result<serde_json::Value> {
        self.call_as_user(
            "eth_getTransactionCount",
            serde_json::json!([format!("{address:#x}"), "latest"]),
            signer,
        )
        .await
    }

    /// Authorize an access key for a root account on the zone keychain precompile.
    pub(crate) async fn authorize_keychain_key(
        &mut self,
        root_signer: &alloy_signer_local::PrivateKeySigner,
        key_id: Address,
        signature_type: KeyInfoSignatureType,
        expiry: u64,
    ) -> eyre::Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(root_signer.clone())
            .connect_http(self.zone.http_url().clone());
        let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider);
        let pending = keychain
            .authorizeKey_1(
                key_id,
                signature_type,
                KeyRestrictions {
                    expiry,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            )
            .send()
            .await?;
        self.fixture.inject_empty_block(self.zone.deposit_queue());
        let receipt = pending.get_receipt().await?;
        eyre::ensure!(receipt.status(), "authorizeKey failed");
        Ok(())
    }

    /// Revoke an access key from a root account on the zone keychain precompile.
    pub(crate) async fn revoke_keychain_key(
        &mut self,
        root_signer: &alloy_signer_local::PrivateKeySigner,
        key_id: Address,
    ) -> eyre::Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(root_signer.clone())
            .connect_http(self.zone.http_url().clone());
        let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider);
        let pending = keychain.revokeKey(key_id).send().await?;
        self.fixture.inject_empty_block(self.zone.deposit_queue());
        let receipt = pending.get_receipt().await?;
        eyre::ensure!(receipt.status(), "revokeKey failed");
        Ok(())
    }
}

async fn start_redacted_rpc_url(
    zone: &ZoneTestNode,
    config: zone_node::rpc::RedactedRpcConfig,
) -> eyre::Result<url::Url> {
    let local_addr =
        zone_node::rpc::start_redacted_rpc(config.clone(), zone.rpc_api(config).await?).await?;
    Ok(format!("http://{local_addr}").parse()?)
}

fn build_redacted_rpc_ctx(
    zone: ZoneTestNode,
    redacted_rpc_url: url::Url,
    sequencer_signer: alloy_signer_local::PrivateKeySigner,
    config: zone_node::rpc::RedactedRpcConfig,
    fixture: L1Fixture,
) -> RedactedRpcTestCtx {
    RedactedRpcTestCtx {
        zone,
        redacted_rpc_url,
        sequencer_signer,
        config,
        fixture,
    }
}

/// Start a zone node with a redacted RPC server for testing.
///
/// Returns a context with:
/// - A running zone node with L1 state cache seeded
/// - A redacted RPC server on a random port
/// - Sequencer credentials for testing access control
pub(crate) async fn start_zone_with_redacted_rpc() -> eyre::Result<RedactedRpcTestCtx> {
    let sequencer_signer = alloy_signer_local::PrivateKeySigner::random();
    let sequencer_address = sequencer_signer.address();

    let zone = ZoneTestNode::launch(
        DUMMY_L1_URL.to_string(),
        Address::ZERO,
        next_unique_chain_id(),
    )
    .await?;
    let fixture = L1Fixture::new();

    fixture.seed_l1_cache(
        zone.l1_state_cache(),
        zone.enabled_tokens(),
        Address::ZERO,
        sequencer_address,
        20,
    );

    let chain_id = zone.provider().get_chain_id().await?;

    let config = zone_node::rpc::RedactedRpcConfig {
        listen_addr: ([127, 0, 0, 1], 0).into(),
        zone_id: 0,
        chain_id,
        max_auth_token_validity: zone_node::rpc::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY,
        max_response_size: 160 * 1024 * 1024,
        zone_portal: Address::ZERO,
    };

    let redacted_rpc_url = start_redacted_rpc_url(&zone, config.clone()).await?;

    Ok(build_redacted_rpc_ctx(
        zone,
        redacted_rpc_url,
        sequencer_signer,
        config,
        fixture,
    ))
}

/// Start a zone with a redacted RPC server backed by a real L1 + ZonePortal.
pub(crate) async fn start_zone_with_redacted_rpc_l1() -> eyre::Result<RedactedRpcL1TestCtx> {
    start_zone_with_redacted_rpc_l1_inner().await
}

/// Start a zone with a redacted RPC server backed by a real L1 and a portal
/// with a registered encryption key.
pub(crate) async fn start_zone_with_redacted_rpc_l1_with_encryption()
-> eyre::Result<RedactedRpcL1TestCtx> {
    start_zone_with_redacted_rpc_l1_inner().await
}

async fn start_zone_with_redacted_rpc_l1_inner() -> eyre::Result<RedactedRpcL1TestCtx> {
    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;

    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;

    zone.wait_for_l2_tempo_finalized(0, DEFAULT_TIMEOUT).await?;

    let chain_id = zone.provider().get_chain_id().await?;

    let config = zone_node::rpc::RedactedRpcConfig {
        listen_addr: ([127, 0, 0, 1], 0).into(),
        zone_id: 1,
        chain_id,
        max_auth_token_validity: zone_node::rpc::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY,
        max_response_size: 160 * 1024 * 1024,
        zone_portal: portal_address,
    };

    let redacted_rpc_url = start_redacted_rpc_url(&zone, config.clone()).await?;
    let sequencer_signer = l1.dev_signer();

    Ok(RedactedRpcL1TestCtx {
        ctx: build_redacted_rpc_ctx(
            zone,
            redacted_rpc_url,
            sequencer_signer,
            config,
            L1Fixture::new(),
        ),
        l1,
        portal_address,
    })
}

/// Cleartext input used to construct encrypted deposit events in injection tests.
#[derive(Clone)]
pub(crate) struct DepositFixture {
    pub token: Address,
    pub sender: Address,
    pub to: Address,
    pub amount: u128,
    pub memo: B256,
}

/// A synthetic L1 block produced by [`L1Fixture`].
///
/// Clonable so the same block can be enqueued into multiple zone deposit queues,
/// simulating multiple zones observing the same L1 block.
#[derive(Clone)]
pub(crate) struct FixtureBlock {
    /// The L1 block header. Use `header.inner.number` to read the block number.
    pub header: TempoHeader,
}

/// Builder for creating realistic L1 block headers and deposits for injection
/// into a [`ZoneTestNode`]'s deposit queue.
///
/// Maintains monotonic block numbers and timestamps, and chains parent hashes
/// to mirror what the real L1Subscriber would produce.
pub(crate) struct L1Fixture {
    next_block_number: u64,
    next_timestamp: u64,
    last_hash: B256,
    /// Raw L1 caches seeded by this fixture, updated with state implied by injected deposits.
    caches: Mutex<Vec<L1StateCache>>,
    /// Enabled-token registries kept in sync with injected portal events.
    enabled_token_registries: Mutex<Vec<EnabledTokenRegistry>>,
}

impl L1Fixture {
    pub(crate) fn new() -> Self {
        // TempoState stores tempoBlockHash = keccak256(rlp(default TempoHeader)),
        // so the first injected L1 block must have parent_hash matching this.
        Self {
            next_block_number: 1,
            next_timestamp: 1_000_000,
            last_hash: TempoHeader::default().hash_slow(),
            caches: Mutex::new(Vec::new()),
            enabled_token_registries: Mutex::new(Vec::new()),
        }
    }

    fn encryption_key() -> k256::SecretKey {
        k256::SecretKey::from_slice(&[0x01; 32]).expect("valid fixture encryption key")
    }

    fn encrypt_fixture_deposit(&self, deposit: &DepositFixture) -> Deposit {
        let public_key = Self::encryption_key().public_key();
        self.make_real_deposit(
            public_key.as_affine(),
            Address::ZERO,
            U256::ZERO,
            deposit.token,
            deposit.sender,
            deposit.to,
            deposit.amount,
            deposit.memo,
        )
    }

    pub(crate) fn portal_events_from_deposits(
        &self,
        deposits: &[DepositFixture],
    ) -> L1PortalEvents {
        L1PortalEvents::from_deposits(
            deposits
                .iter()
                .map(|deposit| L1Deposit::Deposit(self.encrypt_fixture_deposit(deposit)))
                .collect(),
        )
    }

    /// Pre-populate the L1 state cache with values that `advanceTempo` will read
    /// via the TempoState precompile.
    ///
    /// Without a real L1, the precompile would fail with a hard error on cache miss.
    /// This seeds the cache so that handler L1-reads succeed for each block we plan to inject.
    pub(crate) fn seed_l1_cache(
        &self,
        cache_handle: &L1StateCache,
        enabled_tokens: &EnabledTokenRegistry,
        portal_address: Address,
        sequencer: Address,
        num_blocks: u64,
    ) {
        let mut cache = cache_handle.lock();
        let deposit_queue_hash_slot = portal::slots::CURRENT_DEPOSIT_QUEUE_HASH.into();
        let refunds_slot = portal::slots::REFUNDS.into();
        let sequencer_membership_slot: B256 = sequencer.mapping_slot(portal::slots::ROLE).into();
        let path_usd_config_slot: B256 = PATH_USD_ADDRESS
            .mapping_slot(portal::slots::TOKEN_CONFIGS)
            .into();
        let enabled_token_config = enabled_deposits_active_token_config();
        let max_tempo_gas_rate = B256::from(U256::from(1_000_000_000_000_000_000_u128));
        let encryption_key = Self::encryption_key();
        let (encryption_key_x, encryption_key_y_parity) =
            compressed_x_and_parity(encryption_key.public_key().as_affine());
        let encryption_entries_base: U256 =
            keccak256(B256::from(portal::slots::ENCRYPTION_KEYS)).into();

        // Local fixtures have no RPC fallback. Transfers to protocol accounts still consult their
        // address-level receive policies, so seed their absence as baseline raw L1 state.
        for recipient in [ZONE_OUTBOX_ADDRESS, ZONE_FEE_MANAGER_ADDRESS] {
            let receive_policy_slot =
                recipient.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES);
            cache.set(
                TIP403_REGISTRY_ADDRESS,
                receive_policy_slot.into(),
                0,
                B256::ZERO,
            );
        }

        for block in 0..=num_blocks {
            cache.set(
                portal_address,
                sequencer_membership_slot,
                block,
                B256::with_last_byte(u8::from(PortalRole::Sequencer)),
            );
            // Deposit queue hash slot (3) — read by ZoneInbox after finalizeTempo.
            // The initial value is B256::ZERO (empty queue).
            cache.set(portal_address, deposit_queue_hash_slot, block, B256::ZERO);
            cache.set(
                portal_address,
                portal::slots::ENCRYPTION_KEYS.into(),
                block,
                B256::with_last_byte(1),
            );
            cache.set(
                portal_address,
                encryption_entries_base.into(),
                block,
                encryption_key_x,
            );
            cache.set(
                portal_address,
                (encryption_entries_base + U256::ONE).into(),
                block,
                B256::with_last_byte(encryption_key_y_parity),
            );
            cache.set(portal_address, refunds_slot, block, B256::ZERO);
            // Synthetic fixtures use open account and gateway modes so their tests do not need
            // unrelated closed-loop membership setup or a reachable L1 RPC fallback.
            cache.set(
                portal_address,
                portal::slots::IS_ACCESS_ENFORCED.into(),
                block,
                B256::ZERO,
            );
            // The Portal is unpaused in synthetic fixtures. Seed the packed pause slot so
            // withdrawal validation does not fall back to an unavailable L1 RPC endpoint.
            cache.set(
                portal_address,
                portal::slots::PAUSE_EXPIRY.into(),
                block,
                B256::ZERO,
            );
            // Permit the protocol-wide maximum in synthetic fixtures. Production values are
            // imported from the finalized ZonePortal storage slot.
            cache.set(
                portal_address,
                portal::slots::MAX_TEMPO_GAS_RATE.into(),
                block,
                max_tempo_gas_rate,
            );
            // Local fixtures treat pathUSD as the default enabled bridge token.
            // ZoneOutbox reads the L1 ZonePortal TokenConfig mapping directly, so
            // seed the packed { enabled, depositsActive } value to avoid a dummy
            // RPC fallback on self-contained tests.
            cache.set(
                portal_address,
                path_usd_config_slot,
                block,
                enabled_token_config,
            );
        }

        // System transactions resolve their zero-address fee token before execution. Keep that
        // synthetic token permissive in RPC-free fixtures, matching the old policy-provider stub.
        seed_raw_tip403_token_policy(&mut cache, 0, Address::ZERO, ALLOW_ALL_POLICY_ID);
        seed_raw_tip403_token_policy(&mut cache, 0, PATH_USD_ADDRESS, ALLOW_ALL_POLICY_ID);
        drop(cache);
        self.caches.lock().unwrap().push(cache_handle.clone());
        self.enabled_token_registries
            .lock()
            .unwrap()
            .push(enabled_tokens.clone());
    }

    /// Build a TIP-403 checker and seed the token and account policy state it consumes.
    pub(crate) fn tip403_registry_check(
        &self,
        zone: &ZoneTestNode,
        token: Address,
        no_receive_policy_accounts: &[Address],
        block_number: u64,
        policy_id: u64,
    ) -> eyre::Result<Check403Registry> {
        for &account in no_receive_policy_accounts {
            self.seed_no_receive_policy_at(block_number, account)?;
        }
        seed_raw_tip403_token_policy(
            &mut zone.l1_state_cache().lock(),
            block_number,
            token,
            policy_id,
        );
        Ok(Check403Registry {
            provider: zone.provider(),
            token,
        })
    }

    /// Seed the absence of an address-level TIP-403 receive policy at the current Zone anchor.
    pub(crate) fn seed_no_receive_policy(&self, recipient: Address) -> eyre::Result<()> {
        let current_anchor = self.next_block_number.saturating_sub(1);
        self.seed_no_receive_policy_at(current_anchor, recipient)
    }

    fn seed_no_receive_policy_at(&self, block_number: u64, recipient: Address) -> eyre::Result<()> {
        // TODO(rusowsky): make `ReceivePolicy` public upstream to use the handlers
        let receive_policy_slot = recipient.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES);
        for cache in self.caches.lock().unwrap().iter() {
            cache.lock().set(
                TIP403_REGISTRY_ADDRESS,
                receive_policy_slot.into(),
                block_number,
                B256::ZERO,
            );
        }
        Ok(())
    }

    fn seed_fixture_deposit_policy_state(&self, block_number: u64, deposits: &[DepositFixture]) {
        for deposit in deposits {
            self.seed_no_receive_policy_at(block_number, deposit.to)
                .expect("deposit receive-policy fixture seed must be admitted");
        }
    }

    fn seed_enabled_token_policy_state(&self, block_number: u64, tokens: &[EnabledToken]) {
        for cache in self.caches.lock().unwrap().iter() {
            let mut cache = cache.lock();
            for token in tokens {
                seed_raw_tip403_token_policy(
                    &mut cache,
                    block_number,
                    token.token,
                    ALLOW_ALL_POLICY_ID,
                );
            }
        }
    }

    fn apply_enabled_token_events(&self, tokens: &[EnabledToken]) {
        for registry in self.enabled_token_registries.lock().unwrap().iter() {
            registry
                .write()
                .extend(tokens.iter().map(|enabled| enabled.token));
        }
    }

    /// The next L1 block number this fixture will inject.
    pub(crate) fn next_anchor_number(&self) -> u64 {
        self.next_block_number
    }

    /// Build a [`TempoHeader`] for the next L1 block.
    fn next_header(&mut self) -> TempoHeader {
        let number = self.next_block_number;
        let timestamp = self.next_timestamp;
        let parent_hash = self.last_hash;

        let header = TempoHeader {
            inner: Header {
                number,
                timestamp,
                parent_hash,
                ..Default::default()
            },
            ..Default::default()
        };

        // Advance state: TempoState stores keccak256(rlp(header)) as tempoBlockHash,
        // so the next block's parent_hash must match this value.
        self.last_hash = header.hash_slow();
        self.next_block_number += 1;
        self.next_timestamp += 1; // 1s per L1 block

        // Synthetic injection bypasses the subscriber, so publish the same verified-receipt
        // coverage the subscriber would publish before the engine consumes this block.
        for cache in self.caches.lock().unwrap().iter() {
            cache.lock().invalidate_and_set_anchor(number, []);
        }

        header
    }

    /// Build the next L1 block without injecting it into any queue.
    ///
    /// Use with [`enqueue`](Self::enqueue) to broadcast the same block
    /// to multiple zone deposit queues.
    pub(crate) fn next_block(&mut self) -> FixtureBlock {
        let header = self.next_header();
        FixtureBlock { header }
    }

    /// Build the next L1 block at an explicit timestamp, preserving the parent hash chain.
    /// Hardfork tests use this to align L1 headers with activation.
    pub(crate) fn next_block_at(&mut self, timestamp: u64) -> FixtureBlock {
        assert!(
            timestamp >= self.next_timestamp,
            "fixture timestamps must increase"
        );
        self.next_timestamp = timestamp;
        self.next_block()
    }

    /// Enqueue a pre-built block into a deposit queue with the given deposits.
    pub(crate) fn enqueue(
        &self,
        block: &FixtureBlock,
        queue: &DepositQueue,
        deposits: Vec<DepositFixture>,
    ) {
        self.seed_fixture_deposit_policy_state(block.header.inner.number, &deposits);
        let events = self.portal_events_from_deposits(&deposits);
        queue.enqueue(block.header.clone(), events);
    }

    /// Enqueue a pre-built block into a deposit queue with full portal events.
    pub(crate) fn enqueue_events(
        &self,
        block: &FixtureBlock,
        queue: &DepositQueue,
        events: L1PortalEvents,
    ) {
        let block_number = block.header.inner.number;
        self.seed_enabled_token_policy_state(block_number, &events.enabled_tokens);
        self.apply_enabled_token_events(&events.enabled_tokens);
        for deposit in &events.deposits {
            match deposit {
                L1Deposit::WithdrawalBounceBack(deposit) => {
                    self.seed_no_receive_policy_at(block_number, deposit.to)
                        .expect("event receive-policy fixture seed must be admitted");
                }
                L1Deposit::Deposit(deposit) => {
                    if let Some(decrypted) = zone_precompiles::ecies::decrypt_deposit(
                        &Self::encryption_key(),
                        &deposit.ephemeral_pubkey_x,
                        deposit.ephemeral_pubkey_y_parity,
                        &deposit.ciphertext,
                        &deposit.nonce,
                        &deposit.tag,
                        Address::ZERO,
                        deposit.key_index,
                        deposit.sender,
                    ) {
                        self.seed_no_receive_policy_at(block_number, decrypted.to)
                            .expect("encrypted receive-policy fixture seed must be admitted");
                    }
                }
            }
        }
        queue.enqueue(block.header.clone(), events);
    }

    /// Create a [`DepositFixture`] for a specific L1 block.
    pub(crate) fn make_deposit_for_block(
        token: Address,
        sender: Address,
        to: Address,
        amount: u128,
    ) -> DepositFixture {
        DepositFixture {
            token,
            sender,
            to,
            amount,
            memo: B256::ZERO,
        }
    }

    /// Inject an L1 block with enabled tokens (no deposits) into the queue.
    pub(crate) fn inject_enabled_tokens(
        &mut self,
        queue: &DepositQueue,
        tokens: Vec<EnabledToken>,
    ) {
        let header = self.next_header();
        self.seed_enabled_token_policy_state(header.inner.number, &tokens);
        self.apply_enabled_token_events(&tokens);
        let events = L1PortalEvents {
            deposits: vec![],
            enabled_tokens: tokens,
            ..Default::default()
        };
        queue.enqueue(header, events);
    }

    /// Inject an empty L1 block (no deposits) into the queue.
    pub(crate) fn inject_empty_block(&mut self, queue: &DepositQueue) -> NumHash {
        let header = self.next_header();
        let anchor = SealedHeader::seal_slow(header.clone()).num_hash();
        queue.enqueue(header, L1PortalEvents::default());
        anchor
    }

    /// Inject the same empty L1 block into multiple queues.
    pub(crate) fn inject_empty_block_into(&mut self, queues: &[&DepositQueue]) -> NumHash {
        let block = self.next_block();
        let anchor = SealedHeader::seal_slow(block.header.clone()).num_hash();
        for queue in queues {
            self.enqueue(&block, queue, vec![]);
        }
        anchor
    }

    /// Inject `n` empty L1 blocks (no deposits) into the queue.
    pub(crate) fn inject_empty_blocks(&mut self, queue: &DepositQueue, n: u64) {
        for _ in 0..n {
            self.inject_empty_block(queue);
        }
    }

    /// Produce empty Zone blocks one at a time so each injected Tempo block is the current
    /// operational import rather than part of a checkpoint-only catch-up range.
    pub(crate) async fn produce_empty_zone_blocks(
        &mut self,
        zone: &ZoneTestNode,
        count: u64,
    ) -> eyre::Result<u64> {
        let mut height = zone.provider().get_block_number().await?;
        for _ in 0..count {
            self.inject_empty_block(zone.deposit_queue());
            height += 1;
            zone.wait_for_block_number(height, DEFAULT_TIMEOUT).await?;
        }
        Ok(height)
    }

    /// Inject an L1 block with the given deposits into the queue.
    pub(crate) fn inject_deposits(
        &mut self,
        queue: &DepositQueue,
        deposits: Vec<DepositFixture>,
    ) -> NumHash {
        let header = self.next_header();
        self.seed_fixture_deposit_policy_state(header.inner.number, &deposits);
        let anchor = SealedHeader::seal_slow(header.clone()).num_hash();
        let events = self.portal_events_from_deposits(&deposits);
        queue.enqueue(header, events);
        anchor
    }

    /// Inject the same L1 block and deposits into multiple queues.
    pub(crate) fn inject_deposits_into(
        &mut self,
        queues: &[&DepositQueue],
        deposits: Vec<DepositFixture>,
    ) -> NumHash {
        let block = self.next_block();
        let anchor = SealedHeader::seal_slow(block.header.clone()).num_hash();
        for queue in queues {
            self.enqueue(&block, queue, deposits.clone());
        }
        anchor
    }

    /// Inject an L1 block with mixed regular and encrypted deposits.
    #[allow(dead_code)]
    pub(crate) fn inject_l1_deposits(&mut self, queue: &DepositQueue, deposits: Vec<L1Deposit>) {
        let header = self.next_header();
        let events = L1PortalEvents::from_deposits(deposits);
        queue.enqueue(header, events);
    }

    /// Create an [`Deposit`] for testing with dummy ECIES parameters.
    #[allow(dead_code)]
    pub(crate) fn make_dummy_deposit(
        &self,
        token: Address,
        sender: Address,
        amount: u128,
    ) -> Deposit {
        Deposit {
            token,
            sender,
            amount,
            fee: 0,
            tempo_refund_recipient: sender,
            key_index: alloy_primitives::U256::ZERO,
            ephemeral_pubkey_x: B256::ZERO,
            ephemeral_pubkey_y_parity: 0x02,
            ciphertext: vec![0u8; 64], // ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE = 64
            nonce: [0u8; 12],
            tag: [0u8; 16],
        }
    }

    /// Create a [`DepositFixture`] for testing.
    pub(crate) fn make_deposit(
        &self,
        token: Address,
        sender: Address,
        to: Address,
        amount: u128,
    ) -> DepositFixture {
        DepositFixture {
            token,
            sender,
            to,
            amount,
            memo: B256::ZERO,
        }
    }

    /// Create an [`Deposit`] with proper ECIES encryption against the
    /// sequencer's real public key.
    ///
    /// Uses a deterministic ephemeral key for reproducibility.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(crate) fn make_real_deposit(
        &self,
        sequencer_pub: &k256::AffinePoint,
        portal_address: Address,
        key_index: alloy_primitives::U256,
        token: Address,
        sender: Address,
        recipient: Address,
        amount: u128,
        memo: B256,
    ) -> Deposit {
        use k256::{ProjectivePoint, Scalar};
        use sha2::{Digest, Sha256};
        use zone_precompiles::ecies::{build_plaintext, encrypt_plaintext, hkdf_info, hkdf_sha256};

        // Deterministic ephemeral key for reproducibility
        let eph_bytes: [u8; 32] = Sha256::digest(b"test-ephemeral-key-for-e2e").into();
        let eph_key = k256::SecretKey::from_slice(&eph_bytes).expect("valid ephemeral key");
        let eph_scalar: Scalar = *eph_key.to_nonzero_scalar();
        let eph_pub = k256::AffinePoint::from(ProjectivePoint::GENERATOR * eph_scalar);
        let (eph_pub_x, eph_pub_y_parity) = compressed_x_and_parity(&eph_pub);

        // ECDH: shared = eph_scalar * sequencer_pub
        let shared_proj = ProjectivePoint::from(*sequencer_pub) * eph_scalar;
        let shared_affine = k256::AffinePoint::from(shared_proj);
        let (shared_secret_x, _) = compressed_x_and_parity(&shared_affine);

        // HKDF-SHA256 key derivation (matching ecies.rs)
        let info = hkdf_info(&portal_address, &key_index, &eph_pub_x, &sender);
        let aes_key = hkdf_sha256(&shared_secret_x, b"ecies-aes-key", &info);

        // Build and encrypt plaintext (deterministic zero nonce)
        let plaintext = build_plaintext(&recipient, &memo);
        let (ciphertext, nonce, tag) = encrypt_plaintext(&aes_key, &plaintext);

        Deposit {
            token,
            sender,
            amount,
            fee: 0,
            tempo_refund_recipient: sender,
            key_index,
            ephemeral_pubkey_x: eph_pub_x,
            ephemeral_pubkey_y_parity: eph_pub_y_parity,
            ciphertext,
            nonce,
            tag,
        }
    }
}
