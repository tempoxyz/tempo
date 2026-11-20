//! ZoneIdentity across the T14 to T15 transition: the predeploy appears at T15, the registrar and
//! org admins configure orgs through zone transactions, and once the portal admin's L1 config turns
//! enforcement on, org edges gate transfers, deposits and withdrawals.
//! An org's admin and designated readers can access its members' account-scoped state, txs and logs.

use alloy::network::Ethereum;
use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::{DynProvider, PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy_rpc_types_eth::{Log, TransactionRequest};
use alloy_sol_types::{SolCall, SolEvent, SolInterface};
use eyre::OptionExt;
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{TEMPO_T0_BASE_FEE, TempoHardforks},
};
use tempo_contracts::{
    precompiles::ITIP20,
    zones::{
        IZoneIdentity::{self, OrgKey},
        IZoneOutbox, ZONE_IDENTITY_ADDRESS, ZONE_OUTBOX_ADDRESS, ZoneIdentityError,
    },
};
use tempo_precompiles::PATH_USD_ADDRESS;
use zone_chainspec::{ZoneChainSpec, test_utils::set_tempo_fork};

use crate::utils::{
    DEFAULT_TIMEOUT, L1Fixture, WITHDRAWAL_TX_GAS, ZoneTestNode, build_auth_token, now_secs,
    signer_at, start_local_zone_with_fixture_and_withdrawal_batch_interval, start_redacted_rpc_url,
};

/// pathUSD each zone account receives before T15, for fees and transfers.
const FUNDING: u128 = 100_000_000;

/// A zone account with a provider that signs as it.
struct Party {
    address: Address,
    provider: DynProvider,
}

impl Party {
    fn new(zone: &ZoneTestNode, index: u32) -> Self {
        let signer = signer_at(index);
        Self {
            address: signer.address(),
            provider: ProviderBuilder::new()
                .wallet(signer)
                .connect_http(zone.http_url().clone())
                .erased(),
        }
    }

    fn identity(&self) -> IZoneIdentity::IZoneIdentityInstance<DynProvider> {
        IZoneIdentity::new(ZONE_IDENTITY_ADDRESS, self.provider.clone())
    }

    /// Sends `call` to `to`. New ZoneIdentity storage slots cost far more than a TIP-20 transfer's
    /// usual limit, so every transaction gets the withdrawal limit.
    async fn send(
        &self,
        to: Address,
        call: impl SolCall,
    ) -> eyre::Result<PendingTransactionBuilder<Ethereum>> {
        let request = TransactionRequest::default()
            .to(to)
            .input(Bytes::from(call.abi_encode()).into())
            .gas_limit(WITHDRAWAL_TX_GAS)
            .gas_price(u128::from(TEMPO_T0_BASE_FEE));
        Ok(self.provider.send_transaction(request).await?)
    }

    async fn transfer(
        &self,
        to: Address,
        amount: u64,
    ) -> eyre::Result<PendingTransactionBuilder<Ethereum>> {
        self.send(
            PATH_USD_ADDRESS,
            ITIP20::transferCall {
                to,
                amount: U256::from(amount),
            },
        )
        .await
    }
}

/// Produces one zone block holding `pending` and returns each transaction's status.
async fn mine(
    fixture: &mut L1Fixture,
    zone: &ZoneTestNode,
    pending: Vec<PendingTransactionBuilder<Ethereum>>,
) -> eyre::Result<Vec<bool>> {
    fixture.inject_empty_block(zone.deposit_queue());
    let mut statuses = Vec::with_capacity(pending.len());
    for tx in pending {
        statuses.push(tx.get_receipt().await?.status());
    }
    Ok(statuses)
}

/// Revert data of an `eth_call` from `from`, or `None` when it succeeds.
async fn revert_of(
    zone: &ZoneTestNode,
    from: Address,
    to: Address,
    call: impl SolCall,
) -> eyre::Result<Option<Bytes>> {
    let request = TransactionRequest::default()
        .from(from)
        .to(to)
        .input(Bytes::from(call.abi_encode()).into());
    match zone.provider().call(request.into()).await {
        Ok(_) => Ok(None),
        Err(error) => Ok(Some(
            error
                .as_error_resp()
                .and_then(|response| response.as_revert_data())
                .ok_or_eyre("call failed without revert data")?,
        )),
    }
}

fn forbids(from: Address, to: Address) -> Bytes {
    ZoneIdentityError::org_policy_forbids(PATH_USD_ADDRESS, from, to)
        .abi_encode()
        .into()
}

/// Asserts a pathUSD transfer from `from` to `to` succeeds, or reverts with `OrgPolicyForbids`.
async fn assert_transfer(
    zone: &ZoneTestNode,
    from: Address,
    to: Address,
    allowed: bool,
) -> eyre::Result<()> {
    let call = ITIP20::transferCall {
        to,
        amount: U256::ONE,
    };
    assert_eq!(
        revert_of(zone, from, PATH_USD_ADDRESS, call).await?,
        (!allowed).then(|| forbids(from, to)),
        "transfer {from} -> {to}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_t14_to_t15_zone_identity_orgs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // A zone block takes the later of its L1 header's timestamp and the wall clock, so an L1 header
    // stamped at activation moves the zone to T15 without waiting for the wall clock.
    let activation = now_secs() + 3600;
    let mut genesis = zone_node::genesis::genesis_template()?;
    set_tempo_fork(&mut genesis, TempoHardfork::T15, activation);
    genesis.config.chain_id = zone_primitives::constants::zone_chain_id(1_337, 1515)?;
    let spec = ZoneChainSpec::from_genesis(genesis.clone())?;
    assert_eq!(spec.tempo_hardfork_at(activation - 1), TempoHardfork::T14);
    assert_eq!(spec.tempo_hardfork_at(activation), TempoHardfork::T15);

    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(1515, 4, 1, genesis).await?;
    let registrar = Party::new(&zone, 160);
    let admin_a = Party::new(&zone, 161);
    let admin_b = Party::new(&zone, 162);
    let alice = Party::new(&zone, 163);
    let bob = Party::new(&zone, 164);
    let carol = Party::new(&zone, 165);
    let dave = Party::new(&zone, 166);
    // L1-only endpoints: the depositor Tempo approves for org A, and an off-ramp.
    let bridge = signer_at(167).address();
    let offramp = signer_at(168).address();
    let stranger = signer_at(169).address();
    fixture.seed_no_commitment(ZONE_IDENTITY_ADDRESS);

    // T14: no ZoneIdentity, and deposits from any sender are credited.
    let parties = [&registrar, &admin_a, &admin_b, &alice, &bob, &carol, &dave];
    let t14 = fixture.next_block_at(now_secs());
    fixture.enqueue(
        &t14,
        zone.deposit_queue(),
        parties
            .iter()
            .map(|party| {
                L1Fixture::make_deposit_for_block(
                    PATH_USD_ADDRESS,
                    stranger,
                    party.address,
                    FUNDING,
                )
            })
            .collect(),
    );
    zone.wait_for_block_number(1, DEFAULT_TIMEOUT).await?;
    for party in parties {
        assert_eq!(
            zone.balance_of(PATH_USD_ADDRESS, party.address).await?,
            U256::from(FUNDING)
        );
    }
    let block_timestamp = async |number: u64| -> eyre::Result<u64> {
        Ok(zone
            .provider()
            .get_block_by_number(number.into())
            .await?
            .ok_or_eyre("zone block")?
            .header
            .timestamp())
    };
    assert!(
        block_timestamp(1).await? < activation,
        "block 1 must run T14"
    );
    let org_admin_request = TransactionRequest::default()
        .to(ZONE_IDENTITY_ADDRESS)
        .input(Bytes::from(IZoneIdentity::orgAdminCall { orgId: 0 }.abi_encode()).into());
    let before = zone
        .provider()
        .call(org_admin_request.clone().into())
        .await?;
    assert!(before.is_empty(), "ZoneIdentity must not exist before T15");

    // Approve the outbox while transfers need no edge, for the withdrawals below.
    let approve = alice
        .send(
            PATH_USD_ADDRESS,
            ITIP20::approveCall {
                spender: ZONE_OUTBOX_ADDRESS,
                amount: U256::MAX,
            },
        )
        .await?;

    // Dave, who joins no org, may spend Alice's pathUSD: transferFrom is checked from the owner.
    let approve_dave = alice
        .send(
            PATH_USD_ADDRESS,
            ITIP20::approveCall {
                spender: dave.address,
                amount: U256::MAX,
            },
        )
        .await?;

    // T15: the predeploy answers. No registrar is set yet, so org 0's admin is zero.
    let t15 = fixture.next_block_at(activation);
    fixture.enqueue(&t15, zone.deposit_queue(), vec![]);
    zone.wait_for_block_number(2, DEFAULT_TIMEOUT).await?;
    assert!(approve.get_receipt().await?.status());
    assert!(approve_dave.get_receipt().await?.status());
    assert!(
        block_timestamp(2).await? >= activation,
        "block 2 must run T15"
    );
    let after = zone.provider().call(org_admin_request.into()).await?;
    assert_eq!(
        IZoneIdentity::orgAdminCall::abi_decode_returns(&after)?,
        Address::ZERO
    );

    // The portal admin sets the registrar on Tempo; enforcement stays off for now.
    fixture.seed_identity_config(registrar.address, false);
    for recipient in [
        alice.address,
        bob.address,
        carol.address,
        dave.address,
        offramp,
    ] {
        fixture.seed_transfer_recipient(recipient)?;
    }

    // Orgs: A and B for members, and two endpoint orgs Tempo administers.
    let (org_a, org_b, funding, exits) = (1, 2, 3, 4);
    let org_admins = [
        (org_a, admin_a.address),
        (org_b, admin_b.address),
        (funding, registrar.address),
        (exits, registrar.address),
    ];
    for (_, admin) in org_admins {
        let pending = registrar
            .send(
                ZONE_IDENTITY_ADDRESS,
                IZoneIdentity::createOrgCall { admin },
            )
            .await?;
        assert_eq!(mine(&mut fixture, &zone, vec![pending]).await?, [true]);
    }
    for (org, admin) in org_admins {
        assert_eq!(registrar.identity().orgAdmin(org).call().await?, admin);
    }
    // Only the registrar creates orgs.
    let create = IZoneIdentity::createOrgCall {
        admin: alice.address,
    };
    assert_eq!(
        revert_of(&zone, alice.address, ZONE_IDENTITY_ADDRESS, create).await?,
        Some(ZoneIdentityError::unauthorized().abi_encode().into())
    );

    // Members, added in one batch per org by its admin.
    let members = [
        (&admin_a, org_a, vec![alice.address, bob.address]),
        (&admin_b, org_b, vec![carol.address]),
        (&registrar, funding, vec![bridge]),
        (&registrar, exits, vec![offramp]),
    ];
    for (admin, org, accounts) in members {
        let call = IZoneIdentity::addMembersCall {
            orgId: org,
            accounts,
        };
        let pending = admin.send(ZONE_IDENTITY_ADDRESS, call).await?;
        assert_eq!(mine(&mut fixture, &zone, vec![pending]).await?, [true]);
    }
    let members_block = zone.provider().get_block_number().await?;
    let alice_org = alice.identity().orgOf(alice.address).call().await?;
    assert_eq!((alice_org.orgId, alice_org.frozen), (org_a, false));
    // Membership is private to the account, its org's admin and the registrar.
    let org_of = IZoneIdentity::orgOfCall {
        account: alice.address,
    };
    assert_eq!(
        revert_of(&zone, dave.address, ZONE_IDENTITY_ADDRESS, org_of).await?,
        Some(ZoneIdentityError::unauthorized().abi_encode().into())
    );

    // Edges: A internally; A offers B transfers, which B has not accepted yet; deposits from the
    // approved depositor's Tempo address into A; withdrawals from A to the off-ramp's Tempo address.
    let usd = vec![PATH_USD_ADDRESS];
    let set_edge = |from, to| IZoneIdentity::setEdgeCall {
        from,
        to,
        tokens: usd.clone(),
        allowed: true,
    };
    // Each admin sets its own halves; A's admin sets both halves of A's edge to itself in one call.
    let edges = [
        (&admin_a, OrgKey::zone(org_a), OrgKey::zone(org_a)),
        (&admin_a, OrgKey::zone(org_a), OrgKey::zone(org_b)),
        (&registrar, OrgKey::l1(funding), OrgKey::zone(org_a)),
        (&admin_a, OrgKey::l1(funding), OrgKey::zone(org_a)),
        (&admin_a, OrgKey::zone(org_a), OrgKey::l1(exits)),
        (&registrar, OrgKey::zone(org_a), OrgKey::l1(exits)),
    ];
    for (admin, from, to) in edges {
        let pending = admin
            .send(ZONE_IDENTITY_ADDRESS, set_edge(from, to))
            .await?;
        assert_eq!(mine(&mut fixture, &zone, vec![pending]).await?, [true]);
    }
    let edge = async |from, to| {
        admin_a
            .identity()
            .edge(OrgKey::zone(from), OrgKey::zone(to), PATH_USD_ADDRESS)
            .call()
            .await
    };
    assert!(edge(org_a, org_a).await?);
    assert!(!edge(org_a, org_b).await?);

    // Until the portal enforces it, edges change nothing.
    assert_transfer(&zone, alice.address, carol.address, true).await?;

    fixture.seed_identity_config(registrar.address, true);

    // Inside an org transfers pass; A to B waits for B's half; B to A and org 0 have no edge.
    let to_bob = alice.transfer(bob.address, 1_000).await?;
    let to_carol = alice.transfer(carol.address, 1_000).await?;
    assert_eq!(
        mine(&mut fixture, &zone, vec![to_bob, to_carol]).await?,
        [true, false]
    );
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, carol.address).await?,
        U256::from(FUNDING)
    );
    assert_transfer(&zone, alice.address, carol.address, false).await?;
    let accept = admin_b
        .send(
            ZONE_IDENTITY_ADDRESS,
            set_edge(OrgKey::zone(org_a), OrgKey::zone(org_b)),
        )
        .await?;
    assert_eq!(mine(&mut fixture, &zone, vec![accept]).await?, [true]);
    let to_carol = alice.transfer(carol.address, 1_000).await?;
    let before_reader_tx = *to_carol.tx_hash();
    assert_eq!(mine(&mut fixture, &zone, vec![to_carol]).await?, [true]);
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, carol.address).await?,
        U256::from(FUNDING + 1_000)
    );
    assert_transfer(&zone, carol.address, alice.address, false).await?;
    assert_transfer(&zone, dave.address, alice.address, false).await?;
    assert_transfer(&zone, alice.address, dave.address, false).await?;
    let transfer_from = |to| ITIP20::transferFromCall {
        from: alice.address,
        to,
        amount: U256::ONE,
    };
    assert_eq!(
        revert_of(
            &zone,
            dave.address,
            PATH_USD_ADDRESS,
            transfer_from(bob.address)
        )
        .await?,
        None
    );
    assert_eq!(
        revert_of(
            &zone,
            dave.address,
            PATH_USD_ADDRESS,
            transfer_from(dave.address)
        )
        .await?,
        Some(forbids(alice.address, dave.address))
    );
    // The off-ramp's edge is to its Tempo address only, so a Zone transfer to it is refused.
    assert_transfer(&zone, alice.address, offramp, false).await?;

    // Deposits: the approved depositor reaches A; any other sender bounces.
    let alice_before = zone.balance_of(PATH_USD_ADDRESS, alice.address).await?;
    let bob_before = zone.balance_of(PATH_USD_ADDRESS, bob.address).await?;
    let deposits = fixture.next_block();
    fixture.enqueue(
        &deposits,
        zone.deposit_queue(),
        vec![
            L1Fixture::make_deposit_for_block(PATH_USD_ADDRESS, bridge, alice.address, 700),
            L1Fixture::make_deposit_for_block(PATH_USD_ADDRESS, stranger, bob.address, 500),
        ],
    );
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        alice.address,
        alice_before + U256::from(700),
        DEFAULT_TIMEOUT,
    )
    .await?;
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, bob.address).await?,
        bob_before
    );

    // Withdrawals: A reaches the off-ramp but not an address in no org.
    let withdraw = |to: Address| IZoneOutbox::requestWithdrawalCall {
        token: PATH_USD_ADDRESS,
        to,
        amount: 100,
        memo: B256::ZERO,
        gasLimit: 0,
        zoneFallbackRecipient: alice.address,
        data: Bytes::new(),
        revealTo: Bytes::new(),
    };
    assert_eq!(
        revert_of(
            &zone,
            alice.address,
            ZONE_OUTBOX_ADDRESS,
            withdraw(dave.address)
        )
        .await?,
        Some(forbids(alice.address, dave.address))
    );
    let pending = alice.send(ZONE_OUTBOX_ADDRESS, withdraw(offramp)).await?;
    assert_eq!(mine(&mut fixture, &zone, vec![pending]).await?, [true]);

    // Freezing a member stops transfers to it, even inside its org.
    let freeze = IZoneIdentity::setFrozenCall {
        account: bob.address,
        frozen: true,
    };
    let pending = admin_a.send(ZONE_IDENTITY_ADDRESS, freeze).await?;
    assert_eq!(mine(&mut fixture, &zone, vec![pending]).await?, [true]);
    assert_transfer(&zone, alice.address, bob.address, false).await?;

    // Reads: org A's admin and the reader it names may read A's members; other orgs' admins and
    // addresses in no org may not, and nobody but the account reads an address in no org.
    let auditor = Party::new(&zone, 170);
    fixture.seed_no_commitment(auditor.address);
    let before_reader = format!("{:#x}", zone.provider().get_block_number().await?);
    let add_reader = IZoneIdentity::setReaderCall {
        orgId: org_a,
        reader: auditor.address,
        allowed: true,
    };
    let pending = admin_a.send(ZONE_IDENTITY_ADDRESS, add_reader).await?;
    assert_eq!(mine(&mut fixture, &zone, vec![pending]).await?, [true]);
    let named_block = zone.provider().get_block_number().await?;
    let named = format!("{named_block:#x}");
    let to_carol = alice.transfer(carol.address, 1).await?;
    let named_tx = *to_carol.tx_hash();
    assert_eq!(mine(&mut fixture, &zone, vec![to_carol]).await?, [true]);
    let reads = [
        (&admin_a, alice.address, true),
        (&auditor, alice.address, true),
        (&admin_b, alice.address, false),
        (&dave, alice.address, false),
        (&admin_a, dave.address, false),
    ];
    for (reader, account, allowed) in reads {
        let balance_of = ITIP20::balanceOfCall { account };
        let revert = revert_of(&zone, reader.address, PATH_USD_ADDRESS, balance_of).await?;
        assert_eq!(
            revert.is_none(),
            allowed,
            "{} reads {account}",
            reader.address
        );
        assert_eq!(reader.identity().canRead(account).call().await?, allowed);
    }

    let chain_id = zone.provider().get_chain_id().await?;
    let config = zone_node::rpc::RedactedRpcConfig {
        listen_addr: ([127, 0, 0, 1], 0).into(),
        zone_id: 0,
        chain_id,
        max_auth_token_validity: zone_node::rpc::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY,
        max_response_size: 16 * 1024 * 1024,
        zone_portal: Address::ZERO,
    };
    let redacted = start_redacted_rpc_url(&zone, config).await?;
    // The redacted RPC's JSON-RPC response to `method` from signer `index`.
    let rpc = async |index: u32, method: &str, params: serde_json::Value| {
        let token = build_auth_token(&signer_at(index), 0, chain_id);
        eyre::Ok(
            reqwest::Client::new()
                .post(redacted.as_str())
                .header("x-authorization-token", token)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "id": 1
                }))
                .send()
                .await?
                .json::<serde_json::Value>()
                .await?,
        )
    };
    let read = async |index: u32, method: &str, account: Address, block: &str| {
        let body = rpc(index, method, serde_json::json!([account, block])).await?;
        eyre::Ok(serde_json::from_value::<U256>(body["result"].clone())?)
    };
    // Signers: 163 Alice herself, 161 org A's admin, 170 its reader, 162 org B's admin.
    for method in ["eth_getBalance", "eth_getTransactionCount"] {
        let own = read(163, method, alice.address, "latest").await?;
        assert_ne!(own, U256::ZERO, "{method}");
        for (index, account, expected) in [
            (161, alice.address, own),
            (170, alice.address, own),
            (162, alice.address, U256::ZERO),
            (161, dave.address, U256::ZERO),
        ] {
            assert_eq!(
                read(index, method, account, "latest").await?,
                expected,
                "{method} of {account} as signer {index}"
            );
        }
    }
    // At `block`, Alice's admin reads her balance and the reader does not.
    let assert_history = async |block: &str| {
        let own = read(163, "eth_getBalance", alice.address, block).await?;
        assert_ne!(own, U256::ZERO);
        assert_eq!(
            read(161, "eth_getBalance", alice.address, block).await?,
            own
        );
        assert_eq!(
            read(170, "eth_getBalance", alice.address, block).await?,
            U256::ZERO
        );
        eyre::Ok(())
    };
    // Reads are checked at the requested block: the reader may not read Alice from before it was
    // named, while the admin already could.
    assert_history(&before_reader).await?;
    // Alice's transactions and receipts follow the same rule at the transaction's block.
    let assert_tx = async |hash: B256, index: u32, readable: bool| {
        for method in ["eth_getTransactionByHash", "eth_getTransactionReceipt"] {
            let body = rpc(index, method, serde_json::json!([hash])).await?;
            assert_eq!(
                !body["result"].is_null(),
                readable,
                "{method} of {hash} as signer {index}: {body}"
            );
        }
        eyre::Ok(())
    };
    for (hash, index, readable) in [
        (before_reader_tx, 163, true),
        (before_reader_tx, 161, true),
        (before_reader_tx, 170, false),
        (before_reader_tx, 162, false),
        (named_tx, 170, true),
        (named_tx, 162, false),
    ] {
        assert_tx(hash, index, readable).await?;
    }
    // So do the logs of Alice's transfers.
    let new_filter = serde_json::json!({
        "address": PATH_USD_ADDRESS,
        "topics": [ITIP20::Transfer::SIGNATURE_HASH, alice.address.into_word()],
    });
    let mut alice_filter = new_filter.clone();
    alice_filter["fromBlock"] = "0x0".into();
    let alice_logs = async |index: u32| {
        let body = rpc(index, "eth_getLogs", serde_json::json!([alice_filter])).await?;
        eyre::Ok(serde_json::from_value::<Vec<Log>>(body["result"].clone())?)
    };
    let own_logs = alice_logs(163).await?;
    let hashes = own_logs
        .iter()
        .filter_map(|log| log.transaction_hash)
        .collect::<Vec<_>>();
    assert!(hashes.contains(&before_reader_tx) && hashes.contains(&named_tx));
    let own_logs_since = |block: u64| {
        own_logs
            .iter()
            .filter(|log| log.block_number >= Some(block))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(alice_logs(161).await?, own_logs_since(members_block));
    assert_eq!(alice_logs(170).await?, own_logs_since(named_block));
    assert_eq!(alice_logs(162).await?, []);
    // A log filter the reader polls returns Alice's new logs.
    let filter_id =
        rpc(170, "eth_newFilter", serde_json::json!([new_filter])).await?["result"].clone();
    let filter_changes = async || {
        let body = rpc(170, "eth_getFilterChanges", serde_json::json!([filter_id])).await?;
        let mut hashes = serde_json::from_value::<Vec<Log>>(body["result"].clone())?
            .into_iter()
            .filter_map(|log| log.transaction_hash)
            .collect::<Vec<_>>();
        hashes.dedup();
        eyre::Ok(hashes)
    };
    // The first poll covers the block the filter was installed at.
    assert_eq!(filter_changes().await?, [named_tx]);
    let to_carol = alice.transfer(carol.address, 1).await?;
    let polled_tx = *to_carol.tx_hash();
    assert_eq!(mine(&mut fixture, &zone, vec![to_carol]).await?, [true]);
    assert_eq!(filter_changes().await?, [polled_tx]);
    // eth_call and eth_estimateGas at an earlier block apply the same rule to precompile getters.
    let balance_of_alice = ITIP20::balanceOfCall {
        account: alice.address,
    };
    let unauthorized = Bytes::from(ZoneIdentityError::unauthorized().abi_encode()).to_string();
    let assert_call = async |method: &str, index: u32, block: &str, allowed: bool| {
        let call = serde_json::json!({
            "from": signer_at(index).address(),
            "to": PATH_USD_ADDRESS,
            "input": Bytes::from(balance_of_alice.abi_encode()),
        });
        let body = rpc(index, method, serde_json::json!([call, block])).await?;
        let error = body["error"]["message"].as_str();
        assert_eq!(
            error.map(|message| message.contains(&unauthorized)),
            (!allowed).then_some(true),
            "{method} as signer {index} at {block}: {body}"
        );
        eyre::Ok(())
    };
    assert_call("eth_call", 170, &named, true).await?;
    assert_call("eth_call", 170, &before_reader, false).await?;

    // Removing the reader also revokes its reads of blocks where it was named.
    let remove_reader = IZoneIdentity::setReaderCall {
        orgId: org_a,
        reader: auditor.address,
        allowed: false,
    };
    let pending = admin_a.send(ZONE_IDENTITY_ADDRESS, remove_reader).await?;
    assert_eq!(mine(&mut fixture, &zone, vec![pending]).await?, [true]);
    assert_history(&named).await?;
    assert_tx(named_tx, 170, false).await?;
    assert_tx(named_tx, 161, true).await?;
    assert_eq!(alice_logs(170).await?, []);
    let to_carol = alice.transfer(carol.address, 1).await?;
    assert_eq!(mine(&mut fixture, &zone, vec![to_carol]).await?, [true]);
    assert_eq!(filter_changes().await?, Vec::<B256>::new());
    for (method, index, block, allowed) in [
        ("eth_call", 163, named.as_str(), true),
        ("eth_call", 161, named.as_str(), true),
        ("eth_call", 170, named.as_str(), false),
        ("eth_call", 161, "latest", true),
        ("eth_call", 170, "latest", false),
        ("eth_estimateGas", 163, named.as_str(), true),
        ("eth_estimateGas", 161, named.as_str(), true),
        ("eth_estimateGas", 170, named.as_str(), false),
    ] {
        assert_call(method, index, block, allowed).await?;
    }

    // Turning enforcement off on Tempo lifts every edge check.
    fixture.seed_identity_config(registrar.address, false);
    fixture.inject_empty_block(zone.deposit_queue());
    let height = zone.provider().get_block_number().await? + 1;
    zone.wait_for_block_number(height, DEFAULT_TIMEOUT).await?;
    assert_transfer(&zone, dave.address, alice.address, true).await?;
    // Reads do not depend on enforcement.
    assert_eq!(
        revert_of(&zone, admin_a.address, PATH_USD_ADDRESS, balance_of_alice).await?,
        None
    );
    assert_eq!(
        read(161, "eth_getBalance", alice.address, "latest").await?,
        read(163, "eth_getBalance", alice.address, "latest").await?
    );
    Ok(())
}
