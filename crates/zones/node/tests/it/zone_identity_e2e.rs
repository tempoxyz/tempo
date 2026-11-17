//! ZoneIdentity across the T14 to T15 transition: the predeploy appears at T15, the registrar and
//! org admins configure orgs through zone transactions, and once the portal admin's L1 config turns
//! enforcement on, org edges gate transfers, deposits and withdrawals.

use alloy::network::Ethereum;
use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::{DynProvider, PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{SolCall, SolInterface};
use eyre::OptionExt;
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{TEMPO_T0_BASE_FEE, TempoHardforks},
};
use tempo_contracts::{
    precompiles::ITIP20,
    zones::{
        IZoneIdentity, IZoneOutbox, ZONE_IDENTITY_ADDRESS, ZONE_OUTBOX_ADDRESS, ZoneIdentityError,
    },
};
use tempo_precompiles::PATH_USD_ADDRESS;
use zone_chainspec::{ZoneChainSpec, test_utils::set_tempo_fork};

use crate::utils::{
    DEFAULT_TIMEOUT, L1Fixture, WITHDRAWAL_TX_GAS, ZoneTestNode, now_secs, signer_at,
    start_local_zone_with_fixture_and_withdrawal_batch_interval,
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

    // T15: the predeploy answers. No registrar is set yet, so org 0's admin is zero.
    let t15 = fixture.next_block_at(activation);
    fixture.enqueue(&t15, zone.deposit_queue(), vec![]);
    zone.wait_for_block_number(2, DEFAULT_TIMEOUT).await?;
    assert!(approve.get_receipt().await?.status());
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

    // Members, each added by its org's admin.
    let members = [
        (&admin_a, org_a, alice.address),
        (&admin_a, org_a, bob.address),
        (&admin_b, org_b, carol.address),
        (&registrar, funding, bridge),
        (&registrar, exits, offramp),
    ];
    for (admin, org, account) in members {
        let pending = admin
            .send(
                ZONE_IDENTITY_ADDRESS,
                IZoneIdentity::addMemberCall {
                    orgId: org,
                    account,
                },
            )
            .await?;
        assert_eq!(mine(&mut fixture, &zone, vec![pending]).await?, [true]);
    }
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
    // approved depositor into A; withdrawals from A to the off-ramp.
    let usd = vec![PATH_USD_ADDRESS];
    let set_inbound = |to, from| IZoneIdentity::setInboundCall {
        toOrg: to,
        fromOrg: from,
        tokens: usd.clone(),
        allowed: true,
    };
    let edges = [
        (&admin_a, true, org_a, org_a),
        (&admin_a, false, org_a, org_a),
        (&admin_a, true, org_a, org_b),
        (&registrar, true, funding, org_a),
        (&admin_a, false, org_a, funding),
        (&admin_a, true, org_a, exits),
        (&registrar, false, exits, org_a),
    ];
    for (admin, outbound, org, other) in edges {
        let pending = if outbound {
            let call = IZoneIdentity::setOutboundCall {
                fromOrg: org,
                toOrg: other,
                tokens: usd.clone(),
                allowed: true,
            };
            admin.send(ZONE_IDENTITY_ADDRESS, call).await?
        } else {
            admin
                .send(ZONE_IDENTITY_ADDRESS, set_inbound(org, other))
                .await?
        };
        assert_eq!(mine(&mut fixture, &zone, vec![pending]).await?, [true]);
    }
    let edge = async |from, to| {
        admin_a
            .identity()
            .edge(from, to, PATH_USD_ADDRESS)
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
        .send(ZONE_IDENTITY_ADDRESS, set_inbound(org_b, org_a))
        .await?;
    assert_eq!(mine(&mut fixture, &zone, vec![accept]).await?, [true]);
    let to_carol = alice.transfer(carol.address, 1_000).await?;
    assert_eq!(mine(&mut fixture, &zone, vec![to_carol]).await?, [true]);
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, carol.address).await?,
        U256::from(FUNDING + 1_000)
    );
    assert_transfer(&zone, carol.address, alice.address, false).await?;
    assert_transfer(&zone, dave.address, alice.address, false).await?;
    assert_transfer(&zone, alice.address, dave.address, false).await?;

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

    // Turning enforcement off on Tempo lifts every edge check.
    fixture.seed_identity_config(registrar.address, false);
    fixture.inject_empty_block(zone.deposit_queue());
    let height = zone.provider().get_block_number().await? + 1;
    zone.wait_for_block_number(height, DEFAULT_TIMEOUT).await?;
    assert_transfer(&zone, dave.address, alice.address, true).await?;
    Ok(())
}
