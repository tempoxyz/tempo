//! [`Network`]: a dev L1 with zones and funded accounts, started in one call.

use std::{ops::Deref, rc::Rc, time::Duration};

use alloy_primitives::{Address, U256};
use alloy_signer_local::PrivateKeySigner;
use futures::future::try_join_all;
use k256::SecretKey;
use tempo_primitives::test_utils::signers_vec;

use super::{
    L1_TIMEOUT, L1TestNode, ZoneAccount, ZoneCreationConfig, ZoneLaunch, ZoneTestNode,
    spawn_sequencer,
};

/// pathUSD the portal admin and each zone sequencer receive for L1 gas.
const GAS_FUNDING: u128 = 10_000_000;

/// Time a withdrawal has to settle: a batch, its submission and its processing.
const WITHDRAWAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Builds a [`Network`]. See [`Network::builder`].
pub(crate) struct NetworkBuilder {
    zones: Vec<ZoneCreationConfig>,
    accounts: usize,
    fund: u128,
}

impl NetworkBuilder {
    /// Adds a zone. A closed zone also admits the network's accounts.
    pub fn zone(mut self, config: ZoneCreationConfig) -> Self {
        self.zones.push(config);
        self
    }

    /// Adds `count` accounts holding `fund` pathUSD each on the L1.
    pub fn accounts(mut self, count: usize, fund: u128) -> Self {
        self.accounts = count;
        self.fund = fund;
        self
    }

    /// Starts the L1, funds every key and launches each zone on its own sequencer key.
    pub async fn start(self) -> eyre::Result<Network> {
        let l1 = Rc::new(L1TestNode::start().await?);
        let accounts = signers_vec(self.accounts);
        let sequencers = signers_vec(self.zones.len());
        l1.fund_users(
            std::iter::once((l1.admin_address(), GAS_FUNDING))
                .chain(
                    sequencers
                        .iter()
                        .map(|sequencer| (sequencer.address(), GAS_FUNDING)),
                )
                .chain(
                    accounts
                        .iter()
                        .map(|account| (account.address(), self.fund)),
                ),
        )
        .await?;

        // Portal creation shares the dev key's nonce, so it stays sequential. Each zone then
        // registers its encryption key with its own sequencer key, concurrently with the others.
        let factory = l1.native_zone_factory().await?;
        let mut portals = Vec::with_capacity(self.zones.len());
        for (mut config, sequencer) in self.zones.into_iter().zip(&sequencers) {
            if config.access_mode {
                config
                    .allowed_accounts
                    .extend(accounts.iter().map(PrivateKeySigner::address));
                config.allowed_accounts.sort_unstable();
                config.allowed_accounts.dedup();
            }
            portals.push(
                l1.create_zone_with_admin_sequencer_and_config(
                    factory,
                    l1.admin_address(),
                    sequencer.address(),
                    config,
                )
                .await?,
            );
        }

        let zones = try_join_all(portals.into_iter().zip(sequencers).map(
            |(portal_address, sequencer)| {
                let l1 = l1.clone();
                async move {
                    l1.set_sequencer_encryption_key_with_signer(
                        portal_address,
                        &SecretKey::from(sequencer.credential()),
                        sequencer.clone(),
                    )
                    .await?;
                    let node = ZoneTestNode::launch(ZoneLaunch {
                        sequencer_signer: sequencer.clone(),
                        ..ZoneLaunch::from_l1(&l1, portal_address)
                    })
                    .await?;
                    node.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
                    eyre::Ok(Zone {
                        node,
                        l1,
                        portal_address,
                        sequencer,
                    })
                }
            },
        ))
        .await?;

        Ok(Network {
            l1,
            zones,
            accounts,
        })
    }
}

/// A dev L1 with zones and funded accounts, started by [`NetworkBuilder::start`].
pub(crate) struct Network {
    l1: Rc<L1TestNode>,
    zones: Vec<Zone>,
    accounts: Vec<PrivateKeySigner>,
}

impl Network {
    /// Returns a builder for a network with no zones and no accounts.
    pub fn builder() -> NetworkBuilder {
        NetworkBuilder {
            zones: Vec::new(),
            accounts: 0,
            fund: 0,
        }
    }

    /// Returns the L1.
    pub fn l1(&self) -> &L1TestNode {
        &self.l1
    }

    /// Returns the zones, in the order they were added. Panics unless there are `N`.
    pub fn zones<const N: usize>(&self) -> &[Zone; N] {
        self.zones
            .as_slice()
            .try_into()
            .expect("network has a different number of zones")
    }

    /// Returns the funded accounts. Panics unless there are `N`.
    pub fn accounts<const N: usize>(&self) -> &[PrivateKeySigner; N] {
        self.accounts
            .as_slice()
            .try_into()
            .expect("network has a different number of accounts")
    }
}

/// A zone of a [`Network`]. Derefs to its [`ZoneTestNode`].
pub(crate) struct Zone {
    node: ZoneTestNode,
    l1: Rc<L1TestNode>,
    portal_address: Address,
    sequencer: PrivateKeySigner,
}

impl Deref for Zone {
    type Target = ZoneTestNode;

    fn deref(&self) -> &ZoneTestNode {
        &self.node
    }
}

impl Zone {
    /// Returns the zone's portal on the L1.
    pub fn portal_address(&self) -> Address {
        self.portal_address
    }

    /// Deposits `amount` pathUSD from `from` to itself and returns its zone balance once credited.
    pub async fn deposit(&self, from: &PrivateKeySigner, amount: u128) -> eyre::Result<U256> {
        self.deposit_to(from, from.address(), amount).await
    }

    /// Deposits `amount` pathUSD from `from` to `to` and returns `to`'s zone balance once credited.
    pub async fn deposit_to(
        &self,
        from: &PrivateKeySigner,
        to: Address,
        amount: u128,
    ) -> eyre::Result<U256> {
        self.account(from)
            .deposit_to(to, amount, L1_TIMEOUT, &self.node)
            .await
    }

    /// Withdraws to `account`'s L1 address and returns its L1 balance once processed.
    pub async fn withdraw(
        &self,
        account: &PrivateKeySigner,
        token: Address,
        amount: u128,
    ) -> eyre::Result<U256> {
        let before = self.l1.balance_of(token, account.address()).await?;
        self.account(account).withdraw_token(token, amount).await?;
        self.l1
            .wait_for_withdrawal_on_l1_token(
                self.portal_address,
                token,
                account.address(),
                before,
                amount,
                WITHDRAWAL_TIMEOUT,
            )
            .await
    }

    /// Returns `signer`'s [`ZoneAccount`] on this zone.
    pub fn account(&self, signer: &PrivateKeySigner) -> ZoneAccount {
        ZoneAccount::with_signer(signer.clone(), &self.l1, &self.node, self.portal_address)
    }

    /// Spawns the zone's batch submitter and withdrawal processor, signing with its sequencer key.
    pub async fn spawn_sequencer(&self) -> zone_sequencer::ZoneSequencerHandle {
        spawn_sequencer(
            &self.l1,
            &self.node,
            self.portal_address,
            self.sequencer.clone(),
        )
        .await
    }
}
