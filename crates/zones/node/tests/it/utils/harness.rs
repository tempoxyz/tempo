//! [`Network`]: starts a dev L1 with zones and funded accounts in one call.

use std::{ops::Deref, rc::Rc, time::Duration};

use alloy_primitives::{Address, U256};
use alloy_signer_local::PrivateKeySigner;
use futures::future::try_join_all;
use k256::SecretKey;
use tempo_primitives::test_utils::signers;

use super::{
    L1_TIMEOUT, L1TestNode, ZoneAccount, ZoneCreationConfig, ZoneLaunch, ZoneTestNode,
    spawn_sequencer,
};

/// pathUSD the portal admin and each zone sequencer receive for L1 gas.
const GAS_FUNDING: u128 = 10_000_000;

/// Time a withdrawal has to settle: a batch, its submission and its processing.
const WITHDRAWAL_TIMEOUT: Duration = Duration::from_secs(120);

/// A dev L1 with zones and funded accounts, started by [`Self::start`].
#[derive(Default)]
pub(crate) struct Network {
    zones: Vec<ZoneCreationConfig>,
    fund: u128,
}

impl Network {
    /// Adds a zone (one closed zone by default). Closed zones admit the network's accounts.
    pub fn zone(mut self, config: ZoneCreationConfig) -> Self {
        self.zones.push(config);
        self
    }

    /// Funds each account with `amount` pathUSD on the L1.
    pub fn fund(mut self, amount: u128) -> Self {
        self.fund = amount;
        self
    }

    /// Starts the L1, `Z` zones and `A` funded accounts. Fails unless `Z` zones were added.
    pub async fn start<const Z: usize, const A: usize>(
        self,
    ) -> eyre::Result<(Rc<L1TestNode>, [Zone; Z], [PrivateKeySigner; A])> {
        let zones = if self.zones.is_empty() {
            vec![ZoneCreationConfig::closed(Vec::new())]
        } else {
            self.zones
        };
        eyre::ensure!(
            zones.len() == Z,
            "network has {} zones, not {Z}",
            zones.len()
        );
        let l1 = Rc::new(L1TestNode::start().await?);
        let accounts = signers::<A>();
        let sequencers = signers::<Z>();
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
        let mut portals = Vec::with_capacity(zones.len());
        for (mut config, sequencer) in zones.into_iter().zip(&sequencers) {
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

        let zones = zones
            .try_into()
            .unwrap_or_else(|_| unreachable!("one zone per config"));
        Ok((l1, zones, accounts))
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
