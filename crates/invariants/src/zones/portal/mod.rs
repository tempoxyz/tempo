//! Zone portals (TIP-1091): the Tempo-side contract that escrows a zone's tokens, queues its
//! deposits and withdrawals and records its settled batches, read through its views and the
//! factory that registered it.
//!
//! A portal's lists (enabled tokens, encryption keys, sequencers, the withdrawal queue) are read up
//! to [`MAX_READ`] entries, so the checks compare only the entries both reads hold.

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use tempo_contracts::precompiles::ITIP20;

use crate::{Observe, ObserveError, Step, Tx, Views, decode, optional};

pub use tempo_contracts::{
    precompiles::{IZoneFactory, ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS, ZONE_PORTAL_PREFIX},
    zones::{DepositType, NO_QUEUE_INDEX, WithdrawalBounceBackDeposit, ZoneMessenger, ZonePortal},
};

mod checks;

pub use checks::*;

/// A step of a portal, read before and after a transaction.
pub type PortalStep = Step<Portal, Option<Tx>>;

/// How many entries of each portal list, and of the withdrawal queue, are read.
pub const MAX_READ: u64 = 64;

/// `FIXED_DEPOSIT_GAS` of the portal runtime: the deposit fee is this times `zoneGasRate`.
pub const FIXED_DEPOSIT_GAS: u128 = 100_000;

/// `MAX_GAS_FEE_RATE` of the portal runtime, the bound on its governed gas rates.
pub const MAX_GAS_FEE_RATE: u128 = 1_000_000_000_000_000_000;

/// `ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE`: the ciphertext length of every deposit.
pub const CIPHERTEXT_LEN: usize = 64;

/// The secp256k1 field prime.
const SECP256K1_P: U256 = U256::from_limbs([
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
]);

/// A zone portal's state, as its views and the zone factory report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Portal {
    pub portal: Address,
    pub zone_id: u32,
    pub admin: Address,
    pub pending_admin: Address,
    pub messenger: Address,
    /// The portal the factory registered under `zone_id`.
    pub registered: Address,
    /// Whether the factory reports `portal` as one of its portals.
    pub is_zone_portal: bool,
    pub zone_gas_rate: u128,
    pub max_tempo_gas_rate: u128,
    pub bounceback_gas: u64,
    /// `calculateDepositFee()` in the block the views ran in.
    pub deposit_fee: u128,
    /// `calculateBouncebackFee()` in the block the views ran in.
    pub bounceback_fee: u128,
    pub paused: bool,
    pub withdrawal_batch_index: u64,
    pub block_hash: B256,
    pub deposit_queue_hash: B256,
    pub deposit_count: u64,
    pub last_processed_deposit: u64,
    pub queue: WithdrawalQueue,
    /// `enabledTokenCount()`; `tokens` holds the first [`MAX_READ`] of them.
    pub token_count: u64,
    /// The enabled tokens in list order.
    pub tokens: Vec<Token>,
    pub token_enablement_hash: B256,
    /// `encryptionKeyCount()`; `keys` holds the first [`MAX_READ`] of them.
    pub key_count: u64,
    pub keys: Vec<Key>,
    pub sequencers: Vec<Address>,
    /// `refunds(token, owner)` for each enabled token and observed owner that answered.
    pub refunds: BTreeMap<(Address, Address), u128>,
}

impl Portal {
    /// The portal at `portal` before the factory created it: nothing set, nothing listed.
    pub fn absent(portal: Address) -> Self {
        Self {
            portal,
            zone_id: 0,
            admin: Address::ZERO,
            pending_admin: Address::ZERO,
            messenger: Address::ZERO,
            registered: Address::ZERO,
            is_zone_portal: false,
            zone_gas_rate: 0,
            max_tempo_gas_rate: 0,
            bounceback_gas: 0,
            deposit_fee: 0,
            bounceback_fee: 0,
            paused: false,
            withdrawal_batch_index: 0,
            block_hash: B256::ZERO,
            deposit_queue_hash: B256::ZERO,
            deposit_count: 0,
            last_processed_deposit: 0,
            queue: WithdrawalQueue {
                head: U256::ZERO,
                tail: U256::ZERO,
                slots: BTreeMap::new(),
            },
            token_count: 0,
            tokens: Vec::new(),
            token_enablement_hash: B256::ZERO,
            key_count: 0,
            keys: Vec::new(),
            sequencers: Vec::new(),
            refunds: BTreeMap::new(),
        }
    }

    /// The listed token at `token`, if it is one.
    pub fn token(&self, token: Address) -> Option<&Token> {
        self.tokens.iter().find(|t| t.token == token)
    }

    /// Whether `token` is listed, enabled and open to deposits.
    pub fn accepts_deposits(&self, token: Address) -> bool {
        self.token(token)
            .is_some_and(|t| t.enabled && t.deposits_active)
    }

    /// Whether `account` is one of the portal's sequencers.
    pub fn is_sequencer(&self, account: Address) -> bool {
        self.sequencers.contains(&account)
    }
}

/// One enabled token and the portal's custody of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub token: Address,
    pub enabled: bool,
    pub deposits_active: bool,
    /// The portal's balance of the token; `None` when nothing answered it.
    pub balance: Option<U256>,
}

/// One entry of the portal's encryption key history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub x: B256,
    pub y_parity: u8,
    pub activation_block: u64,
    /// Whether `isEncryptionKeyValid` accepts it for new deposits in the block the views ran in.
    pub valid: bool,
}

/// The portal's withdrawal queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalQueue {
    pub head: U256,
    pub tail: U256,
    /// The slots read: the two below `head`, those from `head` up to [`MAX_READ`] of them, and
    /// `tail`.
    pub slots: BTreeMap<U256, B256>,
}

impl WithdrawalQueue {
    /// The queue indices whose slots are read.
    fn indices(head: U256, tail: U256) -> Vec<U256> {
        let mut indices = Vec::new();
        let mut index = head.saturating_sub(U256::from(2));
        while index < head {
            indices.push(index);
            index += U256::ONE;
        }
        let mut index = head;
        while index < tail && indices.len() < MAX_READ as usize + 2 {
            indices.push(index);
            index += U256::ONE;
        }
        indices.push(tail);
        indices.dedup();
        indices
    }
}

impl Observe for Portal {
    type At<'a> = At<'a>;

    /// Reads the portal's configuration, counters and queue bounds, then its lists, queue slots
    /// and the factory's record of it, then its token configs and balances and the observed
    /// owners' refunds, in three batches of view calls. The portal's own views must answer; over
    /// partial views a token balance or refund nothing answers is left out.
    fn observe<V: Views>(views: &mut V, at: At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let At {
            portal,
            factory,
            owners,
        } = at;
        let calls: Vec<(Address, Bytes)> = [
            ZonePortal::zoneIdCall {}.abi_encode(),
            ZonePortal::adminCall {}.abi_encode(),
            ZonePortal::pendingAdminCall {}.abi_encode(),
            ZonePortal::messengerCall {}.abi_encode(),
            ZonePortal::zoneGasRateCall {}.abi_encode(),
            ZonePortal::maxTempoGasRateCall {}.abi_encode(),
            ZonePortal::bouncebackGasCall {}.abi_encode(),
            ZonePortal::calculateDepositFeeCall {}.abi_encode(),
            ZonePortal::calculateBouncebackFeeCall {}.abi_encode(),
            ZonePortal::pausedCall {}.abi_encode(),
            ZonePortal::withdrawalBatchIndexCall {}.abi_encode(),
            ZonePortal::blockHashCall {}.abi_encode(),
            ZonePortal::currentDepositQueueHashCall {}.abi_encode(),
            ZonePortal::depositCountCall {}.abi_encode(),
            ZonePortal::lastProcessedDepositNumberCall {}.abi_encode(),
            ZonePortal::withdrawalQueueHeadCall {}.abi_encode(),
            ZonePortal::withdrawalQueueTailCall {}.abi_encode(),
            ZonePortal::enabledTokenCountCall {}.abi_encode(),
            ZonePortal::tokenEnablementHashCall {}.abi_encode(),
            ZonePortal::encryptionKeyCountCall {}.abi_encode(),
            ZonePortal::sequencerCountCall {}.abi_encode(),
        ]
        .into_iter()
        .map(|input| (portal, input.into()))
        .collect();
        let mut out = views.call(&calls).map_err(ObserveError::Views)?.into_iter();
        let zone_id = decode::<ZonePortal::zoneIdCall, _>(portal, out.next())?;
        let admin = decode::<ZonePortal::adminCall, _>(portal, out.next())?;
        let pending_admin = decode::<ZonePortal::pendingAdminCall, _>(portal, out.next())?;
        let messenger = decode::<ZonePortal::messengerCall, _>(portal, out.next())?;
        let zone_gas_rate = decode::<ZonePortal::zoneGasRateCall, _>(portal, out.next())?;
        let max_tempo_gas_rate = decode::<ZonePortal::maxTempoGasRateCall, _>(portal, out.next())?;
        let bounceback_gas = decode::<ZonePortal::bouncebackGasCall, _>(portal, out.next())?;
        let deposit_fee = decode::<ZonePortal::calculateDepositFeeCall, _>(portal, out.next())?;
        let bounceback_fee =
            decode::<ZonePortal::calculateBouncebackFeeCall, _>(portal, out.next())?;
        let paused = decode::<ZonePortal::pausedCall, _>(portal, out.next())?;
        let withdrawal_batch_index =
            decode::<ZonePortal::withdrawalBatchIndexCall, _>(portal, out.next())?;
        let block_hash = decode::<ZonePortal::blockHashCall, _>(portal, out.next())?;
        let deposit_queue_hash =
            decode::<ZonePortal::currentDepositQueueHashCall, _>(portal, out.next())?;
        let deposit_count = decode::<ZonePortal::depositCountCall, _>(portal, out.next())?;
        let last_processed_deposit =
            decode::<ZonePortal::lastProcessedDepositNumberCall, _>(portal, out.next())?;
        let head = decode::<ZonePortal::withdrawalQueueHeadCall, _>(portal, out.next())?;
        let tail = decode::<ZonePortal::withdrawalQueueTailCall, _>(portal, out.next())?;
        let token_count = decode::<ZonePortal::enabledTokenCountCall, _>(portal, out.next())?;
        let token_enablement_hash =
            decode::<ZonePortal::tokenEnablementHashCall, _>(portal, out.next())?;
        let key_count = decode::<ZonePortal::encryptionKeyCountCall, _>(portal, out.next())?;
        let sequencer_count = decode::<ZonePortal::sequencerCountCall, _>(portal, out.next())?;
        let count = |count: U256| count.saturating_to::<u64>();
        let (token_count, key_count) = (count(token_count), count(key_count));

        // The lists, the queue's slots and the factory's record of the zone.
        let queue_slots = WithdrawalQueue::indices(head, tail);
        let indices = |count: u64| (0..count.min(MAX_READ)).map(U256::from);
        let mut calls: Vec<(Address, Bytes)> = vec![
            (
                factory,
                IZoneFactory::zonesCall { id: zone_id }.abi_encode().into(),
            ),
            (
                factory,
                IZoneFactory::isZonePortalCall { portal }
                    .abi_encode()
                    .into(),
            ),
        ];
        calls.extend(queue_slots.iter().map(|&queue_index| {
            let call = ZonePortal::withdrawalQueueSlotCall {
                queueIndex: queue_index,
            };
            (portal, call.abi_encode().into())
        }));
        calls.extend(indices(token_count).map(|index| {
            (
                portal,
                ZonePortal::enabledTokenAtCall { index }.abi_encode().into(),
            )
        }));
        for index in indices(key_count) {
            calls.push((
                portal,
                ZonePortal::encryptionKeyAtCall { index }
                    .abi_encode()
                    .into(),
            ));
            let valid = ZonePortal::isEncryptionKeyValidCall { keyIndex: index };
            calls.push((portal, valid.abi_encode().into()));
        }
        calls.extend(indices(count(sequencer_count)).map(|index| {
            (
                portal,
                ZonePortal::sequencerAtCall { index }.abi_encode().into(),
            )
        }));
        let mut out = views.call(&calls).map_err(ObserveError::Views)?.into_iter();
        let registered = decode::<IZoneFactory::zonesCall, _>(factory, out.next())?.portal;
        let is_zone_portal = decode::<IZoneFactory::isZonePortalCall, _>(factory, out.next())?;
        let mut slots = BTreeMap::new();
        for index in queue_slots {
            let slot = decode::<ZonePortal::withdrawalQueueSlotCall, _>(portal, out.next())?;
            slots.insert(index, slot);
        }
        let listed = indices(token_count)
            .map(|_| decode::<ZonePortal::enabledTokenAtCall, _>(portal, out.next()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut keys = Vec::new();
        for _ in indices(key_count) {
            let entry = decode::<ZonePortal::encryptionKeyAtCall, _>(portal, out.next())?;
            let valid = decode::<ZonePortal::isEncryptionKeyValidCall, _>(portal, out.next())?;
            keys.push(Key {
                x: entry.x,
                y_parity: entry.yParity,
                activation_block: entry.activationBlock,
                valid: valid.valid,
            });
        }
        let sequencers = indices(count(sequencer_count))
            .map(|_| decode::<ZonePortal::sequencerAtCall, _>(portal, out.next()))
            .collect::<Result<Vec<_>, _>>()?;

        // Each token's config, the portal's balance of it, and the owners' refunds of it.
        let mut calls: Vec<(Address, Bytes)> = Vec::new();
        for &token in &listed {
            calls.push((
                portal,
                ZonePortal::tokenConfigCall { token }.abi_encode().into(),
            ));
            calls.push((
                token,
                ITIP20::balanceOfCall { account: portal }
                    .abi_encode()
                    .into(),
            ));
            calls.extend(owners.iter().map(|&owner| {
                (
                    portal,
                    ZonePortal::refundsCall { token, owner }.abi_encode().into(),
                )
            }));
        }
        let mut out = views.call(&calls).map_err(ObserveError::Views)?.into_iter();
        let mut tokens = Vec::new();
        let mut refunds = BTreeMap::new();
        for &token in &listed {
            let config = decode::<ZonePortal::tokenConfigCall, _>(portal, out.next())?;
            let balance = optional(views, decode::<ITIP20::balanceOfCall, _>(token, out.next()))?;
            for &owner in owners {
                let refund = decode::<ZonePortal::refundsCall, _>(portal, out.next());
                if let Some(refund) = optional(views, refund)? {
                    refunds.insert((token, owner), refund);
                }
            }
            tokens.push(Token {
                token,
                enabled: config.enabled,
                deposits_active: config.depositsActive,
                balance,
            });
        }

        Ok(Self {
            portal,
            zone_id,
            admin,
            pending_admin,
            messenger,
            registered,
            is_zone_portal,
            zone_gas_rate,
            max_tempo_gas_rate,
            bounceback_gas,
            deposit_fee,
            bounceback_fee,
            paused,
            withdrawal_batch_index,
            block_hash,
            deposit_queue_hash,
            deposit_count,
            last_processed_deposit,
            queue: WithdrawalQueue { head, tail, slots },
            token_count,
            tokens,
            token_enablement_hash,
            key_count,
            keys,
            sequencers,
            refunds,
        })
    }
}

impl fmt::Display for Portal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "portal {} (zone {})", self.portal, self.zone_id)
    }
}

/// A portal, the factory that registered it, and the accounts whose refunds to read.
#[derive(Debug, Clone, Copy)]
pub struct At<'a> {
    pub portal: Address,
    pub factory: Address,
    pub owners: &'a [Address],
}

/// A deposit-queue entry an event reports.
#[derive(Debug, Clone)]
pub enum Enqueued {
    Deposit(ZonePortal::DepositMade),
    BounceBack(ZonePortal::WithdrawalBounceBack),
}

impl Enqueued {
    /// The queue hash after this entry, from the hash before it:
    /// `keccak256(abi.encode(depositType, entry, previous))`.
    pub fn next_hash(&self, previous: B256) -> B256 {
        match self {
            Self::Deposit(d) => {
                let deposit = ZonePortal::Deposit {
                    token: d.token,
                    sender: d.sender,
                    amount: d.netAmount,
                    tempoRefundRecipient: d.tempoRefundRecipient,
                    keyIndex: d.keyIndex,
                    encrypted: ZonePortal::DepositPayload {
                        ephemeralPubkeyX: d.ephemeralPubkeyX,
                        ephemeralPubkeyYParity: d.ephemeralPubkeyYParity,
                        ciphertext: d.ciphertext.clone(),
                        nonce: d.nonce,
                        tag: d.tag,
                    },
                };
                keccak256((DepositType::Deposit, deposit, previous).abi_encode_params())
            }
            Self::BounceBack(b) => {
                // The bounce-back's `to` carries its fallback nonce.
                let bounce = WithdrawalBounceBackDeposit {
                    token: b.token,
                    to: Address::from_word(B256::from(U256::from(b.fallbackNonce))),
                    amount: b.amount,
                };
                keccak256((DepositType::WithdrawalBounceBack, bounce, previous).abi_encode_params())
            }
        }
    }

    /// The queue hash the event reports after this entry.
    pub fn reported_hash(&self) -> B256 {
        match self {
            Self::Deposit(d) => d.newCurrentDepositQueueHash,
            Self::BounceBack(b) => b.newCurrentDepositQueueHash,
        }
    }

    /// The deposit number the event reports for this entry.
    pub fn number(&self) -> u64 {
        match self {
            Self::Deposit(d) => d.depositNumber,
            Self::BounceBack(b) => b.depositNumber,
        }
    }
}

/// A batch a `BatchSubmitted` event reports, either version of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settled {
    pub batch_index: u64,
    /// The withdrawal queue index its withdrawals took, [`NO_QUEUE_INDEX`] when it had none.
    pub queue_index: U256,
    pub block_hash: B256,
    pub withdrawal_queue_hash: B256,
    pub last_processed_deposit: u64,
}

/// The deposit-queue entries the step's portal appended, in order.
pub fn enqueued(step: &PortalStep) -> Vec<Enqueued> {
    step.logs_from(step.post.portal)
        .filter_map(|log| {
            ZonePortal::DepositMade::decode_log_data(&log.data)
                .map(Enqueued::Deposit)
                .or_else(|_| {
                    ZonePortal::WithdrawalBounceBack::decode_log_data(&log.data)
                        .map(Enqueued::BounceBack)
                })
                .ok()
        })
        .collect()
}

/// The deposits the step's portal queued, in order.
pub fn deposits(step: &PortalStep) -> Vec<ZonePortal::DepositMade> {
    step.events(step.post.portal)
}

/// The batches the step's portal settled, in order.
pub fn settled(step: &PortalStep) -> Vec<Settled> {
    step.logs_from(step.post.portal)
        .filter_map(|log| {
            if let Ok(e) = ZonePortal::BatchSubmitted_1::decode_log_data(&log.data) {
                return Some(Settled {
                    batch_index: e.withdrawalBatchIndex,
                    queue_index: e.withdrawalQueueIndex,
                    block_hash: e.nextBlockHash,
                    withdrawal_queue_hash: e.withdrawalQueueHash,
                    last_processed_deposit: e.lastProcessedDepositNumber,
                });
            }
            let e = ZonePortal::BatchSubmitted_0::decode_log_data(&log.data).ok()?;
            Some(Settled {
                batch_index: e.withdrawalBatchIndex,
                queue_index: e.withdrawalQueueIndex,
                block_hash: e.nextBlockHash,
                withdrawal_queue_hash: e.withdrawalQueueHash,
                last_processed_deposit: e.lastProcessedDepositNumber,
            })
        })
        .collect()
}

/// The `prevBlockHash` of each `submitBatch` call into the step's portal that returned, either
/// version of it, in order.
pub fn submitted_prev_hashes(step: &PortalStep) -> Vec<B256> {
    step.calls_to(step.post.portal)
        .filter(|frame| frame.success)
        .filter_map(|frame| {
            frame
                .decode::<ZonePortal::submitBatch_1Call>()
                .map(|call| call.blockTransition.prevBlockHash)
                .or_else(|| {
                    frame
                        .decode::<ZonePortal::submitBatch_0Call>()
                        .map(|call| call.blockTransition.prevBlockHash)
                })
        })
        .collect()
}

/// The token-enablement commitment after `enabled`, from the commitment before:
/// `keccak256(abi.encode(previous, token, name, symbol, currency))`.
pub fn next_enablement_hash(previous: B256, enabled: &ZonePortal::TokenEnabled) -> B256 {
    let ZonePortal::TokenEnabled {
        token,
        name,
        symbol,
        currency,
    } = enabled;
    keccak256(
        (
            previous,
            *token,
            name.clone(),
            symbol.clone(),
            currency.clone(),
        )
            .abi_encode_params(),
    )
}

/// The withdrawal-queue hash chain of `withdrawals` ahead of `remaining`:
/// `keccak256(abi.encode(withdrawal, rest))` from the last withdrawal to the first.
pub fn withdrawal_chain(withdrawals: &[ZonePortal::Withdrawal], remaining: B256) -> B256 {
    withdrawals
        .iter()
        .rev()
        .fold(remaining, |rest, withdrawal| {
            keccak256((withdrawal.clone(), rest).abi_encode_params())
        })
}

/// The portal a zone factory deploys for `zone_id`: [`ZONE_PORTAL_PREFIX`] then the ID as eight
/// big-endian bytes (TIP-1091).
pub fn portal_address(zone_id: u32) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..12].copy_from_slice(ZONE_PORTAL_PREFIX.as_slice());
    bytes[12..].copy_from_slice(&u64::from(zone_id).to_be_bytes());
    Address::from(bytes)
}

/// Whether `address` is in the zone factory's portal address range.
pub fn is_portal_address(address: Address) -> bool {
    address[..12] == ZONE_PORTAL_PREFIX[..]
}

/// Whether `x` with `y_parity` (`0x02` or `0x03`) is a compressed secp256k1 point: `x` is in the
/// field and `x^3 + 7` is a square in it.
pub fn is_compressed_point(x: B256, y_parity: u8) -> bool {
    let x = U256::from_be_bytes(x.0);
    if !matches!(y_parity, 2 | 3) || x >= SECP256K1_P {
        return false;
    }
    let rhs = x
        .pow_mod(U256::from(3), SECP256K1_P)
        .add_mod(U256::from(7), SECP256K1_P);
    rhs.pow_mod((SECP256K1_P - U256::ONE) >> 1, SECP256K1_P) <= U256::ONE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Report, Tx};
    use alloy_primitives::{Log, address, b256};
    use invariants_core::{CallKind, Frame};

    const PORTAL: Address = Address::repeat_byte(0x90);
    const ADMIN: Address = Address::repeat_byte(0xad);
    const NEXT_ADMIN: Address = Address::repeat_byte(0xae);
    const OTHER: Address = Address::repeat_byte(0x0e);
    const SEQUENCER: Address = Address::repeat_byte(0x5e);
    const TOKEN: Address = Address::repeat_byte(0x20);

    /// A successful top-level call of `call` on [`PORTAL`] from `caller`.
    fn portal_call(caller: Address, call: impl SolCall) -> Frame {
        Frame {
            depth: 0,
            kind: CallKind::Call,
            caller,
            target: PORTAL,
            input: call.abi_encode().into(),
            value: U256::ZERO,
            success: true,
            output: Bytes::new(),
        }
    }

    /// How many subjects check `id` judged on `step`, and its violations.
    fn judge(id: &str, step: &PortalStep) -> (u64, Vec<String>) {
        let mut report = Report::default();
        report.run(STEP_CHECKS, step);
        let armed = report.counts.get(id).map_or(0, |c| c.armed);
        let fired = report
            .violations
            .into_iter()
            .filter(|v| v.id == id)
            .map(|v| v.detail)
            .collect();
        (armed, fired)
    }

    /// A successful transaction's step from `pre` to `post`, emitting `logs` and making `calls`.
    fn step(pre: Portal, post: Portal, logs: Vec<Log>, calls: Vec<Frame>) -> PortalStep {
        PortalStep {
            pre,
            post,
            changes: Vec::new(),
            logs,
            calls,
            tx: Some(Tx {
                sender: ADMIN,
                success: true,
            }),
        }
    }

    /// A step from a portal administered by [`ADMIN`] to one administered by `post_admin`,
    /// making `calls`.
    fn admin_step(post_admin: Address, calls: Vec<Frame>) -> PortalStep {
        let pre = Portal {
            admin: ADMIN,
            ..Portal::absent(PORTAL)
        };
        let post = Portal {
            admin: post_admin,
            ..Portal::absent(PORTAL)
        };
        step(pre, post, Vec::new(), calls)
    }

    /// The selector of `C` alone as a successful top-level call on [`PORTAL`] from `caller`, for
    /// checks that read only which function a call ran.
    fn selector_call<C: SolCall>(caller: Address) -> Frame {
        Frame {
            input: C::SELECTOR.to_vec().into(),
            ..portal_call(caller, ZonePortal::acceptAdminCall {})
        }
    }

    /// The admin a portal was created with governs it from the creating transaction on.
    #[test]
    fn a_portal_created_in_the_step_is_governed_by_its_initial_admin() {
        let created = IZoneFactory::ZoneCreated {
            zoneId: 1,
            portal: PORTAL,
            initialToken: Address::ZERO,
            accessMode: false,
            gatewayMode: false,
            admin: ADMIN,
            sequencers: Vec::new(),
            threshold: 1,
            verifier: Address::ZERO,
        };
        let log = Log {
            address: ZONE_FACTORY_ADDRESS,
            data: created.encode_log_data(),
        };
        let set_rate =
            |caller| portal_call(caller, ZonePortal::setZoneGasRateCall { newZoneGasRate: 1 });
        let post = Portal {
            admin: ADMIN,
            ..Portal::absent(PORTAL)
        };
        let valid = step(
            Portal::absent(PORTAL),
            post.clone(),
            vec![log.clone()],
            vec![set_rate(ADMIN)],
        );
        assert_eq!(judge(ADMIN_ONLY_GOVERNANCE, &valid), (1, vec![]));
        let other = step(
            Portal::absent(PORTAL),
            post,
            vec![log],
            vec![set_rate(OTHER)],
        );
        assert_eq!(
            judge(ADMIN_ONLY_GOVERNANCE, &other).1,
            vec![format!("admin is {ADMIN}")]
        );
    }

    #[test]
    fn an_admin_handed_over_within_one_step_acts_as_admin_from_then_on() {
        let transfer = |to| portal_call(ADMIN, ZonePortal::transferAdminCall { newAdmin: to });
        let accept = || portal_call(NEXT_ADMIN, ZonePortal::acceptAdminCall {});
        let set_leader = |caller| {
            portal_call(
                caller,
                ZonePortal::setLeaderCall {
                    newLeader: NEXT_ADMIN,
                    expectedEpoch: 0,
                },
            )
        };
        let set_rate = portal_call(ADMIN, ZonePortal::setZoneGasRateCall { newZoneGasRate: 1 });
        let governance = |calls| judge(ADMIN_ONLY_GOVERNANCE, &admin_step(NEXT_ADMIN, calls));
        let not_pending = |pending: Address| vec![format!("pending admin is {pending}")];

        assert_eq!(
            governance(vec![transfer(NEXT_ADMIN), accept()]),
            (2, vec![])
        );
        assert_eq!(governance(vec![accept()]), (1, not_pending(Address::ZERO)));
        // Accepting before the transfer that names it, or after a later transfer replaced it.
        assert_eq!(
            governance(vec![accept(), transfer(NEXT_ADMIN)]),
            (2, not_pending(Address::ZERO))
        );
        assert_eq!(
            governance(vec![transfer(NEXT_ADMIN), transfer(OTHER), accept()]),
            (3, not_pending(OTHER))
        );
        // The old admin has handed over.
        assert_eq!(
            governance(vec![transfer(NEXT_ADMIN), accept(), set_rate]),
            (3, vec![format!("admin is {NEXT_ADMIN}")])
        );

        let ops = |post_admin, calls| judge(SEQUENCER_ONLY_OPS, &admin_step(post_admin, calls));
        let not_admin = vec!["the caller is not a sequencer or the admin".to_string()];
        assert_eq!(
            ops(
                NEXT_ADMIN,
                vec![transfer(NEXT_ADMIN), accept(), set_leader(NEXT_ADMIN)]
            ),
            (1, vec![])
        );
        // Acting before becoming admin.
        assert_eq!(
            ops(
                NEXT_ADMIN,
                vec![set_leader(NEXT_ADMIN), transfer(NEXT_ADMIN), accept()]
            ),
            (1, not_admin.clone())
        );
        assert_eq!(
            ops(NEXT_ADMIN, vec![set_leader(NEXT_ADMIN)]),
            (1, not_admin)
        );
    }

    #[test]
    fn a_dequeue_may_take_the_batch_queued_earlier_in_its_step() {
        let withdrawal = ZonePortal::Withdrawal {
            token: TOKEN,
            senderTag: B256::ZERO,
            to: OTHER,
            amount: 1,
            memo: B256::ZERO,
            gasLimit: 0,
            fallbackNonce: 1,
            callbackData: Bytes::new(),
            encryptedSender: Bytes::new(),
        };
        let chain = withdrawal_chain(std::slice::from_ref(&withdrawal), B256::ZERO);
        let queue = |head: u64, slots: &[u64]| WithdrawalQueue {
            head: U256::from(head),
            tail: U256::from(head),
            slots: slots.iter().map(|&i| (U256::from(i), B256::ZERO)).collect(),
        };
        // An empty queue; the batch takes slot 0 and the dequeue empties it again.
        let pre = Portal {
            queue: queue(0, &[0]),
            ..Portal::absent(PORTAL)
        };
        let post = Portal {
            queue: WithdrawalQueue {
                tail: U256::ONE,
                ..queue(1, &[0, 1])
            },
            ..Portal::absent(PORTAL)
        };
        let batch = ZonePortal::BatchSubmitted_1 {
            withdrawalBatchIndex: 1,
            withdrawalQueueIndex: U256::ZERO,
            nextProcessedDepositQueueHash: B256::ZERO,
            nextBlockHash: B256::ZERO,
            withdrawalQueueHash: chain,
            lastProcessedDepositNumber: 0,
            lastProcessedEnabledTokenCount: 0,
        };
        let logs = vec![Log {
            address: PORTAL,
            data: batch.encode_log_data(),
        }];
        let submit = selector_call::<ZonePortal::submitBatch_1Call>(SEQUENCER);
        let process = portal_call(
            SEQUENCER,
            ZonePortal::processWithdrawalsCall {
                withdrawals: vec![withdrawal],
                remainingQueue: B256::ZERO,
            },
        );
        let dequeue = |calls| {
            judge(
                WITHDRAWAL_DEQUEUE_AUTH,
                &step(pre.clone(), post.clone(), logs.clone(), calls),
            )
        };

        assert_eq!(dequeue(vec![submit.clone(), process.clone()]), (1, vec![]));
        // Dequeued before the batch queued anything.
        assert_eq!(
            dequeue(vec![process, submit]),
            (
                1,
                vec![format!(
                    "dequeued 1 withdrawals hashing to {chain}, head slot 0 held {}",
                    B256::ZERO
                )]
            )
        );
    }

    #[test]
    fn a_deposit_pays_the_zone_gas_rate_in_force_when_it_ran() {
        let fee = FIXED_DEPOSIT_GAS * 2;
        let portal = Portal {
            admin: ADMIN,
            zone_gas_rate: 1,
            ..Portal::absent(PORTAL)
        };
        let deposit = ZonePortal::DepositMade {
            newCurrentDepositQueueHash: B256::ZERO,
            sender: OTHER,
            token: TOKEN,
            netAmount: 1,
            fee,
            keyIndex: U256::ZERO,
            ephemeralPubkeyX: B256::ZERO,
            ephemeralPubkeyYParity: 2,
            ciphertext: Bytes::new(),
            nonce: Default::default(),
            tag: Default::default(),
            tempoRefundRecipient: OTHER,
            depositNumber: 1,
        };
        let paid = ITIP20::Transfer {
            from: PORTAL,
            to: ADMIN,
            amount: U256::from(fee),
        };
        let logs = vec![
            Log {
                address: PORTAL,
                data: deposit.encode_log_data(),
            },
            Log {
                address: TOKEN,
                data: paid.encode_log_data(),
            },
        ];
        let set_rate = |rate| {
            portal_call(
                ADMIN,
                ZonePortal::setZoneGasRateCall {
                    newZoneGasRate: rate,
                },
            )
        };
        let deposit_call = selector_call::<ZonePortal::depositCall>(OTHER);
        let snapshot = |calls| {
            judge(
                DEPOSIT_FEE_SNAPSHOT,
                &step(portal.clone(), portal.clone(), logs.clone(), calls),
            )
        };

        // The rate is 2 only while the deposit runs, 1 before and after the step.
        assert_eq!(
            snapshot(vec![set_rate(2), deposit_call.clone(), set_rate(1)]),
            (1, vec![])
        );
        assert_eq!(
            snapshot(vec![deposit_call, set_rate(2), set_rate(1)]),
            (1, vec![format!("fee {fee}, zoneGasRate 1 when it ran")])
        );
        // Untraced, the rate before or after the step is all there is to go on.
        assert_eq!(
            snapshot(vec![]),
            (1, vec![format!("fee {fee}, zoneGasRate before 1 after 1")])
        );
    }

    #[test]
    fn portal_addresses_carry_the_zone_id_big_endian() {
        assert_eq!(
            portal_address(0x0102_0304),
            address!("5ad0000000000000000000000000000001020304")
        );
        assert!(is_portal_address(portal_address(7)));
        assert!(!is_portal_address(ZONE_FACTORY_ADDRESS));
    }

    #[test]
    fn the_generator_is_a_compressed_point_and_zero_is_not() {
        let gx = b256!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        assert!(is_compressed_point(gx, 2));
        assert!(is_compressed_point(gx, 3));
        assert!(!is_compressed_point(gx, 4));
        assert!(!is_compressed_point(B256::from(SECP256K1_P), 2));
        // x = 5: 5^3 + 7 = 132 is not a square mod p.
        assert!(!is_compressed_point(B256::from(U256::from(5)), 2));
    }
}
