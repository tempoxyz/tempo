//! Fuzz inputs: what a zone fuzz case contains, independent of how it is executed.

use arbitrary::{Arbitrary, Unstructured};
use tempo_chainspec::hardfork::TempoHardfork;

/// Number of funded zone accounts that sign user transactions.
pub const SIGNERS: usize = 4;
/// Most zone blocks a case executes in one batch.
pub const MAX_BLOCKS: usize = 3;
/// Most user transactions in one zone block.
pub const MAX_CALLS: usize = 6;
/// Most virtual-address masters registered on Tempo L1.
pub const MAX_MASTERS: usize = 3;

/// One fuzz case: a zone on `fork`, the Tempo L1 state it reads, and the zone blocks it executes
/// as a single proven batch.
#[derive(Debug, Clone, Arbitrary)]
pub struct ZoneCase {
    /// The Tempo hardfork active on the zone from genesis.
    pub fork: Fork,
    /// The Tempo L1 state every zone block reads at its anchor.
    pub l1: L1Input,
    /// The zone blocks, in order. Clamped to `1..=MAX_BLOCKS`.
    pub blocks: Vec<BlockInput>,
}

impl ZoneCase {
    /// The blocks this case executes, clamped to `1..=MAX_BLOCKS` with at most `MAX_CALLS` calls
    /// each.
    pub fn blocks(&self) -> Vec<&[Call]> {
        let mut blocks: Vec<&[Call]> = self
            .blocks
            .iter()
            .take(MAX_BLOCKS)
            .map(|block| &block.calls[..block.calls.len().min(MAX_CALLS)])
            .collect();
        if blocks.is_empty() {
            blocks.push(&[]);
        }
        blocks
    }

    /// The masters this case registers, at most `MAX_MASTERS`.
    pub fn masters(&self) -> &[MasterInput] {
        &self.l1.masters[..self.l1.masters.len().min(MAX_MASTERS)]
    }
}

/// The Tempo hardforks a zone can run, from the first one zones launched on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fork {
    /// T13.
    T13,
    /// T14.
    T14,
    /// T15: zone transfers (TIP-1160) and zone virtual addresses (TIP-1179).
    T15,
}

impl<'a> Arbitrary<'a> for Fork {
    /// T15 two times in three, since its features are what the harness targets.
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=5u8)? {
            0 => Self::T13,
            1 => Self::T14,
            _ => Self::T15,
        })
    }
}

impl From<Fork> for TempoHardfork {
    fn from(fork: Fork) -> Self {
        match fork {
            Fork::T13 => Self::T13,
            Fork::T14 => Self::T14,
            Fork::T15 => Self::T15,
        }
    }
}

/// The Tempo L1 state the zone reads.
#[derive(Debug, Clone)]
pub struct L1Input {
    /// The portal's TIP-1160 `transfersEnabled` opt-in.
    pub transfers_enabled: bool,
    /// Whether pathUSD is paused on Tempo, which TIP-1160 mirrors into the zone.
    pub path_usd_paused: bool,
    /// TIP-1022 masters registered in Tempo's address registry.
    pub masters: Vec<MasterInput>,
}

impl<'a> Arbitrary<'a> for L1Input {
    /// Transfers enabled three times in four and pathUSD paused one time in eight: a paused fee
    /// token refuses every transaction, so it leaves little to check.
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            transfers_enabled: u.ratio(3u8, 4)?,
            path_usd_paused: u.ratio(1u8, 8)?,
            masters: Arbitrary::arbitrary(u)?,
        })
    }
}

/// A TIP-1022 master registered on Tempo L1.
#[derive(Debug, Clone, Copy, Arbitrary)]
pub struct MasterInput {
    /// The master ID, bytes `[0:4]` of its virtual addresses.
    pub id: [u8; 4],
    /// The zone signer the ID resolves to.
    pub owner: Signer,
}

/// One zone block's user transactions.
#[derive(Debug, Clone)]
pub struct BlockInput {
    /// The calls, each sent as one transaction. Clamped to `MAX_CALLS`.
    pub calls: Vec<Call>,
}

impl<'a> Arbitrary<'a> for BlockInput {
    /// One to `MAX_CALLS` calls.
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let count = u.int_in_range(1..=MAX_CALLS)?;
        let calls = (0..count)
            .map(|_| Call::arbitrary(u))
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self { calls })
    }
}

/// A user transaction.
#[derive(Debug, Clone, Arbitrary)]
pub enum Call {
    /// `pathUSD.transfer`, or `transferWithMemo` with a memo.
    Transfer {
        /// The sender.
        from: Signer,
        /// The recipient.
        to: Recipient,
        /// The amount, in base units.
        amount: Amount,
        /// The memo, which selects `transferWithMemo`.
        memo: Option<[u8; 32]>,
    },
    /// `pathUSD.approve`.
    Approve {
        /// The owner granting the allowance.
        owner: Signer,
        /// The spender.
        spender: Signer,
        /// The allowance, in base units.
        amount: Amount,
    },
    /// `pathUSD.transferFrom`.
    TransferFrom {
        /// The spender sending the transaction.
        spender: Signer,
        /// The account debited.
        from: Signer,
        /// The recipient.
        to: Recipient,
        /// The amount, in base units.
        amount: Amount,
    },
    /// Arbitrary calldata to a zone system contract or pathUSD.
    Raw {
        /// The sender.
        from: Signer,
        /// The contract called.
        to: Target,
        /// The calldata.
        data: Vec<u8>,
    },
}

/// A pathUSD amount: usually small enough to afford, sometimes any `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Amount(pub u64);

impl<'a> Arbitrary<'a> for Amount {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(if u.ratio(7u8, 8)? {
            u.int_in_range(0..=1_000_000_000)?
        } else {
            u64::arbitrary(u)?
        }))
    }
}

impl From<Amount> for u64 {
    fn from(amount: Amount) -> Self {
        amount.0
    }
}

/// A zone signer, by index modulo `SIGNERS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
pub struct Signer(pub u8);

impl Signer {
    /// The signer's index.
    pub fn index(self) -> usize {
        usize::from(self.0) % SIGNERS
    }
}

/// A transfer recipient.
#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum Recipient {
    /// A zone signer.
    Signer(Signer),
    /// A virtual address of one of the case's masters, by index modulo the master count.
    Virtual {
        /// The master's index.
        master: u8,
        /// The user tag, bytes `[14:20]`.
        tag: [u8; 6],
    },
    /// A virtual address of a master ID that may not be registered.
    AnyVirtual {
        /// The master ID.
        id: [u8; 4],
        /// The user tag.
        tag: [u8; 6],
    },
    /// Any address.
    Address([u8; 20]),
}

/// A contract a raw call targets.
#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum Target {
    /// pathUSD.
    PathUsd,
    /// The `ZoneInbox` system contract.
    Inbox,
    /// The `ZoneOutbox` system contract.
    Outbox,
    /// The `TempoState` system contract.
    TempoState,
    /// The TIP-1022 address registry address, which has no precompile on zones.
    AddressRegistry,
}
