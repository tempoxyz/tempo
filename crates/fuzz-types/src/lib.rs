//! The typed inputs and outcomes of the Tempo fuzz harness, shared by the harness and the runners
//! that load it. They are exchanged bincode-encoded across the harness's C ABI;
//! [`TYPED_HARNESS_SCHEMA_VERSION`] changes with their encoding.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, Bytes, Log, U256};
use revm::context::result::{HaltReason, ResultGas};
use serde::{Deserialize, Serialize};
use tempo_hardfork::{TempoHardfork, constants::moderato::MODERATO_CHAIN_ID};

/// What a C ABI function returns.
pub type FuzzStatus = i32;

/// The input did not decode, or the output buffer was too small. The output buffer is unchanged.
pub const FUZZ_REJECT: FuzzStatus = 0;
/// The output was written.
pub const FUZZ_ACCEPT: FuzzStatus = 1;

/// The version of these types' encoding, reported in [`TempoHarnessCapabilities`].
pub const TYPED_HARNESS_SCHEMA_VERSION: u32 = 3;

/// Why an input, or part of it, did not execute.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ErrorClass {
    /// Everything executed.
    #[default]
    None = 0,
    /// The input contradicts itself or this harness's contract, e.g. a decreasing hardfork
    /// schedule, senders that do not match the transactions, or blocks out of timestamp order.
    InvalidInput = 1,
    /// A transaction or header does not decode, or has trailing bytes.
    RlpDecode = 2,
    /// The node would reject it: a sender does not recover, a header or block fails validation, or
    /// a transaction is invalid.
    Rejected = 3,
    /// The executor failed for a reason other than the block being invalid.
    Internal = 4,
    /// Execution read an account, storage slot, code or block hash that an exact pre-state
    /// ([`PreState::Exact`]) does not hold.
    IncompletePreState = 5,
}

/// A sequence with at least one element.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "Vec<T>", bound(deserialize = "T: Deserialize<'de>"))]
pub struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// The elements, to change in place; their number stays the same.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.0
    }

    /// Appends `item`.
    pub fn push(&mut self, item: T) {
        self.0.push(item);
    }
}

impl<T> TryFrom<Vec<T>> for NonEmpty<T> {
    type Error = &'static str;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        if items.is_empty() {
            Err("expected at least one element")
        } else {
            Ok(Self(items))
        }
    }
}

/// Accounts by address.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StateInput {
    pub accounts: BTreeMap<Address, AccountInput>,
}

/// An account and the storage slots given for it.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AccountInput {
    pub balance: U256,
    pub nonce: u64,
    pub code: Bytes,
    pub storage: BTreeMap<U256, U256>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BlockContextInput {
    pub block_number: u64,
    pub timestamp: u64,
    pub timestamp_millis_part: u64,
    pub basefee: u64,
    pub gas_limit: u64,
    pub beneficiary: Address,
    pub hardfork: TempoHardfork,
    /// The header's extra data. From T8 on, an epoch-boundary block must carry the DKG outcome
    /// here, or it is rejected.
    pub extra_data: Bytes,
}

impl Default for BlockContextInput {
    fn default() -> Self {
        Self {
            block_number: 1,
            timestamp: 1,
            timestamp_millis_part: 0,
            basefee: 0,
            gas_limit: 30_000_000,
            beneficiary: Address::ZERO,
            hardfork: TempoHardfork::T1,
            extra_data: Bytes::new(),
        }
    }
}

/// The chain to execute on: the dev genesis configuration with this chain ID and these hardfork
/// activation timestamps. Everything else comes from the dev genesis, including its epoch length,
/// so a network block at one of that network's epoch boundaries does not replay faithfully.
///
/// A hardfork the schedule does not list activates at its [`TempoHardfork::variant_index`], or with
/// the hardfork before it if that is later. A listed activation must not be earlier than that of
/// any hardfork before it, listed or not: `{T3: 0}` is invalid, as the unlisted T0 to T2 activate
/// after 0.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ChainSpecInput {
    pub chain_id: u64,
    pub hardforks: BTreeMap<TempoHardfork, u64>,
}

/// Seconds between the activations [`ChainSpecInput::default`] gives the hardforks Moderato has not
/// scheduled.
const UNSCHEDULED_SPACING: u64 = 1_000_000;

impl Default for ChainSpecInput {
    /// Moderato's chain ID and schedule. Hardforks Moderato has not scheduled follow its last one,
    /// a million seconds apart, so each can be selected on its own.
    fn default() -> Self {
        let mut previous = 0;
        let hardforks = TempoHardfork::VARIANTS
            .iter()
            .map(|&fork| {
                let activation = fork
                    .moderato_activation_timestamp()
                    .unwrap_or(previous + UNSCHEDULED_SPACING);
                previous = activation;
                (fork, activation)
            })
            .collect();
        Self {
            chain_id: MODERATO_CHAIN_ID,
            hardforks,
        }
    }
}

/// An input mode, as [`TempoHarnessCapabilities`] lists the ones a harness accepts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum HarnessInputKind {
    Transaction,
    State,
    Blockchain,
}

/// What to execute. Each mode has the [`TempoHarnessOutcome`] variant of the same name.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum TempoHarnessInput {
    Transaction(TempoTransactionInput),
    State(TempoStateInput),
    Blockchain(TempoBlockchainInput),
}

/// A transaction to decode and recover the sender of, without executing it.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TempoTransactionInput {
    pub tx: Bytes,
    /// Sender verified by the ingress boundary. `None` asks the harness to recover it.
    pub sender: Option<Address>,
}

/// One transaction, executed in a block described by `block_context` on the dev genesis plus
/// `pre_state`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TempoStateInput {
    pub chain_spec: ChainSpecInput,
    pub pre_state: StateInput,
    pub block_context: BlockContextInput,
    pub tx: Bytes,
    /// Sender verified by the ingress boundary. `None` asks the harness to recover it.
    pub sender: Option<Address>,
}

/// Blocks executed in order on `pre_state`, stopping at the first that fails.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TempoBlockchainInput {
    pub chain_spec: ChainSpecInput,
    pub pre_state: PreState,
    pub blocks: NonEmpty<TempoBlock>,
}

/// The state blocks execute on.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum PreState {
    /// The dev genesis allocation plus these accounts, which must not be genesis accounts. Anything
    /// else reads as empty.
    Genesis(StateInput),
    /// Exactly this state, e.g. a block's pre-state taken from a node, and the block hashes
    /// `BLOCKHASH` may read. Reading anything it does not hold fails the input with
    /// [`ErrorClass::IncompletePreState`]: an unlisted account, an unlisted slot of a listed
    /// account, or an unlisted block hash. An account with no balance, nonce or code whose listed
    /// slots are all zero does not exist, so all its slots read as zero.
    Exact {
        state: StateInput,
        block_hashes: BTreeMap<u64, B256>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TempoBlock {
    pub header: BlockHeaderInput,
    /// EIP-2718 encoded transactions.
    pub txs: Vec<Bytes>,
    /// Verified transaction senders in transaction order. Empty asks the harness to recover them.
    pub senders: Vec<Address>,
}

/// How a block's header is given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum BlockHeaderInput {
    /// The fields a fuzzer picks. The harness fills in the rest, and moves the timestamp into the
    /// window where the requested hardfork is active.
    Context(BlockContextInput),
    /// An RLP-encoded Tempo header, executed as given if the node's header checks accept it. It is
    /// not checked against a parent or against what the block produced.
    Rlp(Bytes),
}

/// The outcome of [`TempoTransactionInput`]. `sender` and `tx_type` are `None` when the transaction
/// does not decode; `sender` is also `None` when it cannot be recovered.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TransactionOutcome {
    pub error: ErrorClass,
    pub sender: Option<Address>,
    pub tx_type: Option<u8>,
}

/// A protocol invariant broken at `scope`. `id` names the invariant, e.g. `TEMPO-TIP20-SUPPLY-CAP`;
/// `message` describes this instance.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct InvariantFailure {
    pub id: String,
    pub message: String,
    pub scope: InvariantScope,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum InvariantScope {
    Transaction { block_index: u64, tx_index: u64 },
    Block { block_index: u64 },
    Execution,
}

/// The outcome of a [`TempoHarnessInput`], in the variant of the same name.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TempoHarnessOutcome {
    Transaction(TransactionOutcome),
    State(TempoExecutionOutcome),
    Blockchain(TempoExecutionOutcome),
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TempoExecutionOutcome {
    /// Why execution stopped: a block failed, or the input could not be executed at all, in which
    /// case the rest of the outcome is empty. [`ErrorClass::None`] when every block applied.
    pub error: ErrorClass,
    /// Receipts of the blocks that applied, in order.
    pub receipts: Vec<TxReceiptOutput>,
    /// The state root of `final_state`. `None` for an exact pre-state, which holds only part of the
    /// state.
    pub state_root: Option<B256>,
    /// The state after the last block that applied, without empty accounts and zero slots. A block
    /// that fails leaves no changes.
    pub final_state: StateInput,
    /// What changed, overall and at each step of each block that applied.
    pub state_diff: StateDiff,
    /// Invariants broken after a block's pre-execution changes or after a transaction. They do not
    /// stop execution.
    pub invariant_failures: Vec<InvariantFailure>,
}

/// What a harness build accepts, so a runner that loads several builds can generate inputs all of
/// them support.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TempoHarnessCapabilities {
    pub schema_version: u32,
    pub implementation: String,
    pub git_revision: String,
    pub supported_hardforks: NonEmpty<TempoHardfork>,
    pub supported_inputs: NonEmpty<HarnessInputKind>,
}

/// What changed, overall and at each step of each block that applied.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateDiff {
    /// How `final_state` differs from the pre-state.
    pub total: StateChanges,
    pub blocks: Vec<BlockChanges>,
}

/// The net changes of each step of a block.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockChanges {
    /// System calls before the transactions.
    pub pre_block: StateChanges,
    /// One entry per transaction, in order.
    pub txs: Vec<StateChanges>,
    /// System calls after the transactions.
    pub post_block: StateChanges,
}

/// Net state changes, by address and then slot.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StateChanges {
    pub accounts: Vec<AccountDiff>,
    pub storage: Vec<StorageChangeOutput>,
}

/// What changed about an account; each field is `None` or `false` when it did not change.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AccountDiff {
    pub address: Address,
    /// Whether the account exists now, if that changed.
    pub exists: Option<bool>,
    pub balance: Option<U256>,
    pub nonce: Option<u64>,
    pub code: Option<Bytes>,
    /// Whether all of its storage was cleared first.
    pub storage_cleared: bool,
}

/// How a transaction ended. A revert's data is the receipt's `output`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum TxOutcome {
    Success,
    Revert,
    Halt(HaltReason),
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TxReceiptOutput {
    pub block_index: u64,
    pub tx_index: u64,
    pub outcome: TxOutcome,
    pub gas: ResultGas,
    pub cumulative_gas_used: u64,
    pub effective_gas_price: u128,
    pub output: Bytes,
    pub logs: Vec<Log>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StorageChangeOutput {
    pub address: Address,
    pub slot: U256,
    pub before: U256,
    pub after: U256,
}
