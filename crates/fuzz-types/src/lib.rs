use std::fmt;

use serde::{
    de::{Error as DeError, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

pub type FuzzStatus = i32;

pub const FUZZ_REJECT: FuzzStatus = 0;
pub const FUZZ_ACCEPT: FuzzStatus = 1;

pub const TYPED_HARNESS_SCHEMA_VERSION: u32 = 1;

pub const PINNED_CHAIN_ID: u64 = 42431;
pub const MODERATO_T0_TIMESTAMP: u64 = 1_770_303_600;
pub const MODERATO_T1_TIMESTAMP: u64 = MODERATO_T0_TIMESTAMP;
pub const MODERATO_T2_TIMESTAMP: u64 = 1_774_537_200;
pub const MODERATO_T3_TIMESTAMP: u64 = 1_776_780_000;
pub const MODERATO_T4_TIMESTAMP: u64 = 1_778_767_200;
/// Synthetic T5 activation used by fuzz harnesses. T5 is not scheduled on
/// Moderato yet, but fuzzing needs a deterministic activation boundary.
pub const FUZZ_T5_TIMESTAMP: u64 = MODERATO_T4_TIMESTAMP + 1_000_000;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ErrorClass {
    None = 0,
    InvalidInput = 1,
    RlpDecode = 2,
    Rejected = 3,
    Reverted = 4,
    Unimplemented = 5,
    Internal = 6,
    Invariant = 7,
}

impl Default for ErrorClass {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NonEmpty<T> {
    items: Vec<T>,
}

impl<T> NonEmpty<T> {
    pub fn new(items: Vec<T>) -> Result<Self, Vec<T>> {
        if items.is_empty() {
            Err(items)
        } else {
            Ok(Self { items })
        }
    }

    pub fn as_slice(&self) -> &[T] {
        &self.items
    }
}

impl<'de, T> Deserialize<'de> for NonEmpty<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NonEmptyVisitor<T> {
            marker: std::marker::PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for NonEmptyVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = NonEmpty<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-empty sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let first = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("expected at least one element"))?;
                let mut items = vec![first];
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(NonEmpty { items })
            }
        }

        deserializer.deserialize_seq(NonEmptyVisitor {
            marker: std::marker::PhantomData,
        })
    }
}

impl<T> Serialize for NonEmpty<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.items.serialize(serializer)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StateInput {
    pub accounts: Vec<AccountInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AccountInput {
    pub address: [u8; 20],
    pub balance: [u8; 32],
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage: Vec<StorageInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StorageInput {
    pub slot: [u8; 32],
    pub value: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BlockContextInput {
    pub block_number: u64,
    pub timestamp: u64,
    pub timestamp_millis_part: u64,
    pub basefee: u64,
    pub gas_limit: u64,
    pub beneficiary: [u8; 20],
    pub hardfork: u8,
}

impl Default for BlockContextInput {
    fn default() -> Self {
        Self {
            block_number: 1,
            timestamp: 1,
            timestamp_millis_part: 0,
            basefee: 0,
            gas_limit: 30_000_000,
            beneficiary: [0; 20],
            hardfork: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ChainSpecInput {
    pub chain_id: u64,
    pub hardforks: Vec<HardforkActivationInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct HardforkActivationInput {
    pub hardfork: u8,
    pub timestamp: u64,
}

impl Default for ChainSpecInput {
    fn default() -> Self {
        Self {
            chain_id: PINNED_CHAIN_ID,
            hardforks: vec![
                HardforkActivationInput {
                    hardfork: 3,
                    timestamp: MODERATO_T3_TIMESTAMP,
                },
                HardforkActivationInput {
                    hardfork: 4,
                    timestamp: MODERATO_T4_TIMESTAMP,
                },
                HardforkActivationInput {
                    hardfork: 5,
                    timestamp: FUZZ_T5_TIMESTAMP,
                },
            ],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Fixture {
    pub metadata: FixtureMetadata,
    pub input: BlockInput,
    pub expected: Option<BlockResult>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FixtureMetadata {
    pub fixture_id: [u8; 32],
    pub tempo_revision: String,
    pub harness_revision: String,
    pub hardfork: u8,
    pub generator: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockInput {
    pub chain_spec: ChainSpecInput,
    pub pre_state: StateInput,
    pub blocks: Vec<BlockPayload>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TxInput {
    pub chain_spec: ChainSpecInput,
    pub pre_state: StateInput,
    pub context: BlockContextInput,
    pub tx: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum HarnessInputKind {
    Transaction,
    State,
    Blockchain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TempoHarnessInput {
    Transaction(TempoTransactionInput),
    State(TempoStateInput),
    Blockchain(TempoBlockchainInput),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TempoTransactionInput {
    pub chain_spec: ChainSpecInput,
    pub fork: u8,
    pub tx: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TempoStateInput {
    pub chain_spec: ChainSpecInput,
    pub pre_state: StateInput,
    pub block_context: BlockContextInput,
    pub tx: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TempoBlockchainInput {
    pub chain_spec: ChainSpecInput,
    pub pre_state: StateInput,
    pub blocks: NonEmpty<TempoBlock>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TempoBlock {
    pub context: BlockContextInput,
    pub txs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockResult {
    pub receipts: Vec<TxReceiptOutput>,
    pub final_state: StateInput,
    #[serde(default)]
    pub state_diff: StateDiff,
    pub error: ErrorClass,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TxResult {
    pub receipt: Option<TxReceiptOutput>,
    pub final_state: StateInput,
    #[serde(default)]
    pub state_diff: StateDiff,
    pub error: ErrorClass,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TransactionOutcome {
    pub error: ErrorClass,
    pub sender: Option<[u8; 20]>,
    pub tx_type: Option<u8>,
    pub intrinsic_gas: Option<u64>,
}

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TempoHarnessOutcome {
    Transaction(TransactionOutcome),
    State(TempoExecutionOutcome),
    Blockchain(TempoExecutionOutcome),
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TempoExecutionOutcome {
    pub error: ErrorClass,
    pub receipts: Vec<TxReceiptOutput>,
    pub state_root: Option<[u8; 32]>,
    pub final_state: Option<StateInput>,
    pub state_diff: StateDiff,
    pub invariant_failures: Vec<InvariantFailure>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessCapabilities {
    #[serde(default)]
    pub supported_hardforks: Vec<u8>,
}

impl Default for HarnessCapabilities {
    fn default() -> Self {
        Self {
            supported_hardforks: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TempoHarnessCapabilities {
    pub schema_version: u32,
    pub implementation: String,
    pub git_revision: String,
    pub supported_hardforks: NonEmpty<u8>,
    pub supported_inputs: NonEmpty<HarnessInputKind>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StateDiff {
    pub accounts: Vec<AccountDiff>,
    pub storage: Vec<StorageChangeOutput>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AccountDiff {
    pub address: [u8; 20],
    pub balance: Option<[u8; 32]>,
    pub nonce: Option<u64>,
    pub code: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BlockPayload {
    pub context: BlockContextInput,
    pub txs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockExecutionResultOutput {
    pub blocks: Vec<ExecutedBlockOutput>,
    pub storage_changes: Vec<StorageChangeOutput>,
}

impl BlockExecutionResultOutput {
    pub fn receipts(&self) -> impl Iterator<Item = &TxReceiptOutput> {
        self.blocks.iter().flat_map(|block| block.receipts.iter())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutedBlockOutput {
    pub block_index: u64,
    pub receipts: Vec<TxReceiptOutput>,
    pub gas_used: u64,
    pub blob_gas_used: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TxReceiptOutput {
    pub block_index: u64,
    pub tx_index: u64,
    pub success: bool,
    pub cumulative_gas_used: u64,
    pub gas_used: u64,
    pub effective_gas_price: u128,
    pub output: Vec<u8>,
    pub logs: Vec<LogOutput>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LogOutput {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StorageChangeOutput {
    pub address: [u8; 20],
    pub slot: [u8; 32],
    pub before: [u8; 32],
    pub after: [u8; 32],
}
