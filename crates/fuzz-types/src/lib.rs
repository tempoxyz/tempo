use serde::{Deserialize, Serialize};

pub const STATUS_OK: i32 = 1;
pub const STATUS_INVALID_INPUT: i32 = -1;
pub const STATUS_BUFFER_TOO_SMALL: i32 = -2;
pub const STATUS_INTERNAL_ERROR: i32 = -3;
pub const STATUS_UNIMPLEMENTED: i32 = -4;

pub const PINNED_CHAIN_ID: u64 = 42431;
pub const MODERATO_T0_TIMESTAMP: u64 = 1_770_303_600;
pub const MODERATO_T1_TIMESTAMP: u64 = MODERATO_T0_TIMESTAMP;
pub const MODERATO_T2_TIMESTAMP: u64 = 1_774_537_200;
pub const MODERATO_T3_TIMESTAMP: u64 = 1_776_780_000;
pub const MODERATO_T4_TIMESTAMP: u64 = 1_778_767_200;
/// Synthetic T5 activation used by fuzz harnesses. T5 is not scheduled on
/// Moderato yet, but fuzzing needs a deterministic activation boundary.
pub const FUZZ_T5_TIMESTAMP: u64 = MODERATO_T4_TIMESTAMP + 1_000_000;
/// Synthetic T6 activation used by fuzz harnesses. T6 is not scheduled on
/// Moderato yet, but fuzzing needs a deterministic activation boundary.
pub const FUZZ_T6_TIMESTAMP: u64 = FUZZ_T5_TIMESTAMP + 1_000_000;
/// Synthetic T7 activation used by fuzz harnesses. T7 is not scheduled on
/// Moderato yet, but fuzzing needs a deterministic activation boundary.
pub const FUZZ_T7_TIMESTAMP: u64 = FUZZ_T6_TIMESTAMP + 1_000_000;

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
                HardforkActivationInput {
                    hardfork: 6,
                    timestamp: FUZZ_T6_TIMESTAMP,
                },
                HardforkActivationInput {
                    hardfork: 7,
                    timestamp: FUZZ_T7_TIMESTAMP,
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

/// Writes `bytes` into the caller-provided FFI output buffer.
///
/// # Safety
///
/// `written` must be either null or valid for writing one `usize`. If `dst` is non-null and
/// `dst_len >= bytes.len()`, `dst` must be valid for writes of `bytes.len()` bytes and must not
/// overlap `bytes`.
pub unsafe fn write_caller_buffer(
    dst: *mut u8,
    dst_len: usize,
    written: *mut usize,
    bytes: &[u8],
) -> i32 {
    if written.is_null() {
        return STATUS_INVALID_INPUT;
    }

    unsafe { *written = bytes.len() };

    if dst.is_null() || dst_len < bytes.len() {
        return STATUS_BUFFER_TOO_SMALL;
    }

    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };

    STATUS_OK
}
