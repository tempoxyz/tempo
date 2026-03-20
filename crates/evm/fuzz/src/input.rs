use arbitrary::Arbitrary;

/// Top-level fuzz input for concurrent execution paths.
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzInput {
    pub swarm: SwarmConfig,
    pub accounts: Vec<AccountSpec>,
    pub validators: Vec<ValidatorSpec>,
    pub blocks: Vec<BlockSpec>,
}

/// Swarm testing configuration - varies which code paths are exercised.
#[derive(Debug, Clone, Arbitrary)]
pub struct SwarmConfig {
    /// Which section layout pattern to test
    pub section_layout: SectionLayoutMode,
    /// How to order metadata entries
    pub metadata_order: MetadataOrderMode,
    /// Gas edge case mode
    pub gas_mode: GasSkewMode,
    /// Expiring nonce edge case mode
    pub expiry_mode: ExpirySkewMode,
    /// Weight for hot accounts (0-255, normalized to percentage)
    pub hot_account_weight: u8,
    /// Weight for expiring nonce txs
    pub expiring_nonce_weight: u8,
    /// Number of hot nonce keys (1-8)
    pub hot_nonce_key_count: u8,
    /// Whether to compare cached vs uncached reads
    pub compare_cache_modes: bool,
    /// Seed for randomized delivery ordering
    pub schedule_seed: u64,
}

/// Account specification for fuzzing.
#[derive(Debug, Clone, Arbitrary)]
pub struct AccountSpec {
    /// Seed for deterministic key generation
    pub key_seed: u64,
    /// Initial balance (in wei)
    pub initial_balance: u128,
    /// Initial protocol nonce
    pub initial_protocol_nonce: u64,
    /// Initial user nonce keys and values
    pub user_nonce_seeds: Vec<UserNonceSeed>,
    /// Whether this account is "hot" (frequently accessed)
    pub hot: bool,
}

/// User nonce key seed.
#[derive(Debug, Clone, Arbitrary)]
pub struct UserNonceSeed {
    pub nonce_key_raw: u128,
    pub nonce_value: u64,
}

/// Validator specification.
#[derive(Debug, Clone, Arbitrary)]
pub struct ValidatorSpec {
    /// Seed for deterministic ed25519 key generation
    pub key_seed: u64,
    /// Seed for deterministic fee recipient address
    pub fee_recipient_seed: u64,
    /// Whether this validator is active
    pub active: bool,
}

/// Block specification - describes one block in the sequence.
#[derive(Debug, Clone, Arbitrary)]
pub struct BlockSpec {
    /// Timestamp delta in seconds from previous block
    pub timestamp_delta_secs: u8,
    /// Gas limit for the block
    pub gas_limit: u32,
    /// Shared gas limit
    pub shared_gas_limit: u32,
    /// General (non-payment) gas limit
    pub general_gas_limit: u32,
    /// Normal transactions in the block
    pub normal_txs: Vec<TxSpec>,
    /// Candidate subblocks
    pub candidate_subblocks: Vec<SubblockSpec>,
    /// System transaction spec
    pub system: SystemSpec,
}

/// Transaction specification.
#[derive(Debug, Clone, Arbitrary)]
pub struct TxSpec {
    /// Index into accounts array (mod len)
    pub sender_idx: u8,
    /// Optional fee payer index
    pub fee_payer_idx: Option<u8>,
    /// Transaction kind
    pub tx_kind: TxKindSpec,
    /// Nonce mode
    pub nonce_mode: NonceMode,
    /// Raw nonce key (normalized based on nonce_mode)
    pub nonce_key_raw: u128,
    /// Explicit nonce value (if provided, overrides auto-increment)
    pub explicit_nonce: Option<u64>,
    /// Expiry delta for expiring nonces (seconds from now)
    pub valid_before_delta: Option<u8>,
    /// Gas limit for this tx
    pub gas_limit: u32,
    /// Value to send (in small units)
    pub value: u64,
    /// Optional subblock validator index (makes this a subblock tx)
    pub subblock_validator_idx: Option<u8>,
    /// Whether this is a payment tx
    pub is_payment: bool,
    /// Duplicate of another tx in this block (by index)
    pub duplicate_of: Option<u16>,
}

/// Subblock specification.
#[derive(Debug, Clone, Arbitrary)]
pub struct SubblockSpec {
    /// Index into validators array (mod len)
    pub validator_idx: u8,
    /// Indices of txs to include (from normal_txs, mod len)
    pub tx_indexes: Vec<u16>,
    /// Fee recipient mode
    pub fee_recipient_mode: FeeRecipientMode,
    /// Signature mode (valid, wrong key, corrupt)
    pub signature_mode: SignatureMode,
}

/// System transaction specification.
#[derive(Debug, Clone, Arbitrary)]
pub struct SystemSpec {
    /// Whether to include the metadata system tx
    pub include_metadata_tx: bool,
    /// Whether to duplicate the metadata tx
    pub duplicate_metadata_tx: bool,
    /// Whether to corrupt the RLP encoding
    pub corrupt_rlp: bool,
    /// Whether to use wrong block number
    pub wrong_block_number: bool,
    /// Metadata ordering mode
    pub metadata_order: MetadataOrderMode,
}

// --- Enums ---

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum TxKindSpec {
    LegacyTransfer,
    LegacyPayment,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum NonceMode {
    /// Protocol nonce (key 0) - should be rejected by NonceManager
    Protocol,
    /// User nonce key (1..N)
    UserKey,
    /// Expiring nonce (hash-based replay protection)
    Expiring,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum SectionLayoutMode {
    /// Standard ordering: StartOfBlock -> NonShared -> SubBlock -> GasIncentive -> System
    Canonical,
    /// Try to interleave NonShared and SubBlock txs
    InterleaveNonSharedAndSubblock,
    /// Place regular tx immediately after subblock section
    RegularAfterSubblock,
    /// Place regular tx after system tx (should fail)
    RegularAfterSystem,
    /// Send duplicate system metadata tx
    DuplicateSystemTx,
    /// Gas exactly at boundary to flip into GasIncentive
    GasBoundaryFlip,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum MetadataOrderMode {
    /// In the order subblocks were seen
    AsSeen,
    /// Shuffled order
    Shuffled,
    /// Missing one non-empty subblock
    MissingOneNonEmpty,
    /// Same validator appears twice
    DuplicateValidator,
    /// Unknown validator in metadata
    UnknownValidator,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum GasSkewMode {
    /// Gas limits are comfortable
    Loose,
    /// Gas near the NonShared limit
    NearNonSharedLimit,
    /// Gas near the general limit
    NearGeneralLimit,
    /// Gas near per-validator shared allocation
    NearPerValidatorSharedLimit,
    /// Gas exceeds budget by exactly 1
    OverByOne,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum ExpirySkewMode {
    /// valid_before in the past
    Past,
    /// valid_before == now (boundary, should be invalid)
    AtNow,
    /// valid_before == now + 1 (minimum valid)
    AtNowPlus1,
    /// valid_before == now + 30 (maximum valid)
    AtMaxWindow,
    /// valid_before == now + 31 (just over max, should be invalid)
    OverMaxWindow,
    /// Bias ring pointer near wraparound
    WrapAroundBias,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum FeeRecipientMode {
    /// Fee recipient matches expected validator
    MatchExpected,
    /// Fee recipient is wrong
    WrongRecipient,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum SignatureMode {
    /// Valid signature
    Valid,
    /// Signed with wrong key
    WrongKey,
    /// Corrupted signature bytes
    CorruptBytes,
}
