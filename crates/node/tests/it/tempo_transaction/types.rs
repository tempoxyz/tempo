use alloy::{
    primitives::{Address, B256, U256},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use tempo_node::rpc::TempoTransactionRequest;
use tempo_primitives::SignatureType;

/// Test environment abstraction for matrix tests and scenario runners.
///
/// Unifies local (single-node) and testnet runners behind one interface so
/// the matrix tests and scenario runners in `runners.rs` can be generic
/// over the environment.
pub(crate) trait TestEnv: Sized {
    type P: Provider + Clone;

    fn provider(&self) -> &Self::P;
    fn chain_id(&self) -> u64;

    /// Fund `addr` with fee tokens so it can transact.
    /// Returns the funded amount.
    async fn fund_account(&mut self, addr: Address) -> eyre::Result<U256>;

    /// Submit a signed, encoded transaction and wait until it is mined.
    /// Returns the receipt JSON.
    async fn submit_tx(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value>;

    /// Submit a transaction that is expected to be rejected by the RPC.
    /// If `expected_reason` is provided, the error message must contain it.
    async fn submit_tx_expecting_rejection(
        &self,
        encoded: Vec<u8>,
        expected_reason: Option<&str>,
    ) -> eyre::Result<()> {
        let result = self
            .provider()
            .raw_request::<_, B256>("eth_sendRawTransaction".into(), [encoded])
            .await;
        assert!(result.is_err(), "Transaction should be rejected");
        if let (Some(reason), Err(err)) = (expected_reason, &result) {
            let err_str = err.to_string().to_lowercase();
            assert!(
                err_str.contains(&reason.to_lowercase()),
                "Rejection error should contain '{reason}', got: {err}"
            );
        }
        Ok(())
    }

    /// Submit a transaction that enters the pool but is excluded by the block
    /// builder (execution simulation fails). Asserts no receipt exists after mining.
    async fn submit_tx_excluded_by_builder(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<()>;

    /// Submit a signed, encoded transaction and wait until it is mined.
    /// Returns the receipt JSON WITHOUT asserting status (caller checks).
    async fn submit_tx_unchecked(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value>;

    /// Submit via `eth_sendRawTransactionSync` (blocks until receipt).
    async fn submit_tx_sync(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value>;

    /// Bump the protocol (nonce-key 0) nonce by sending `count` no-op txs.
    async fn bump_protocol_nonce(
        &mut self,
        signer: &PrivateKeySigner,
        signer_addr: Address,
        count: u64,
    ) -> eyre::Result<()>;

    /// Return the current block timestamp (may advance blocks to ensure freshness).
    async fn current_block_timestamp(&mut self) -> eyre::Result<u64>;

    // -----------------------------------------------------------------------
    // Matrix runners (default implementations)
    // -----------------------------------------------------------------------

    async fn run_raw_send_matrix(&mut self) -> eyre::Result<()> {
        super::runners::run_raw_send_matrix(self).await
    }

    async fn run_send_matrix(&mut self) -> eyre::Result<()> {
        super::runners::run_send_matrix(self).await
    }

    async fn run_fill_transaction_matrix(&mut self) -> eyre::Result<()> {
        super::runners::run_fill_transaction_matrix(self).await
    }

    async fn run_fill_sign_send_matrix(&mut self) -> eyre::Result<()> {
        super::runners::run_fill_sign_send_matrix(self).await
    }

    async fn run_estimate_gas_matrix(&mut self) -> eyre::Result<()> {
        super::runners::run_estimate_gas_matrix(self).await
    }

    async fn run_fee_payer_cosign_scenario(&mut self) -> eyre::Result<()> {
        super::runners::run_fee_payer_cosign_scenario(self).await
    }

    async fn run_authorization_list_scenario(&mut self) -> eyre::Result<()> {
        super::runners::run_authorization_list_scenario(self).await
    }

    async fn run_keychain_auth_list_skipped_scenario(&mut self) -> eyre::Result<()> {
        super::runners::run_keychain_auth_list_skipped_scenario(self).await
    }

    async fn run_keychain_expiry_scenario(&mut self) -> eyre::Result<()> {
        super::runners::run_keychain_expiry_scenario(self).await
    }

    async fn run_fee_payer_negative_scenario(&mut self) -> eyre::Result<()> {
        super::runners::run_fee_payer_negative_scenario(self).await
    }

    async fn run_create_contract_address_scenario(&mut self) -> eyre::Result<()> {
        super::runners::run_create_contract_address_scenario(self).await
    }

    async fn run_gas_fee_boundary_scenario(&mut self) -> eyre::Result<()> {
        super::runners::run_gas_fee_boundary_scenario(self).await
    }

    async fn run_nonce_rejection_scenario(&mut self) -> eyre::Result<()> {
        super::runners::run_nonce_rejection_scenario(self).await
    }

    async fn run_send_negative_scenario(&mut self) -> eyre::Result<()> {
        super::runners::run_send_negative_scenario(self).await
    }
}

/// Key type for matrix tests
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum KeyType {
    Secp256k1,
    P256,
    WebAuthn,
}

/// What kind of action the raw send case performs.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) enum TestAction {
    /// No-op call to a random address.
    #[default]
    NoOp,
    /// Empty calls vec — expects pool rejection.
    Empty,
    /// Invalid CREATE (0xef initcode) — expects revert (status=0x0), nonce still bumps.
    InvalidCreate,
    /// TIP-20 transfer of `amount` to a random recipient.
    Transfer(U256),
    /// Admin call (updateSpendingLimit) targeting the keychain precompile.
    AdminCall,
}

/// Chain ID used in the KeyAuthorization (only relevant for access key setups).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) enum AuthChainId {
    /// key_authorization.chain_id == tx.chain_id (default).
    #[default]
    Matching,
    /// chain_id + 1 → pool rejection.
    Wrong,
    /// 0 (wildcard) → accepted.
    Wildcard,
}

/// Spending limits for an access key.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) enum SpendingLimits {
    /// Default 100-token limit on DEFAULT_FEE_TOKEN.
    #[default]
    Default,
    /// No limits at all (limits: None in KeyAuthorization).
    Unlimited,
    /// Empty limits vec (limits: Some([])) — no spending allowed.
    Empty,
    /// Custom per-token limit.
    Custom(U256),
}

/// Expiry for an access key authorization.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) enum KeyExpiry {
    /// No expiry (default, expiry: None).
    #[default]
    None,
    /// Already expired (expiry: Some(1)) → rejection.
    Past,
}

/// How the access key / keychain is set up for the raw send case.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) enum KeySetup {
    /// Sign with the root key directly (no access key).
    #[default]
    RootKey,
    /// Call authorizeKey precompile with keyId = Address::ZERO → revert.
    ZeroPubKey,
    /// Normal access key with configurable limits and expiry.
    AccessKey {
        limits: SpendingLimits,
        expiry: KeyExpiry,
    },
    /// Authorize the access key first, then re-use the same
    /// key_authorization (duplicate auth) → reject.
    DuplicateAuth,
    /// Authorize key1 first, main case has key1 sign a tx that includes a
    /// key_authorization for key2 → reject.
    UnauthorizedAuthorize,
    /// Sign with a never-authorized key → rejection.
    UnauthorizedKey,
    /// KeyAuthorization signed by the wrong signer → rejection.
    InvalidAuthSignature,
}

#[derive(Debug, Clone)]
pub(crate) struct RawSendTestCase {
    pub name: String,
    pub key_type: KeyType,
    pub fee_payer: bool,
    pub sync: bool,
    pub test_action: TestAction,
    pub auth_chain_id: AuthChainId,
    pub key_setup: KeySetup,
    pub expected: ExpectedOutcome,
    expected_override: Option<ExpectedOutcome>,
}

impl RawSendTestCase {
    pub(crate) fn new(key_type: KeyType) -> Self {
        Self {
            name: build_raw_name(key_type, &[]),
            key_type,
            fee_payer: false,
            sync: false,
            test_action: TestAction::NoOp,
            auth_chain_id: AuthChainId::Matching,
            key_setup: KeySetup::RootKey,
            expected: ExpectedOutcome::Success,
            expected_override: None,
        }
    }

    pub(crate) fn fee_payer(mut self) -> Self {
        self.fee_payer = true;
        self.recompute_expected();
        self.rebuild_name();
        self
    }

    pub(crate) fn key_setup(mut self, setup: KeySetup) -> Self {
        self.key_setup = setup;
        self.recompute_expected();
        self.rebuild_name();
        self
    }

    pub(crate) fn sync(mut self) -> Self {
        self.sync = true;
        self.recompute_expected();
        self.rebuild_name();
        self
    }

    pub(crate) fn test_action(mut self, action: TestAction) -> Self {
        self.test_action = action;
        self.recompute_expected();
        self.rebuild_name();
        self
    }

    pub(crate) fn auth_chain_id(mut self, chain_id: AuthChainId) -> Self {
        self.auth_chain_id = chain_id;
        self.recompute_expected();
        self.rebuild_name();
        self
    }

    pub(crate) fn expected(mut self, expected: ExpectedOutcome) -> Self {
        self.expected_override = Some(expected);
        self.recompute_expected();
        self.rebuild_name();
        self
    }

    /// Derive the canonical expected outcome from the full state.
    /// Precedence: Rejection > Revert > Success.
    fn recompute_expected(&mut self) {
        let mut outcome = ExpectedOutcome::Success;

        // 1. key_setup
        match &self.key_setup {
            KeySetup::ZeroPubKey => outcome = ExpectedOutcome::Revert,
            KeySetup::DuplicateAuth => outcome = ExpectedOutcome::ExcludedByBuilder,
            KeySetup::AccessKey {
                expiry: KeyExpiry::Past,
                ..
            }
            | KeySetup::UnauthorizedAuthorize
            | KeySetup::UnauthorizedKey
            | KeySetup::InvalidAuthSignature => outcome = ExpectedOutcome::Rejection,
            KeySetup::RootKey | KeySetup::AccessKey { .. } => {}
        }

        // 2. auth_chain_id (only relevant for AccessKey-ish setups)
        if matches!(self.auth_chain_id, AuthChainId::Wrong)
            && matches!(
                self.key_setup,
                KeySetup::AccessKey { .. }
                    | KeySetup::DuplicateAuth
                    | KeySetup::UnauthorizedAuthorize
            )
        {
            outcome = ExpectedOutcome::Rejection;
        }

        // 3. test_action — don't downgrade a Rejection to Revert
        if !matches!(outcome, ExpectedOutcome::Rejection) {
            match &self.test_action {
                TestAction::Empty => outcome = ExpectedOutcome::Rejection,
                TestAction::InvalidCreate | TestAction::AdminCall => {
                    outcome = ExpectedOutcome::Revert;
                }
                TestAction::NoOp | TestAction::Transfer(_) => {}
            }
        }

        // 4. explicit override last
        if let Some(ov) = self.expected_override {
            outcome = ov;
        }

        self.expected = outcome;
    }

    fn rebuild_name(&mut self) {
        self.name = build_raw_name(self.key_type, &self.flag_names());
    }

    fn flag_names(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.fee_payer {
            flags.push("fee_payer");
        }
        match &self.key_setup {
            KeySetup::RootKey => {}
            KeySetup::ZeroPubKey => flags.push("zero_pubkey_auth"),
            KeySetup::AccessKey { limits, expiry } => {
                flags.push("access_key");
                match limits {
                    SpendingLimits::Default => {}
                    SpendingLimits::Unlimited => flags.push("unlimited"),
                    SpendingLimits::Empty => flags.push("no_spending"),
                    SpendingLimits::Custom(_) => flags.push("custom_limit"),
                }
                if matches!(expiry, KeyExpiry::Past) {
                    flags.push("past_expiry");
                }
            }
            KeySetup::DuplicateAuth => {
                flags.push("access_key");
                flags.push("duplicate_auth");
            }
            KeySetup::UnauthorizedAuthorize => {
                flags.push("access_key");
                flags.push("unauthorized_authorize");
            }
            KeySetup::UnauthorizedKey => flags.push("unauthorized_key"),
            KeySetup::InvalidAuthSignature => flags.push("invalid_auth_sig"),
        }
        if self.sync {
            flags.push("sync");
        }
        match &self.test_action {
            TestAction::NoOp => {}
            TestAction::Empty => flags.push("empty_calls"),
            TestAction::InvalidCreate => flags.push("invalid_create"),
            TestAction::Transfer(_) => flags.push("transfer"),
            TestAction::AdminCall => flags.push("admin_call"),
        }
        match self.auth_chain_id {
            AuthChainId::Matching => {}
            AuthChainId::Wrong => flags.push("wrong_chain_id"),
            AuthChainId::Wildcard => flags.push("wildcard_chain_id"),
        }
        match self.expected {
            ExpectedOutcome::Success => {}
            ExpectedOutcome::Rejection => flags.push("reject"),
            ExpectedOutcome::Revert => flags.push("revert"),
            ExpectedOutcome::ExcludedByBuilder => flags.push("excluded"),
        }
        flags
    }
}

fn key_type_label(key_type: KeyType) -> &'static str {
    match key_type {
        KeyType::Secp256k1 => "secp256k1",
        KeyType::P256 => "p256",
        KeyType::WebAuthn => "webauthn",
    }
}

fn nonce_mode_label(nonce_mode: &NonceMode) -> &'static str {
    match nonce_mode {
        NonceMode::Protocol => "protocol",
        NonceMode::TwoD(_) => "2d",
        NonceMode::Expiring => "expiring",
        NonceMode::ExpiringAtBoundary => "expiring_at_boundary",
        NonceMode::ExpiringExceedsBoundary => "expiring_exceeds_boundary",
        NonceMode::ExpiringInPast => "expiring_in_past",
    }
}

fn build_case_name(prefix: &str, base: &str, parts: &[&str]) -> String {
    let mut name = String::with_capacity(prefix.len() + base.len() + parts.len() * 8 + 2);
    name.push_str(prefix);
    name.push_str("::");
    name.push_str(base);
    for part in parts {
        name.push('_');
        name.push_str(part);
    }
    name
}

fn build_raw_name(key_type: KeyType, flags: &[&str]) -> String {
    build_case_name("send_raw", key_type_label(key_type), flags)
}

#[derive(Debug, Clone)]
pub(crate) struct SendTestCase {
    pub name: String,
    pub key_type: KeyType,
    pub fee_payer: bool,
    pub access_key: bool,
    pub batch_calls: bool,
    pub transfer_amount: Option<U256>,
}

impl SendTestCase {
    pub(crate) fn new(key_type: KeyType) -> Self {
        Self {
            name: build_send_name(key_type, &[], &[]),
            key_type,
            fee_payer: false,
            access_key: false,
            batch_calls: false,
            transfer_amount: None,
        }
    }

    pub(crate) fn fee_payer(mut self) -> Self {
        self.fee_payer = true;
        self.rebuild_name();
        self
    }

    pub(crate) fn access_key(mut self) -> Self {
        self.access_key = true;
        self.rebuild_name();
        self
    }

    pub(crate) fn batch_calls(mut self) -> Self {
        self.batch_calls = true;
        self.rebuild_name();
        self
    }

    fn rebuild_name(&mut self) {
        self.name = build_send_name(self.key_type, &self.flag_names(), &self.opt_names());
    }

    fn flag_names(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.fee_payer {
            flags.push("fee_payer");
        }
        if self.access_key {
            flags.push("access_key");
        }
        if self.batch_calls {
            flags.push("batch_calls");
        }
        flags
    }

    fn opt_names(&self) -> Vec<&'static str> {
        let mut opts = Vec::new();
        if self.transfer_amount.is_some() {
            opts.push("transfer_amount");
        }
        opts
    }
}

fn build_send_name(key_type: KeyType, flags: &[&str], opts: &[&str]) -> String {
    let mut parts = Vec::with_capacity(flags.len() + opts.len());
    parts.extend_from_slice(flags);
    parts.extend_from_slice(opts);
    build_case_name("send", key_type_label(key_type), &parts)
}

fn build_fill_name(nonce_mode: &NonceMode, key_type: KeyType, parts: &[&str]) -> String {
    let base = format!(
        "{}_{}",
        nonce_mode_label(nonce_mode),
        key_type_label(key_type)
    );
    build_case_name("fill", &base, parts)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FeePayerContext {
    pub addr: Address,
    pub token: Address,
    pub balance_before: U256,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum NonceMode {
    Protocol,
    TwoD(u64),
    Expiring,
    ExpiringAtBoundary,
    ExpiringExceedsBoundary,
    ExpiringInPast,
}

/// Expected outcome for E2E test
#[derive(Debug, Clone, Copy)]
pub(crate) enum ExpectedOutcome {
    Success,
    /// Rejected at pool/RPC validation level (never enters chain).
    Rejection,
    /// Mined but reverted (status 0x0). Nonce still bumps.
    Revert,
    /// Enters pool but excluded by block builder (execution simulation fails).
    /// Tx is never mined — no receipt exists.
    ExcludedByBuilder,
}

/// Test case definition for fill tests and E2E matrix
pub(crate) struct FillTestCase {
    pub name: String,
    pub nonce_mode: NonceMode,
    pub key_type: KeyType,
    pub include_nonce_key: bool,
    pub fee_token: Option<Address>,
    pub fee_payer: bool,
    pub valid_before_offset: Option<i64>,
    pub valid_after_offset: Option<i64>,
    pub explicit_nonce: Option<u64>,
    pub pre_bump_nonce: Option<u64>,
    pub expected: ExpectedOutcome,
}

impl FillTestCase {
    pub(crate) fn new(nonce_mode: NonceMode, key_type: KeyType) -> Self {
        let name = build_fill_name(&nonce_mode, key_type, &[]);
        Self {
            name,
            nonce_mode,
            key_type,
            include_nonce_key: true,
            fee_token: None,
            fee_payer: false,
            valid_before_offset: None,
            valid_after_offset: None,
            explicit_nonce: None,
            pre_bump_nonce: None,
            expected: ExpectedOutcome::Success,
        }
    }

    pub(crate) fn omit_nonce_key(mut self) -> Self {
        self.include_nonce_key = false;
        self.rebuild_name();
        self
    }

    pub(crate) fn fee_payer(mut self) -> Self {
        self.fee_payer = true;
        self.rebuild_name();
        self
    }

    pub(crate) fn reject(mut self) -> Self {
        self.expected = ExpectedOutcome::Rejection;
        self.rebuild_name();
        self
    }

    pub(crate) fn fee_token(mut self, token: Address) -> Self {
        self.fee_token = Some(token);
        self.rebuild_name();
        self
    }

    pub(crate) fn valid_before_offset(mut self, offset: i64) -> Self {
        self.valid_before_offset = Some(offset);
        self.rebuild_name();
        self
    }

    pub(crate) fn valid_after_offset(mut self, offset: i64) -> Self {
        self.valid_after_offset = Some(offset);
        self.rebuild_name();
        self
    }

    pub(crate) fn explicit_nonce(mut self, nonce: u64) -> Self {
        self.explicit_nonce = Some(nonce);
        self.rebuild_name();
        self
    }

    pub(crate) fn pre_bump_nonce(mut self, count: u64) -> Self {
        self.pre_bump_nonce = Some(count);
        self.rebuild_name();
        self
    }

    fn rebuild_name(&mut self) {
        let mut parts = self.flag_names();
        parts.extend_from_slice(&self.opt_names());
        self.name = build_fill_name(&self.nonce_mode, self.key_type, &parts);
    }

    fn flag_names(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if !self.include_nonce_key {
            flags.push("omit_nonce_key");
        }
        if self.fee_payer {
            flags.push("fee_payer");
        }
        if matches!(self.expected, ExpectedOutcome::Rejection) {
            flags.push("reject");
        }
        flags
    }

    fn opt_names(&self) -> Vec<&'static str> {
        let mut opts = Vec::new();
        if self.fee_token.is_some() {
            opts.push("fee_token");
        }
        if self.valid_before_offset.is_some() {
            opts.push("valid_before_offset");
        }
        if self.valid_after_offset.is_some() {
            opts.push("valid_after_offset");
        }
        if self.explicit_nonce.is_some() {
            opts.push("explicit_nonce");
        }
        if self.pre_bump_nonce.is_some() {
            opts.push("pre_bump_nonce");
        }
        opts
    }
}

pub(crate) struct FillRequestContext {
    pub request: TempoTransactionRequest,
    pub expected_nonce: Option<u64>,
    pub expected_nonce_key: U256,
    pub expected_valid_before: Option<u64>,
    pub expected_valid_after: Option<u64>,
}

pub(crate) fn key_type_to_signature_type(key_type: KeyType) -> SignatureType {
    match key_type {
        KeyType::Secp256k1 => SignatureType::Secp256k1,
        KeyType::P256 => SignatureType::P256,
        KeyType::WebAuthn => SignatureType::WebAuthn,
    }
}

// ===========================================================================
// Gas estimation matrix types
// ===========================================================================

#[derive(Clone)]
pub(crate) enum GasCaseKind {
    KeyType {
        key_type: SignatureType,
        key_data: Option<alloy::primitives::Bytes>,
    },
    Keychain {
        key_type: Option<SignatureType>,
        num_limits: usize,
    },
    KeyAuth {
        key_type: SignatureType,
        num_limits: usize,
    },
}

pub(crate) enum ExpectedGasDiff {
    Range(std::ops::RangeInclusive<u64>),
    GreaterThan(&'static str),
}

pub(crate) struct GasCase {
    pub name: &'static str,
    pub kind: GasCaseKind,
    pub expected: ExpectedGasDiff,
}
