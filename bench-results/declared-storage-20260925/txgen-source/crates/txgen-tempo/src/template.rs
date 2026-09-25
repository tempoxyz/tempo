use alloy_primitives::{Address, Bytes, Selector, B256, U256};
use eyre::{bail, Result};
use serde::{Deserialize, Deserializer};
use tempo_primitives::transaction::{CallScope, SelectorRule, TokenLimit};
use txgen_core::{AccountPoolDef, AccountRef, CallDef, GenValue};

/// Tempo transaction type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TempoTxType {
    Legacy,
    Eip2930,
    Eip1559,
    Tempo,
}

/// Template for Tempo transactions.
///
/// Supports all EVM transaction types (legacy, eip2930, eip1559) plus
/// Tempo native 0x76 transactions with parallel nonces, sponsorship,
/// fee tokens, and batched calls.
#[derive(Debug, Clone, Deserialize)]
pub struct TempoTemplate {
    /// Transaction type.
    #[serde(rename = "type")]
    pub tx_type: TempoTxType,

    /// Sender account reference.
    pub from: AccountRef,

    /// Gas limit.
    pub gas_limit: u64,

    /// Value to transfer.
    #[serde(default)]
    pub value: GenValue<U256>,

    /// Recipient address (None for contract creation).
    #[serde(default)]
    pub to: Option<GenValue<Address>>,

    /// Raw input data when not using `call`.
    #[serde(default)]
    pub input: Option<GenValue<Bytes>>,

    /// Contract call definition (alternative to raw `to`/`value`/`input`).
    #[serde(default)]
    pub call: Option<CallDef>,

    /// EIP-2930 access list, also supported by native Tempo and EIP-1559 transactions.
    #[serde(default)]
    pub access_list: Vec<crate::AccessListEntry>,

    /// Gas price for legacy/eip2930 transactions.
    #[serde(default)]
    pub gas_price: Option<u128>,

    /// Max fee per gas for EIP-1559+ transactions.
    #[serde(default)]
    pub max_fee_per_gas: Option<u128>,

    /// Max priority fee per gas for EIP-1559+ transactions.
    #[serde(default)]
    pub max_priority_fee_per_gas: Option<u128>,

    /// Nonce key for parallel nonces (Tempo 0x76).
    /// Key 0 is the protocol nonce, keys 1-N are user nonces for parallelization.
    #[serde(default)]
    pub nonce_key: Option<GenValue<U256>>,

    /// Explicit transaction nonce.
    ///
    /// When set, txgen uses this value directly instead of fetching or
    /// incrementing nonce state during ordinary generation. Online scenario
    /// execution requires it to match the lane's pending nonce and reserves it
    /// so concurrent submissions cannot reuse the same value.
    #[serde(default)]
    pub nonce: Option<u64>,

    /// Use Tempo expiring nonce mode (TIP-1009).
    ///
    /// When enabled, txgen sets `nonce_key = U256::MAX` and `nonce = 0`
    /// automatically, and requires either `valid_before` or `valid_for_secs`.
    #[serde(default)]
    pub expiring_nonce: bool,

    /// Fee token address for paying gas in stablecoins (Tempo 0x76).
    #[serde(default)]
    pub fee_token: Option<GenValue<Address>>,

    /// Fee payer/sponsor account (Tempo 0x76).
    #[serde(default)]
    pub sponsor: Option<AccountRef>,

    /// Transaction valid after this timestamp (Tempo 0x76).
    #[serde(default)]
    pub valid_after: Option<u64>,

    /// Transaction valid before this timestamp (Tempo 0x76).
    #[serde(default)]
    pub valid_before: Option<u64>,

    /// Relative expiry window in seconds for standard and sponsored transactions.
    /// With `--defer-signing`, these resolve it immediately before submission.
    ///
    /// Only used with `expiring_nonce: true`.
    #[serde(default)]
    pub valid_for_secs: Option<u64>,

    /// Batched calls (Tempo 0x76).
    #[serde(default)]
    pub calls: Option<Vec<CallDef>>,

    /// Tempo account-keychain authentication.
    #[serde(default)]
    pub auth: Option<TempoAuthDef>,
}

/// Tempo account-keychain auth mode.
#[derive(Debug, Clone, Deserialize)]
pub struct TempoAuthDef {
    /// Authentication mode.
    pub mode: TempoAuthMode,

    /// Access-key selection or derivation.
    #[serde(default)]
    pub access_key: Option<AccessKeyDef>,

    /// Access-key signature type. Only secp256k1 generation is currently supported.
    #[serde(default)]
    pub key_type: Option<KeyTypeDef>,

    /// Optional key expiry as a Unix timestamp.
    #[serde(default)]
    pub expiry: Option<u64>,

    /// Optional TIP20 spending limits.
    #[serde(default)]
    pub limits: Option<Vec<TokenLimitDef>>,

    /// Optional call scopes. Omitted or `unrestricted` means unrestricted calls.
    #[serde(default)]
    pub allowed_calls: Option<AllowedCallsDef>,

    /// Optional TIP-1053 witness for inline key_authorization.
    #[serde(default)]
    pub witness: Option<GenValue<B256>>,
}

/// Supported Tempo account-keychain auth modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TempoAuthMode {
    /// Sign the transaction with a pre-authorized access key.
    Keychain,
    /// Attach an inline key_authorization and sign with the authorized access key.
    KeyAuthorization,
}

/// Supported generated access-key signature types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyTypeDef {
    Secp256k1,
}

/// Access-key selection or derivation config.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessKeyDef {
    /// Setup step id to pair from.
    #[serde(default)]
    pub from_setup: Option<String>,

    /// Pairing mode for setup-derived keys.
    #[serde(default)]
    pub pair: Option<AccessKeyPairMode>,

    /// Inline derivation mode.
    #[serde(default)]
    pub derive: Option<AccessKeyDeriveMode>,

    /// BIP-39 mnemonic used for inline per-transaction access keys.
    #[serde(default)]
    pub mnemonic: Option<String>,

    /// Single starting account index for inline access-key derivation.
    pub index: Option<u32>,

    /// Account index range `[start, end)` for inline access-key derivation.
    pub range: Option<[u32; 2]>,
}

impl AccessKeyDef {
    pub(crate) fn inline_source(&self) -> Result<Option<AccountPoolDef>> {
        let has_index = self.index.is_some();
        let has_range = self.range.is_some();
        if has_index && has_range {
            bail!("inline access_key must set at most one of `index` or `range`");
        }

        let Some(mnemonic) = &self.mnemonic else {
            if has_index || has_range {
                bail!("inline access_key `index` or `range` requires `mnemonic`");
            }
            return Ok(None);
        };

        Ok(Some(AccountPoolDef {
            mnemonic: Some(mnemonic.clone()),
            index: self.index,
            range: self.range,
            fast_signable: None,
        }))
    }

    pub(crate) fn has_inline_source_fields(&self) -> bool {
        self.mnemonic.is_some() || self.index.is_some() || self.range.is_some()
    }
}

/// Setup access-key pairing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyPairMode {
    SameIndex,
}

/// Inline access-key derivation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyDeriveMode {
    PerTx,
}

/// YAML token spending limit.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenLimitDef {
    /// TIP20 token address.
    pub token: Address,

    /// Spending amount.
    #[serde(alias = "amount")]
    pub limit: GenValue<U256>,

    /// Reset period in seconds. `0` means one-time limit.
    #[serde(default)]
    pub period: u64,
}

/// YAML call-scope definition.
#[derive(Debug, Clone)]
pub enum AllowedCallsDef {
    /// No call restrictions.
    Unrestricted,
    /// Scoped mode with no allowed calls.
    DenyAll,
    /// Explicit call scopes.
    Scopes(Vec<CallScopeDef>),
}

/// Per-target allowed call scope.
#[derive(Debug, Clone, Deserialize)]
pub struct CallScopeDef {
    /// Target contract.
    pub target: Address,

    /// Selector rules for this target. Empty means any selector is allowed.
    #[serde(default, alias = "selector_rules")]
    pub selectors: Vec<SelectorRuleDef>,
}

/// Selector-level allowed call scope.
#[derive(Debug, Clone, Deserialize)]
pub struct SelectorRuleDef {
    /// 4-byte selector as `0x`-prefixed hex.
    pub selector: Selector,

    /// Optional first-address-argument allowlist.
    #[serde(default)]
    pub recipients: Vec<Address>,
}

impl<'de> Deserialize<'de> for AllowedCallsDef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Def {
            Mode(String),
            Scopes(Vec<CallScopeDef>),
        }

        match Def::deserialize(deserializer)? {
            Def::Mode(mode) if mode == "unrestricted" => Ok(Self::Unrestricted),
            Def::Mode(mode) if mode == "deny_all" || mode == "none" => Ok(Self::DenyAll),
            Def::Mode(other) => Err(serde::de::Error::unknown_variant(
                &other,
                &["unrestricted", "deny_all", "none"],
            )),
            Def::Scopes(scopes) => Ok(Self::Scopes(scopes)),
        }
    }
}

impl KeyTypeDef {
    pub(crate) fn signature_type(self) -> tempo_primitives::SignatureType {
        match self {
            Self::Secp256k1 => tempo_primitives::SignatureType::Secp256k1,
        }
    }
}

impl AllowedCallsDef {
    pub(crate) fn resolve(&self) -> Vec<CallScope> {
        match self {
            Self::Unrestricted => Vec::new(),
            Self::DenyAll => Vec::new(),
            Self::Scopes(scopes) => scopes.iter().map(CallScopeDef::resolve).collect(),
        }
    }
}

impl CallScopeDef {
    fn resolve(&self) -> CallScope {
        CallScope {
            target: self.target,
            selector_rules: self.selectors.iter().map(SelectorRuleDef::resolve).collect(),
        }
    }
}

impl SelectorRuleDef {
    fn resolve(&self) -> SelectorRule {
        SelectorRule { selector: self.selector.into(), recipients: self.recipients.clone() }
    }
}

pub(crate) fn resolve_allowed_calls(def: &Option<AllowedCallsDef>) -> Option<Vec<CallScope>> {
    match def {
        None | Some(AllowedCallsDef::Unrestricted) => None,
        Some(allowed_calls) => Some(allowed_calls.resolve()),
    }
}

pub(crate) fn token_limit(token: Address, limit: U256, period: u64) -> TokenLimit {
    TokenLimit { token, limit, period }
}
