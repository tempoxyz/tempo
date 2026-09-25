mod access_list;
pub use access_list::{AccessListEntry, StorageKeyRange, StorageKeys};
pub mod auth_token_map;
pub mod late_sign;
mod nonce;
mod template;
mod zone;
pub mod zone_auth;

pub use late_sign::{
    sign_tempo_expiring, SignerLocator, TempoExpiringPayload, TempoLateSigner,
    FORMAT_TEMPO_EXPIRING_RELATIVE,
};
pub use nonce::{prefetch_parallel_nonces, NONCE_PRECOMPILE};
pub use txgen_cli::fetch_protocol_nonces;

use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_network::TransactionBuilder;
use alloy_primitives::{keccak256, Address, Bytes, TxKind, U256};
use alloy_provider::{network::Ethereum, DynProvider};
use alloy_signer::SignerSync;
use eyre::{bail, Result, WrapErr};
use rand::RngCore;
use serde::Deserialize;
use std::{collections::HashMap, num::NonZeroU64, sync::OnceLock};
use tempo_alloy::{
    provider::keychain::{authorize_key, KeyRestrictions},
    rpc::TempoTransactionRequest,
    TempoNetwork,
};
use tempo_primitives::{
    transaction::{
        Call, KeyAuthorization, KeychainSignature, PrimitiveSignature, SignatureType,
        TEMPO_EXPIRING_NONCE_KEY, TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS,
    },
    TempoSignature, TempoTxEnvelope,
};
use txgen_cli::{
    sign_standard_request, GenerateContext, NetworkAdapter, RequestSignContext,
    ScenarioActionContext, TxRequest,
};
use txgen_core::{
    derive_mnemonic_signer, AccountPoolDef, BuildContext, EcdsaSigner, GeneratedTx, SchedulingKey,
    SelectedSigner, TxPhase,
};

use template::{
    resolve_allowed_calls, token_limit, AccessKeyDef, AccessKeyDeriveMode, AccessKeyPairMode,
    AllowedCallsDef, KeyTypeDef, TempoAuthDef, TempoAuthMode, TokenLimitDef,
};
pub use template::{TempoTemplate, TempoTxType};

/// Internal nonce-tracker slot used to derive deterministic uniqueness bumps for
/// expiring nonce transactions.
const EXPIRING_UNIQUENESS_COUNTER_KEY: [u8; 20] = *b"tempo-expiring-seq!!";
const INLINE_ACCESS_KEY_MNEMONIC: &str =
    "test test test test test test test test test test test junk";
const INLINE_ACCESS_KEY_START_INDEX: u32 = 1_000_000;

/// Extract the signed validity deadline for bench's shared pending tracker.
/// Unknown/non-Tempo envelopes retain the generic inclusion timeout.
pub fn transaction_expiry(raw: &Bytes) -> Option<u64> {
    TempoTxEnvelope::decode_2718(&mut raw.as_ref())
        .ok()?
        .as_aa()?
        .tx()
        .valid_before
        .map(NonZeroU64::get)
}

/// Tempo network adapter for transaction generation.
///
/// Supports all Ethereum transaction types (legacy, EIP-2930, EIP-1559)
/// plus Tempo native 0x76 transactions.
///
/// Holds the RPC [`DynProvider`] populated by [`Self::prefetch_nonces`] so
/// [`Self::build_request`] can lazy-fetch nonces for `(account, nonce_key)`
/// pairs that [`prefetch_parallel_nonces`] cannot enumerate up front (any
/// non-literal `nonce_key`, such as `uniform` or `choice`).
#[derive(Default)]
pub struct TempoAdapter {
    /// Set exactly once by [`Self::prefetch_nonces`], then read lock-free
    /// on the hot path by [`Self::next_nonce_lazy`].
    nonce_rpc: OnceLock<NonceRpc>,
    /// Keychain setup state keyed by setup step id.
    keychain_setups: HashMap<String, TempoKeychainSetup>,
}

struct NonceRpc {
    provider: DynProvider<Ethereum>,
    pending: bool,
}

#[derive(Clone)]
struct TempoKeychainSetup {
    account_pool: String,
    key_type: SignatureType,
    access_keys: Vec<EcdsaSigner>,
}

#[derive(Clone, Default)]
pub enum TempoSignContext {
    /// Sign the request with the selected account as a normal Tempo transaction.
    #[default]
    Standard,
    /// Sign the request with an authorized access key on behalf of `user_address`.
    Keychain { user_address: Address, access_signer: EcdsaSigner },
    /// Apply signatures that depend on the fully built request before its
    /// primary account or keychain signature.
    Deferred {
        primary: Box<TempoSignContext>,
        key_authorization: Option<KeyAuthorization>,
        sponsor: Option<EcdsaSigner>,
        user_address: Address,
    },
}

impl RequestSignContext<TempoNetwork> for TempoSignContext {
    fn sign_request(
        self,
        name: String,
        phase: TxPhase,
        mut request: TempoTransactionRequest,
        signer: EcdsaSigner,
        key: [u8; 20],
        inclusion_keys: Vec<SchedulingKey>,
    ) -> Result<GeneratedTx>
    where
        <TempoNetwork as alloy_network::Network>::UnsignedTx:
            alloy_consensus::SignableTransaction<alloy_primitives::Signature>,
        <TempoNetwork as alloy_network::Network>::TxEnvelope: From<alloy_consensus::Signed<<TempoNetwork as alloy_network::Network>::UnsignedTx>>
            + Encodable2718,
    {
        match self {
            Self::Standard => sign_standard_request::<TempoNetwork>(
                name,
                phase,
                request,
                signer,
                key,
                inclusion_keys,
            ),
            Self::Keychain { user_address, access_signer } => sign_keychain_request(
                name,
                phase,
                request,
                access_signer,
                user_address,
                key,
                inclusion_keys,
            ),
            Self::Deferred { primary, key_authorization, sponsor, user_address } => {
                if let Some(authorization) = key_authorization {
                    let signature = signer.sign_hash_sync(&authorization.signature_hash())?;
                    request.set_key_authorization(
                        authorization.into_signed(PrimitiveSignature::Secp256k1(signature)),
                    );
                }
                if let Some(sponsor) = sponsor {
                    let transaction = request.clone().build_aa().map_err(|error| {
                        eyre::eyre!("failed to build AA tx for sponsor: {error}")
                    })?;
                    let fee_payer_hash = transaction.fee_payer_signature_hash(user_address);
                    request.set_fee_payer_signature(sponsor.sign_hash_sync(&fee_payer_hash)?);
                }
                primary.sign_request(name, phase, request, signer, key, inclusion_keys)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct KeychainAuthorizePoolDef {
    accounts: KeychainAccountsDef,
    access_keys: AccountPoolDef,
    #[serde(default)]
    key_type: Option<KeyTypeDef>,
    #[serde(default)]
    expiry: Option<u64>,
    #[serde(default)]
    limits: Option<Vec<TokenLimitDef>>,
    #[serde(default)]
    allowed_calls: Option<AllowedCallsDef>,
    #[serde(default)]
    gas_limit: Option<u64>,
    #[serde(default)]
    max_fee_per_gas: Option<u128>,
    #[serde(default)]
    max_priority_fee_per_gas: Option<u128>,
    #[serde(default)]
    fee_token: Option<Address>,
}

#[derive(Debug, Clone, Deserialize)]
struct KeychainAccountsDef {
    pool: String,
}

impl TempoAdapter {
    /// Create a new adapter. The nonce RPC is populated by
    /// [`Self::prefetch_nonces`] when `--rpc` is supplied.
    pub fn new() -> Self {
        Self::default()
    }

    fn register_keychain_setup(&mut self, step_id: &str, setup: TempoKeychainSetup) -> Result<()> {
        if self.keychain_setups.insert(step_id.to_string(), setup).is_some() {
            bail!("duplicate keychain setup step id '{step_id}'");
        }
        Ok(())
    }

    fn keychain_setup(&self, step_id: &str) -> Result<&TempoKeychainSetup> {
        self.keychain_setups
            .get(step_id)
            .ok_or_else(|| eyre::eyre!("keychain setup step '{step_id}' not found"))
    }

    /// Return the next nonce for `scheduling_key`, fetching the on-chain
    /// value once if the [`txgen_core::NonceTracker`] hasn't seen this lane
    /// before.
    ///
    /// Bridges from the sync `BuildContext` to the async provider via
    /// `tokio::task::block_in_place`; the `txgen-tempo` binary uses
    /// `#[tokio::main]` (multi-threaded), where this is permitted.
    fn next_nonce_lazy(
        &self,
        ctx: &mut BuildContext<'_>,
        scheduling_key: [u8; 20],
        address: Address,
        nonce_key: U256,
    ) -> Result<u64> {
        if !ctx.nonces.contains(&scheduling_key) &&
            let Some(nonce_rpc) = self.nonce_rpc.get()
        {
            if nonce_rpc.pending {
                bail!(
                    "online Tempo nonce lane was not prepared before synchronous materialization"
                );
            }
            let n = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(nonce::fetch_lane_nonce(
                    &nonce_rpc.provider,
                    address,
                    nonce_key,
                    nonce_rpc.pending,
                ))
            })?;
            ctx.nonces.reset(scheduling_key, n);
        }
        Ok(ctx.next_nonce(scheduling_key))
    }

    fn expand_keychain_authorize_pool(
        &mut self,
        step_id: &str,
        def: KeychainAuthorizePoolDef,
        ctx: &mut BuildContext<'_>,
    ) -> Result<Vec<serde_yaml::Value>> {
        let account_pool = ctx.accounts.get_pool(&def.accounts.pool)?;
        if account_pool.is_empty() {
            bail!("keychain setup accounts pool '{}' is empty", def.accounts.pool);
        }

        let access_keys = def
            .access_keys
            .derive_signers()
            .wrap_err("failed to derive keychain setup access keys")?;
        if access_keys.len() != account_pool.len() {
            bail!(
                "keychain setup access key count ({}) must match account pool '{}' count ({})",
                access_keys.len(),
                def.accounts.pool,
                account_pool.len()
            );
        }

        let key_type = def.key_type.unwrap_or(KeyTypeDef::Secp256k1).signature_type();
        let mut templates = Vec::with_capacity(access_keys.len());
        for (idx, access_key) in access_keys.iter().enumerate() {
            let restrictions =
                build_key_restrictions(def.expiry, &def.limits, &def.allowed_calls, ctx)
                    .wrap_err_with(|| {
                        format!("failed to build key restrictions for account index {idx}")
                    })?;
            let call = authorize_key(access_key.address(), key_type, restrictions);
            templates.push(keychain_setup_template_value(&def, idx, call)?);
        }

        self.register_keychain_setup(
            step_id,
            TempoKeychainSetup { account_pool: def.accounts.pool, key_type, access_keys },
        )?;

        Ok(templates)
    }

    fn apply_auth(
        &self,
        template: &TempoTemplate,
        selected: &SelectedSigner,
        req: &mut TempoTransactionRequest,
        sign_context: &mut TempoSignContext,
        deferred_key_authorization: &mut Option<KeyAuthorization>,
        ctx: &mut BuildContext<'_>,
    ) -> Result<()> {
        let Some(auth) = &template.auth else {
            return Ok(());
        };

        let key_type = auth.key_type.unwrap_or(KeyTypeDef::Secp256k1).signature_type();
        match auth.mode {
            TempoAuthMode::Keychain => {
                let access_signer = self.resolve_setup_access_signer(auth, selected, key_type)?;
                req.set_key_type(key_type);
                req.set_key_id(access_signer.address());
                *sign_context =
                    TempoSignContext::Keychain { user_address: selected.address, access_signer };
            }
            TempoAuthMode::KeyAuthorization => {
                let access_signer = derive_inline_access_signer(auth, ctx)?;
                let key_id = access_signer.address();
                let authorization = build_key_authorization(auth, key_type, key_id, ctx)?;
                *deferred_key_authorization = Some(authorization);
                req.set_key_type(key_type);
                req.set_key_id(key_id);
                *sign_context =
                    TempoSignContext::Keychain { user_address: selected.address, access_signer };
            }
        }

        Ok(())
    }

    fn resolve_setup_access_signer(
        &self,
        auth: &TempoAuthDef,
        selected: &SelectedSigner,
        key_type: SignatureType,
    ) -> Result<EcdsaSigner> {
        if auth.expiry.is_some() ||
            auth.limits.is_some() ||
            auth.allowed_calls.is_some() ||
            auth.witness.is_some()
        {
            bail!(
                "`auth.mode: keychain` uses restrictions from its setup step; put expiry, limits, allowed_calls, and witness on the setup or use `key_authorization`"
            );
        }

        let access_key = auth
            .access_key
            .as_ref()
            .ok_or_else(|| eyre::eyre!("`auth.mode: keychain` requires `access_key`"))?;
        if access_key.derive.is_some() {
            bail!("`auth.mode: keychain` does not support `access_key.derive`");
        }
        if access_key.has_inline_source_fields() {
            bail!(
                "`auth.mode: keychain` does not support inline access-key `mnemonic`, `index`, or `range`"
            );
        }
        if access_key.pair.unwrap_or(AccessKeyPairMode::SameIndex) != AccessKeyPairMode::SameIndex {
            bail!("only `access_key.pair: same_index` is supported");
        }
        let setup_id = access_key
            .from_setup
            .as_deref()
            .ok_or_else(|| eyre::eyre!("`auth.mode: keychain` requires `access_key.from_setup`"))?;
        let setup = self.keychain_setup(setup_id)?;
        if setup.account_pool != selected.pool {
            bail!(
                "keychain setup '{setup_id}' was created for account pool '{}', but template selected pool '{}'",
                setup.account_pool,
                selected.pool
            );
        }
        if setup.key_type != key_type {
            bail!("keychain setup '{setup_id}' key_type does not match template auth key_type");
        }
        setup.access_keys.get(selected.index).cloned().ok_or_else(|| {
            eyre::eyre!(
                "selected account index {} has no paired access key in setup '{}'",
                selected.index,
                setup_id
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TempoNonceMode {
    Protocol,
    Parallel(U256),
    Expiring,
}

impl NetworkAdapter for TempoAdapter {
    type Template = TempoTemplate;
    type Network = TempoNetwork;
    type SignContext = TempoSignContext;

    fn network_name() -> &'static str {
        "tempo"
    }

    fn scenario_actions() -> &'static [&'static str] {
        zone::SCENARIO_ACTIONS
    }

    async fn invoke_scenario_action(
        &self,
        action: &str,
        arguments: &serde_yaml::Value,
        context: ScenarioActionContext<'_>,
    ) -> Result<serde_yaml::Value> {
        zone::invoke(action, arguments, context).await
    }

    fn build_request(
        &self,
        template: Self::Template,
        ctx: &mut BuildContext<'_>,
    ) -> Result<TxRequest<TempoTransactionRequest, TempoSignContext>> {
        let selected = ctx.select_signer(&template.from)?;
        let is_tempo = template.tx_type == TempoTxType::Tempo;
        if template.auth.is_some() && !is_tempo {
            bail!("Tempo keychain auth is only supported for `type: tempo` templates");
        }
        let nonce_mode = resolve_nonce_mode(&template, is_tempo, ctx)?;
        if !matches!(nonce_mode, TempoNonceMode::Expiring) &&
            let Some(valid_for_secs) = template.valid_for_secs
        {
            bail!(
                "`valid_for_secs` is only supported for expiring Tempo transactions (got {valid_for_secs}s on {:?})",
                template.tx_type
            );
        }
        let scheduling_key = compute_scheduling_key(selected.address, nonce_mode, ctx);
        if matches!(nonce_mode, TempoNonceMode::Expiring) && template.nonce.is_some() {
            bail!("`nonce` must not be set for an expiring Tempo transaction");
        }
        let nonce = if let Some(nonce) = template.nonce {
            if !matches!(nonce_mode, TempoNonceMode::Expiring) &&
                self.nonce_rpc.get().is_some_and(|rpc| rpc.pending)
            {
                let expected = self.next_nonce_lazy(
                    ctx,
                    scheduling_key,
                    selected.address,
                    match nonce_mode {
                        TempoNonceMode::Protocol => U256::ZERO,
                        TempoNonceMode::Parallel(nonce_key) => nonce_key,
                        TempoNonceMode::Expiring => unreachable!("excluded above"),
                    },
                )?;
                if nonce != expected {
                    bail!(
                        "explicit nonce {nonce} does not match pending nonce {expected} for the selected Tempo lane"
                    );
                }
            }
            nonce
        } else {
            match nonce_mode {
                TempoNonceMode::Expiring => 0,
                TempoNonceMode::Protocol => {
                    self.next_nonce_lazy(ctx, scheduling_key, selected.address, U256::ZERO)?
                }
                TempoNonceMode::Parallel(nonce_key) => {
                    self.next_nonce_lazy(ctx, scheduling_key, selected.address, nonce_key)?
                }
            }
        };

        let (to, value, input, calls) = resolve_call_data(&template, is_tempo, ctx)?;

        let mut req = TempoTransactionRequest::default();
        req.set_chain_id(ctx.chain_id);
        req.set_nonce(nonce);
        req.set_gas_limit(template.gas_limit);
        if template.tx_type == TempoTxType::Legacy && !template.access_list.is_empty() {
            bail!("legacy transactions do not support access lists");
        }
        if !template.access_list.is_empty() || template.tx_type == TempoTxType::Eip2930 {
            req.set_access_list(access_list::resolve_access_list(&template.access_list, ctx)?);
        }
        let mut sign_context = TempoSignContext::Standard;
        let mut deferred_key_authorization = None;
        let mut deferred_sponsor = None;
        let mut late_sign = None;

        match template.tx_type {
            TempoTxType::Tempo => {
                req.set_max_fee_per_gas(
                    template.max_fee_per_gas.unwrap_or(ctx.gas.max_fee_per_gas),
                );
                req.set_max_priority_fee_per_gas(
                    template.max_priority_fee_per_gas.unwrap_or(ctx.gas.max_priority_fee_per_gas),
                );

                req.calls = calls;

                let is_expiring = matches!(nonce_mode, TempoNonceMode::Expiring);
                let is_late_sign = ctx.defer_signing() &&
                    is_expiring &&
                    template.valid_for_secs.is_some() &&
                    template.auth.is_none();
                let valid_before = match nonce_mode {
                    TempoNonceMode::Protocol => template.valid_before,
                    TempoNonceMode::Parallel(nonce_key) => {
                        req.set_nonce_key(nonce_key);
                        template.valid_before
                    }
                    TempoNonceMode::Expiring => {
                        req.set_nonce_key(TEMPO_EXPIRING_NONCE_KEY);
                        if is_late_sign {
                            validate_expiring_valid_for_secs(&template)?;
                            None
                        } else {
                            Some(resolve_expiring_valid_before(&template)?)
                        }
                    }
                };

                if let Some(fee_token) = &template.fee_token {
                    req.set_fee_token(ctx.resolve_value(fee_token)?);
                }
                if let Some(valid_after) = template.valid_after {
                    let valid_after = NonZeroU64::new(valid_after).ok_or_else(|| {
                        eyre::eyre!("Tempo transactions require `valid_after` to be greater than 0")
                    })?;
                    req.set_valid_after(valid_after);
                }
                if let Some(valid_before) = valid_before {
                    let valid_before = NonZeroU64::new(valid_before).ok_or_else(|| {
                        eyre::eyre!(
                            "Tempo transactions require `valid_before` to be greater than 0"
                        )
                    })?;
                    req.set_valid_before(valid_before);
                }
                if is_expiring {
                    apply_expiring_uniqueness_bump(&mut req, ctx)?;
                }

                self.apply_auth(
                    &template,
                    &selected,
                    &mut req,
                    &mut sign_context,
                    &mut deferred_key_authorization,
                    ctx,
                )?;

                if let Some(ref sponsor_ref) = template.sponsor {
                    let sponsor = ctx.select_signer(sponsor_ref)?;
                    if is_late_sign {
                        late_sign = Some(
                            TempoExpiringPayload {
                                signer: SignerLocator {
                                    pool: selected.pool.clone(),
                                    index: selected.index,
                                },
                                sponsor: Some(SignerLocator {
                                    pool: sponsor.pool,
                                    index: sponsor.index,
                                }),
                                valid_for_secs: template
                                    .valid_for_secs
                                    .expect("late signing requires valid_for_secs"),
                                request: req.clone(),
                            }
                            .into_spec()?,
                        );
                    } else {
                        deferred_sponsor =
                            Some(ctx.accounts.get_by_index(&sponsor.pool, sponsor.index)?.clone());
                    }
                } else if is_late_sign {
                    late_sign = Some(
                        TempoExpiringPayload {
                            signer: SignerLocator {
                                pool: selected.pool.clone(),
                                index: selected.index,
                            },
                            sponsor: None,
                            valid_for_secs: template
                                .valid_for_secs
                                .expect("late signing requires valid_for_secs"),
                            request: req.clone(),
                        }
                        .into_spec()?,
                    );
                }
            }
            TempoTxType::Legacy => {
                req.set_gas_price(template.gas_price.unwrap_or(ctx.gas.max_fee_per_gas));
                req.set_kind(to);
                req.set_value(value);
                if !input.is_empty() {
                    req.set_input(input);
                }
            }
            TempoTxType::Eip2930 => {
                req.set_gas_price(template.gas_price.unwrap_or(ctx.gas.max_fee_per_gas));
                req.set_kind(to);
                req.set_value(value);
                if !input.is_empty() {
                    req.set_input(input);
                }
            }
            TempoTxType::Eip1559 => {
                req.set_max_fee_per_gas(
                    template.max_fee_per_gas.unwrap_or(ctx.gas.max_fee_per_gas),
                );
                req.set_max_priority_fee_per_gas(
                    template.max_priority_fee_per_gas.unwrap_or(ctx.gas.max_priority_fee_per_gas),
                );
                req.set_kind(to);
                req.set_value(value);
                if !input.is_empty() {
                    req.set_input(input);
                }
            }
        }

        if deferred_key_authorization.is_some() || deferred_sponsor.is_some() {
            sign_context = TempoSignContext::Deferred {
                primary: Box::new(sign_context),
                key_authorization: deferred_key_authorization,
                sponsor: deferred_sponsor,
                user_address: selected.address,
            };
        }

        Ok(TxRequest {
            request: req,
            signer_pool: selected.pool,
            signer_index: selected.index,
            key: scheduling_key,
            sign_context,
            late_sign,
        })
    }

    fn late_signer(
        &self,
        spec: &txgen_core::WorkloadSpec,
    ) -> Result<Option<std::sync::Arc<dyn bench_core::LateSigner>>> {
        Ok(Some(std::sync::Arc::new(TempoLateSigner::from_spec(spec)?)))
    }

    fn scenario_unique_nonce_group(
        &self,
        template: &serde_yaml::Value,
        overlay: &serde_yaml::Value,
    ) -> Result<Option<String>> {
        let mut materialized = template.clone();
        txgen_core::merge_yaml(&mut materialized, overlay.clone());
        let Some(auth) = materialized
            .as_mapping()
            .and_then(|mapping| mapping.get(serde_yaml::Value::String("auth".to_string())))
            .filter(|auth| !auth.is_null())
        else {
            return Ok(None);
        };
        let Some(mode) = auth
            .as_mapping()
            .and_then(|mapping| mapping.get(serde_yaml::Value::String("mode".to_string())))
            .and_then(serde_yaml::Value::as_str)
        else {
            // Dynamic auth is materialized at execution time. Conservatively
            // reserve a dense identity: non-inline modes simply ignore it.
            return Ok(Some("tempo:inline-access-key".to_string()));
        };
        match mode {
            "key_authorization" => Ok(Some("tempo:inline-access-key".to_string())),
            _ => Ok(None),
        }
    }

    async fn prepare_request(
        &self,
        value: &serde_yaml::Value,
        ctx: &mut BuildContext<'_>,
    ) -> Result<()> {
        let template: TempoTemplate = serde_yaml::from_value(value.clone())
            .wrap_err("failed to parse Tempo template while preparing nonce state")?;
        if template.expiring_nonce {
            return Ok(());
        }

        // Preview only the signer and nonce-key choices. build_request performs
        // these as its first RNG operations, so cloning the RNG finds the same
        // lane without consuming the instance's deterministic stream twice.
        let mut preview_rng = (*ctx.rng).clone();
        let mut preview_nonces = txgen_core::NonceTracker::new();
        let mut preview = BuildContext::new_with_address_pools(
            ctx.chain_id,
            ctx.gas,
            ctx.accounts,
            ctx.address_pools,
            ctx.artifacts,
            &mut preview_nonces,
            &mut preview_rng,
        );
        let selected = preview.select_signer(&template.from)?;
        let nonce_mode =
            resolve_nonce_mode(&template, template.tx_type == TempoTxType::Tempo, &mut preview)?;
        let (scheduling_key, nonce_key) = match nonce_mode {
            TempoNonceMode::Protocol => (selected.address.0 .0, U256::ZERO),
            TempoNonceMode::Parallel(nonce_key) => {
                (compute_parallel_scheduling_key(selected.address, nonce_key), nonce_key)
            }
            TempoNonceMode::Expiring => return Ok(()),
        };
        if ctx.nonces.contains(&scheduling_key) {
            return Ok(());
        }
        let nonce_rpc = self
            .nonce_rpc
            .get()
            .ok_or_else(|| eyre::eyre!("online Tempo nonce provider is not initialized"))?;
        let nonce = nonce::fetch_lane_nonce(
            &nonce_rpc.provider,
            selected.address,
            nonce_key,
            nonce_rpc.pending,
        )
        .await?;
        ctx.nonces.reset(scheduling_key, nonce);
        Ok(())
    }

    fn expand_setup_extension(
        &mut self,
        step_id: &str,
        extension_name: &str,
        value: serde_yaml::Value,
        ctx: &mut BuildContext<'_>,
    ) -> Result<Option<Vec<serde_yaml::Value>>> {
        if extension_name != "keychain_authorize_pool" {
            return Ok(None);
        }

        let def: KeychainAuthorizePoolDef = serde_yaml::from_value(value)
            .wrap_err("failed to parse keychain_authorize_pool setup step")?;
        self.expand_keychain_authorize_pool(step_id, def, ctx).map(Some)
    }

    async fn prepare_nonces(
        &self,
        spec: &txgen_core::WorkloadSpec,
        accounts: &txgen_core::AccountManager,
        nonces: &mut txgen_core::NonceTracker,
        rpc: &str,
    ) -> Result<()> {
        use alloy_provider::{Provider, ProviderBuilder};
        use eyre::WrapErr;

        let provider = ProviderBuilder::<_, _, Ethereum>::new()
            .connect_http(rpc.parse().wrap_err("invalid RPC URL")?)
            .erased();

        txgen_cli::fetch_pending_protocol_nonces(accounts, nonces, rpc).await?;

        nonce::prefetch_pending_parallel_nonces(&provider, accounts, spec, nonces).await?;

        // Keep the provider so build_request can lazy-fetch nonces for any
        // (account, nonce_key) pair not enumerated by prefetch_parallel_nonces
        // (any non-literal `nonce_key` such as `uniform` or `choice`). `set`
        // only ever fails if called twice; the second call is a no-op we
        // accept silently because prefetch is only invoked once per run.
        let _ = self.nonce_rpc.set(NonceRpc { provider, pending: true });

        Ok(())
    }

    async fn prefetch_nonces(&self, ctx: &mut GenerateContext, rpc: &str) -> Result<()> {
        use alloy_provider::{Provider, ProviderBuilder};
        use eyre::WrapErr;

        let provider = ProviderBuilder::<_, _, Ethereum>::new()
            .connect_http(rpc.parse().wrap_err("invalid RPC URL")?)
            .erased();
        let (spec, accounts, nonces) = ctx.prefetch_state();
        txgen_cli::fetch_protocol_nonces(accounts, nonces, rpc).await?;
        prefetch_parallel_nonces(&provider, accounts, spec, nonces).await?;
        let _ = self.nonce_rpc.set(NonceRpc { provider, pending: false });

        Ok(())
    }
}

fn resolve_nonce_mode(
    template: &TempoTemplate,
    is_tempo: bool,
    ctx: &mut BuildContext<'_>,
) -> Result<TempoNonceMode> {
    let resolved_nonce_key =
        template.nonce_key.as_ref().map(|nonce_key| ctx.resolve_value(nonce_key)).transpose()?;

    if !is_tempo {
        if template.expiring_nonce || resolved_nonce_key == Some(TEMPO_EXPIRING_NONCE_KEY) {
            bail!("expiring nonce mode is only supported for Tempo transactions");
        }
        return Ok(TempoNonceMode::Protocol);
    }

    if template.expiring_nonce {
        if resolved_nonce_key.is_some() {
            bail!(
                "expiring nonce templates must not set `nonce_key`; txgen sets the reserved key automatically"
            );
        }
        return Ok(TempoNonceMode::Expiring);
    }

    match resolved_nonce_key.unwrap_or(U256::ZERO) {
        key if key == TEMPO_EXPIRING_NONCE_KEY => Ok(TempoNonceMode::Expiring),
        key if key.is_zero() => Ok(TempoNonceMode::Protocol),
        key => Ok(TempoNonceMode::Parallel(key)),
    }
}

fn resolve_expiring_valid_before(template: &TempoTemplate) -> Result<u64> {
    match (template.valid_before, template.valid_for_secs) {
        (Some(_), Some(_)) => {
            bail!(
                "expiring nonce templates must set either `valid_before` or `valid_for_secs`, not both"
            );
        }
        (Some(valid_before), None) => {
            if valid_before == 0 {
                bail!("expiring nonce templates require `valid_before` to be greater than 0");
            }
            Ok(valid_before)
        }
        (None, Some(valid_for_secs)) => {
            if valid_for_secs == 0 {
                bail!("expiring nonce templates require `valid_for_secs` to be greater than 0");
            }
            if valid_for_secs > TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS {
                bail!(
                    "expiring nonce templates require `valid_for_secs` <= {} seconds",
                    TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS
                );
            }
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0)
                .checked_add(valid_for_secs)
                .ok_or_else(|| {
                    eyre::eyre!("expiring nonce `valid_for_secs` overflowed unix timestamp")
                })
        }
        (None, None) => {
            bail!("expiring nonce templates require either `valid_before` or `valid_for_secs`");
        }
    }
}

fn validate_expiring_valid_for_secs(template: &TempoTemplate) -> Result<()> {
    if template.valid_before.is_some() {
        bail!(
            "expiring nonce templates must set either `valid_before` or `valid_for_secs`, not both"
        );
    }
    let valid_for_secs = template
        .valid_for_secs
        .ok_or_else(|| eyre::eyre!("expiring nonce templates require `valid_for_secs`"))?;
    if valid_for_secs == 0 {
        bail!("expiring nonce templates require `valid_for_secs` to be greater than 0");
    }
    if valid_for_secs > TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS {
        bail!(
            "expiring nonce templates require `valid_for_secs` <= {} seconds",
            TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS
        );
    }
    Ok(())
}

/// Deterministically perturb the maximum fee so expiring nonce transactions never
/// produce identical signed payloads within one generation run.
///
/// Tempo expiring nonce replay protection is hash-based, so two otherwise
/// identical transactions from the same sender can collide if their signed
/// payload is identical. txgen uses a local monotonic counter to bump
/// `max_fee_per_gas` before any signatures are produced while leaving
/// `max_priority_fee_per_gas` exactly as configured.
fn apply_expiring_uniqueness_bump(
    req: &mut TempoTransactionRequest,
    ctx: &mut BuildContext<'_>,
) -> Result<()> {
    let encoded_uniqueness = match ctx.unique_nonce_hint() {
        Some(hint) => {
            ctx.reserve_unique_nonce(EXPIRING_UNIQUENESS_COUNTER_KEY, hint);
            hint.checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| eyre::eyre!("deterministic expiring nonce identity overflow"))?
        }
        None => ctx
            .next_unique_nonce(EXPIRING_UNIQUENESS_COUNTER_KEY)
            .checked_mul(2)
            .ok_or_else(|| eyre::eyre!("expiring nonce uniqueness counter overflow"))?,
    };
    // Scenario-assigned identities use odd values while ordinary generation
    // counters use even values. This keeps both domains disjoint without large
    // gas-price changes, and retries of one scenario step remain idempotent.
    let bump = u128::from(encoded_uniqueness) + 1;

    let max_fee_per_gas = req
        .max_fee_per_gas()
        .ok_or_else(|| eyre::eyre!("Tempo expiring transactions require max_fee_per_gas"))?
        .checked_add(bump)
        .ok_or_else(|| eyre::eyre!("expiring nonce max_fee_per_gas overflowed uniqueness bump"))?;

    req.set_max_fee_per_gas(max_fee_per_gas);

    Ok(())
}

/// Compute the sender scheduling key used by txgen/bench submission ordering.
///
/// `bench send` serializes transactions that share the same scheduling key and
/// allows different keys to be sent in parallel.
///
/// - Protocol nonces use the sender address directly.
/// - 2D nonce lanes use a hash of `(sender, nonce_key)` so each lane is ordered independently.
/// - Expiring nonces use a fresh random key per transaction so txgen does not artificially
///   serialize them like a 2D lane.
pub(crate) fn compute_scheduling_key(
    sender: Address,
    nonce_mode: TempoNonceMode,
    ctx: &mut BuildContext<'_>,
) -> [u8; 20] {
    match nonce_mode {
        TempoNonceMode::Protocol => sender.0 .0,
        TempoNonceMode::Parallel(nonce_key) => compute_parallel_scheduling_key(sender, nonce_key),
        TempoNonceMode::Expiring => {
            let mut key = [0u8; 20];
            ctx.rng.fill_bytes(&mut key);
            key
        }
    }
}

/// Compute the stable scheduling key for a Tempo 2D nonce lane.
///
/// Transactions from the same sender and `nonce_key` share this key and must be
/// sent sequentially because the lane uses ordered nonces `0, 1, 2, ...`.
pub(crate) fn compute_parallel_scheduling_key(sender: Address, nonce_key: U256) -> [u8; 20] {
    let mut data = [0u8; 52];
    data[..20].copy_from_slice(sender.as_slice());
    data[20..52].copy_from_slice(&nonce_key.to_be_bytes::<32>());
    let hash = keccak256(data);
    let mut key = [0u8; 20];
    key.copy_from_slice(&hash[..20]);
    key
}

/// Resolve call data from the template into (to, value, input, calls).
///
/// For tempo transactions, the result is returned as `calls`; for EVM types
/// it is returned as `(to, value, input)`.
fn resolve_call_data(
    template: &TempoTemplate,
    is_tempo: bool,
    ctx: &mut BuildContext<'_>,
) -> Result<(TxKind, U256, Bytes, Vec<Call>)> {
    if let Some(ref call_defs) = template.calls {
        let mut calls = Vec::with_capacity(call_defs.len());
        for call_def in call_defs {
            let encoded = ctx.encode_call(call_def)?;
            calls.push(Call {
                to: TxKind::Call(encoded.to),
                value: encoded.value,
                input: encoded.input,
            });
        }
        Ok((TxKind::Create, U256::ZERO, Bytes::new(), calls))
    } else if let Some(ref call_def) = template.call {
        let encoded = ctx.encode_call(call_def)?;
        if is_tempo {
            Ok((
                TxKind::Create,
                U256::ZERO,
                Bytes::new(),
                vec![Call {
                    to: TxKind::Call(encoded.to),
                    value: encoded.value,
                    input: encoded.input,
                }],
            ))
        } else {
            Ok((TxKind::Call(encoded.to), encoded.value, encoded.input, Vec::new()))
        }
    } else {
        let to = ctx.resolve_to(&template.to)?;
        let value: U256 = ctx.resolve_value(&template.value)?;
        let input = template
            .input
            .as_ref()
            .map(|input| ctx.resolve_value(input))
            .transpose()?
            .unwrap_or_default();
        if is_tempo {
            Ok((TxKind::Create, U256::ZERO, Bytes::new(), vec![Call { to, value, input }]))
        } else {
            Ok((to, value, input, Vec::new()))
        }
    }
}

fn sign_keychain_request(
    name: String,
    phase: TxPhase,
    request: TempoTransactionRequest,
    access_signer: EcdsaSigner,
    user_address: Address,
    key: [u8; 20],
    inclusion_keys: Vec<SchedulingKey>,
) -> Result<GeneratedTx> {
    let tx = request
        .build_aa()
        .map_err(|e| eyre::eyre!("failed to build AA tx from template '{name}': {e}"))?;
    let signing_hash = KeychainSignature::signing_hash(tx.signature_hash(), user_address);
    let signature = access_signer
        .sign_hash_sync(&signing_hash)
        .map_err(|e| eyre::eyre!("failed to sign keychain tx from template '{name}': {e}"))?;
    let signature = TempoSignature::Keychain(KeychainSignature::new(
        user_address,
        PrimitiveSignature::Secp256k1(signature),
    ));
    let envelope = TempoTxEnvelope::AA(tx.into_signed(signature));
    let raw = Bytes::from(envelope.encoded_2718());

    Ok(GeneratedTx {
        depends_on: Vec::new(),
        phase,
        id: Some(name),
        raw,
        late_sign: None,
        sender: Some(user_address),
        submission_keys: vec![SchedulingKey::from(key)],
        inclusion_keys,
    })
}

fn derive_inline_access_signer(
    auth: &TempoAuthDef,
    ctx: &mut BuildContext<'_>,
) -> Result<EcdsaSigner> {
    let source = inline_access_key_source(auth.access_key.as_ref())?;
    let counter_key = inline_access_key_counter_key();
    let offset = match ctx.dense_unique_nonce_hint() {
        Some(hint) => {
            let offset =
                ctx.nonces.current(&counter_key).checked_add(hint).ok_or_else(|| {
                    eyre::eyre!("deterministic inline access-key identity overflow")
                })?;
            ctx.reserve_unique_nonce(counter_key, offset);
            offset
        }
        None => ctx.next_unique_nonce(counter_key),
    };
    let offset = u32::try_from(offset)
        .map_err(|_| eyre::eyre!("inline key_authorization access-key counter exceeded u32"))?;
    match source {
        InlineAccessKeySource::Default => {
            let index = INLINE_ACCESS_KEY_START_INDEX.checked_add(offset).ok_or_else(|| {
                eyre::eyre!("inline key_authorization access-key index overflowed")
            })?;
            derive_mnemonic_signer(INLINE_ACCESS_KEY_MNEMONIC, index)
        }
        InlineAccessKeySource::Configured(source) => {
            let (start, len) = inline_access_key_range(&source)?;
            let offset_usize = usize::try_from(offset).map_err(|_| {
                eyre::eyre!("inline key_authorization access-key counter exceeded usize")
            })?;
            if offset_usize >= len {
                bail!(
                    "inline access_key range exhausted after {len} key(s); increase `access_key.range`"
                );
            }
            let index = start.checked_add(offset).ok_or_else(|| {
                eyre::eyre!("inline key_authorization access-key index overflowed")
            })?;
            derive_mnemonic_signer(
                source
                    .mnemonic
                    .as_deref()
                    .ok_or_else(|| eyre::eyre!("inline access_key pool requires a mnemonic"))?,
                index,
            )
        }
    }
}

enum InlineAccessKeySource {
    Default,
    Configured(AccountPoolDef),
}

fn inline_access_key_source(access_key: Option<&AccessKeyDef>) -> Result<InlineAccessKeySource> {
    let Some(access_key) = access_key else {
        return Ok(InlineAccessKeySource::Default);
    };

    if access_key.from_setup.is_some() {
        bail!("`auth.mode: key_authorization` does not support `access_key.from_setup`");
    }
    if access_key.pair.is_some() {
        bail!("`auth.mode: key_authorization` does not support `access_key.pair`");
    }
    if access_key.derive.unwrap_or(AccessKeyDeriveMode::PerTx) != AccessKeyDeriveMode::PerTx {
        bail!("only `access_key.derive: per_tx` is supported");
    }

    match access_key.inline_source()? {
        Some(source) => Ok(InlineAccessKeySource::Configured(source)),
        None => Ok(InlineAccessKeySource::Default),
    }
}

fn inline_access_key_range(source: &AccountPoolDef) -> Result<(u32, usize)> {
    if let Some(index) = source.index {
        return Ok((index, usize::MAX));
    }
    if let Some([start, end]) = source.range {
        let len = end
            .checked_sub(start)
            .ok_or_else(|| eyre::eyre!("inline access_key range end must be >= start"))?;
        if len == 0 {
            bail!("inline access_key range must not be empty");
        }
        return Ok((start, len as usize));
    }

    Ok((INLINE_ACCESS_KEY_START_INDEX, usize::MAX))
}

fn inline_access_key_counter_key() -> [u8; 20] {
    let hash = keccak256(b"txgen:tempo:inline-access-key");
    let mut key = [0u8; 20];
    key.copy_from_slice(&hash[..20]);
    key
}

fn build_key_authorization(
    auth: &TempoAuthDef,
    key_type: SignatureType,
    key_id: Address,
    ctx: &mut BuildContext<'_>,
) -> Result<KeyAuthorization> {
    let mut authorization = KeyAuthorization::unrestricted(ctx.chain_id, key_type, key_id);
    if let Some(expiry) = auth.expiry {
        if expiry == 0 {
            bail!("key_authorization expiry must be greater than 0");
        }
        authorization = authorization.with_expiry(expiry);
    }
    if let Some(limits) = resolve_token_limits(&auth.limits, ctx)? {
        authorization = authorization.with_limits(limits);
    }
    if let Some(allowed_calls) = resolve_allowed_calls(&auth.allowed_calls) {
        authorization = authorization.with_allowed_calls(allowed_calls);
    }
    if let Some(witness) = &auth.witness {
        authorization = authorization.with_witness(ctx.resolve_value(witness)?);
    }
    Ok(authorization)
}

fn build_key_restrictions(
    expiry: Option<u64>,
    limits: &Option<Vec<TokenLimitDef>>,
    allowed_calls: &Option<AllowedCallsDef>,
    ctx: &mut BuildContext<'_>,
) -> Result<KeyRestrictions> {
    let mut restrictions = KeyRestrictions::default();
    if let Some(expiry) = expiry {
        if expiry == 0 {
            bail!("keychain setup expiry must be greater than 0");
        }
        restrictions = restrictions.with_expiry(expiry);
    }
    if let Some(limits) = resolve_token_limits(limits, ctx)? {
        restrictions = restrictions.with_limits(limits);
    }
    if let Some(allowed_calls) = resolve_allowed_calls(allowed_calls) {
        restrictions = restrictions.with_allowed_calls(allowed_calls);
    }
    Ok(restrictions)
}

fn resolve_token_limits(
    limits: &Option<Vec<TokenLimitDef>>,
    ctx: &mut BuildContext<'_>,
) -> Result<Option<Vec<tempo_primitives::transaction::TokenLimit>>> {
    let Some(limits) = limits else {
        return Ok(None);
    };

    limits
        .iter()
        .map(|limit| {
            let amount = ctx.resolve_value(&limit.limit)?;
            Ok(token_limit(limit.token, amount, limit.period))
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn keychain_setup_template_value(
    def: &KeychainAuthorizePoolDef,
    account_index: usize,
    call: Call,
) -> Result<serde_yaml::Value> {
    let to = call
        .to
        .into_to()
        .ok_or_else(|| eyre::eyre!("keychain authorize call unexpectedly targets CREATE"))?;
    let mut mapping = serde_yaml::Mapping::new();
    insert_yaml(&mut mapping, "type", "tempo")?;
    insert_yaml(&mut mapping, "from", account_ref_value(&def.accounts.pool, account_index)?)?;
    insert_yaml(&mut mapping, "gas_limit", def.gas_limit.unwrap_or(400_000))?;
    if let Some(max_fee_per_gas) = def.max_fee_per_gas {
        insert_yaml(&mut mapping, "max_fee_per_gas", max_fee_per_gas)?;
    }
    if let Some(max_priority_fee_per_gas) = def.max_priority_fee_per_gas {
        insert_yaml(&mut mapping, "max_priority_fee_per_gas", max_priority_fee_per_gas)?;
    }
    if let Some(fee_token) = def.fee_token {
        insert_yaml(&mut mapping, "fee_token", fee_token.to_string())?;
    }
    insert_yaml(&mut mapping, "to", to.to_string())?;
    if !call.value.is_zero() {
        insert_yaml(&mut mapping, "value", call.value.to_string())?;
    }
    insert_yaml(&mut mapping, "input", call.input.to_string())?;

    Ok(serde_yaml::Value::Mapping(mapping))
}

fn insert_yaml<T: serde::Serialize>(
    mapping: &mut serde_yaml::Mapping,
    key: &str,
    value: T,
) -> Result<()> {
    mapping.insert(serde_yaml::Value::String(key.to_string()), serde_yaml::to_value(value)?);
    Ok(())
}

fn account_ref_value(pool: &str, index: usize) -> Result<serde_yaml::Value> {
    let mut select = serde_yaml::Mapping::new();
    insert_yaml(&mut select, "index", index)?;

    let mut account = serde_yaml::Mapping::new();
    insert_yaml(&mut account, "pool", pool)?;
    account.insert(
        serde_yaml::Value::String("select".to_string()),
        serde_yaml::Value::Mapping(select),
    );

    Ok(serde_yaml::Value::Mapping(account))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::SignableTransaction;
    use alloy_eips::eip2718::{Decodable2718, Encodable2718};
    use alloy_network::{NetworkTransactionBuilder, TxSignerSync};
    use alloy_primitives::Address;
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_transport::mock::Asserter;
    use rand::{rngs::StdRng, SeedableRng};
    use std::collections::HashMap;
    use tempo_primitives::TEMPO_TX_TYPE_ID;
    use txgen_core::{
        AccountManager, AccountPoolDef, AccountRef, ArtifactManager, GasConfig, GenValue,
        Generator, NonceReservationKind, NonceTracker, SelectMode,
    };

    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

    fn sign_and_encode<A: NetworkAdapter>(
        adapter: &A,
        template: A::Template,
        ctx: &mut BuildContext<'_>,
    ) -> Bytes
    where
        <A::Network as alloy_network::Network>::UnsignedTx:
            SignableTransaction<alloy_primitives::Signature>,
        <A::Network as alloy_network::Network>::TxEnvelope: From<alloy_consensus::Signed<<A::Network as alloy_network::Network>::UnsignedTx>>
            + Encodable2718,
    {
        let tx_req = adapter.build_request(template, ctx).unwrap();
        let mut unsigned = tx_req.request.build_unsigned().unwrap();
        let signer = ctx.accounts.get_by_index(&tx_req.signer_pool, tx_req.signer_index).unwrap();
        let sig = signer.sign_transaction_sync(&mut unsigned).unwrap();
        let signed = unsigned.into_signed(sig);
        let envelope = <A::Network as alloy_network::Network>::TxEnvelope::from(signed);
        Bytes::from(envelope.encoded_2718())
    }

    fn sign_tempo_request(
        tx_req: TxRequest<TempoTransactionRequest, TempoSignContext>,
        ctx: &BuildContext<'_>,
        name: &str,
    ) -> GeneratedTx {
        let signer =
            ctx.accounts.get_by_index(&tx_req.signer_pool, tx_req.signer_index).unwrap().clone();
        let TxRequest { request, signer_pool: _, signer_index: _, key, sign_context, late_sign: _ } =
            tx_req;
        sign_context
            .sign_request(name.to_string(), TxPhase::Workload, request, signer, key, Vec::new())
            .unwrap()
    }

    fn assert_keychain_signature(raw: &Bytes) {
        let envelope = TempoTxEnvelope::decode_2718(&mut raw.as_ref()).unwrap();
        let TempoTxEnvelope::AA(tx) = envelope else {
            panic!("expected Tempo AA envelope");
        };
        assert!(tx.signature().is_keychain());
    }

    fn test_accounts() -> AccountManager {
        let mut accounts_map = HashMap::new();
        accounts_map.insert(
            "users".to_string(),
            AccountPoolDef {
                mnemonic: Some(TEST_MNEMONIC.to_string()),
                index: None,
                range: Some([0, 10]),
                fast_signable: None,
            },
        );
        AccountManager::from_spec(&accounts_map).unwrap()
    }

    fn base_template(tx_type: TempoTxType) -> TempoTemplate {
        TempoTemplate {
            tx_type,
            from: AccountRef { pool: "users".to_string(), select: SelectMode::Index(0) },
            gas_limit: 21000,
            value: GenValue::Literal(U256::from(1000)),
            to: Some(GenValue::Literal(Address::ZERO)),
            input: None,
            call: None,
            access_list: Vec::new(),
            gas_price: None,
            max_fee_per_gas: Some(1_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce_key: None,
            nonce: None,
            expiring_nonce: false,
            fee_token: None,
            sponsor: None,
            valid_after: None,
            valid_before: None,
            valid_for_secs: None,
            calls: None,
            auth: None,
        }
    }

    fn sponsored_expiring_template() -> TempoTemplate {
        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;
        template.valid_before = Some(1_700_000_000);
        template.sponsor =
            Some(AccountRef { pool: "users".to_string(), select: SelectMode::Index(1) });
        template
    }

    #[test]
    fn access_lists_survive_signing_for_supported_transaction_types() {
        use alloy_consensus::Transaction;
        for tx_type in [TempoTxType::Tempo, TempoTxType::Eip2930, TempoTxType::Eip1559] {
            let accounts = test_accounts();
            let artifacts = ArtifactManager::empty();
            let gas = GasConfig::default();
            let mut nonces = NonceTracker::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);
            let mut template = base_template(tx_type);
            template.access_list = serde_yaml::from_str(
                r#"
- address: "0x1111111111111111111111111111111111111111"
  storage_keys:
    range: { start: "0xfe", count: 3 }
"#,
            )
            .unwrap();
            let raw = sign_and_encode(&TempoAdapter::new(), template, &mut ctx);
            let envelope = TempoTxEnvelope::decode_2718(&mut raw.as_ref()).unwrap();
            let list = envelope.access_list().unwrap();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].address, Address::repeat_byte(0x11));
            let actual: Vec<_> =
                list[0].storage_keys.iter().map(|k| U256::from_be_slice(k.as_slice())).collect();
            assert_eq!(actual, [U256::from(254), U256::from(255), U256::from(256)]);
        }
    }

    #[test]
    fn access_list_rejects_legacy_and_invalid_ranges() {
        for (kind, start, count) in [
            (TempoTxType::Legacy, U256::ZERO, 1),
            (TempoTxType::Tempo, U256::MAX, 2),
            (TempoTxType::Tempo, U256::ZERO, 0),
            (TempoTxType::Tempo, U256::ZERO, 65_537),
        ] {
            let accounts = test_accounts();
            let artifacts = ArtifactManager::empty();
            let gas = GasConfig::default();
            let mut nonces = NonceTracker::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);
            let mut template = base_template(kind);
            template.access_list = vec![AccessListEntry {
                address: GenValue::Literal(Address::ZERO),
                storage_keys: StorageKeys::Range {
                    range: StorageKeyRange { start: GenValue::Literal(start), count },
                },
            }];
            assert!(TempoAdapter::new().build_request(template, &mut ctx).is_err());
        }
    }

    #[test]
    fn access_list_explicit_keys_and_deferred_request_are_preserved() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);
        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);
        ctx.set_defer_signing(true);
        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;
        template.valid_for_secs = Some(25);
        template.access_list = serde_yaml::from_str(
            r#"
- address: "0x1111111111111111111111111111111111111111"
  storage_keys:
    - "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
"#,
        )
        .unwrap();
        let result = TempoAdapter::new().build_request(template, &mut ctx).unwrap();
        assert!(result.late_sign.is_some());
        assert_eq!(
            result.request.access_list().unwrap()[0].storage_keys,
            [alloy_primitives::B256::repeat_byte(0xff)]
        );
        use alloy_consensus::Transaction;
        let payload = TempoExpiringPayload::from_spec(&result.late_sign.unwrap()).unwrap();
        let raw = sign_tempo_expiring(&payload, &accounts).unwrap();
        let envelope = TempoTxEnvelope::decode_2718(&mut raw.as_ref()).unwrap();
        let list = envelope.access_list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].address, Address::repeat_byte(0x11));
        assert_eq!(list[0].storage_keys, [alloy_primitives::B256::repeat_byte(0xff)]);
    }

    #[test]
    fn test_build_tempo_transfer() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let raw =
            sign_and_encode(&TempoAdapter::new(), base_template(TempoTxType::Tempo), &mut ctx);

        assert!(!raw.is_empty());
        assert_eq!(raw[0], TEMPO_TX_TYPE_ID);
    }

    #[test]
    fn test_build_tempo_with_parallel_nonce() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let mut template = base_template(TempoTxType::Tempo);
        template.nonce_key = Some(GenValue::Literal(U256::from(42)));

        let raw = sign_and_encode(&TempoAdapter::new(), template, &mut ctx);

        assert!(!raw.is_empty());
        assert_eq!(raw[0], TEMPO_TX_TYPE_ID);
    }

    #[test]
    fn test_build_tempo_with_generated_fee_token() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let fee_token: Address = "0x20c0000000000000000000000000000000000001".parse().unwrap();
        let mut template = base_template(TempoTxType::Tempo);
        template.fee_token = Some(GenValue::Generator(Generator::Choice(vec![
            serde_yaml::to_value(fee_token).unwrap(),
        ])));

        let adapter = TempoAdapter::new();
        let tx_req = adapter.build_request(template.clone(), &mut ctx).unwrap();

        assert_eq!(tx_req.request.fee_token, Some(fee_token));
    }

    #[test]
    fn test_keychain_setup_expands_and_workload_signs_with_access_key() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);
        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);
        let mut adapter = TempoAdapter::new();

        let setup_value: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
accounts:
  pool: users
access_keys:
  mnemonic: "{TEST_MNEMONIC}"
  range: [100, 110]
key_type: secp256k1
limits:
  - token: "0x20c0000000000000000000000000000000000000"
    amount: "1000"
    period: 0
allowed_calls: unrestricted
"#
        ))
        .unwrap();
        let templates = adapter
            .expand_setup_extension(
                "authorize_keychain_users",
                "keychain_authorize_pool",
                setup_value,
                &mut ctx,
            )
            .unwrap()
            .unwrap();

        assert_eq!(templates.len(), 10);
        let setup_template: TempoTemplate = serde_yaml::from_value(templates[0].clone()).unwrap();
        assert_eq!(setup_template.tx_type, TempoTxType::Tempo);
        assert_eq!(setup_template.from.pool, "users");
        assert!(setup_template.auth.is_none());

        let workload: TempoTemplate = serde_yaml::from_str(
            r#"
type: tempo
auth:
  mode: keychain
  access_key:
    from_setup: authorize_keychain_users
    pair: same_index
from:
  pool: users
  select: { index: 1 }
gas_limit: 400000
max_fee_per_gas: 1000000000
max_priority_fee_per_gas: 1000000000
to: "0x20c0000000000000000000000000000000000000"
input: "0x"
"#,
        )
        .unwrap();

        let tx_req = adapter.build_request(workload, &mut ctx).unwrap();
        let user_address = accounts.get_by_index("users", 1).unwrap().address();
        let access_key_address = derive_mnemonic_signer(TEST_MNEMONIC, 101).unwrap().address();
        assert_eq!(tx_req.request.key_id, Some(access_key_address));

        let generated = sign_tempo_request(tx_req, &ctx, "keychain");
        assert_eq!(generated.raw[0], TEMPO_TX_TYPE_ID);
        assert_eq!(generated.sender, Some(user_address));
        assert_ne!(generated.sender, Some(access_key_address));
        assert_keychain_signature(&generated.raw);
    }

    #[test]
    fn test_inline_key_authorization_signs_authorization_and_keychain_tx() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);
        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let template: TempoTemplate = serde_yaml::from_str(&format!(
            r#"
type: tempo
auth:
  mode: key_authorization
  access_key:
    derive: per_tx
    mnemonic: "{TEST_MNEMONIC}"
    range: [200, 203]
  key_type: secp256k1
  limits:
    - token: "0x20c0000000000000000000000000000000000000"
      amount: "1000"
      period: 0
  witness:
    random_bytes: 32
from:
  pool: users
  select: {{ index: 0 }}
gas_limit: 400000
max_fee_per_gas: 1000000000
max_priority_fee_per_gas: 1000000000
to: "0x20c0000000000000000000000000000000000000"
input: "0x"
"#
        ))
        .unwrap();

        let adapter = TempoAdapter::new();
        let tx_req = adapter.build_request(template.clone(), &mut ctx).unwrap();
        let user_address = accounts.get_by_index("users", 0).unwrap().address();
        let access_key_address = derive_mnemonic_signer(TEST_MNEMONIC, 200).unwrap().address();
        assert_eq!(tx_req.request.key_id, Some(access_key_address));
        assert!(
            tx_req.request.key_authorization.is_none(),
            "authorization signing should be deferred to the signing worker"
        );

        let generated = sign_tempo_request(tx_req, &ctx, "inline_key_authorization");
        assert_eq!(generated.raw[0], TEMPO_TX_TYPE_ID);
        assert_eq!(generated.sender, Some(user_address));
        assert_ne!(generated.sender, Some(access_key_address));
        assert_keychain_signature(&generated.raw);
        let envelope = TempoTxEnvelope::decode_2718(&mut generated.raw.as_ref()).unwrap();
        let signed_authorization = envelope
            .as_aa()
            .unwrap()
            .tx()
            .key_authorization
            .as_ref()
            .expect("inline auth should attach a signed key_authorization");
        assert_eq!(signed_authorization.recover_signer().unwrap(), user_address);
        assert_eq!(signed_authorization.limits.as_ref().unwrap().len(), 1);
        assert!(signed_authorization.witness().is_some());

        let second = adapter.build_request(template.clone(), &mut ctx).unwrap();
        assert_eq!(
            second.request.key_id,
            Some(derive_mnemonic_signer(TEST_MNEMONIC, 201).unwrap().address()),
            "ordinary generation must consume the configured access-key range densely"
        );
        ctx.set_dense_unique_nonce_hint(0);
        let scenario = adapter.build_request(template, &mut ctx).unwrap();
        assert_eq!(
            scenario.request.key_id,
            Some(derive_mnemonic_signer(TEST_MNEMONIC, 202).unwrap().address()),
            "scenario hint zero must start after the ordinary/setup prefix"
        );
        assert_eq!(
            ctx.take_nonce_reservations()
                .into_iter()
                .filter(|reservation| reservation.key == inline_access_key_counter_key())
                .map(|reservation| (reservation.kind, reservation.nonce))
                .collect::<Vec<_>>(),
            vec![
                (NonceReservationKind::Unique, 0),
                (NonceReservationKind::Unique, 1),
                (NonceReservationKind::Unique, 2),
            ]
        );
    }

    #[test]
    fn scenario_uniqueness_group_tracks_only_inline_key_authorization() {
        let adapter = TempoAdapter::new();
        let ordinary: serde_yaml::Value = serde_yaml::from_str("type: tempo").unwrap();
        let inline: serde_yaml::Value =
            serde_yaml::from_str("type: tempo\nauth: { mode: key_authorization }").unwrap();
        let inline_overlay: serde_yaml::Value =
            serde_yaml::from_str("auth: { mode: key_authorization }").unwrap();
        let dynamic_overlay: serde_yaml::Value =
            serde_yaml::from_str("auth: \"${steps.auth.value}\"").unwrap();

        assert_eq!(
            adapter.scenario_unique_nonce_group(&ordinary, &serde_yaml::Value::Null).unwrap(),
            None
        );
        assert_eq!(
            adapter
                .scenario_unique_nonce_group(&inline, &serde_yaml::Value::Null)
                .unwrap()
                .as_deref(),
            Some("tempo:inline-access-key")
        );
        assert_eq!(
            adapter.scenario_unique_nonce_group(&ordinary, &inline_overlay).unwrap().as_deref(),
            Some("tempo:inline-access-key")
        );
        assert_eq!(
            adapter.scenario_unique_nonce_group(&ordinary, &dynamic_overlay).unwrap().as_deref(),
            Some("tempo:inline-access-key")
        );
    }

    #[test]
    fn test_lazy_fetch_no_provider_falls_back_to_tracker_default() {
        // Without a provider configured, build_request must keep the legacy
        // behaviour: assume `nonce=0` for any unseen scheduling key. This
        // protects callers that build txs without `--rpc` (e.g. unit tests).
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let mut template = base_template(TempoTxType::Tempo);
        template.nonce_key = Some(GenValue::Literal(U256::from(42)));

        let tx_req = TempoAdapter::new().build_request(template, &mut ctx).unwrap();

        assert_eq!(tx_req.request.nonce(), Some(0));
    }

    #[test]
    fn test_explicit_nonce_skips_lane_nonce_tracking() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let mut template = base_template(TempoTxType::Tempo);
        template.nonce_key = Some(GenValue::Literal(U256::from(42)));
        template.nonce = Some(0);

        let tx_req = TempoAdapter::new().build_request(template, &mut ctx).unwrap();

        assert_eq!(tx_req.request.nonce_key, Some(U256::from(42)));
        assert_eq!(tx_req.request.nonce(), Some(0));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_prepare_fetches_generated_pending_lane_without_blocking() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);
        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let asserter = Asserter::new();
        asserter.push_success(&U256::from(7));
        let provider = ProviderBuilder::<_, _, Ethereum>::new()
            .connect_mocked_client(asserter.clone())
            .erased();
        let adapter = TempoAdapter::new();
        assert!(adapter.nonce_rpc.set(NonceRpc { provider, pending: true }).is_ok());

        let value = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
type: tempo
from:
  pool: users
  select: { index: 0 }
to: "0x0000000000000000000000000000000000000001"
value: 0
gas_limit: 21000
max_fee_per_gas: 1000000000
max_priority_fee_per_gas: 1000000000
nonce_key:
  choice: [42]
"#,
        )
        .unwrap();

        adapter.prepare_request(&value, &mut ctx).await.unwrap();
        let template: TempoTemplate = serde_yaml::from_value(value).unwrap();
        let request = adapter.build_request(template, &mut ctx).unwrap();

        let address = accounts.get_by_index("users", 0).unwrap().address();
        let scheduling_key = compute_parallel_scheduling_key(address, U256::from(42));
        assert_eq!(request.request.nonce_key, Some(U256::from(42)));
        assert_eq!(request.request.nonce(), Some(7));
        assert_eq!(ctx.nonces.current(&scheduling_key), 8);
        assert!(asserter.read_q().is_empty());
    }

    #[test]
    fn expiring_nonce_rejects_an_explicit_nonce() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);
        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);
        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;
        template.valid_for_secs = Some(10);
        template.nonce = Some(0);

        let error = match TempoAdapter::new().build_request(template, &mut ctx) {
            Ok(_) => panic!("explicit expiring nonce should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must not be set"));
    }

    #[test]
    fn test_delegates_ethereum_types() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let raw =
            sign_and_encode(&TempoAdapter::new(), base_template(TempoTxType::Eip1559), &mut ctx);

        assert!(!raw.is_empty());
        assert_eq!(raw[0], 0x02);
    }

    #[test]
    fn test_build_tempo_with_expiring_nonce() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let sender = accounts.get_by_index("users", 0).unwrap().address();
        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;
        template.valid_before = Some(1_700_000_000);

        let tx_req = TempoAdapter::new().build_request(template, &mut ctx).unwrap();

        assert_eq!(tx_req.request.nonce(), Some(0));
        assert_eq!(tx_req.request.nonce_key, Some(TEMPO_EXPIRING_NONCE_KEY));
        assert_eq!(tx_req.request.valid_before.map(NonZeroU64::get), Some(1_700_000_000));
        assert_ne!(tx_req.key, sender.0 .0);
        let generated = sign_tempo_request(tx_req, &ctx, "expiry");
        assert_eq!(transaction_expiry(&generated.raw), Some(1_700_000_000));
    }

    #[test]
    fn test_expiring_nonce_requests_do_not_share_lane_state() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;
        template.valid_before = Some(1_700_000_000);

        let first = TempoAdapter::new().build_request(template.clone(), &mut ctx).unwrap();
        let second = TempoAdapter::new().build_request(template, &mut ctx).unwrap();

        assert_eq!(first.request.nonce(), Some(0));
        assert_eq!(second.request.nonce(), Some(0));
        assert_ne!(first.key, second.key);
    }

    #[test]
    fn test_expiring_nonce_transactions_get_unique_signed_payloads() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;
        template.valid_before = Some(1_700_000_000);

        let first = sign_and_encode(&TempoAdapter::new(), template.clone(), &mut ctx);
        let second = sign_and_encode(&TempoAdapter::new(), template, &mut ctx);

        assert_ne!(first, second);
    }

    #[test]
    fn test_expiring_nonce_max_fee_bumps_leave_zero_priority_fee_unchanged() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;
        template.valid_before = Some(1_700_000_000);
        template.max_priority_fee_per_gas = Some(0);

        let first = TempoAdapter::new().build_request(template.clone(), &mut ctx).unwrap().request;
        let second = TempoAdapter::new().build_request(template, &mut ctx).unwrap().request;

        assert_eq!(first.max_priority_fee_per_gas(), Some(0));
        assert_eq!(first.max_fee_per_gas(), Some(1_000_000_001));
        assert_eq!(second.max_priority_fee_per_gas(), Some(0));
        assert_eq!(second.max_fee_per_gas(), Some(1_000_000_003));
    }

    #[test]
    fn test_expiring_nonce_valid_for_secs_is_signed_by_default() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);
        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;
        template.valid_for_secs = Some(25);

        let tx_req = TempoAdapter::new().build_request(template, &mut ctx).unwrap();

        assert!(tx_req.request.valid_before.is_some());
        assert!(tx_req.late_sign.is_none());
    }

    #[test]
    fn test_expiring_nonce_valid_for_secs_is_deferred_until_submission() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);
        ctx.set_defer_signing(true);

        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;
        template.valid_for_secs = Some(25);

        let tx_req = TempoAdapter::new().build_request(template, &mut ctx).unwrap();

        assert!(tx_req.request.valid_before.is_none());
        let late_sign = tx_req.late_sign.expect("relative expiry should be deferred");
        let payload = TempoExpiringPayload::from_spec(&late_sign).unwrap();
        assert_eq!(payload.valid_for_secs, 25);
        assert_eq!(payload.request.nonce_key, Some(TEMPO_EXPIRING_NONCE_KEY));
        let raw = sign_tempo_expiring(&payload, &accounts).unwrap();
        assert_eq!(raw[0], TEMPO_TX_TYPE_ID);
    }

    #[test]
    fn test_sponsored_expiring_nonce_uniqueness_happens_before_fee_payer_signing() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let first =
            TempoAdapter::new().build_request(sponsored_expiring_template(), &mut ctx).unwrap();
        let second =
            TempoAdapter::new().build_request(sponsored_expiring_template(), &mut ctx).unwrap();

        assert_ne!(first.request.max_fee_per_gas(), second.request.max_fee_per_gas());
        assert_eq!(first.request.max_priority_fee_per_gas(), Some(1_000_000_000));
        assert_eq!(second.request.max_priority_fee_per_gas(), Some(1_000_000_000));
        assert!(first.request.fee_payer_signature.is_none());
        assert!(second.request.fee_payer_signature.is_none());
        let first = sign_tempo_request(first, &ctx, "sponsored_first");
        let second = sign_tempo_request(second, &ctx, "sponsored_second");
        let first = TempoTxEnvelope::decode_2718(&mut first.raw.as_ref()).unwrap();
        let second = TempoTxEnvelope::decode_2718(&mut second.raw.as_ref()).unwrap();
        assert_ne!(
            first.as_aa().unwrap().tx().fee_payer_signature,
            second.as_aa().unwrap().tx().fee_payer_signature,
            "fee-payer signature must reflect the per-tx expiring uniqueness bump"
        );
    }

    #[test]
    fn test_sponsored_transaction_uses_transaction_sender_metadata() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let transaction_sender = accounts.get_by_index("users", 0).unwrap().address();
        let sponsor = accounts.get_by_index("users", 1).unwrap().address();
        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let tx_req =
            TempoAdapter::new().build_request(sponsored_expiring_template(), &mut ctx).unwrap();
        let generated = sign_tempo_request(tx_req, &ctx, "sponsored");

        assert_eq!(generated.sender, Some(transaction_sender));
        assert_ne!(generated.sender, Some(sponsor));
    }

    #[test]
    fn test_expiring_nonce_requires_expiry_field() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);

        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);

        let mut template = base_template(TempoTxType::Tempo);
        template.expiring_nonce = true;

        let err = TempoAdapter::new()
            .build_request(template, &mut ctx)
            .err()
            .expect("expiring nonce without expiry should fail");
        assert!(err.to_string().contains(
            "expiring nonce templates require either `valid_before` or `valid_for_secs`"
        ));
    }

    #[test]
    fn test_scheduling_key_parallel_nonce() {
        let sender = Address::repeat_byte(0xab);
        let key1 = compute_parallel_scheduling_key(sender, U256::from(1));
        let key2 = compute_parallel_scheduling_key(sender, U256::from(2));

        assert_ne!(key1, sender.0 .0);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_scheduling_key_protocol_nonce() {
        let accounts = test_accounts();
        let artifacts = ArtifactManager::empty();
        let gas = GasConfig::default();
        let mut nonces = NonceTracker::new();
        let mut rng = StdRng::seed_from_u64(42);
        let sender = Address::repeat_byte(0xab);
        let mut ctx = BuildContext::new(1, &gas, &accounts, &artifacts, &mut nonces, &mut rng);
        let key = compute_scheduling_key(sender, TempoNonceMode::Protocol, &mut ctx);
        assert_eq!(key, sender.0 .0);
    }
}
