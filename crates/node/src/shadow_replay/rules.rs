//! Data-driven expectations loaded from the embedded per-hardfork `expectations/<fork>.json` files.
//!
//! A rule accepts one difference when its boundary matches, its `when` condition holds, and one
//! `accept` entry covers the changed field. `call` rules bind `call.*` references to each
//! envelope call in turn; the call filter matches message calls made at any depth within it.
//! Unavailable operands and failed checked arithmetic propagate as unavailable. Only true
//! conditions accept. `code_upgrade` rules verify canonical pre-block runtime upgrades.

use super::{
    Boundary, TxOutcome,
    analysis::{ACCEPTABLE_FIELDS, AccountDelta, Field},
    expectations::{Context, EnvelopeCall, rejects_only_trailing_bytes},
};
use alloy::consensus::Transaction as _;
use alloy_json_abi::Function;
use alloy_primitives::{Address, B256, KECCAK256_EMPTY, Selector, U256, keccak256};
use serde::Deserialize;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{initial_zone_factory_state, t13_zone_factory_state};

/// Parses and validates per-hardfork rule files, each a JSON array of rules. File order, then rule
/// order, is attribution order. Rule IDs must be unique across all files.
pub(crate) fn load(files: &[(TempoHardfork, &str)]) -> Result<Vec<(TempoHardfork, Rule)>, String> {
    let mut rules = Vec::new();
    for &(hardfork, json) in files {
        let parsed: Vec<Rule> =
            serde_json::from_str(json).map_err(|e| format!("{hardfork} rules: {e}"))?;
        rules.extend(parsed.into_iter().map(|rule| (hardfork, rule)));
    }
    let mut ids = std::collections::HashSet::new();
    for (hardfork, rule) in &mut rules {
        let err = |msg: &str| format!("rule {}: {msg}", rule.id);
        if !ids.insert(&rule.id) {
            return Err(err("duplicate id"));
        }
        if let Some(address) = rule.code_upgrade {
            if rule.boundary.is_some()
                || rule.call.is_some()
                || rule.accept.is_some()
                || !matches!(rule.when, Expr::Bool(true))
            {
                return Err(err("`code_upgrade` cannot be combined with generic rules"));
            }
            let (before, after) = match hardfork {
                TempoHardfork::T13 => (
                    initial_zone_factory_state(Address::ZERO),
                    t13_zone_factory_state(Address::ZERO),
                ),
                _ => return Err(err(&format!("no code upgrades defined for {hardfork}"))),
            };
            rule.code_hashes = before.into_iter().zip(after).find_map(|(before, after)| {
                (before.address == address && after.address == address && before.code != after.code)
                    .then(|| (keccak256(before.code), keccak256(after.code)))
            });
            if rule.code_hashes.is_none() {
                return Err(err(&format!("no code upgrade for {address} at {hardfork}")));
            }
            continue;
        }
        let boundary = rule
            .boundary
            .ok_or_else(|| err("requires `boundary` or `code_upgrade`"))?;
        let call = boundary == RuleBoundary::Call;
        if !call && rule.call.is_some() {
            return Err(err("`call` requires `boundary: call`"));
        }
        expect(&rule.when, Ty::Bool, call).map_err(|msg| err(&msg))?;
        for accept in rule
            .accept
            .as_ref()
            .ok_or_else(|| err("requires `accept`"))?
        {
            if let Some(field) = accept
                .fields
                .iter()
                .find(|f| !ACCEPTABLE_FIELDS.contains(&f.as_str()))
            {
                return Err(err(&format!("unknown or unacceptable field {field:?}")));
            }
            let storage = accept.fields.iter().any(|f| f == "storage");
            match &accept.slot {
                None if storage => return Err(err("`storage` requires `slot`")),
                Some(_) if !storage => return Err(err("`slot` requires `storage`")),
                Some(Scope::Only(slot)) => expect(slot, Ty::U256, call).map_err(|msg| err(&msg))?,
                _ => {}
            }
            expect(&accept.where_, Ty::Bool, call).map_err(|msg| err(&msg))?;
        }
    }
    Ok(rules)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    /// Stable, unique attribution ID; used as the metrics label and in report samples.
    pub(crate) id: String,
    /// Reviewer-facing. Required but not evaluated.
    #[serde(rename = "description")]
    _desc: serde::de::IgnoredAny,
    /// Comparison boundary whose differences the rule may accept.
    boundary: Option<RuleBoundary>,
    /// Address upgraded by this file's introducing hardfork, using canonical runtime definitions.
    code_upgrade: Option<Address>,
    /// Expected old/new hashes, resolved once at load time.
    #[serde(skip)]
    code_hashes: Option<(B256, B256)>,
    /// Only for `boundary: call`. Absent matches every envelope call, including unreached ones.
    call: Option<CallFilter>,
    /// Rule-wide condition. Defaults to true.
    #[serde(default = "always")]
    when: Expr,
    /// Field scopes the rule accepts; any matching entry accepts the difference.
    accept: Option<Vec<Accept>>,
}

impl Rule {
    pub(crate) fn accepts(&self, ctx: &Context<'_>, field: &Field) -> bool {
        if let Some(address) = self.code_upgrade {
            if ctx.boundary != Boundary::PreBlock
                || field.name != "code"
                || field.address != Some(address)
                || field.slot.is_some()
            {
                return false;
            }
            let (Some(real), Some(shadow), Some((old, new))) = (
                ctx.real.pre_block.as_ref(),
                ctx.shadow.pre_block.as_ref(),
                self.code_hashes,
            ) else {
                return false;
            };
            return AccountDelta(real.transitions.get(&address))
                .info(|info| info.code_hash)
                .is_none()
                && AccountDelta(shadow.transitions.get(&address))
                    .info(|info| info.code_hash)
                    .is_some_and(|(before, after)| {
                        (before == KECCAK256_EMPTY || before == old) && after == new
                    });
        }
        let holds = |call| {
            let env = Env { ctx, call };
            self.when.holds(&env)
                && self
                    .accept
                    .iter()
                    .flatten()
                    .any(|accept| accept.matches(&env, field))
        };
        match (self.boundary, ctx.boundary) {
            (Some(RuleBoundary::PreBlock), Boundary::PreBlock)
            | (Some(RuleBoundary::Transaction), Boundary::Transaction(_))
            | (Some(RuleBoundary::PostBlock), Boundary::PostBlock) => holds(None),
            (Some(RuleBoundary::Call), Boundary::Transaction(_)) => ctx.calls().any(|call| {
                self.call
                    .as_ref()
                    .is_none_or(|filter| filter.matches(&call))
                    && holds(Some(call))
            }),
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuleBoundary {
    PreBlock,
    Transaction,
    Call,
    PostBlock,
}

/// Matches a message call made at any depth within an envelope call, in either arm.
/// An empty filter matches every envelope call.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallFilter {
    /// Called address. Absent matches any target.
    to: Option<Address>,
    /// Function signatures, converted to selectors at load time. Empty matches any selector.
    #[serde(default, deserialize_with = "selectors")]
    functions: Vec<Selector>,
}

impl CallFilter {
    fn matches(&self, (.., real, shadow): &EnvelopeCall<'_>) -> bool {
        if self.to.is_none() && self.functions.is_empty() {
            return true;
        }
        [real, shadow]
            .into_iter()
            .flatten()
            .flat_map(|call| &call.invocations)
            .any(|invocation| {
                self.to.is_none_or(|to| invocation.to == to)
                    && (self.functions.is_empty()
                        || invocation
                            .selector
                            .is_some_and(|selector| self.functions.contains(&selector)))
            })
    }
}

fn selectors<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<Selector>, D::Error> {
    Vec::<&str>::deserialize(deserializer)?
        .into_iter()
        .map(|signature| {
            Function::parse(signature)
                .map(|function| function.selector())
                .map_err(|e| {
                    serde::de::Error::custom(format!("invalid signature {signature:?}: {e}"))
                })
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Accept {
    /// Explicit comparison field names, from `ACCEPTABLE_FIELDS`.
    fields: Vec<String>,
    /// Changed account. Transaction-level fields have no address and only match `"any"`.
    address: Scope<Address>,
    /// Changed storage slot. Required for `storage`; must be absent otherwise.
    slot: Option<Scope<Expr>>,
    /// Entry-specific condition. Defaults to true.
    #[serde(rename = "where", default = "always")]
    where_: Expr,
}

impl Accept {
    fn matches(&self, env: &Env<'_>, field: &Field) -> bool {
        self.fields.iter().any(|name| name == field.name)
            && match self.address {
                Scope::Any(_) => true,
                Scope::Only(address) => field.address == Some(address),
            }
            && match (&self.slot, field.slot) {
                (Some(Scope::Only(slot)), Some(changed)) => {
                    slot.eval(env) == Some(Value::U256(changed))
                }
                _ => true,
            }
            && self.where_.holds(env)
    }
}

/// `"any"` or an explicit value.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Scope<T> {
    Any(AnyLit),
    Only(T),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AnyLit {
    Any,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Expr {
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
    Eq(Box<Self>, Box<Self>),
    Lte(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    ToU256(Box<Self>),
    CallChangedStorage(Address),
    Ref(Ref),
    Bool(bool),
    U256(U256),
    Address(Address),
    B256(B256),
    Outcome(TxOutcome),
}

impl Expr {
    fn ty(&self, call: bool) -> Result<Ty, String> {
        Ok(match self {
            Self::All(exprs) | Self::Any(exprs) => {
                exprs.iter().try_for_each(|e| expect(e, Ty::Bool, call))?;
                Ty::Bool
            }
            Self::Not(e) => {
                expect(e, Ty::Bool, call)?;
                Ty::Bool
            }
            Self::Eq(a, b) => {
                expect(b, a.ty(call)?, call)?;
                Ty::Bool
            }
            Self::Lte(a, b) | Self::Sub(a, b) => {
                expect(a, Ty::U256, call)?;
                expect(b, Ty::U256, call)?;
                if matches!(self, Self::Lte(..)) {
                    Ty::Bool
                } else {
                    Ty::U256
                }
            }
            Self::ToU256(e) => {
                expect(e, Ty::Address, call)?;
                Ty::U256
            }
            Self::CallChangedStorage(_) if !call => return Err("requires `boundary: call`".into()),
            Self::CallChangedStorage(_) | Self::Bool(_) => Ty::Bool,
            Self::Ref(r) => match r {
                Ref::RealCallOutcome | Ref::RealCallOutputHash | Ref::CallRejectsOnlyAbiSuffix
                    if !call =>
                {
                    return Err(format!("{r:?} requires `boundary: call`"));
                }
                Ref::RealOutcome | Ref::ShadowOutcome | Ref::RealCallOutcome => Ty::Outcome,
                Ref::RealGasTotalSpent | Ref::TxGasLimit => Ty::U256,
                Ref::RealCallOutputHash => Ty::B256,
                Ref::CallRejectsOnlyAbiSuffix => Ty::Bool,
            },
            Self::U256(_) => Ty::U256,
            Self::Address(_) => Ty::Address,
            Self::B256(_) => Ty::B256,
            Self::Outcome(_) => Ty::Outcome,
        })
    }

    fn holds(&self, env: &Env<'_>) -> bool {
        self.eval(env) == Some(Value::Bool(true))
    }

    fn eval(&self, env: &Env<'_>) -> Option<Value> {
        let bool = |e: &Self| match e.eval(env)? {
            Value::Bool(b) => Some(b),
            _ => None,
        };
        let u256 = |e: &Self| match e.eval(env)? {
            Value::U256(v) => Some(v),
            _ => None,
        };
        Some(match self {
            Self::All(exprs) => {
                Value::Bool(exprs.iter().try_fold(true, |all, e| Some(all & bool(e)?))?)
            }
            Self::Any(exprs) => Value::Bool(
                exprs
                    .iter()
                    .try_fold(false, |any, e| Some(any | bool(e)?))?,
            ),
            Self::Not(e) => Value::Bool(!bool(e)?),
            Self::Eq(a, b) => Value::Bool(a.eval(env)? == b.eval(env)?),
            Self::Lte(a, b) => Value::Bool(u256(a)? <= u256(b)?),
            Self::Sub(a, b) => Value::U256(u256(a)?.checked_sub(u256(b)?)?),
            Self::ToU256(e) => match e.eval(env)? {
                Value::Address(a) => Value::U256(U256::from_be_slice(a.as_slice())),
                _ => return None,
            },
            Self::CallChangedStorage(address) => {
                let (.., real, shadow) = env.call?;
                Value::Bool(
                    [real, shadow]
                        .into_iter()
                        .flatten()
                        .any(|c| c.changed_storage(*address)),
                )
            }
            Self::Ref(r) => env.get(*r)?,
            Self::Bool(b) => Value::Bool(*b),
            Self::U256(v) => Value::U256(*v),
            Self::Address(a) => Value::Address(*a),
            Self::B256(b) => Value::B256(*b),
            Self::Outcome(o) => Value::Outcome(*o),
        })
    }
}

fn always() -> Expr {
    Expr::Bool(true)
}

fn expect(expr: &Expr, ty: Ty, call: bool) -> Result<(), String> {
    let actual = expr.ty(call)?;
    (actual == ty)
        .then_some(())
        .ok_or_else(|| format!("expected {ty:?}, found {actual:?} in {expr:?}"))
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum Ref {
    #[serde(rename = "real.outcome")]
    RealOutcome,
    #[serde(rename = "shadow.outcome")]
    ShadowOutcome,
    #[serde(rename = "real.gas.total_spent")]
    RealGasTotalSpent,
    #[serde(rename = "tx.gas_limit")]
    TxGasLimit,
    #[serde(rename = "real.call.outcome")]
    RealCallOutcome,
    #[serde(rename = "real.call.output_hash")]
    RealCallOutputHash,
    #[serde(rename = "call.rejects_only_abi_suffix")]
    CallRejectsOnlyAbiSuffix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Bool(bool),
    U256(U256),
    B256(B256),
    Address(Address),
    Outcome(TxOutcome),
}

/// Static expression type, validated at load time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    Bool,
    U256,
    B256,
    Address,
    Outcome,
}

/// Evaluation inputs: boundary evidence, optionally bound to one envelope call.
struct Env<'a> {
    /// Boundary evidence for both arms.
    ctx: &'a Context<'a>,
    /// Envelope call bound by a `boundary: call` rule; `None` otherwise.
    call: Option<EnvelopeCall<'a>>,
}

impl Env<'_> {
    fn get(&self, r: Ref) -> Option<Value> {
        let ctx = self.ctx;
        let real_call = || self.call.and_then(|(.., real, _)| real);
        Some(match r {
            Ref::RealOutcome => Value::Outcome(ctx.observed_txs()?.0.outcome),
            Ref::ShadowOutcome => Value::Outcome(ctx.observed_txs()?.1.outcome),
            Ref::RealGasTotalSpent => {
                Value::U256(U256::from(ctx.observed_txs()?.0.gas.total_gas_spent()))
            }
            Ref::TxGasLimit => Value::U256(U256::from(ctx.tx?.gas_limit())),
            Ref::RealCallOutcome => Value::Outcome(real_call()?.outcome),
            Ref::RealCallOutputHash => Value::B256(real_call()?.output_hash),
            Ref::CallRejectsOnlyAbiSuffix => {
                let (kind, calldata, ..) = self.call?;
                Value::Bool(
                    kind.to()
                        .is_some_and(|to| rejects_only_trailing_bytes(*to, calldata)),
                )
            }
        })
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;

    fn file(bodies: &[&str]) -> String {
        let rules: Vec<_> = bodies
            .iter()
            .map(|body| format!(r#"{{"id": "x", "description": "", {body}}}"#))
            .collect();
        format!("[{}]", rules.join(","))
    }

    fn load_t12(json: &str) -> Result<Vec<(TempoHardfork, Rule)>, String> {
        load(&[(TempoHardfork::T12, json)])
    }

    #[test]
    fn call_filter_matches_recorded_nested_selectors_not_envelope_calldata() {
        use super::super::inspector::{Invocation, ObservedCall};
        use alloy_primitives::TxKind;
        let dex = tempo_contracts::precompiles::STABLECOIN_DEX_ADDRESS;
        let filter: CallFilter = serde_json::from_str(&format!(r#"{{"to":"{dex}","functions":["swapExactAmountIn(address,address,uint128,uint128)"]}}"#)).unwrap();
        let mut observed = ObservedCall::default();
        let matches = |observed: &ObservedCall| filter.matches(&(TxKind::Call(Address::repeat_byte(1)), &[], None, Some(observed)));
        assert!(!matches(&observed));
        observed.invocations.push(Invocation { to: dex, selector: Some(filter.functions[0]) });
        assert!(matches(&observed));
        observed.invocations[0].selector = Some(Selector::ZERO);
        assert!(!matches(&observed));
        observed.invocations[0].selector = Some(filter.functions[0]);
        observed.invocations[0].to = Address::ZERO;
        assert!(!matches(&observed));
    }

    #[test]
    fn code_upgrades_require_a_canonical_fork_address_pair() {
        let address = tempo_contracts::precompiles::ZONE_MESSENGER_ADDRESS;
        let json = file(&[&format!(r#""code_upgrade": "{address}""#)]);
        assert!(load_t12(&json).unwrap_err().contains("no code upgrades"));
        assert!(load(&[(TempoHardfork::T13, &json)]).is_ok());
        for body in [
            format!(r#""code_upgrade": "{}""#, Address::ZERO),
            format!(r#""code_upgrade": "{address}", "boundary": "pre_block""#),
            format!(r#""code_upgrade": "{address}", "when": {{"bool": false}}"#),
            format!(r#""code_upgrade": "{address}", "accept": [{{"fields": ["code"], "address": "any"}}]"#),
            format!(r#""code_upgrade": "{address}", "unknown": true"#),
        ] {
            assert!(load(&[(TempoHardfork::T13, &file(&[&body]))]).is_err(), "{body}");
        }
    }

    #[test]
    fn invalid_rules_fail_to_load() {
        let storage = r#""accept": [{"fields": ["storage"], "address": "any", "slot": "any"}]"#;
        for (body, error) in [
            (r#""boundary": "transaction""#, "requires `accept`"),
            (r#""accept": []"#, "requires `boundary`"),
            (r#""boundary": "transaction", "accept": [{"fields": ["execution"], "address": "any"}]"#, "unacceptable field"),
            (r#""boundary": "transaction", "accept": [{"fields": ["storage"], "address": "any"}]"#, "requires `slot`"),
            (r#""boundary": "transaction", "accept": [{"fields": ["code"], "address": "any", "slot": "any"}]"#, "requires `storage`"),
            (&format!(r#""boundary": "transaction", "when": {{"ref": "real.call.outcome"}}, {storage}"# ), "requires `boundary: call`"),
            (
                &format!(r#""boundary": "transaction", "call": {{"functions": []}}, {storage}"#),
                "`call` requires",
            ),
            (&format!(r#""boundary": "transaction", "call": {{"to": "0xdec0000000000000000000000000000000000000"}}, {storage}"# ), "`call` requires"),
            (&format!(r#""boundary": "transaction", "when": {{"eq": [{{"ref": "real.outcome"}}, {{"u256": "1"}}]}}, {storage}"# ), "expected Outcome"),
            (&format!(r#""boundary": "transaction", "when": {{"sub": [{{"u256": "2"}}, {{"u256": "1"}}]}}, {storage}"# ), "expected Bool"),
            (&format!(r#""boundary": "call", "call": {{"functions": ["swap"]}}, {storage}"#), "invalid signature"),
            (&format!(r#""boundary": "transaction", "unknown": 1, {storage}"#), "unknown field"),
        ] {
            let err = load_t12(&file(&[body])).unwrap_err();
            assert!(err.contains(error), "{body}: {err}");
        }
        let body = format!(r#""boundary": "transaction", {storage}"#);
        let valid = file(&[&body]);
        assert!(load_t12(&valid).is_ok());
        assert!(load_t12(&file(&[&body, &body])).unwrap_err().contains("duplicate id"));
        // IDs are unique across hardfork files too.
        let files = [(TempoHardfork::T12, valid.as_str()), (TempoHardfork::T13, &valid)];
        assert!(load(&files).unwrap_err().contains("duplicate id"));
    }
}
