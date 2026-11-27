//! Reviewed baseline and fork-specific expectations for shadow replay.
//!
//! Checks receive one difference, not a transaction, and accept it or leave it unexplained. Fork
//! rules come from one JSON file per candidate hardfork, compiled into the binary.

use super::{
    Arms, Boundary, Evidence, ObservedTx, TxEvidence,
    analysis::Field,
    fees::{fee_hook_slot_change, post_tx_fee},
};
use alloy_consensus::Transaction as _;
use alloy_primitives::{Address, B256, U256, keccak256};
use eyre::{OptionExt as _, WrapErr as _};
use serde::{Deserialize, Deserializer, de::Error as _};
use std::collections::HashSet;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::{
    precompiles::ZONE_PORTAL_IMPL_ADDRESS,
    zones::{T13_ZONE_PORTAL_RUNTIME, T14_ZONE_PORTAL_RUNTIME, T15_ZONE_PORTAL_RUNTIME},
};
use tempo_precompiles::{storage::StorageAction, tip_fee_manager::amm::compute_amount_out};
use tempo_primitives::{TempoTxEnvelope, transaction::calc_gas_balance_spending};

#[derive(Debug)]
pub(crate) struct Expectation {
    pub id: &'static str,
    pub check: Check,
}

impl Expectation {
    /// Whether this expectation explains the difference in `field`.
    pub(super) fn accepts(&self, ctx: &Context<'_>, field: &Field) -> Option<()> {
        let upgrades = match &self.check {
            Check::Fn(check) => return check(ctx, field),
            Check::RuntimeUpgrade(upgrades) => upgrades,
        };
        if ctx.boundary != Boundary::PreBlock || field.name != "code" || field.slot.is_some() {
            return None;
        }
        let address = field.address?;
        let upgrade = upgrades.iter().find(|upgrade| upgrade.address == address)?;
        let Arms { real, shadow } = ctx.evidence.pre_block.as_ref()?;

        // The canonical arm may stop at an earlier runtime the shadow arm skips.
        if real
            .account(address)
            .info(|info| info.code_hash)
            .is_some_and(|(_, after)| !upgrade.from.contains(&after))
        {
            return None;
        }
        let change = shadow.account(address).0?;
        let after = change.after.as_ref()?.code_hash;

        (change
            .before
            .as_ref()
            .is_none_or(|info| info.is_empty_code_hash() || upgrade.from.contains(&info.code_hash))
            && after == upgrade.to)
            .then_some(())
    }
}

#[derive(Debug)]
pub(crate) enum Check {
    /// A check written in Rust. `None` leaves the difference unexplained.
    Fn(fn(&Context<'_>, &Field) -> Option<()>),
    /// Pre-block code changes the candidate makes to these accounts.
    RuntimeUpgrade(Vec<RuntimeUpgrade>),
}

/// A code change the candidate's pre-block setup makes to `address`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeUpgrade {
    /// The account whose code changes.
    #[serde(deserialize_with = "address")]
    address: Address,
    /// Code hashes the account may have before the change, besides empty code.
    #[serde(deserialize_with = "runtimes")]
    from: Vec<B256>,
    /// The code hash after the change.
    #[serde(deserialize_with = "runtime")]
    to: B256,
}

#[derive(Clone, Copy)]
pub(crate) struct Context<'a> {
    pub boundary: Boundary,
    pub evidence: &'a Evidence,
    pub base_fee: Option<u64>,
    pub tx: Option<&'a TempoTxEnvelope>,
}

impl Context<'_> {
    /// Returns the observed transaction pair as `(real, shadow)` at this boundary.
    fn observed_txs(&self) -> Option<(&ObservedTx, &ObservedTx)> {
        let Boundary::Transaction(index) = self.boundary else {
            return None;
        };
        let TxEvidence::Differs(arms) = self.evidence.txs.get(index)? else {
            return None;
        };
        Some((&arms.real, &arms.shadow))
    }

    /// Returns normalized log hashes only when both fee transfers match their gas charges.
    /// Normalization already checked each logged amount against its recorded hook charge.
    pub(super) fn verified_fee_log_hashes(&self) -> Option<(B256, B256)> {
        let (real, shadow) = self.observed_txs()?;
        let (real_fee, shadow_fee) = (post_tx_fee(&real.actions)?, post_tx_fee(&shadow.actions)?);
        let price = self.tx?.effective_gas_price(self.base_fee);
        (real_fee.log == shadow_fee.log
            && real_fee.charged == calc_gas_balance_spending(real.charged_gas, price)
            && shadow_fee.charged == calc_gas_balance_spending(shadow.charged_gas, price))
        .then_some((real.fee_normalized?, shadow.fee_normalized?))
    }
}

/// Accepts only the storage effect of a verified, gas-derived post-transaction fee hook.
static FEE_STATE: Expectation = Expectation {
    id: "fee.post-tx-state",
    check: Check::Fn(|ctx, field| {
        if field.name != "storage" || !field.fee_associated {
            return None;
        }
        let (address, slot) = (field.address?, field.slot?);
        let (real, shadow) = ctx.observed_txs()?;
        ctx.verified_fee_log_hashes()?;
        let (real_fee, shadow_fee) = (post_tx_fee(&real.actions)?, post_tx_fee(&shadow.actions)?);
        if (real_fee.token, real_fee.payer, real_fee.max)
            != (shadow_fee.token, shadow_fee.payer, shadow_fee.max)
        {
            return None;
        }
        // A different fee route cannot be inferred from a changed fee amount alone.
        let route = |actions: &[StorageAction], mut amount: U256| -> Option<Vec<U256>> {
            let mut keys = Vec::new();
            for action in actions {
                if let StorageAction::FeeAmmSwap(key, _, amount_in) = action {
                    if *amount_in != amount || keys.len() == 2 {
                        return None;
                    }
                    keys.push(*key);
                    amount = compute_amount_out(amount).ok()?;
                }
            }
            Some(keys)
        };
        if route(real_fee.actions, real_fee.charged)?
            != route(shadow_fee.actions, shadow_fee.charged)?
        {
            return None;
        }
        let (real_before, real_after) = fee_hook_slot_change(real_fee.actions, address, slot)?;
        let (shadow_before, shadow_after) =
            fee_hook_slot_change(shadow_fee.actions, address, slot)?;
        // Compare application state at hook entry, not merely the transaction's initial state.
        if real_before != shadow_before {
            return None;
        }
        let real_net = real.changes.account(address).storage(slot)?;
        let shadow_net = shadow.changes.account(address).storage(slot)?;
        (real_net.0 == shadow_net.0 && real_net.1 == real_after && shadow_net.1 == shadow_after)
            .then_some(())
    }),
};

/// What replay under one candidate hardfork expects, from its rule file.
#[derive(Debug, Default)]
pub(crate) struct Rules {
    /// Expectations, each with the fork that introduces it, in fork order.
    expectations: Vec<(TempoHardfork, Expectation)>,
    /// Rules that skip the header checks their fork introduces, in fork order.
    skip_header_checks: Vec<(TempoHardfork, &'static str)>,
}

impl Rules {
    /// The baseline check, then the expectations of forks `canonical` does not have, in order.
    pub(crate) fn between(&self, canonical: TempoHardfork) -> Vec<&Expectation> {
        // Gas-derived fee differences can occur for any fork pair.
        std::iter::once(&FEE_STATE)
            .chain(
                self.expectations
                    .iter()
                    .filter(|(fork, _)| *fork > canonical)
                    .map(|(_, rule)| rule),
            )
            .collect()
    }

    /// The rules that make the candidate skip its header checks on a block of the `canonical`
    /// fork. Any one skips them all, since the executor can only skip them all at once.
    pub(crate) fn skipped_header_checks(&self, canonical: TempoHardfork) -> Vec<&'static str> {
        self.skip_header_checks
            .iter()
            .filter(|(fork, _)| *fork > canonical)
            .map(|(_, id)| *id)
            .collect()
    }
}

/// The rules for replay under `candidate`. Errors if `candidate` has no rule file or its file is
/// invalid.
pub(crate) fn load(candidate: TempoHardfork) -> eyre::Result<Rules> {
    let json =
        rule_file(candidate).ok_or_eyre(format!("no shadow expectations for {candidate}"))?;
    parse(candidate, json).wrap_err_with(|| format!("invalid shadow expectations for {candidate}"))
}

fn rule_file(candidate: TempoHardfork) -> Option<&'static str> {
    match candidate {
        TempoHardfork::T14 => Some(include_str!("t14.json")),
        TempoHardfork::T15 => Some(include_str!("t15.json")),
        _ => None,
    }
}

fn parse(candidate: TempoHardfork, json: &'static str) -> eyre::Result<Rules> {
    let mut ids = HashSet::from([FEE_STATE.id]);
    let mut previous = TempoHardfork::Genesis;
    let mut rules = Rules::default();
    for rule in serde_json::from_str::<Vec<Rule<'static>>>(json)? {
        let (Rule::RuntimeUpgrade { id, fork, .. } | Rule::SkipHeaderChecks { id, fork }) = rule;
        eyre::ensure!(ids.insert(id), "duplicate expectation {id}");
        eyre::ensure!(
            previous <= fork && fork <= candidate,
            "expectation {id} for {fork} is out of fork order or after {candidate}"
        );
        previous = fork;
        match rule {
            Rule::RuntimeUpgrade { accounts, .. } => {
                let mut addresses = HashSet::new();
                if let Some(upgrade) = accounts
                    .iter()
                    .find(|upgrade| !addresses.insert(upgrade.address))
                {
                    eyre::bail!("expectation {id} lists account {} twice", upgrade.address);
                }
                let check = Check::RuntimeUpgrade(accounts);
                rules.expectations.push((fork, Expectation { id, check }));
            }
            Rule::SkipHeaderChecks { .. } => rules.skip_header_checks.push((fork, id)),
        }
    }
    Ok(rules)
}

/// A fork rule as a rule file lists it, naming `tempo-contracts` constants.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Rule<'a> {
    RuntimeUpgrade {
        id: &'a str,
        fork: TempoHardfork,
        accounts: Vec<RuntimeUpgrade>,
    },
    /// The candidate skips the header checks the fork introduces, which read state blocks of
    /// earlier forks never read.
    SkipHeaderChecks { id: &'a str, fork: TempoHardfork },
}

/// Defines `$name`, deserializing `$map` of a constant a rule file names.
macro_rules! named_constants {
    ($name:ident -> $ty:ty = $map:path { $($constant:ident),* $(,)? }) => {
        fn $name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<$ty, D::Error> {
            match <&str>::deserialize(deserializer)? {
                $(stringify!($constant) => Ok($map($constant)),)*
                name => Err(D::Error::custom(format!("unknown constant {name}"))),
            }
        }
    };
}

fn runtimes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<B256>, D::Error> {
    #[derive(Deserialize)]
    struct Runtime(#[serde(deserialize_with = "runtime")] B256);
    Ok(Vec::<Runtime>::deserialize(deserializer)?
        .into_iter()
        .map(|runtime| runtime.0)
        .collect())
}

named_constants!(address -> Address = Address::from { ZONE_PORTAL_IMPL_ADDRESS });

named_constants!(runtime -> B256 = keccak256 {
    T13_ZONE_PORTAL_RUNTIME,
    T14_ZONE_PORTAL_RUNTIME,
    T15_ZONE_PORTAL_RUNTIME,
});

#[cfg(test)]
mod tests {
    use super::{
        super::{
            Block, Failure, RecoveredBlock, ReplayOutcome,
            analysis::{AccountChange, MAX_SAMPLES, Report, StepChanges},
            tests::missing_account,
        },
        *,
    };
    use alloy_primitives::{Address, Bytes, KECCAK256_EMPTY, Signature};
    use evm2::evm::AccountInfo;
    use tempo_contracts::{
        precompiles::ZONE_VERIFIER_ADDRESS,
        zones::{T13_ZONE_VERIFIER_RUNTIME, ZONE_PORTAL_RUNTIME},
    };
    use tempo_precompiles::storage::FeeHook;
    use tempo_primitives::{TempoTransaction, transaction::Call};
    use test_case::test_case;

    fn changes(address: Address, change: AccountChange) -> StepChanges {
        StepChanges([(address, change)].into())
    }

    fn code_change(before: Option<AccountInfo>, code_hash: B256) -> AccountChange {
        AccountChange {
            before,
            after: Some(AccountInfo {
                code_hash,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn accepts_pre_block(
        rule: &Expectation,
        field: &Field,
        real: StepChanges,
        shadow: StepChanges,
    ) -> bool {
        let evidence = Evidence {
            pre_block: Some(Arms { real, shadow }),
            ..Default::default()
        };
        let ctx = Context {
            boundary: Boundary::PreBlock,
            evidence: &evidence,
            base_fee: None,
            tx: None,
        };
        rule.accepts(&ctx, field).is_some()
    }

    /// The rule `id` from the T15 rule file, which lists every fork rule.
    fn rule(id: &str) -> Expectation {
        load(TempoHardfork::T15)
            .unwrap()
            .expectations
            .into_iter()
            .find_map(|(_, rule)| (rule.id == id).then_some(rule))
            .unwrap()
    }

    #[test]
    fn accepts_exact_bytecode_upgrades() {
        let address = ZONE_PORTAL_IMPL_ADDRESS;
        let step = |before, code_hash| changes(address, code_change(before, code_hash));
        let unchanged = || step(Some(AccountInfo::default()), KECCAK256_EMPTY);
        let upgraded = |runtime: &Bytes| step(None, keccak256(runtime));
        let code = Field {
            name: "code",
            address: Some(address),
            slot: None,
            fee_associated: false,
        };
        let t14 = &rule("t14.zone-portal-upgrade");
        assert!(accepts_pre_block(
            t14,
            &code,
            unchanged(),
            upgraded(&T14_ZONE_PORTAL_RUNTIME)
        ));
        assert!(accepts_pre_block(
            t14,
            &code,
            upgraded(&T13_ZONE_PORTAL_RUNTIME),
            upgraded(&T14_ZONE_PORTAL_RUNTIME)
        ));
        assert!(!accepts_pre_block(
            t14,
            &code,
            step(None, keccak256("unexpected")),
            upgraded(&T14_ZONE_PORTAL_RUNTIME)
        ));
        assert!(!accepts_pre_block(
            t14,
            &code,
            unchanged(),
            upgraded(&T13_ZONE_PORTAL_RUNTIME)
        ));

        let verifier = Field {
            address: Some(ZONE_VERIFIER_ADDRESS),
            ..code
        };
        let upgraded = || {
            changes(
                ZONE_VERIFIER_ADDRESS,
                code_change(None, keccak256(&T13_ZONE_VERIFIER_RUNTIME)),
            )
        };
        let real = StepChanges::default;
        let t15 = &rule("t15.zone-runtime-upgrade");
        // T14 and T15 leave the verifier on its T13 runtime.
        assert!(!accepts_pre_block(t14, &verifier, real(), upgraded()));
        assert!(!accepts_pre_block(t15, &verifier, real(), upgraded()));

        let upgrades = |before: &Bytes, after: &Bytes| {
            let before = AccountInfo {
                code_hash: keccak256(before),
                ..Default::default()
            };
            accepts_pre_block(t15, &code, real(), step(Some(before), keccak256(after)))
        };
        for before in [T13_ZONE_PORTAL_RUNTIME, T14_ZONE_PORTAL_RUNTIME] {
            assert!(upgrades(&before, &T15_ZONE_PORTAL_RUNTIME));
        }
        assert!(!upgrades(&ZONE_PORTAL_RUNTIME, &T15_ZONE_PORTAL_RUNTIME));
        assert!(!upgrades(
            &T13_ZONE_PORTAL_RUNTIME,
            &T14_ZONE_PORTAL_RUNTIME
        ));
    }

    #[test]
    fn selects_only_newly_active_forks() {
        use TempoHardfork::*;
        let ids = |canonical, candidate| {
            load(candidate)
                .unwrap()
                .between(canonical)
                .into_iter()
                .map(|rule| rule.id)
                .collect::<Vec<_>>()
        };
        let [fee, t14, t15] = [
            FEE_STATE.id,
            "t14.zone-portal-upgrade",
            "t15.zone-runtime-upgrade",
        ];
        assert_eq!(ids(T13, T14), [fee, t14]);
        assert_eq!(ids(T14, T14), [fee]);
        assert_eq!(ids(T14, T15), [fee, t15]);
        assert_eq!(ids(T13, T15), [fee, t14, t15]);
        let skipped =
            |canonical, candidate| load(candidate).unwrap().skipped_header_checks(canonical);
        let [fee_recipient, dkg_outcome] = [
            "t14.proposer-fee-recipient-check",
            "t15.boundary-dkg-outcome-check",
        ];
        assert_eq!(skipped(T13, T14), [fee_recipient]);
        assert!(skipped(T14, T14).is_empty());
        assert_eq!(skipped(T13, T15), [fee_recipient, dkg_outcome]);
        assert_eq!(skipped(T14, T15), [dkg_outcome]);
        assert!(skipped(T15, T15).is_empty());
        assert_eq!(
            load(T13).unwrap_err().to_string(),
            "no shadow expectations for T13"
        );
    }

    #[test]
    fn rule_files_load_and_agree_on_shared_rules() {
        let mut rules = std::collections::HashMap::new();
        for &fork in TempoHardfork::VARIANTS {
            let Some(json) = rule_file(fork) else {
                continue;
            };
            load(fork).unwrap();
            for rule in serde_json::from_str::<Vec<serde_json::Value>>(json).unwrap() {
                let id = rule["id"].as_str().unwrap().to_owned();
                let first = rules.entry(id.clone()).or_insert_with(|| rule.clone());
                assert_eq!(*first, rule, "{id} differs in the {fork} rule file");
            }
        }
    }

    const PORTAL: &str = "ZONE_PORTAL_IMPL_ADDRESS";

    #[test_case(&[("a", "T14", &[PORTAL]), ("a", "T14", &[PORTAL])], None => "duplicate expectation a")]
    #[test_case(&[("fee.post-tx-state", "T14", &[PORTAL])], None => "duplicate expectation fee.post-tx-state")]
    #[test_case(&[("a", "T14", &[PORTAL]), ("b", "T13", &[PORTAL])], None => "expectation b for T13 is out of fork order or after T14")]
    #[test_case(&[("a", "T15", &[PORTAL])], None => "expectation a for T15 is out of fork order or after T14")]
    #[test_case(&[("a", "T14", &["ZONE_PORTAL"])], None => "unknown constant ZONE_PORTAL at line 1 column 142")]
    #[test_case(&[("a", "T14", &[PORTAL, PORTAL])], None => "expectation a lists account 0x5AD1000000000000000000000000000000000000 twice")]
    #[test_case(&[("a", "T14", &[PORTAL])], Some((r#""to""#, r#""extra": 1, "to""#)) => "unknown field `extra`, expected one of `address`, `from`, `to` at line 1 column 167")]
    #[test_case(&[("a", "T14", &[PORTAL])], Some((r#""kind""#, r#""extra": 1, "kind""#)) => "unknown field `extra`, expected one of `id`, `fork`, `accounts` at line 1 column 167")]
    #[test_case(&[("a", "T14", &[PORTAL])], Some(("runtime-upgrade", "skip-header-checks")) => "unknown field `accounts`, expected `id` or `fork` at line 1 column 158")]
    #[test_case(&[("a", "T14", &[PORTAL])], Some(("runtime-upgrade", "storage")) => "unknown variant `storage`, expected `runtime-upgrade` or `skip-header-checks` at line 1 column 45")]
    fn invalid_rule_file(rules: &[(&str, &str, &[&str])], edit: Option<(&str, &str)>) -> String {
        let rules = rules.iter().map(|(id, fork, addresses)| {
            let accounts = addresses.iter().map(|address| {
                format!(r#"{{"address": "{address}", "from": [], "to": "T14_ZONE_PORTAL_RUNTIME"}}"#)
            });
            let accounts = accounts.collect::<Vec<_>>().join(", ");
            format!(r#"{{"id": "{id}", "fork": "{fork}", "kind": "runtime-upgrade", "accounts": [{accounts}]}}"#)
        });
        let mut json = format!("[{}]", rules.collect::<Vec<_>>().join(", "));
        if let Some((from, to)) = edit {
            json = json.replace(from, to);
        }
        format!("{:#}", parse(TempoHardfork::T14, json.leak()).unwrap_err())
    }

    /// A block of `txs` empty transactions at a zero base fee.
    fn block(txs: usize) -> RecoveredBlock<Block> {
        let mut block = Block::default();
        block.header.inner.base_fee_per_gas = Some(0);
        block.body.transactions = vec![signed_tx(vec![]); txs];
        let senders = vec![Address::ZERO; txs];
        RecoveredBlock::new_unhashed(block, senders)
    }

    /// Complete evidence of `txs` transactions the candidate reproduced exactly.
    fn evidence(txs: usize) -> Evidence {
        Evidence {
            pre_block: Some(Arms::default()),
            txs: (0..txs).map(|_| TxEvidence::Same).collect(),
            post_block: Some(Arms::default()),
            ..Default::default()
        }
    }

    /// Marks transaction `index` as differing, charged `gas` in each arm, and returns both arms.
    fn differs(evidence: &mut Evidence, index: usize, gas: [u64; 2]) -> &mut Arms<ObservedTx> {
        let observed = |charged_gas| ObservedTx {
            charged_gas,
            ..Default::default()
        };
        evidence.txs[index] = TxEvidence::Differs(Box::new(Arms {
            real: observed(gas[0]),
            shadow: observed(gas[1]),
        }));
        let TxEvidence::Differs(arms) = &mut evidence.txs[index] else {
            unreachable!("set above");
        };
        arms
    }

    fn write_slot(tx: &mut ObservedTx, value: u64) {
        let address = Address::ZERO;
        let slot = U256::ZERO;
        tx.changes = changes(
            address,
            AccountChange {
                before: Some(AccountInfo::default()),
                after: Some(AccountInfo::default()),
                storage: [(slot, (U256::from(1_000), U256::from(value)))].into(),
                ..Default::default()
            },
        );
        tx.actions = post_fee(U256::ZERO, 0);
        tx.actions.insert(
            3,
            StorageAction::Sstore(address, slot, U256::from(1_000), U256::from(value)),
        );
    }

    #[test]
    fn equal_boundaries_do_not_invoke_rules() {
        let rule = Expectation {
            id: "must-not-run",
            check: Check::Fn(|_, _| panic!("equal values")),
        };
        let mut evidence = evidence(2);
        differs(&mut evidence, 1, [21_000, 21_000]);
        let report = Report::analyze(&evidence, &[&rule], &block(2));
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Match);
        assert_eq!(report.boundaries_evaluated, 4);
        assert_eq!(report.boundaries_not_evaluated, 0);
    }

    #[test]
    fn skipped_header_checks_are_expected() {
        let mut evidence = evidence(1);
        evidence.skipped_header_checks = vec!["t14.proposer-fee-recipient-check"];
        let report = Report::analyze(&evidence, &[], &block(1));
        assert_eq!(
            report.expected,
            [("t14.proposer-fee-recipient-check", 1)].into()
        );
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Expected);
    }

    #[test]
    fn gas_only_difference_does_not_hide_unverified_fee_state() {
        let mut evidence = evidence(2);
        differs(&mut evidence, 0, [21_000, 21_200]);
        let report = Report::analyze(&evidence, &[], &block(2));
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Match);

        write_slot(&mut differs(&mut evidence, 0, [21_000, 21_200]).shadow, 800);
        let report = Report::analyze(&evidence, &[&FEE_STATE], &block(2));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Findings);
        let field = report.samples[0].1.field;
        assert_eq!(field.name, "storage");
        assert_eq!(field.address, Some(Address::ZERO));
        assert_eq!(field.slot, Some(U256::ZERO));
        assert!(field.fee_associated);
    }

    fn post_fee(charged: U256, log: usize) -> Vec<StorageAction> {
        vec![
            StorageAction::Marker(FeeHook::PreTx {
                payer: Address::ZERO,
                token: Address::ZERO,
                amount: charged,
            }),
            StorageAction::Marker(FeeHook::End),
            StorageAction::Marker(FeeHook::PostTx {
                refund: U256::ZERO,
                log,
            }),
            StorageAction::Marker(FeeHook::End),
        ]
    }

    fn signed_tx(calls: Vec<Call>) -> TempoTxEnvelope {
        TempoTransaction {
            max_priority_fee_per_gas: 1_000_000_000_000,
            max_fee_per_gas: 1_000_000_000_000,
            gas_limit: 35_212,
            calls,
            ..Default::default()
        }
        .into_signed(Signature::test_signature().into())
        .into()
    }

    #[test]
    fn only_verified_fee_amount_is_masked_in_ordered_receipt_logs() {
        let original = B256::repeat_byte(1);
        let changed = B256::repeat_byte(2);
        let normalized = B256::repeat_byte(3);
        let mut evidence = evidence(1);
        let arms = differs(&mut evidence, 0, [1_000, 1_200]);
        for (tx, amount, hash) in [
            (&mut arms.real, 1_000, original),
            (&mut arms.shadow, 1_200, changed),
        ] {
            tx.receipt_logs_hash = hash;
            tx.actions = post_fee(U256::from(amount), 0);
            tx.fee_normalized = Some(normalized);
        }
        let block = block(1);
        let report = |evidence: &Evidence| Report::analyze(evidence, &[], &block);
        assert_eq!(report(&evidence).outcome(&evidence), ReplayOutcome::Match);

        fn shadow(evidence: &mut Evidence) -> &mut ObservedTx {
            match &mut evidence.txs[0] {
                TxEvidence::Differs(arms) => &mut arms.shadow,
                _ => unreachable!("set above"),
            }
        }
        shadow(&mut evidence).fee_normalized = Some(B256::repeat_byte(4));
        assert_eq!(report(&evidence).unexplained, 1);
        shadow(&mut evidence).fee_normalized = Some(normalized);
        shadow(&mut evidence).actions = post_fee(U256::ZERO, 0);
        assert_eq!(report(&evidence).unexplained, 1);
        shadow(&mut evidence).actions = post_fee(U256::from(1_200), 1);
        assert_eq!(report(&evidence).unexplained, 1);
    }

    #[test]
    fn first_accepting_rule_owns_attribution() {
        let first = Expectation {
            id: "test.first-output",
            check: Check::Fn(|_, field| (field.name == "output").then_some(())),
        };
        let second = Expectation {
            id: "test.second-output",
            check: Check::Fn(|_, field| (field.name == "output").then_some(())),
        };
        let unreachable = Expectation {
            id: "must-not-run",
            check: Check::Fn(|_, _| panic!("already accepted")),
        };
        let mut evidence = evidence(1);
        differs(&mut evidence, 0, [21_000, 21_200])
            .shadow
            .output_hash = B256::repeat_byte(1);
        for rules in [
            [&first, &second, &unreachable],
            [&second, &first, &unreachable],
        ] {
            let report = Report::analyze(&evidence, &rules, &block(1));
            assert_eq!(report.unexplained, 0);
            assert_eq!(report.expected, [(rules[0].id, 1)].into());
        }
    }

    #[test]
    fn uncaptured_shadow_reads_are_inconclusive() {
        let mut evidence = evidence(2);
        evidence.txs[0] = TxEvidence::Failed(missing_account());
        let report = Report::analyze(&evidence, &[], &block(2));
        assert_eq!(report.unexplained, 0);
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Inconclusive);

        let evidence = Evidence {
            failure: Some(Failure {
                boundary: Boundary::PreBlock,
                error: missing_account(),
            }),
            ..Default::default()
        };
        let report = Report::analyze(&evidence, &[], &block(2));
        assert_eq!(report.boundaries_not_evaluated, 4);
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Inconclusive);
    }

    #[test]
    fn rejected_shadow_tx_does_not_hide_later_transaction_findings() {
        let mut evidence = evidence(2);
        evidence.txs[0] = TxEvidence::Failed(eyre::eyre!("rejected"));
        differs(&mut evidence, 1, [21_000, 21_000]).shadow.outcome = (1, "Revert".into());

        let report = Report::analyze(&evidence, &[], &block(2));

        assert_eq!(report.unexplained, 2);
        assert_eq!(report.boundaries_evaluated, 4);
        assert_eq!(report.boundaries_not_evaluated, 0);
        assert_eq!(report.samples[0].1.field.name, "execution");
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Findings);
    }

    #[test]
    fn created_code_is_compared_even_when_both_accounts_are_created() {
        let mut evidence = evidence(1);
        let arms = differs(&mut evidence, 0, [21_000, 21_000]);
        for (tx, hash) in [
            (&mut arms.real, B256::repeat_byte(1)),
            (&mut arms.shadow, B256::repeat_byte(2)),
        ] {
            tx.changes = changes(Address::ZERO, code_change(None, hash));
        }
        let report = Report::analyze(&evidence, &[], &block(1));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.samples[0].1.field.name, "code");
    }

    #[test]
    fn sampling_does_not_truncate_counts() {
        let mut evidence = evidence(20);
        for index in 0..20 {
            differs(&mut evidence, index, [21_000, 21_000])
                .shadow
                .output_hash = B256::repeat_byte(1);
        }
        let report = Report::analyze(&evidence, &[], &block(20));
        assert_eq!(report.unexplained, 20);
        assert_eq!(report.samples.len(), MAX_SAMPLES);
        assert_eq!(report.boundaries_evaluated, 22);
    }

    #[test]
    fn storage_reset_is_compared_without_enumerated_slots() {
        let mut evidence = evidence(2);
        differs(&mut evidence, 0, [21_000, 21_000]).shadow.changes = changes(
            Address::ZERO,
            AccountChange {
                before: Some(AccountInfo::default()),
                after: Some(AccountInfo::default()),
                storage_reset: true,
                ..Default::default()
            },
        );
        let report = Report::analyze(&evidence, &[], &block(2));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.samples[0].1.field.name, "storage_reset");
    }
}
