use quote::ToTokens;
use std::{collections::BTreeMap, env, fs, path::Path};
use syn::{Expr, Item, Stmt, visit::Visit};
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("unsupported source shape: {0}")]
    Unsupported(&'static str),
    #[error(transparent)]
    Parse(#[from] syn::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn tokens(value: &impl ToTokens) -> String {
    value.to_token_stream().to_string()
}

fn same(value: &impl ToTokens, expected: &str) -> bool {
    syn::parse_str::<Expr>(expected).is_ok_and(|expr| tokens(value) == tokens(&expr))
}

#[derive(Debug, PartialEq)]
enum Op {
    SpendCredit,
    Changed,
    SpendBudget,
    Store,
    Charge,
    Refund,
    Finite(Vec<Op>),
}

#[derive(Debug)]
struct Program {
    arms: Vec<(String, Vec<Op>)>,
    source_match: String,
    cost: u64,
}

fn lower_block(block: &syn::Block) -> Result<Vec<Op>, Error> {
    block.stmts.iter().map(|stmt| {
        let Stmt::Expr(expr, Some(_)) = stmt else {
            // Rust permits a final if expression without a semicolon.
            if let Stmt::Expr(Expr::If(branch), None) = stmt {
                return lower_if(branch);
            }
            return Err(Error::Unsupported("statement (only explicit policy operations accepted)"));
        };
        if let Expr::If(branch) = expr {
            return lower_if(branch);
        }
        for (source, op) in [
            ("credit -= 1", Op::SpendCredit),
            ("was_changed = true", Op::Changed),
            ("transient_state.budget -= 1", Op::SpendBudget),
            ("store_credit_state(backend, account_slot, transient_state)?", Op::Store),
            ("backend.charge_gas(STORAGE_CREDIT_VALUE)?", Op::Charge),
            ("transient_state.pending_refunds = transient_state.pending_refunds.saturating_add(1)", Op::Refund),
        ] {
            if same(expr, source) { return Ok(op); }
        }
        Err(Error::Unsupported("statement/operator/method/arithmetic"))
    }).collect()
}

fn lower_if(branch: &syn::ExprIf) -> Result<Op, Error> {
    if !branch.attrs.is_empty()
        || !same(&branch.cond, "transient_state.budget != u64::MAX")
        || branch.else_branch.is_some()
    {
        return Err(Error::Unsupported("finite budget guard"));
    }
    Ok(Op::Finite(lower_block(&branch.then_branch)?))
}

struct Creation<'a> {
    branches: Vec<&'a syn::ExprIf>,
}
impl<'a> Visit<'a> for Creation<'a> {
    fn visit_expr_if(&mut self, branch: &'a syn::ExprIf) {
        if same(&branch.cond, "sstore_flags.is_zero_to_nonzero()") {
            self.branches.push(branch);
        }
        syn::visit::visit_expr_if(self, branch);
    }
}

fn extract(source: &str, cost: u64) -> Result<Program, Error> {
    let ast = syn::parse_file(source)?;
    if ast.attrs.iter().any(|attr| !attr.path().is_ident("doc")) {
        return Err(Error::Unsupported("accounting file attributes"));
    }
    let expected_import: syn::ItemUse =
        syn::parse_str("use tempo_chainspec::constants::gas::STORAGE_CREDIT_VALUE;")?;
    if !ast
        .items
        .iter()
        .any(|item| matches!(item, Item::Use(import) if tokens(import) == tokens(&expected_import)))
    {
        return Err(Error::Unsupported("storage credit constant import"));
    }
    struct Shadowed(bool);
    impl<'ast> Visit<'ast> for Shadowed {
        fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
            self.0 |= pattern.ident == "STORAGE_CREDIT_VALUE";
            syn::visit::visit_pat_ident(self, pattern);
        }
        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            self.0 |= item.ident == "STORAGE_CREDIT_VALUE";
            syn::visit::visit_item_const(self, item);
        }
    }
    let mut shadowed = Shadowed(false);
    shadowed.visit_file(&ast);
    if shadowed.0 {
        return Err(Error::Unsupported("shadowed storage credit constant"));
    }
    let functions: Vec<_> = ast
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "sstore_storage_credits" => Some(function),
            _ => None,
        })
        .collect();
    if functions.len() != 1 {
        return Err(Error::Unsupported("unique sstore_storage_credits function"));
    }
    if functions[0]
        .attrs
        .iter()
        .any(|attr| !attr.path().is_ident("doc"))
    {
        return Err(Error::Unsupported("accounting function attributes"));
    }
    // Only a top-level else-if of the deletion branch is in the supported scope.
    let mut visitor = Creation {
        branches: Vec::new(),
    };
    visitor.visit_block(&functions[0].block);
    if visitor.branches.len() != 1 {
        return Err(Error::Unsupported("unique creation branch"));
    }
    let creation = visitor.branches[0];
    let is_else_if = functions[0].block.stmts.iter().any(|stmt| {
        let Stmt::Expr(Expr::If(branch), _) = stmt else { return false; };
        branch.attrs.is_empty() && same(&branch.cond, "sstore_flags.is_nonzero_to_zero()") &&
            matches!(&branch.else_branch, Some((_, expr)) if matches!(expr.as_ref(), Expr::If(inner) if std::ptr::eq(inner, creation)))
    });
    if !is_else_if || creation.else_branch.is_some() || !creation.attrs.is_empty() {
        return Err(Error::Unsupported("creation must be deletion else-if"));
    }
    let [Stmt::Local(local), Stmt::Expr(Expr::Match(matched), None)] =
        creation.then_branch.stmts.as_slice()
    else {
        return Err(Error::Unsupported("creation prelude and match"));
    };
    let expected: syn::Block = syn::parse_str(
        "{ let mut transient_state: TransientState = backend.tload(STORAGE_CREDITS_ADDRESS, account_slot).try_into().map_err(|_| B::Error::fatal_external())?; }",
    )?;
    if tokens(local) != tokens(&expected.stmts[0])
        || !same(&matched.expr, "transient_state.mode")
        || !matched.attrs.is_empty()
    {
        return Err(Error::Unsupported("transient load or match scrutinee"));
    }
    let mut arms = Vec::new();
    for arm in &matched.arms {
        if !arm.attrs.is_empty() {
            return Err(Error::Unsupported("arm attributes"));
        }
        let pattern = tokens(&arm.pat);
        let kind = match pattern.as_str() {
            "CreditMode :: Direct"
                if arm.guard.as_ref().is_some_and(|(_, guard)| {
                    same(guard, "credit > 0 && transient_state.budget > 0")
                }) =>
            {
                "DirectSpend"
            }
            "CreditMode :: Direct | CreditMode :: Preserve" if arm.guard.is_none() => "Pay",
            "CreditMode :: Refund" if arm.guard.is_none() => "Refund",
            _ => return Err(Error::Unsupported("arm pattern or spend guard")),
        };
        let Expr::Block(body) = arm.body.as_ref() else {
            return Err(Error::Unsupported("arm block"));
        };
        if body.label.is_some() || !body.attrs.is_empty() {
            return Err(Error::Unsupported("arm block attributes/label"));
        }
        arms.push((kind.to_owned(), lower_block(&body.block)?));
    }
    if arms
        .iter()
        .map(|(kind, _)| kind.as_str())
        .collect::<Vec<_>>()
        != ["DirectSpend", "Pay", "Refund"]
    {
        return Err(Error::Unsupported("arm order or completeness"));
    }
    Ok(Program {
        arms,
        source_match: tokens(matched),
        cost,
    })
}

fn resolve_cost(source: &str) -> Result<u64, Error> {
    let ast = syn::parse_file(source)?;
    let modules: Vec<_> = ast
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module)
                if module.ident == "gas"
                    && module.attrs.iter().all(|attr| attr.path().is_ident("doc")) =>
            {
                module.content.as_ref()
            }
            _ => None,
        })
        .collect();
    if modules.len() != 1 {
        return Err(Error::Unsupported("unique gas constants module"));
    }
    let mut constants = BTreeMap::new();
    for item in &modules[0].1 {
        if let Item::Const(item) = item
            && item.attrs.iter().any(|attr| !attr.path().is_ident("doc"))
        {
            return Err(Error::Unsupported("gas constant attributes"));
        }
        if let Item::Const(item) = item
            && constants
                .insert(item.ident.to_string(), item.expr.as_ref())
                .is_some()
        {
            return Err(Error::Unsupported("duplicate gas constant"));
        }
    }
    fn evaluate(
        expr: &Expr,
        constants: &BTreeMap<String, &Expr>,
        depth: usize,
    ) -> Result<u64, Error> {
        if depth > constants.len() {
            return Err(Error::Unsupported("constant cycle"));
        }
        match expr {
            Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(value),
                ..
            }) => Ok(value.base10_parse()?),
            Expr::Path(path) if path.path.segments.len() == 1 => evaluate(
                constants
                    .get(&tokens(path))
                    .ok_or(Error::Unsupported("unknown constant"))?,
                constants,
                depth + 1,
            ),
            Expr::Binary(binary) if matches!(binary.op, syn::BinOp::Sub(_)) => {
                evaluate(&binary.left, constants, depth + 1)?
                    .checked_sub(evaluate(&binary.right, constants, depth + 1)?)
                    .ok_or(Error::Unsupported("constant underflow"))
            }
            _ => Err(Error::Unsupported("constant expression")),
        }
    }
    evaluate(
        constants
            .get("STORAGE_CREDIT_VALUE")
            .ok_or(Error::Unsupported("missing storage credit constant"))?,
        &constants,
        0,
    )
}

fn emit_program(program: &Program) -> Result<String, Error> {
    let direct = &program.arms[0].1;
    let pay = &program.arms[1].1;
    let refund = &program.arms[2].1;
    if direct
        != &vec![
            Op::SpendCredit,
            Op::Changed,
            Op::Finite(vec![Op::SpendBudget, Op::Store]),
        ]
        || pay != &vec![Op::Charge]
        || refund != &vec![Op::Charge, Op::Refund, Op::Store]
    {
        return Err(Error::Unsupported("instruction order or fixed-shape IR"));
    }
    let credit_positive = program.arms[0].0 == "DirectSpend";
    let budget_positive = credit_positive;
    let decrement_credit = direct.contains(&Op::SpendCredit);
    let finite_only = matches!(&direct[2], Op::Finite(_));
    let refund_charge_first = refund.first() == Some(&Op::Charge);
    let saturating_refund = refund.contains(&Op::Refund);
    let store_finite = matches!(&direct[2], Op::Finite(ops) if ops.contains(&Op::Store));
    let store_refund = refund.contains(&Op::Store);
    let checked_credit = !direct.contains(&Op::SpendCredit);
    Ok(format!(
        "verus! {{\nspec fn source_program() -> Program {{ Program {{ credit_positive: {credit_positive}, budget_positive: {budget_positive}, decrement_credit: {decrement_credit}, finite_only: {finite_only}, charge_amount: {}u64, refund_charge_first: {refund_charge_first}, saturating_refund: {saturating_refund}, store_finite: {store_finite}, store_refund: {store_refund}, checked_credit: {checked_credit} }} }}\nproof fn source_conforms() ensures p2(source_program()), p1(source_program()), p0(source_program()) {{ witness_satisfiable(); }}\n}}\n",
        program.cost
    ))
}

fn fixture(program: &Program) -> String {
    format!(
        r#"// Trusted AST bridge: actual creation match, with abstract backend/state definitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreditMode {{ Direct, Preserve, Refund }}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransientState {{ pub mode: CreditMode, pub budget: u64, pub pending_refunds: u64 }}
#[derive(Debug, PartialEq, Eq)]
pub struct Backend {{ pub gas: u64, pub writes: u64, pub stored: Option<TransientState> }}
impl Backend {{ fn charge_gas(&mut self, cost: u64) -> Result<(), ()> {{
    if self.gas < cost {{ Err(()) }} else {{ self.gas -= cost; Ok(()) }}
}} }}
const STORAGE_CREDIT_VALUE: u64 = {};
fn store_credit_state(backend: &mut Backend, _: u64, state: TransientState) -> Result<(), ()> {{
    backend.writes += 1; backend.stored = Some(state); Ok(())
}}
pub fn creation(backend: &mut Backend, mut credit: u64, mut transient_state: TransientState) -> Result<(u64, bool, TransientState), ()> {{
    let account_slot = 0;
    let mut was_changed = false;
    {};
    Ok((credit, was_changed, transient_state))
}}
"#,
        program.cost, program.source_match
    )
}

fn main() -> Result<(), Error> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 3 {
        return Err(Error::Unsupported(
            "usage: pop-source-frontend SOURCE_PATH OUTPUT_DIR",
        ));
    }
    let source = Path::new(&args[1]);
    let output = Path::new(&args[2]);
    let root = source
        .ancestors()
        .find(|path| path.join("crates/hardfork/src/constants.rs").is_file())
        .ok_or(Error::Unsupported("repository constants path"))?;
    let cost = resolve_cost(&fs::read_to_string(
        root.join("crates/hardfork/src/constants.rs"),
    )?)?;
    let program = extract(&fs::read_to_string(source)?, cost)?;
    let generated = emit_program(&program)?;
    let proof = fs::read_to_string(root.join("scripts/pop-refinement/proof.rs"))?;
    fs::create_dir_all(output.join("fixture/src"))?;
    fs::write(output.join("program.rs"), &generated)?;
    fs::write(output.join("extracted.rs"), format!("{proof}\n{generated}"))?;
    fs::write(output.join("fixture/src/lib.rs"), fixture(&program))?;
    fs::write(
        output.join("fixture/Cargo.toml"),
        "[package]\nname = \"extracted-storage-creation\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\n",
    )?;
    println!(
        "lowered actual creation match (trusted syn bridge); cost={cost}; wrote program.rs, extracted.rs, fixture/Cargo.toml, fixture/src/lib.rs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str =
        include_str!("../../../../crates/precompiles/src/storage_credits/accounting.rs");
    const CONSTANTS: &str = include_str!("../../../../crates/hardfork/src/constants.rs");

    #[test]
    fn actual_source_and_layout_changes_accept() {
        let cost = resolve_cost(CONSTANTS).unwrap();
        assert_eq!(cost, 245_000);
        let program = extract(SOURCE, cost).unwrap();
        assert_eq!(program.arms[2].1, vec![Op::Charge, Op::Refund, Op::Store]);
        let reformatted = SOURCE.replace("credit > 0", "/* layout */ credit\n > 0");
        assert_eq!(
            extract(&reformatted, cost).unwrap().arms[0].1,
            program.arms[0].1
        );
    }

    #[test]
    fn changed_spend_guard_rejects() {
        let mutated = SOURCE.replace("credit > 0", "credit >= 0");
        assert!(matches!(
            extract(&mutated, 245_000),
            Err(Error::Unsupported("arm pattern or spend guard"))
        ));
    }

    #[test]
    fn disabled_enclosing_branch_rejects() {
        let mutated = SOURCE.replace(
            "if sstore_flags.is_nonzero_to_zero()",
            "#[cfg(any())] if sstore_flags.is_nonzero_to_zero()",
        );
        assert_ne!(mutated, SOURCE);
        assert!(matches!(
            extract(&mutated, 245_000),
            Err(Error::Unsupported("creation must be deletion else-if"))
        ));
    }

    #[test]
    fn inverted_unlimited_guard_rejects() {
        let mutated = SOURCE.replace(
            "transient_state.budget != u64::MAX",
            "transient_state.budget == u64::MAX",
        );
        assert!(matches!(
            extract(&mutated, 245_000),
            Err(Error::Unsupported("finite budget guard"))
        ));
    }

    #[test]
    fn unsupported_method_and_statement_reject() {
        let mutated = SOURCE.replace(
            "pending_refunds.saturating_add(1)",
            "pending_refunds.wrapping_add(1)",
        );
        assert!(matches!(
            extract(&mutated, 245_000),
            Err(Error::Unsupported("statement/operator/method/arithmetic"))
        ));
        let mutated = SOURCE.replace("credit -= 1;", "credit -= 1; mysterious();");
        assert!(matches!(
            extract(&mutated, 245_000),
            Err(Error::Unsupported("statement/operator/method/arithmetic"))
        ));
    }

    #[test]
    fn source_cost_resolved_and_unsupported_constant_rejects() {
        assert_eq!(
            resolve_cost(&CONSTANTS.replace("250_000", "260_000")).unwrap(),
            255_000
        );
        assert!(matches!(
            resolve_cost(&CONSTANTS.replace(
                "SSTORE_CREATE_COST - SSTORE_SET_COST",
                "SSTORE_CREATE_COST * SSTORE_SET_COST"
            )),
            Err(Error::Unsupported("constant expression"))
        ));
    }

    #[test]
    fn charge_after_write_rejects_explicitly() {
        let before = "backend.charge_gas(STORAGE_CREDIT_VALUE)?;\n                transient_state.pending_refunds = transient_state.pending_refunds.saturating_add(1);\n                store_credit_state(backend, account_slot, transient_state)?;";
        let after = "transient_state.pending_refunds = transient_state.pending_refunds.saturating_add(1);\n                store_credit_state(backend, account_slot, transient_state)?;\n                backend.charge_gas(STORAGE_CREDIT_VALUE)?;";
        assert!(SOURCE.contains(before));
        let program = extract(&SOURCE.replace(before, after), 245_000).unwrap();
        assert!(matches!(
            emit_program(&program),
            Err(Error::Unsupported("instruction order or fixed-shape IR"))
        ));
    }

    #[test]
    fn actual_extracted_fixture_matches_lowered_interpreter_at_boundaries() {
        // This is bridge testing, not verification of the parser or compiler.
        #[derive(Clone)]
        struct State {
            credit: u64,
            budget: u64,
            pending: u64,
            gas: u64,
            changed: bool,
            writes: u64,
            stored: Option<(u64, u64)>,
        }
        fn run(ops: &[Op], state: &mut State, cost: u64) -> bool {
            for op in ops {
                match op {
                    Op::SpendCredit => state.credit -= 1,
                    Op::Changed => state.changed = true,
                    Op::SpendBudget => state.budget -= 1,
                    Op::Store => {
                        state.writes += 1;
                        state.stored = Some((state.budget, state.pending));
                    }
                    Op::Charge => {
                        if state.gas < cost {
                            return false;
                        }
                        state.gas -= cost;
                    }
                    Op::Refund => state.pending = state.pending.saturating_add(1),
                    Op::Finite(body) => {
                        if state.budget != u64::MAX && !run(body, state, cost) {
                            return false;
                        }
                    }
                }
            }
            true
        }
        let program = extract(SOURCE, resolve_cost(CONSTANTS).unwrap()).unwrap();
        let mut code = fixture(&program);
        code.push_str("\n#[test] fn differential_boundaries() {\n");
        let mut count = 0;
        for mode in ["Direct", "Preserve", "Refund"] {
            for credit in [0u64, 1, u64::MAX] {
                for budget in [0u64, 1, u64::MAX] {
                    for pending in [0u64, 1, u64::MAX - 1, u64::MAX] {
                        for gas in [0u64, program.cost - 1, program.cost, u64::MAX] {
                            let mut state = State {
                                credit,
                                budget,
                                pending,
                                gas,
                                changed: false,
                                writes: 0,
                                stored: None,
                            };
                            let arm = if mode == "Direct" && credit > 0 && budget > 0 {
                                0
                            } else if mode == "Refund" {
                                2
                            } else {
                                1
                            };
                            let success = run(&program.arms[arm].1, &mut state, program.cost);
                            let expected = if success {
                                format!(
                                    "Ok(({}u64, {}, TransientState {{ mode: CreditMode::{mode}, budget: {}u64, pending_refunds: {}u64 }}))",
                                    state.credit, state.changed, state.budget, state.pending
                                )
                            } else {
                                "Err(())".to_owned()
                            };
                            let stored = match state.stored {
                                None => "None".to_owned(),
                                Some((budget, pending)) => format!(
                                    "Some(TransientState {{ mode: CreditMode::{mode}, budget: {budget}u64, pending_refunds: {pending}u64 }})"
                                ),
                            };
                            code.push_str(&format!("{{ let mut backend = Backend {{ gas: {gas}u64, writes: 0, stored: None }}; assert_eq!(creation(&mut backend, {credit}u64, TransientState {{ mode: CreditMode::{mode}, budget: {budget}u64, pending_refunds: {pending}u64 }}), {expected}); assert_eq!(backend, Backend {{ gas: {}u64, writes: {}, stored: {stored} }}); }}\n", state.gas, state.writes));
                            count += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(count, 432);
        code.push_str("}\n");
        let directory = env::temp_dir().join(format!("pop-fixture-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("fixture.rs"), code).unwrap();
        let compilation = std::process::Command::new("rustc")
            .arg("--test")
            .arg(directory.join("fixture.rs"))
            .arg("-o")
            .arg(directory.join("fixture-test"))
            .output()
            .unwrap();
        assert!(
            compilation.status.success(),
            "{}",
            String::from_utf8_lossy(&compilation.stderr)
        );
        let execution = std::process::Command::new(directory.join("fixture-test"))
            .output()
            .unwrap();
        assert!(
            execution.status.success(),
            "{} {}",
            String::from_utf8_lossy(&execution.stdout),
            String::from_utf8_lossy(&execution.stderr)
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn conditional_compilation_and_constant_shadowing_reject() {
        let mutated = SOURCE.replace(
            "if transient_state.budget != u64::MAX",
            "#[cfg(any())] if transient_state.budget != u64::MAX",
        );
        assert!(matches!(
            extract(&mutated, 245_000),
            Err(Error::Unsupported("finite budget guard"))
        ));
        let mutated = SOURCE.replace(
            "let mut was_changed = false;",
            "let STORAGE_CREDIT_VALUE: u64 = 0; let mut was_changed = false;",
        );
        assert!(matches!(
            extract(&mutated, 245_000),
            Err(Error::Unsupported("shadowed storage credit constant"))
        ));
        let mutated = SOURCE.replace(
            "pub fn sstore_storage_credits",
            "#[cfg(any())] pub fn sstore_storage_credits",
        );
        assert!(matches!(
            extract(&mutated, 245_000),
            Err(Error::Unsupported("accounting function attributes"))
        ));
        assert!(matches!(
            resolve_cost(&CONSTANTS.replace("pub mod gas", "#[cfg(any())] pub mod gas")),
            Err(Error::Unsupported("unique gas constants module"))
        ));
        assert!(matches!(
            resolve_cost(&CONSTANTS.replace(
                "pub const STORAGE_CREDIT_VALUE",
                "#[cfg(any())] pub const STORAGE_CREDIT_VALUE"
            )),
            Err(Error::Unsupported("gas constant attributes"))
        ));
    }
}
