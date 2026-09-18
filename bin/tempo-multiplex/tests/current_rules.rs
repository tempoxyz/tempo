//! Source-level guard: metadata must not reintroduce execution-time fork switches.
use std::{fs, path::Path};
use syn::{
    Attribute, ExprMethodCall, ItemFn, ItemMod,
    visit::{self, Visit},
};

fn test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("test")
            || (attribute.path().is_ident("cfg")
                && attribute
                    .parse_args::<syn::Path>()
                    .is_ok_and(|path| path.is_ident("test")))
    })
}

fn execution_selector(name: &str) -> bool {
    name == "tempo_hardfork_at"
        || name == "is_amsterdam_eip8037_enabled"
        || name == "amsterdam_eip8037_enabled"
        || name
            .strip_prefix("is_t")
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
}

struct NoForkSwitches<'a>(&'a Path);
impl<'ast> Visit<'ast> for NoForkSwitches<'_> {
    fn visit_item_mod(&mut self, module: &'ast ItemMod) {
        if !test_only(&module.attrs) {
            visit::visit_item_mod(self, module);
        }
    }
    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        if !test_only(&function.attrs) {
            visit::visit_item_fn(self, function);
        }
    }
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        assert!(
            !execution_selector(&call.method.to_string()),
            "execution selector {} in {}",
            call.method,
            self.0.display()
        );
        visit::visit_expr_method_call(self, call);
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        // Dispatch and quote bodies are token streams rather than ordinary expressions.
        if mac.path.is_ident("dispatch") || mac.path.is_ident("quote") {
            let tokens = mac.tokens.to_string();
            assert!(
                !tokens.contains("# [schedule"),
                "scheduled selector in {}",
                self.0.display()
            );
            for pair in tokens.split_whitespace().collect::<Vec<_>>().windows(2) {
                assert!(
                    !(pair[0] == "." && execution_selector(pair[1])),
                    "generated execution selector in {}",
                    self.0.display()
                );
            }
        }
    }
}

fn check_directory(path: &Path) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if name.starts_with("test") || name == "benches" {
            continue;
        }
        if path.is_dir() {
            check_directory(&path);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path).unwrap();
            let syntax = syn::parse_file(&source)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            NoForkSwitches(&path).visit_file(&syntax);
        }
    }
}

#[test]
fn execution_has_no_hardfork_selectors() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for directory in [
        "crates/evm/src",
        "crates/revm/src",
        "crates/precompiles/src",
        "crates/precompiles-macros/src",
        "crates/transaction-pool/src",
        "crates/payload/builder/src",
        "crates/primitives/src",
        "crates/alloy/src/rpc",
    ] {
        check_directory(&root.join(directory));
    }
}
