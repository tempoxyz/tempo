#!/usr/bin/env bash
# Check the source-derived candidate, extraction artifact, and negative controls.
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../.." && pwd)
: "${VERUS_BIN:?Run setup.sh and source its env.sh first}"
: "${CHARON_BIN:?Run setup.sh and source its env.sh first}"
out=${1:-$(mktemp -d "${TMPDIR:-/tmp}/tempo-pop.XXXXXXXX")}
mkdir -p "$out"
out=$(cd -- "$out" && pwd)
if [[ -n $(find "$out" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo 'Use an empty output directory so stale artifacts cannot pass.' >&2
    exit 1
fi
"$VERUS_BIN" --version | tee "$out/verus-version.txt"
"$CHARON_BIN" version | tee "$out/charon-version.txt"
grep -q '0.2026.11.02.8bf68ee' "$out/verus-version.txt"
grep -q 'c04983b' "$out/charon-version.txt"
manifest="$here/frontend/Cargo.toml"
cargo +1.99.1 test --locked --manifest-path "$manifest"
cargo +1.99.1 run --locked --manifest-path "$manifest" -- \
    "$root/crates/precompiles/src/storage_credits/accounting.rs" "$out"
"$VERUS_BIN" "$out/extracted.rs" 2>&1 | tee "$out/verification.log"
cargo +1.99.1 check --manifest-path "$out/fixture/Cargo.toml"
"$CHARON_BIN" cargo --sysroot default --dest-file "$out/extracted_storage_creation.llbc" -- \
    --manifest-path "$out/fixture/Cargo.toml" --lib 2>&1 | tee "$out/charon.log"
# A nonempty artifact alone does not show that the policy body was translated.
check_extraction() {
    jq -e '
        .has_errors == false and .charon_version == "0.1.314" and
        ([.translated.fun_decls[] | select(any(.item_meta.name[]?; .Ident[0]? == "creation"))] |
            length == 1 and .[0].item_meta.has_errors == false and
            (.[0].body.Structured.body.statements | type == "array" and length > 0))
    ' "$1" > /dev/null
}
check_extraction "$out/extracted_storage_creation.llbc"
jq '.has_errors = true' "$out/extracted_storage_creation.llbc" > "$out/invalid-extraction.llbc"
if check_extraction "$out/invalid-extraction.llbc"; then
    echo 'ERROR: extraction errors accepted' >&2
    exit 1
fi
jq '(.translated.fun_decls[] | select(any(.item_meta.name[]?; .Ident[0]? == "creation")) | .body) = null' \
    "$out/extracted_storage_creation.llbc" > "$out/missing-body.llbc"
if check_extraction "$out/missing-body.llbc"; then
    echo 'ERROR: missing policy body accepted' >&2
    exit 1
fi
# These controls must fail semantically, not merely because the parser rejected them.
for field in credit_positive budget_positive finite_only refund_charge_first saturating_refund; do
    file="$out/mutant-$field.rs"
    cat "$here/proof.rs" > "$file"
    printf '\nverus! { proof fn mutation_must_fail() ensures p0(Program { %s: false, ..production_program() }) {} }\n' "$field" >> "$file"
    if "$VERUS_BIN" --crate-name pop_mutant "$file" > "$out/mutant-$field.log" 2>&1; then
        echo "ERROR: invalid refinement accepted: $field" >&2
        exit 1
    fi
    if ! grep -q 'postcondition not satisfied' "$out/mutant-$field.log"; then
        cat "$out/mutant-$field.log" >&2
        echo "ERROR: $field failed for a reason other than its proof obligation" >&2
        exit 1
    fi
    echo "Rejected semantic mutant: $field"
done
printf 'PASS: source candidate, Rust checks, Charon extraction, and five semantic negative controls.\nArtifacts: %s\n' "$out"
