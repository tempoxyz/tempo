#!/usr/bin/env bash
#
# Publish tempo-contracts, tempo-primitives, and tempo-alloy to crates.io
# by stripping all reth-specific code and dependencies.
#
# Usage:
#   ./scripts/publish-crates.sh              # dry-run (default)
#   ./scripts/publish-crates.sh --publish    # actually publish
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRY_RUN=true
SEMVER_CHECK=false

case "${1:-}" in
    "")              DRY_RUN=true ;;
    --publish)       DRY_RUN=false ;;
    --semver-check)  SEMVER_CHECK=true ;;
    *)               echo "Usage: $0 [--publish|--semver-check]" >&2; exit 1 ;;
esac

# ── Helpers ────────────────────────────────────────────────────────────────────
log() { printf '  \033[1;34m→\033[0m %s\n' "$*"; }
err() { printf '  \033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

SANITIZE_PY="$REPO_ROOT/scripts/sanitize_toml.py"
SANITIZE_RS="$REPO_ROOT/scripts/sanitize_source.py"

# ── Create temp workspace ──────────────────────────────────────────────────────
TMP_WORK_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_WORK_DIR"' EXIT

log "Copying crates to temporary directory …"
cp -R "$REPO_ROOT/crates/contracts"  "$TMP_WORK_DIR/contracts"
cp -R "$REPO_ROOT/crates/primitives" "$TMP_WORK_DIR/primitives"
cp -R "$REPO_ROOT/crates/alloy"      "$TMP_WORK_DIR/alloy"

# ── 1. Delete compat modules ──────────────────────────────────────────────────
log "Deleting reth_compat modules …"
rm -rf "$TMP_WORK_DIR/primitives/src/reth_compat"
rm -f  "$TMP_WORK_DIR/alloy/src/rpc/reth_compat.rs"

# ── 2. Strip reth/compat references from source ──────────────────────────────
log "Stripping reth references from source …"
python3 "$SANITIZE_RS" "$TMP_WORK_DIR/primitives" "$TMP_WORK_DIR/alloy"

# ── 3. Sanitize Cargo.toml (strip deps/features, keep workspace refs) ────────
log "Sanitizing Cargo.toml files …"

WS_VERSION=$(python3 "$SANITIZE_PY" get_version "$REPO_ROOT/Cargo.toml")
log "Workspace version: $WS_VERSION"

for crate_toml in "$TMP_WORK_DIR/primitives/Cargo.toml" "$TMP_WORK_DIR/alloy/Cargo.toml" "$TMP_WORK_DIR/contracts/Cargo.toml"; do
    python3 "$SANITIZE_PY" sanitize_base "$crate_toml" "$WS_VERSION" "$REPO_ROOT/Cargo.toml"
done

python3 "$SANITIZE_PY" sanitize_primitives "$TMP_WORK_DIR/primitives/Cargo.toml"
python3 "$SANITIZE_PY" sanitize_alloy "$TMP_WORK_DIR/alloy/Cargo.toml" "$REPO_ROOT/Cargo.toml"

# ── 4. Verify compilation (before resolving workspace deps) ───────────────────
# Use a temp workspace that provides all workspace deps via the real root,
# plus local path overrides for the three internal crates.
log "Verifying compilation …"

cat > "$TMP_WORK_DIR/Cargo.toml" <<EOF
[workspace]
members = ["contracts", "primitives", "alloy"]
resolver = "3"
EOF

# Generate workspace deps, dynamically filtering out reth-* and all internal
# path-only crates, then overriding the 3 publish targets with local paths.
python3 "$SANITIZE_PY" gen_workspace "$REPO_ROOT/Cargo.toml" "$TMP_WORK_DIR/Cargo.toml" \
    "tempo-contracts,tempo-primitives,tempo-alloy"

log "Running cargo check …"
if ! cargo check --manifest-path "$TMP_WORK_DIR/Cargo.toml" 2>&1; then
    err "Stripped crates failed to compile!"
fi

log "Running cargo check --all-features …"
if ! cargo check --manifest-path "$TMP_WORK_DIR/Cargo.toml" --all-features 2>&1; then
    err "Stripped crates failed to compile with --all-features!"
fi

log "Compilation verified ✓"

# ── 5. Pre-resolve validation ─────────────────────────────────────────────────
# Validate BEFORE resolve_deps so that internal deps (which still have
# workspace/path markers) can be detected. After resolve_deps, a leaked
# internal dep like `tempo-foo.workspace = true` becomes
# `tempo-foo = { version = "1.x.0" }` and is much harder to catch.
log "Pre-resolve validation …"

# Dynamically discover all internal path-only deps from the workspace root
# and ban any that aren't one of the three publish targets.
SANITIZE_DIR=$(dirname "$SANITIZE_PY")
INTERNAL_PATH_DEPS=$(python3 -c "
import sys; sys.path.insert(0, '$SANITIZE_DIR')
from sanitize_toml import parse_workspace_deps
_, _, ws_path_deps, _, _ = parse_workspace_deps('$REPO_ROOT/Cargo.toml')
keep = {'tempo-contracts', 'tempo-primitives', 'tempo-alloy'}
for d in sorted(ws_path_deps - keep):
    print(d)
")

for crate_toml in "$TMP_WORK_DIR/primitives/Cargo.toml" "$TMP_WORK_DIR/alloy/Cargo.toml" "$TMP_WORK_DIR/contracts/Cargo.toml"; do
    crate_name=$(basename "$(dirname "$crate_toml")")

    # No reth-* deps should remain
    grep -qE '^\s*reth-' "$crate_toml" && \
        err "reth dependency still in $crate_name/Cargo.toml"

    # No internal path-only workspace crates should remain
    for dep in $INTERNAL_PATH_DEPS; do
        grep -qE "^\s*${dep}[\s.=]" "$crate_toml" && \
            err "Internal dep '$dep' still in $crate_name/Cargo.toml"
    done
done

# Primitives: no forbidden features
for feat in reth reth-codec serde-bincode-compat rpc; do
    grep -qE "^\s*${feat}\s*=" "$TMP_WORK_DIR/primitives/Cargo.toml" && \
        err "Feature '$feat' still defined in tempo-primitives Cargo.toml"
done

# Alloy: no reth feature
grep -qE "^\s*reth\s*=" "$TMP_WORK_DIR/alloy/Cargo.toml" && \
    err "Feature 'reth' still defined in tempo-alloy Cargo.toml"

# Source: no forbidden references
(
    grep -rq 'feature = "reth"' "$TMP_WORK_DIR/primitives/src/" || \
    grep -rq 'feature = "reth-codec"' "$TMP_WORK_DIR/primitives/src/" || \
    grep -rq 'reth_codecs' "$TMP_WORK_DIR/primitives/src/" || \
    grep -rq 'feature = "rpc"' "$TMP_WORK_DIR/primitives/src/"
) && err "reth-gated code still in tempo-primitives source"

grep -rq 'feature = "reth"' "$TMP_WORK_DIR/alloy/src/" && \
    err "reth-gated code still in tempo-alloy source"

log "Pre-resolve validation passed ✓"

# ── 6. Resolve workspace deps to concrete versions for publishing ─────────────
log "Resolving workspace dependencies …"

for crate_toml in "$TMP_WORK_DIR/primitives/Cargo.toml" "$TMP_WORK_DIR/alloy/Cargo.toml" "$TMP_WORK_DIR/contracts/Cargo.toml"; do
    python3 "$SANITIZE_PY" resolve_deps "$crate_toml" "$REPO_ROOT/Cargo.toml"
done

# ── 7. Post-resolve validation ────────────────────────────────────────────────
log "Post-resolve validation …"

for crate_toml in "$TMP_WORK_DIR/primitives/Cargo.toml" "$TMP_WORK_DIR/alloy/Cargo.toml" "$TMP_WORK_DIR/contracts/Cargo.toml"; do
    crate_name=$(basename "$(dirname "$crate_toml")")
    grep -q 'workspace = true' "$crate_toml" && \
        err "Unresolved 'workspace = true' in $crate_name/Cargo.toml"
    grep -q 'path = ' "$crate_toml" && \
        err "Unresolved 'path = ' dep in $crate_name/Cargo.toml"
    grep -q 'git = ' "$crate_toml" && \
        err "Unresolved 'git = ' dep in $crate_name/Cargo.toml"
done

log "Post-resolve validation passed ✓"

# ── 8. Final build check on resolved manifests ───────────────────────────────
# resolve_deps can change semantics (features, default-features, optional),
# so verify the resolved manifests still compile.
log "Final build check on resolved manifests …"

cat > "$TMP_WORK_DIR/Cargo.toml" <<EOF
[workspace]
members = ["contracts", "primitives", "alloy"]
resolver = "3"

[patch.crates-io]
tempo-contracts = { path = "contracts" }
tempo-primitives = { path = "primitives" }
tempo-alloy = { path = "alloy" }
EOF

log "Running final cargo check …"
if ! cargo check --manifest-path "$TMP_WORK_DIR/Cargo.toml" 2>&1; then
    err "Resolved crates failed to compile!"
fi

log "Running final cargo check --all-features …"
if ! cargo check --manifest-path "$TMP_WORK_DIR/Cargo.toml" --all-features 2>&1; then
    err "Resolved crates failed to compile with --all-features!"
fi

log "Final build check passed ✓"

# ── 9. Semver check (optional) ────────────────────────────────────────────────
# Runs cargo-semver-checks against the last published version on crates.io.
# Uses the sanitized + resolved workspace so the API surface matches what's
# actually published.
if $SEMVER_CHECK; then
    log "Running cargo-semver-checks …"
    SEMVER_FAILED=false
    SEMVER_SKIPPED_ALL=true
    for crate_dir in "$TMP_WORK_DIR/contracts" "$TMP_WORK_DIR/primitives" "$TMP_WORK_DIR/alloy"; do
        crate_name=$(grep -m1 'name = ' "$crate_dir/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
        crate_ver=$(grep -m1 'version = ' "$crate_dir/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
        log "Checking $crate_name@$crate_ver …"

        # Query crates.io for the latest published version.
        # Using the API directly instead of `cargo info` which resolves
        # the local workspace version when run inside a workspace.
        published_ver=$(curl -sL "https://crates.io/api/v1/crates/$crate_name" \
            -H "User-Agent: tempo-publish-script" | \
            python3 -c "import sys,json; d=json.load(sys.stdin); print(d['crate']['max_stable_version'] or d['crate']['max_version'])" 2>/dev/null)
        if [ -z "$published_ver" ] || [ "$published_ver" = "null" ]; then
            log "$crate_name not yet published, skipping"
            continue
        fi

        # Skip if version was already bumped — cargo-semver-checks can't resolve
        # inter-crate deps that reference the unpublished version.
        if [ "$crate_ver" != "$published_ver" ]; then
            log "$crate_name version bumped ($published_ver → $crate_ver), skipping"
            continue
        fi

        SEMVER_SKIPPED_ALL=false
        if ! cargo semver-checks \
            --manifest-path "$TMP_WORK_DIR/Cargo.toml" \
            --package "$crate_name" \
            --default-features 2>&1; then
            SEMVER_FAILED=true
        fi
    done

    if $SEMVER_SKIPPED_ALL; then
        log "All crates have bumped versions, nothing to semver-check"
    elif $SEMVER_FAILED; then
        printf '\n  \033[1;33m⚠\033[0m Semver-incompatible changes detected.\n'
        printf '    If intentional, add a changelog entry with the appropriate bump level.\n\n'
        exit 1
    else
        log "Semver checks passed ✓"
    fi
fi

# ── 10. Publish ────────────────────────────────────────────────────────────────
retry_publish() {
    local crate_dir="$1"
    local name
    name=$(grep -m1 'name = ' "$crate_dir/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
    local max_attempts=10
    local delay=15

    for ((i = 1; i <= max_attempts; i++)); do
        log "Publishing $name (attempt $i/$max_attempts) …"
        local output
        if output=$(cargo publish --manifest-path "$crate_dir/Cargo.toml" --allow-dirty 2>&1); then
            log "$name published ✓"
            return 0
        fi
        echo "$output"
        # Already published — treat as success
        if echo "$output" | grep -qE 'already uploaded|already exists'; then
            log "$name already published, skipping ✓"
            return 0
        fi
        if ((i < max_attempts)); then
            log "Publish failed, retrying in ${delay}s …"
            sleep "$delay"
        fi
    done
    err "Failed to publish $name after $max_attempts attempts"
}

# Publish order: contracts → primitives → alloy
CRATES=("$TMP_WORK_DIR/contracts" "$TMP_WORK_DIR/primitives" "$TMP_WORK_DIR/alloy")

if $DRY_RUN; then
    log "Dry-run complete. Use --publish to actually publish."
else
    # Publish in dependency order. Each crate is published and indexed before
    # the next one starts, so inter-crate deps resolve from crates.io.
    for crate_dir in "${CRATES[@]}"; do
        retry_publish "$crate_dir"
    done
    log "All crates published successfully! 🎉"
fi
