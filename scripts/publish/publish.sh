#!/usr/bin/env bash
#
# Unified publish driver for tempo crate groups.
#
# Usage:
#   ./scripts/publish/publish.sh alloy [--publish|--semver-check]
#   ./scripts/publish/publish.sh revm  [--publish|--semver-check]
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$REPO_ROOT/scripts/publish/common.sh"

GROUP="${1:-}"
shift || true
parse_publish_mode "${1:-}"

SANITIZE_PY="$REPO_ROOT/scripts/sanitize_toml.py"
SANITIZE_RS="$REPO_ROOT/scripts/sanitize_source.py"
ALL_PUBLISHED="tempo-contracts,tempo-primitives,tempo-alloy,tempo-chainspec,tempo-precompiles-macros,tempo-precompiles,tempo-revm"

# ── Group configuration ────────────────────────────────────────────────────────
case "$GROUP" in
    alloy)
        CRATE_DIRS=(contracts primitives alloy)
        PUBLISH_CRATE_NAMES_CSV="tempo-contracts,tempo-primitives,tempo-alloy"
        EXTRA_WORKSPACE_DEPS=()
        ;;
    revm)
        CRATE_DIRS=(chainspec precompiles-macros precompiles revm)
        PUBLISH_CRATE_NAMES_CSV="tempo-chainspec,tempo-precompiles-macros,tempo-precompiles,tempo-revm"
        # revm crates depend on alloy crates at compile time
        EXTRA_WORKSPACE_DEPS=(contracts primitives)
        ;;
    *)
        echo "Usage: $0 <alloy|revm> [--publish|--semver-check]" >&2
        exit 1
        ;;
esac

# ── Create temp workspace ──────────────────────────────────────────────────────
setup_tmp_workspace "${CRATE_DIRS[@]}"

# ── 1. Source & manifest sanitization ──────────────────────────────────────────
case "$GROUP" in
    alloy)
        log "Deleting reth_compat modules …"
        rm -rf "$TMP_WORK_DIR/primitives/src/reth_compat"
        rm -f  "$TMP_WORK_DIR/alloy/src/rpc/reth_compat.rs"

        log "Stripping reth references from source …"
        python3 "$SANITIZE_RS" "$TMP_WORK_DIR/primitives" "$TMP_WORK_DIR/alloy"
        ;;
esac

log "Sanitizing Cargo.toml files …"

WS_VERSION=$(workspace_version "$SANITIZE_PY" "$REPO_ROOT/Cargo.toml")
log "Workspace version: $WS_VERSION"

sanitize_base_manifests "$SANITIZE_PY" "$WS_VERSION" "$REPO_ROOT/Cargo.toml" "${CRATE_MANIFESTS[@]}"

# Copy extra workspace deps needed at compile time (e.g. alloy crates for revm).
# These get the same sanitization as if they were being published themselves,
# so their reth-gated deps/features don't leak into the workspace.
if [ "${#EXTRA_WORKSPACE_DEPS[@]}" -gt 0 ]; then
    copy_crates_to_tmp "$TMP_WORK_DIR" "${EXTRA_WORKSPACE_DEPS[@]}"
    extra_manifests=()
    for d in "${EXTRA_WORKSPACE_DEPS[@]}"; do
        extra_manifests+=("$TMP_WORK_DIR/$d/Cargo.toml")
    done
    sanitize_base_manifests "$SANITIZE_PY" "$WS_VERSION" "$REPO_ROOT/Cargo.toml" "${extra_manifests[@]}"
    # Primitives needs its own reth-stripping pass
    [ -d "$TMP_WORK_DIR/primitives" ] && \
        python3 "$SANITIZE_PY" sanitize_primitives "$TMP_WORK_DIR/primitives/Cargo.toml"
fi

case "$GROUP" in
    alloy)
        python3 "$SANITIZE_PY" sanitize_primitives "$TMP_WORK_DIR/primitives/Cargo.toml"
        python3 "$SANITIZE_PY" sanitize_alloy "$TMP_WORK_DIR/alloy/Cargo.toml" "$REPO_ROOT/Cargo.toml"
        ;;
    revm)
        python3 "$SANITIZE_PY" sanitize_chainspec "$TMP_WORK_DIR/chainspec/Cargo.toml"
        python3 "$SANITIZE_PY" sanitize_precompiles "$TMP_WORK_DIR/precompiles/Cargo.toml"
        python3 "$SANITIZE_PY" sanitize_revm "$TMP_WORK_DIR/revm/Cargo.toml"
        ;;
esac

# ── 2. Initial compilation check ──────────────────────────────────────────────
log "Verifying compilation …"

write_workspace_manifest "$TMP_WORK_DIR/Cargo.toml" "$MEMBERS_CSV"

GEN_WS_CRATES="$PUBLISH_CRATE_NAMES_CSV"
for d in "${EXTRA_WORKSPACE_DEPS[@]+"${EXTRA_WORKSPACE_DEPS[@]}"}"; do
    GEN_WS_CRATES="$GEN_WS_CRATES,tempo-$d"
done
python3 "$SANITIZE_PY" gen_workspace "$REPO_ROOT/Cargo.toml" "$TMP_WORK_DIR/Cargo.toml" \
    "$GEN_WS_CRATES"

run_workspace_checks \
    "$TMP_WORK_DIR/Cargo.toml" \
    "Stripped crates failed to compile!" \
    "Stripped crates failed to compile with --all-features!" \
    "Compilation verified ✓"

# ── 3. Pre-resolve validation ─────────────────────────────────────────────────
log "Pre-resolve validation …"

INTERNAL_PATH_DEPS=$(get_internal_path_deps "$SANITIZE_PY" "$REPO_ROOT/Cargo.toml" "$ALL_PUBLISHED")
validate_no_reth_or_internal_deps "$INTERNAL_PATH_DEPS" "${CRATE_MANIFESTS[@]}"

case "$GROUP" in
    alloy)
        assert_no_features "$TMP_WORK_DIR/primitives/Cargo.toml" reth reth-codec serde-bincode-compat rpc
        assert_no_features "$TMP_WORK_DIR/alloy/Cargo.toml" reth
        assert_no_source_refs "$TMP_WORK_DIR/primitives" 'feature = "reth"' 'feature = "reth-codec"' 'reth_codecs' 'feature = "rpc"'
        assert_no_source_refs "$TMP_WORK_DIR/alloy" 'feature = "reth"'
        ;;
    revm)
        assert_no_features "$TMP_WORK_DIR/chainspec/Cargo.toml" reth cli
        assert_no_features "$TMP_WORK_DIR/revm/Cargo.toml" reth rpc
        assert_no_dep "$TMP_WORK_DIR/precompiles/Cargo.toml" tempo-evm
        assert_no_dep "$TMP_WORK_DIR/revm/Cargo.toml" tempo-evm
        ;;
esac

log "Pre-resolve validation passed ✓"

# ── 4. Resolve workspace deps ─────────────────────────────────────────────────
log "Resolving workspace dependencies …"

resolve_workspace_dependencies "$SANITIZE_PY" "$REPO_ROOT/Cargo.toml" "${CRATE_MANIFESTS[@]}"

if [ "${#EXTRA_WORKSPACE_DEPS[@]}" -gt 0 ]; then
    resolve_workspace_dependencies "$SANITIZE_PY" "$REPO_ROOT/Cargo.toml" "${extra_manifests[@]}"
fi

# ── 5. Post-resolve validation ────────────────────────────────────────────────
log "Post-resolve validation …"

validate_resolved_manifests "${CRATE_MANIFESTS[@]}"

log "Post-resolve validation passed ✓"

# ── 6. Final build check on resolved manifests ───────────────────────────────
log "Final build check on resolved manifests …"

FINAL_PATCHES="$PATCHES_CSV"
for d in "${EXTRA_WORKSPACE_DEPS[@]+"${EXTRA_WORKSPACE_DEPS[@]}"}"; do
    FINAL_PATCHES="$FINAL_PATCHES,tempo-$d=$d"
done
write_workspace_manifest "$TMP_WORK_DIR/Cargo.toml" "$MEMBERS_CSV" "$FINAL_PATCHES"

run_workspace_checks \
    "$TMP_WORK_DIR/Cargo.toml" \
    "Resolved crates failed to compile!" \
    "Resolved crates failed to compile with --all-features!" \
    "Final build check passed ✓"

# ── 7. Semver check (optional) ────────────────────────────────────────────────
if $SEMVER_CHECK; then
    SEMVER_PREP=noop_semver_prep
    if [ "$GROUP" = "alloy" ]; then
        prepare_alloy_semver() {
            local crate_dir="$1"
            if [ "$(basename "$crate_dir")" = "contracts" ]; then
                cat >> "$crate_dir/Cargo.toml" <<'EOF'

[package.metadata.cargo-semver-checks.lints]
constructible_struct_adds_field = "warn"
enum_variant_added = "warn"
enum_variant_missing = "warn"
inherent_method_missing = "warn"
struct_missing = "warn"
struct_pub_field_missing = "warn"
EOF
            fi
        }
        SEMVER_PREP=prepare_alloy_semver
    fi

    run_semver_checks \
        "$TMP_WORK_DIR/Cargo.toml" \
        "$SEMVER_PREP" \
        "$PUBLISH_CRATE_NAMES_CSV" \
        "${CRATE_PATHS[@]}"
fi

# ── 8. Publish ─────────────────────────────────────────────────────────────────
publish_crates "All $GROUP crates published successfully! 🎉" "${CRATE_PATHS[@]}"
