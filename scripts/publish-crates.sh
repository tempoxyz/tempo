#!/usr/bin/env bash
# Publish tempo-primitives, tempo-contracts, and tempo-alloy to crates.io
#
# Uses the "polkadot-sdk" technique: strip reth/node-only deps from Cargo.toml
# and source, publish the sanitized crates, then revert. The git state is
# restored automatically on exit (success or failure).
#
# Usage:
#   ./scripts/publish-crates.sh              # dry-run (default)
#   ./scripts/publish-crates.sh --execute    # actually publish
#
# Requirements:
#   - cargo login (already authenticated)
#   - Working directory is the repo root

set -euo pipefail

DRY_RUN=true
if [[ "${1:-}" == "--execute" ]]; then
  DRY_RUN=false
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Crates to publish, in dependency order
CRATES=(tempo-primitives tempo-contracts tempo-alloy)

# Map crate name -> directory
declare -A CRATE_DIR=(
  [tempo-primitives]=crates/primitives
  [tempo-contracts]=crates/contracts
  [tempo-alloy]=crates/alloy
)

# ---------------------------------------------------------------------------
# Restore on exit
# ---------------------------------------------------------------------------
cleanup() {
  echo "🔄 Restoring original files..."
  git checkout -- crates/ Cargo.toml Cargo.lock 2>/dev/null || true
  echo "✅ Restored."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Read the workspace version
# ---------------------------------------------------------------------------
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
echo "📦 Publishing version: $VERSION"

# ---------------------------------------------------------------------------
# Helper: resolve workspace deps to explicit versions in a Cargo.toml
# ---------------------------------------------------------------------------
resolve_workspace_deps() {
  local crate_toml="$1"
  python3 - "$crate_toml" "$REPO_ROOT/Cargo.toml" << 'PYEOF'
import sys, re, tomllib

crate_toml = sys.argv[1]
workspace_toml = sys.argv[2]

with open(workspace_toml, 'rb') as f:
    ws = tomllib.load(f)

ws_deps = ws.get('workspace', {}).get('dependencies', {})
ws_version = ws.get('workspace', {}).get('package', {}).get('version', '')
ws_edition = ws.get('workspace', {}).get('package', {}).get('edition', '2024')
ws_rust_version = ws.get('workspace', {}).get('package', {}).get('rust-version', '')
ws_license = ws.get('workspace', {}).get('package', {}).get('license', '')

# Use tomllib to properly parse and rewrite
with open(crate_toml, 'rb') as f:
    crate = tomllib.load(f)

def get_version(dep_name):
    if dep_name.startswith('tempo-'):
        return ws_version
    ws_dep = ws_deps.get(dep_name, {})
    if isinstance(ws_dep, str):
        return ws_dep
    elif isinstance(ws_dep, dict):
        return ws_dep.get('version', '')
    return ''

def resolve_dep(dep_name, dep_val):
    """Resolve a workspace dep to an explicit version string."""
    if isinstance(dep_val, dict) and dep_val.get('workspace'):
        version = get_version(dep_name)
        if not version:
            return dep_val  # can't resolve
        new = {'version': version}
        for k in ('features', 'default-features', 'optional'):
            if k in dep_val:
                new[k] = dep_val[k]
        return new
    return dep_val

# Now do text-based replacement using the parsed info
# This approach: parse with tomllib to understand structure,
# then do a simpler text rewrite that handles multi-line
with open(crate_toml) as f:
    content = f.read()

# Replace package-level workspace refs
content = re.sub(r'^version\.workspace\s*=\s*true', f'version = "{ws_version}"', content, flags=re.MULTILINE)
content = re.sub(r'^edition\.workspace\s*=\s*true', f'edition = "{ws_edition}"', content, flags=re.MULTILINE)
content = re.sub(r'^rust-version\.workspace\s*=\s*true', f'rust-version = "{ws_rust_version}"', content, flags=re.MULTILINE)
content = re.sub(r'^license\.workspace\s*=\s*true', f'license = "{ws_license}"', content, flags=re.MULTILINE)
content = re.sub(r'^publish\.workspace\s*=\s*true', 'publish = true', content, flags=re.MULTILINE)

# Handle simple: dep.workspace = true
def replace_simple_ws(m):
    dep_name = m.group(1)
    version = get_version(dep_name)
    if version:
        return f'{dep_name} = "{version}"'
    return m.group(0)

content = re.sub(r'^(\S+)\.workspace\s*=\s*true', replace_simple_ws, content, flags=re.MULTILINE)

# Handle inline: dep = { workspace = true, features = [...] }
def replace_inline_ws(m):
    dep_name = m.group(1)
    attrs = m.group(2)
    version = get_version(dep_name)
    if not version:
        return m.group(0)

    parts = [f'version = "{version}"']
    df = re.search(r'default-features\s*=\s*(true|false)', attrs)
    if df:
        parts.append(f'default-features = {df.group(1)}')
    feat = re.search(r'features\s*=\s*\[([^\]]*)\]', attrs)
    if feat:
        parts.append(f'features = [{feat.group(1)}]')
    opt = re.search(r'optional\s*=\s*(true|false)', attrs)
    if opt:
        parts.append(f'optional = {opt.group(1)}')
    return f'{dep_name} = {{ {", ".join(parts)} }}'

content = re.sub(
    r'^(\S+)\s*=\s*\{([^}]*workspace\s*=\s*true[^}]*)\}',
    replace_inline_ws, content, flags=re.MULTILINE
)

# Handle multi-line: dep = { workspace = true, features = [\n...\n] }
# These span multiple lines with the closing } on a later line
def replace_multiline_ws(m):
    dep_name = m.group(1)
    block = m.group(2)
    version = get_version(dep_name)
    if not version:
        return m.group(0)

    parts = [f'version = "{version}"']
    df = re.search(r'default-features\s*=\s*(true|false)', block)
    if df:
        parts.append(f'default-features = {df.group(1)}')
    # Extract features list (may span lines)
    feat = re.search(r'features\s*=\s*\[(.*?)\]', block, re.DOTALL)
    if feat:
        # Normalize the features list to single line
        items = [x.strip().strip('"').strip("'") for x in feat.group(1).split(',') if x.strip().strip('"').strip("'")]
        feat_str = ', '.join(f'"{x}"' for x in items)
        parts.append(f'features = [{feat_str}]')
    opt = re.search(r'optional\s*=\s*(true|false)', block)
    if opt:
        parts.append(f'optional = {opt.group(1)}')
    return f'{dep_name} = {{ {", ".join(parts)} }}'

content = re.sub(
    r'^(\S+)\s*=\s*\{((?:[^}]|\n)*?workspace\s*=\s*true(?:[^}]|\n)*?)\}',
    replace_multiline_ws, content, flags=re.MULTILINE
)

with open(crate_toml, 'w') as f:
    f.write(content)
PYEOF
}

# ---------------------------------------------------------------------------
# Helper: strip reth-gated code from .rs files
# ---------------------------------------------------------------------------
strip_reth_code() {
  local src_dir="$1"
  python3 - "$src_dir" << 'PYEOF'
import os, sys, re

src_dir = sys.argv[1]

# Features that have been removed and whose gated code should be stripped
REMOVED_FEATURES = {'reth', 'reth-codec', 'serde-bincode-compat', 'rpc'}

def should_strip_cfg(cfg_text):
    """Check if a #[cfg(...)] references any removed feature."""
    # Match feature = "xxx" patterns inside the cfg
    features = re.findall(r'feature\s*=\s*"([^"]+)"', cfg_text)
    return any(f in REMOVED_FEATURES for f in features)

def skip_next_item(lines, i):
    """Skip the next Rust item (could be single line or brace-delimited block).

    Handles items where { appears on a later line (e.g. multi-line fn signatures,
    impl blocks with trait bounds spanning lines).
    """
    if i >= len(lines):
        return i

    # Scan forward to find the opening brace
    brace_count = 0
    found_brace = False
    while i < len(lines):
        line = lines[i]
        for ch in line:
            if ch == '{':
                brace_count += 1
                found_brace = True
            elif ch == '}':
                brace_count -= 1
        i += 1
        if found_brace and brace_count == 0:
            break
        # If we hit a semicolon before any brace, it's a single-statement item
        if not found_brace and ';' in line:
            break
    return i

def strip_gated_code(filepath):
    with open(filepath) as f:
        lines = f.readlines()

    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # #[cfg(feature = "reth")] or #[cfg(all(feature = "x", feature = "y"))]
        cfg_match = re.match(r'^\s*#\[cfg\((.*)\)\]\s*$', stripped)
        if cfg_match and should_strip_cfg(cfg_match.group(1)):
            i += 1
            i = skip_next_item(lines, i)
            continue

        # #[cfg_attr(feature = "reth-codec", derive(...))]
        cfg_attr_match = re.match(r'^\s*#\[cfg_attr\((.*)\)\]\s*$', stripped)
        if cfg_attr_match and should_strip_cfg(cfg_attr_match.group(1)):
            i += 1
            continue

        # Multi-line #[cfg_attr(\n  ...\n)]
        ml_cfg_attr = re.match(r'^\s*#\[cfg_attr\($', stripped)
        if ml_cfg_attr:
            # Peek ahead to see if it references removed features
            block = stripped
            j = i + 1
            while j < len(lines) and ')]' not in block:
                block += lines[j]
                j += 1
            if should_strip_cfg(block):
                i = j
                continue

        # #[cfg_attr(test, reth_codecs::...)]
        if re.match(r'^\s*#\[cfg_attr\(test,\s*reth_codecs::', stripped):
            i += 1
            continue

        # use reth_*
        if re.match(r'^\s*use\s+reth_', stripped):
            i += 1
            continue

        result.append(line)
        i += 1

    with open(filepath, 'w') as f:
        f.writelines(result)

for root, dirs, files in os.walk(src_dir):
    for fname in files:
        if fname.endswith('.rs'):
            strip_gated_code(os.path.join(root, fname))
PYEOF
}

# ---------------------------------------------------------------------------
# Helper: strip features from a Cargo.toml
# ---------------------------------------------------------------------------
strip_features() {
  local toml="$1"
  shift
  local features_to_remove=("$@")

  python3 - "$toml" "${features_to_remove[@]}" << 'PYEOF'
import sys, re

toml_path = sys.argv[1]
remove_features = set(sys.argv[2:])

with open(toml_path) as f:
    content = f.read()

lines = content.split('\n')
result = []
in_features = False
skip_feature = False

for line in lines:
    if line.strip() == '[features]':
        in_features = True
        result.append(line)
        continue

    if in_features and re.match(r'^\[', line.strip()) and line.strip() != '[features]':
        in_features = False
        skip_feature = False
        result.append(line)
        continue

    if in_features:
        feat_match = re.match(r'^(\w[\w-]*)\s*=', line)
        if feat_match:
            feat_name = feat_match.group(1)
            if feat_name in remove_features:
                skip_feature = True
                continue
            elif feat_name == 'default':
                # Rewrite default to exclude removed features
                val_match = re.match(r'^default\s*=\s*\[(.*)\]', line)
                if val_match:
                    items = [
                        item.strip().strip('"').strip("'")
                        for item in val_match.group(1).split(',')
                        if item.strip().strip('"').strip("'")
                    ]
                    kept = [f'"{x}"' for x in items if x not in remove_features]
                    result.append(f'default = [{", ".join(kept)}]')
                else:
                    result.append(line)
                skip_feature = False
                continue
            else:
                skip_feature = False
                # Filter out reth refs from this feature's values
                result.append(line)
                continue
        elif skip_feature:
            continue
        else:
            # Inside a kept feature, filter out reth-related entries
            stripped = line.strip().rstrip(',').strip('"').strip("'")
            if any(x in stripped for x in [
                'reth-', 'reth_', 'dep:reth', 'reth-codecs',
                'reth-db', 'reth-ethereum', 'reth-primitives',
                'dep:modular-bitfield',
            ]):
                continue
            result.append(line)
            continue

    result.append(line)

with open(toml_path, 'w') as f:
    f.write('\n'.join(result))
PYEOF
}

# ---------------------------------------------------------------------------
# Step 1: Prepare tempo-primitives
# ---------------------------------------------------------------------------
echo ""
echo "━━━ Preparing tempo-primitives ━━━"

PRIM_TOML="${CRATE_DIR[tempo-primitives]}/Cargo.toml"
PRIM_SRC="${CRATE_DIR[tempo-primitives]}/src"

# Remove reth dep lines
sed -i '/^# Reth$/d' "$PRIM_TOML"
sed -i '/^reth-db-api\b/d' "$PRIM_TOML"
sed -i '/^reth-ethereum-primitives\b/d' "$PRIM_TOML"
sed -i '/^reth-primitives-traits\b/d' "$PRIM_TOML"
sed -i '/^reth-codecs\b/d' "$PRIM_TOML"
sed -i '/^reth-rpc-convert\b/d' "$PRIM_TOML"

# Remove reth-codecs from dev-deps
python3 -c "
import re
with open('$PRIM_TOML') as f: c = f.read()
c = re.sub(r'^reth-codecs\.workspace = true\n', '', c, flags=re.MULTILINE)
with open('$PRIM_TOML','w') as f: f.write(c)
"

# Strip features
strip_features "$PRIM_TOML" reth reth-codec serde-bincode-compat rpc

# Resolve workspace deps
resolve_workspace_deps "$PRIM_TOML"

# Remove [lints] workspace = true
sed -i '/^\[lints\]/,/^workspace = true/d' "$PRIM_TOML"

# Strip reth-gated code
strip_reth_code "$PRIM_SRC"


# Add back TempoReceipt as a type alias using pure alloy types
# (the original uses reth_ethereum_primitives which is not publishable)
echo "" >> "$PRIM_SRC/lib.rs"
echo "/// Tempo receipt." >> "$PRIM_SRC/lib.rs"
echo "pub type TempoReceipt<L = alloy_primitives::Log> = alloy_consensus::Receipt<L>;" >> "$PRIM_SRC/lib.rs"


echo "  ✅ tempo-primitives prepared"

# ---------------------------------------------------------------------------
# Step 2: Prepare tempo-contracts
# ---------------------------------------------------------------------------
echo ""
echo "━━━ Preparing tempo-contracts ━━━"

CONTRACTS_TOML="${CRATE_DIR[tempo-contracts]}/Cargo.toml"

resolve_workspace_deps "$CONTRACTS_TOML"
sed -i '/^\[lints\]/,/^workspace = true/d' "$CONTRACTS_TOML"

echo "  ✅ tempo-contracts prepared"

# ---------------------------------------------------------------------------
# Step 3: Prepare tempo-alloy
# ---------------------------------------------------------------------------
echo ""
echo "━━━ Preparing tempo-alloy ━━━"

ALLOY_TOML="${CRATE_DIR[tempo-alloy]}/Cargo.toml"
ALLOY_SRC="${CRATE_DIR[tempo-alloy]}/src"

# Remove reth and node-only deps
sed -i '/^reth-/d' "$ALLOY_TOML"
sed -i '/^tempo-evm\b/d' "$ALLOY_TOML"
sed -i '/^tempo-revm\b/d' "$ALLOY_TOML"

# Strip features
strip_features "$ALLOY_TOML" tempo-compat

# Resolve workspace deps
resolve_workspace_deps "$ALLOY_TOML"
sed -i '/^\[lints\]/,/^workspace = true/d' "$ALLOY_TOML"

# Strip tempo-compat gated code
python3 - "$ALLOY_SRC" << 'PYEOF'
import os, sys, re

src_dir = sys.argv[1]

def strip_compat(filepath):
    with open(filepath) as f:
        lines = f.readlines()

    result = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()

        if re.match(r'^\s*#\[cfg\(feature\s*=\s*"tempo-compat"\)\]', stripped):
            i += 1
            if i < len(lines):
                if '{' in lines[i]:
                    bc = lines[i].count('{') - lines[i].count('}')
                    i += 1
                    while i < len(lines) and bc > 0:
                        bc += lines[i].count('{') - lines[i].count('}')
                        i += 1
                else:
                    i += 1
            continue

        result.append(lines[i])
        i += 1

    with open(filepath, 'w') as f:
        f.writelines(result)

for root, dirs, files in os.walk(src_dir):
    for f in files:
        if f.endswith('.rs'):
            strip_compat(os.path.join(root, f))
PYEOF

rm -f "${ALLOY_SRC}/rpc/compat.rs"

# Fix receipt types: TempoReceipt (now alloy Receipt) doesn't implement
# Eip2718 traits needed for Network::ReceiptEnvelope. Use ReceiptEnvelope
# (same as Ethereum's Network impl) which does.
# network.rs: ReceiptWithBloom<TempoReceipt> -> ReceiptEnvelope
sed -i 's/ReceiptWithBloom<TempoReceipt>/alloy_consensus::ReceiptEnvelope/' "${ALLOY_SRC}/network.rs"
sed -i 's/, TempoReceipt,/,/' "${ALLOY_SRC}/network.rs"
# Remove unused ReceiptWithBloom import
sed -i 's/use alloy_consensus::{ReceiptWithBloom, TxType/use alloy_consensus::{TxType/' "${ALLOY_SRC}/network.rs"
# receipt.rs: use the default TransactionReceipt (which uses ReceiptEnvelope)
sed -i 's/use tempo_primitives::TempoReceipt;//' "${ALLOY_SRC}/rpc/receipt.rs"
sed -i '/use alloy_consensus::ReceiptWithBloom;/d' "${ALLOY_SRC}/rpc/receipt.rs"
sed -i 's/TransactionReceipt<ReceiptWithBloom<TempoReceipt<Log>>>/TransactionReceipt/' "${ALLOY_SRC}/rpc/receipt.rs"
sed -i '/use alloy_rpc_types_eth::{Log, TransactionReceipt};/s/, Log//' "${ALLOY_SRC}/rpc/receipt.rs"



echo "  ✅ tempo-alloy prepared"

# ---------------------------------------------------------------------------
# Step 4: Verify each crate can be packaged
#
# We package each crate independently by temporarily creating a standalone
# workspace (since the main workspace still references reth features).
#
# For crates that depend on other co-published crates (e.g. tempo-alloy
# depends on tempo-primitives + tempo-contracts), we use `cargo check`
# since `cargo publish --dry-run` would fail trying to resolve them from
# crates.io where they don't exist yet.
# ---------------------------------------------------------------------------
echo ""
echo "━━━ Verifying packages ━━━"

for crate in "${CRATES[@]}"; do
  dir="${CRATE_DIR[$crate]}"
  echo "  📦 Checking $crate..."

  # Create a temporary standalone workspace with all publishable crates
  tmpdir=$(mktemp -d)

  for c in "${CRATES[@]}"; do
    cp -r "${CRATE_DIR[$c]}" "$tmpdir/$(basename "${CRATE_DIR[$c]}")"
  done

  cat > "$tmpdir/Cargo.toml" << WSEOF
[workspace]
members = ["primitives", "contracts", "alloy"]
resolver = "3"
WSEOF

  # For alloy: rewrite version-only deps to path deps so cargo can resolve them
  alloy_toml="$tmpdir/alloy/Cargo.toml"
  if [[ -f "$alloy_toml" ]]; then
    sed -i "s|tempo-contracts = { version = \"$VERSION\"|tempo-contracts = { path = \"../contracts\"|" "$alloy_toml"
    sed -i "s|tempo-primitives = { version = \"$VERSION\"|tempo-primitives = { path = \"../primitives\"|" "$alloy_toml"
  fi

  cd "$tmpdir"

  # For leaf crates (no co-published deps): full publish --dry-run
  # For tempo-alloy: cargo check (deps not on crates.io yet)
  if [[ "$crate" == "tempo-alloy" ]]; then
    if ! cargo check -p "$crate" 2>&1; then
      echo "  ❌ $crate failed to compile"
      cd "$REPO_ROOT"
      rm -rf "$tmpdir"
      exit 1
    fi
  else
    if ! cargo publish -p "$crate" --dry-run --allow-dirty 2>&1; then
      echo "  ❌ $crate failed to package"
      cd "$REPO_ROOT"
      rm -rf "$tmpdir"
      exit 1
    fi
  fi

  echo "  ✅ $crate verified successfully"
  cd "$REPO_ROOT"
  rm -rf "$tmpdir"
done

# ---------------------------------------------------------------------------
# Step 5: Publish (or dry-run)
# ---------------------------------------------------------------------------
echo ""
if $DRY_RUN; then
  echo "━━━ DRY RUN ━━━"
  echo ""
  echo "Prepared Cargo.toml files:"
  echo ""
  for crate in "${CRATES[@]}"; do
    echo "--- ${CRATE_DIR[$crate]}/Cargo.toml ---"
    cat "${CRATE_DIR[$crate]}/Cargo.toml"
    echo ""
  done
  echo ""
  for crate in "${CRATES[@]}"; do
    echo "  Would publish: $crate v$VERSION"
  done
  echo ""
  echo "Run with --execute to actually publish."
else
  echo "━━━ Publishing to crates.io ━━━"
  for crate in "${CRATES[@]}"; do
    echo "  🚀 Publishing $crate..."
    cd "${CRATE_DIR[$crate]}"
    cargo publish --allow-dirty
    cd "$REPO_ROOT"
    echo "  ✅ Published $crate"
    if [[ "$crate" != "${CRATES[-1]}" ]]; then
      echo "  ⏳ Waiting 30s for crates.io index update..."
      sleep 30
    fi
  done
  echo ""
  echo "✅ All crates published!"
fi
