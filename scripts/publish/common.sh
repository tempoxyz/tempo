#!/usr/bin/env bash

log() { printf '  \033[1;34m→\033[0m %s\n' "$*"; }
err() { printf '  \033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

parse_publish_mode() {
    DRY_RUN=true
    SEMVER_CHECK=false

    case "${1:-}" in
        "")             ;;
        --publish)      DRY_RUN=false ;;
        --semver-check) SEMVER_CHECK=true ;;
        *)              echo "Usage: $0 [--publish|--semver-check]" >&2; exit 1 ;;
    esac
}

copy_crates_to_tmp() {
    local tmp_work_dir="$1"
    shift

    log "Copying crates to temporary directory …"
    local crate
    for crate in "$@"; do
        cp -R "$REPO_ROOT/crates/$crate" "$tmp_work_dir/$crate"
    done
}

workspace_version() {
    local sanitize_py="$1"
    local workspace_toml="$2"
    python3 "$sanitize_py" get_version "$workspace_toml"
}

sanitize_base_manifests() {
    local sanitize_py="$1"
    local ws_version="$2"
    local workspace_toml="$3"
    shift 3

    local crate_toml
    for crate_toml in "$@"; do
        python3 "$sanitize_py" sanitize_base "$crate_toml" "$ws_version" "$workspace_toml"
    done
}

write_workspace_manifest() {
    local out_path="$1"
    local members_csv="$2"
    local patches_csv="${3:-}"
    local members=()
    local patches=()
    local first=true
    local member
    local patch

    IFS=, read -r -a members <<< "$members_csv"
    if [ -n "$patches_csv" ]; then
        IFS=, read -r -a patches <<< "$patches_csv"
    fi

    {
        printf '[workspace]\n'
        printf 'members = ['
        for member in "${members[@]}"; do
            [ -z "$member" ] && continue
            if $first; then
                first=false
            else
                printf ', '
            fi
            printf '"%s"' "$member"
        done
        printf ']\n'
        printf 'resolver = "3"\n'

        if [ "${#patches[@]}" -gt 0 ]; then
            printf '\n[patch.crates-io]\n'
            for patch in "${patches[@]}"; do
                printf '%s = { path = "%s" }\n' "${patch%%=*}" "${patch#*=}"
            done
        fi
    } > "$out_path"
}

run_workspace_checks() {
    local manifest_path="$1"
    local check_err="$2"
    local all_features_err="$3"
    local success_message="$4"

    log "Running cargo check …"
    if ! cargo check --manifest-path "$manifest_path" 2>&1; then
        err "$check_err"
    fi

    log "Running cargo check --all-features …"
    if ! cargo check --manifest-path "$manifest_path" --all-features 2>&1; then
        err "$all_features_err"
    fi

    log "$success_message"
}

get_internal_path_deps() {
    local sanitize_py="$1"
    local workspace_toml="$2"
    local keep_csv="$3"

    python3 -c '
import sys
sys.path.insert(0, sys.argv[1])
from sanitize_toml import parse_workspace_deps
_, _, ws_path_deps, _, _, _ = parse_workspace_deps(sys.argv[2])
keep = {entry for entry in sys.argv[3].split(",") if entry}
for dep in sorted(ws_path_deps - keep):
    print(dep)
' "$(dirname "$sanitize_py")" "$workspace_toml" "$keep_csv"
}

validate_no_reth_or_internal_deps() {
    local internal_path_deps="$1"
    shift

    local crate_toml
    local crate_name
    local dep
    for crate_toml in "$@"; do
        crate_name=$(basename "$(dirname "$crate_toml")")
        grep -qE '^\s*reth-' "$crate_toml" && \
            err "reth dependency still in $crate_name/Cargo.toml"
        for dep in $internal_path_deps; do
            grep -qE "^\s*${dep}[\s.=]" "$crate_toml" && \
                err "Internal dep '$dep' still in $crate_name/Cargo.toml"
        done
    done

    return 0
}

# assert_no_features <toml> <feat...>
#   Fails if any listed feature is still defined in the manifest.
assert_no_features() {
    local toml="$1"; shift
    local crate_name
    crate_name=$(basename "$(dirname "$toml")")
    local feat
    for feat in "$@"; do
        grep -qE "^\s*${feat}\s*=" "$toml" && \
            err "Feature '$feat' still defined in $crate_name/Cargo.toml"
    done
    return 0
}

# assert_no_dep <toml> <dep>
#   Fails if the dependency is still present in the manifest.
assert_no_dep() {
    local toml="$1" dep="$2"
    local crate_name
    crate_name=$(basename "$(dirname "$toml")")
    grep -qE "^\s*${dep}[\s.=]" "$toml" && \
        err "Dependency '$dep' still in $crate_name/Cargo.toml"
    return 0
}

# assert_no_source_refs <dir> <pattern...>
#   Fails if any pattern is found in .rs files under dir.
assert_no_source_refs() {
    local dir="$1"; shift
    local crate_name
    crate_name=$(basename "$dir")
    local pat
    for pat in "$@"; do
        grep -rq "$pat" "$dir/src/" && \
            err "Forbidden pattern '$pat' still in $crate_name source"
    done
    return 0
}

# setup_tmp_workspace <crate_dir...>
#   Creates a temp directory, copies crates, and sets:
#   TMP_WORK_DIR, CRATE_MANIFESTS, CRATE_PATHS, MEMBERS_CSV, PATCHES_CSV
setup_tmp_workspace() {
    TMP_WORK_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_WORK_DIR"' EXIT

    copy_crates_to_tmp "$TMP_WORK_DIR" "$@"

    CRATE_MANIFESTS=()
    CRATE_PATHS=()
    MEMBERS_CSV=""
    PATCHES_CSV=""
    local d crate_name
    for d in "$@"; do
        CRATE_MANIFESTS+=("$TMP_WORK_DIR/$d/Cargo.toml")
        CRATE_PATHS+=("$TMP_WORK_DIR/$d")
        crate_name=$(crate_name_from_dir "$TMP_WORK_DIR/$d")
        MEMBERS_CSV="${MEMBERS_CSV:+$MEMBERS_CSV,}$d"
        PATCHES_CSV="${PATCHES_CSV:+$PATCHES_CSV,}$crate_name=$d"
    done
}

resolve_workspace_dependencies() {
    local sanitize_py="$1"
    local workspace_toml="$2"
    shift 2

    local crate_toml
    for crate_toml in "$@"; do
        python3 "$sanitize_py" resolve_deps "$crate_toml" "$workspace_toml"
    done
}

validate_resolved_manifests() {
    local crate_toml
    local crate_name
    for crate_toml in "$@"; do
        crate_name=$(basename "$(dirname "$crate_toml")")
        grep -q 'workspace = true' "$crate_toml" && \
            err "Unresolved 'workspace = true' in $crate_name/Cargo.toml"
        grep -q 'path = ' "$crate_toml" && \
            err "Unresolved 'path = ' dep in $crate_name/Cargo.toml"
        grep -q 'git = ' "$crate_toml" && \
            err "Unresolved 'git = ' dep in $crate_name/Cargo.toml"
    done

    return 0
}

release_type_for_crate() {
    local crate_name="$1"
    python3 - "$crate_name" "$REPO_ROOT" <<'PY'
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

crate_name, repo_root = sys.argv[1], Path(sys.argv[2])
config_path = repo_root / ".changelog" / "config.toml"

bump_rank = {"patch": 0, "minor": 1, "major": 2}

fixed_groups = []
if config_path.exists():
    with config_path.open("rb") as fh:
        config = tomllib.load(fh)
    for group in config.get("fixed", []):
        members = group.get("members", [])
        if isinstance(members, list):
            fixed_groups.append(set(members))

explicit = {}
for changelog in sorted((repo_root / ".changelog").glob("*.md")):
    lines = changelog.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        continue
    try:
        end = next(i for i, line in enumerate(lines[1:], start=1) if line.strip() == "---")
    except StopIteration:
        continue

    for line in lines[1:end]:
        match = re.match(r'^\s*"?([A-Za-z0-9_-]+)"?\s*:\s*(patch|minor|major)\s*$', line)
        if not match:
            continue
        name, bump = match.groups()
        current = explicit.get(name)
        if current is None or bump_rank[bump] > bump_rank[current]:
            explicit[name] = bump

selected = explicit.get(crate_name)
for members in fixed_groups:
    if crate_name not in members:
        continue
    group_bump = None
    for member in members:
        bump = explicit.get(member)
        if bump is None:
            continue
        if group_bump is None or bump_rank[bump] > bump_rank[group_bump]:
            group_bump = bump
    if group_bump is not None:
        selected = group_bump if selected is None or bump_rank[group_bump] > bump_rank[selected] else selected

print(selected or "")
PY
}

crate_name_from_dir() {
    local crate_dir="$1"
    grep -m1 'name = ' "$crate_dir/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/'
}

crate_version_from_dir() {
    local crate_dir="$1"
    grep -m1 'version = ' "$crate_dir/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/'
}

latest_published_version() {
    local crate_name="$1"
    curl -sL "https://crates.io/api/v1/crates/$crate_name" \
        -H "User-Agent: tempo-publish-script" | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d['crate']['max_stable_version'] or d['crate']['max_version'])" 2>/dev/null
}

noop_semver_prep() {
    :
}

run_semver_checks() {
    local workspace_manifest="$1"
    local semver_prep_hook="$2"
    local publish_crates_csv="$3"
    shift 3

    local publish_crates=()
    local crate_dir
    local crate_name
    local crate_ver
    local release_type
    local internal_deps=()
    local dep
    local published_ver
    local semver_failed=false
    local semver_skipped_all=true

    IFS=, read -r -a publish_crates <<< "$publish_crates_csv"

    log "Running cargo-semver-checks …"
    for crate_dir in "$@"; do
        "$semver_prep_hook" "$crate_dir"
        crate_name=$(crate_name_from_dir "$crate_dir")
        crate_ver=$(crate_version_from_dir "$crate_dir")
        log "Checking $crate_name@$crate_ver …"

        release_type=$(release_type_for_crate "$crate_name")
        if [ -z "$release_type" ]; then
            log "$crate_name has no pending changelog release type, skipping semver-check"
            continue
        fi

        internal_deps=()
        for dep in "${publish_crates[@]}"; do
            [ "$dep" = "$crate_name" ] && continue
            if grep -qE "^\s*${dep}\s*=" "$crate_dir/Cargo.toml"; then
                internal_deps+=("$dep")
            fi
        done
        if ((${#internal_deps[@]} > 0)); then
            log "$crate_name depends on releasable internal crates (${internal_deps[*]}), skipping semver-check"
            continue
        fi

        published_ver=$(latest_published_version "$crate_name")
        if [ -z "$published_ver" ] || [ "$published_ver" = "null" ]; then
            log "$crate_name not yet published, skipping"
            continue
        fi

        if [ "$crate_ver" != "$published_ver" ]; then
            log "$crate_name version bumped ($published_ver → $crate_ver), skipping"
            continue
        fi

        semver_skipped_all=false
        if ! cargo semver-checks \
            --manifest-path "$workspace_manifest" \
            --package "$crate_name" \
            --release-type "$release_type" \
            --default-features 2>&1; then
            semver_failed=true
        fi
    done

    if $semver_skipped_all; then
        log "All crates have bumped versions, nothing to semver-check"
    elif $semver_failed; then
        printf '\n  \033[1;33m⚠\033[0m Semver-incompatible changes detected.\n'
        printf '    If intentional, add a changelog entry with the appropriate bump level.\n\n'
        return 1
    else
        log "Semver checks passed ✓"
    fi
}

retry_publish() {
    local crate_dir="$1"
    local name
    name=$(crate_name_from_dir "$crate_dir")
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

publish_crates() {
    local success_message="$1"
    shift

    if $DRY_RUN; then
        log "Dry-run complete. Use --publish to actually publish."
        return 0
    fi

    local crate_dir
    for crate_dir in "$@"; do
        retry_publish "$crate_dir"
    done
    log "$success_message"
}
