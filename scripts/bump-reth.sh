#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

target_rev="${1:-}"
if [ -z "$target_rev" ] || [ "$target_rev" = "latest" ]; then
  target_rev="$(git ls-remote https://github.com/paradigmxyz/reth refs/heads/main | awk '{print $1}')"
fi

if ! [[ "$target_rev" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
  echo "usage: $0 [latest|<reth commit sha>]" >&2
  exit 2
fi

mapfile -t current_revs < <(
  rg -o 'paradigmxyz/reth", rev = "[0-9a-fA-F]+"' -g 'Cargo.toml' \
    | sed 's/.*rev = "\([0-9a-fA-F]*\)"/\1/' \
    | sort -u
)

if [ "${#current_revs[@]}" -eq 0 ]; then
  echo "error: no paradigmxyz/reth git dependencies found" >&2
  exit 1
fi

if [ "${#current_revs[@]}" -ne 1 ]; then
  printf 'error: multiple current reth revs found:\n' >&2
  printf '  %s\n' "${current_revs[@]}" >&2
  exit 1
fi

current_rev="${current_revs[0]}"
if [ "$current_rev" = "$target_rev" ]; then
  echo "reth already at $target_rev"
  exit 0
fi

echo "bumping reth: $current_rev -> $target_rev"

mapfile -t cargo_tomls < <(fd Cargo.toml .)
perl -0pi -e "s#(git = \"https://github.com/paradigmxyz/reth\", rev = \")$current_rev(\")#\${1}$target_rev\${2}#g" "${cargo_tomls[@]}"

mapfile -t reth_packages < <(
  rg '^\s*reth[a-z0-9_-]*\s*=.*git = "https://github.com/paradigmxyz/reth"' Cargo.toml \
    | sed 's/^\s*\(reth[a-z0-9_-]*\)\s*=.*/\1/' \
    | sort -u
)

if [ "${#reth_packages[@]}" -eq 0 ]; then
  echo "error: no reth workspace dependency package names found" >&2
  exit 1
fi

cargo_update=(cargo update)
for package in "${reth_packages[@]}"; do
  cargo_update+=(-p "$package")
done

"${cargo_update[@]}"
