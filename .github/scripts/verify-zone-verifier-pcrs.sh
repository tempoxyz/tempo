#!/usr/bin/env bash
# Verify every zone verifier PCR entry against the prover image it names.
# Usage: verify-zone-verifier-pcrs.sh [path/to/pcrs.json]
# Requires docker, jq and GH_TOKEN with read access to tempoxyz/tempo. For each entry:
# - the commit is on tempoxyz/tempo main, or is the single prover version-bump
#   commit on top of main that Prepare Prover Release tags, and is the image's
#   OCI revision;
# - the image's own nitro-cli measures its EIF with the entry's PCRs;
# - the image's Nitro PCR labels match both the entry and the measured EIF.
# Field formats are enforced at compile time by crates/precompiles/build.rs.
set -euo pipefail

pcrs=${1:-crates/precompiles/src/zone_verifier/pcrs.json}
eif_path=/opt/tempo-zone-prover/tempo-zone-prover.eif

count=$(jq -er 'length' "$pcrs")
echo "Verifying $count PCR entries from $pcrs"
failed=0

on_main() {
  # `behind` or `identical` means the commit is an ancestor of main.
  case "$(gh api "repos/tempoxyz/tempo/compare/main...$1" --jq .status 2>/dev/null || echo missing)" in
    behind | identical) return 0 ;;
    *) return 1 ;;
  esac
}

# Prepare Prover Release tags its version-bump commit on a pre-release branch,
# which a squash merge keeps off main. Accept such a commit only if its one
# parent is on main and it edits nothing but version lines of Cargo.lock and
# the prover manifests, as Zones Docker Build requires for prover/v* tags.
prover_version_bump() {
  local commit
  commit=$(gh api "repos/tempoxyz/tempo/commits/$1") || return 1
  [[ $(jq '.parents | length' <<<"$commit") == 1 ]] || return 1
  on_main "$(jq -r '.parents[0].sha' <<<"$commit")" || return 1
  jq -e '
    (.files | length) > 0 and all(.files[];
      .status == "modified" and (.patch | type) == "string" and
      (.filename | test("^(Cargo\\.lock|bin/prover/[^/]+/Cargo\\.toml)$")) and
      all(.patch | split("\n")[] | select(test("^[+-]"));
        test("^[+-]version = \"[^\"]+\"$")))' <<<"$commit" >/dev/null
}

while read -r -u 3 fork; do
  entry=$(jq -c --arg fork "$fork" '.[$fork]' "$pcrs")
  field() { jq -er --arg key "$1" '.[$key]' <<<"$entry"; }
  image=$(field image)
  sha=$(field commit)
  sha=${sha##*/}
  expected=$(jq -cS '.pcrs' <<<"$entry")
  indexes=$(jq -c '.pcrs | keys' <<<"$entry")
  fail() { echo "::error title=$fork PCRs::$*"; failed=1; }
  echo "::group::$fork: $image"

  on_main "$sha" || prover_version_bump "$sha" ||
    fail "commit $sha is not on tempoxyz/tempo main or a prover version bump on it"

  docker pull --quiet --platform linux/amd64 "$image" >/dev/null
  labels=$(docker image inspect --format '{{json .Config.Labels}}' "$image")
  revision=$(jq -r '.["org.opencontainers.image.revision"] // ""' <<<"$labels")
  source=$(jq -r '.["org.opencontainers.image.source"] // ""' <<<"$labels")
  [[ "$revision" == "$sha" ]] || fail "image revision is '$revision', expected $sha"
  [[ "$source" == https://github.com/tempoxyz/tempo ]] || fail "image source is '$source'"
  label_pcrs=$(jq -cS --argjson indexes "$indexes" \
    '. as $l | $indexes | map({key: ., value: $l["xyz.tempo.zone-prover.nitro.pcr\(.)"]}) | from_entries' <<<"$labels")
  [[ "$label_pcrs" == "$expected" ]] || fail "image PCR labels $label_pcrs differ from $expected"

  # The prover image ships nitro-cli alongside the EIF it measures.
  measured=$(docker run --rm --platform linux/amd64 --entrypoint nitro-cli "$image" \
    describe-eif --eif-path "$eif_path" |
    jq -cS --argjson indexes "$indexes" \
      '.Measurements as $m | $indexes | map({key: ., value: $m["PCR\(.)"]}) | from_entries')
  [[ "$measured" == "$expected" ]] || fail "EIF measures $measured, expected $expected"
  # The labels are what operators and dev-platform read, so they must describe the shipped EIF.
  [[ "$label_pcrs" == "$measured" ]] || fail "image PCR labels $label_pcrs differ from EIF measurements $measured"

  echo "::endgroup::"
done 3< <(jq -r 'keys_unsorted[]' "$pcrs")

exit "$failed"
