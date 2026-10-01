#!/usr/bin/env bash
# Verify every zone verifier PCR entry against the prover image it names.
# Usage: verify-zone-verifier-pcrs.sh [path/to/pcrs.json]
# Requires docker, jq and GH_TOKEN with read access to tempoxyz/zones. For each entry:
# - the commit exists on tempoxyz/zones main and is the image's OCI revision;
# - the image's Nitro PCR labels match the entry;
# - an independently installed nitro-cli measures the image's EIF with the same PCRs.
# Field formats are enforced at compile time by crates/precompiles/build.rs.
set -euo pipefail

pcrs=${1:-crates/precompiles/src/zone_verifier/pcrs.json}
eif_path=/opt/tempo-zone-prover/tempo-zone-prover.eif
# Keep in sync with tempoxyz/zones docker/Dockerfile.prover-host.
nitro_image=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:6d8e068b91f351df5bf6acd4bd261316e42747ad4bae76689ff6f4939e2180a2
nitro_cli=aws-nitro-enclaves-cli-1.4.5-0.amzn2023

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

count=$(jq -er 'length' "$pcrs")
echo "Verifying $count PCR entries from $pcrs"
failed=0

for ((i = 0; i < count; i++)); do
  entry=$(jq -c ".[$i]" "$pcrs")
  field() { jq -er --arg key "$1" '.[$key]' <<<"$entry"; }
  fork=$(field hardfork)
  image=$(field image)
  sha=$(field commit)
  sha=${sha##*/}
  expected=$(jq -c '.pcrs' <<<"$entry")
  fail() { echo "::error title=$fork PCRs::$*"; failed=1; }
  echo "::group::$fork: $image"

  # `behind` or `identical` means the commit is an ancestor of main.
  status=$(gh api "repos/tempoxyz/zones/compare/main...$sha" --jq .status 2>/dev/null || echo missing)
  case "$status" in
    behind | identical) ;;
    *) fail "commit $sha is not on tempoxyz/zones main (compare status: $status)" ;;
  esac

  docker pull --quiet --platform linux/amd64 "$image" >/dev/null
  labels=$(docker image inspect --format '{{json .Config.Labels}}' "$image")
  revision=$(jq -r '.["org.opencontainers.image.revision"] // ""' <<<"$labels")
  source=$(jq -r '.["org.opencontainers.image.source"] // ""' <<<"$labels")
  [[ "$revision" == "$sha" ]] || fail "image revision is '$revision', expected $sha"
  [[ "$source" == https://github.com/tempoxyz/zones ]] || fail "image source is '$source'"
  label_pcrs=$(jq -c '[.["xyz.tempo.zone-prover.nitro.pcr0"], .["xyz.tempo.zone-prover.nitro.pcr1"],
    .["xyz.tempo.zone-prover.nitro.pcr2"]]' <<<"$labels")
  [[ "$label_pcrs" == "$expected" ]] || fail "image PCR labels $label_pcrs differ from $expected"

  # Measure the shipped EIF with a nitro-cli that does not come from the image under test.
  container=$(docker create --platform linux/amd64 "$image")
  docker cp --quiet "$container:$eif_path" "$work/$fork.eif"
  docker rm "$container" >/dev/null
  measured=$(docker run --rm --platform linux/amd64 --volume "$work:/eif:ro" "$nitro_image" sh -euc \
    "dnf install -q -y $nitro_cli >/dev/null && nitro-cli describe-eif --eif-path /eif/$fork.eif" |
    jq -c '[.Measurements.PCR0, .Measurements.PCR1, .Measurements.PCR2]')
  [[ "$measured" == "$expected" ]] || fail "EIF measures $measured, expected $expected"

  echo "::endgroup::"
done

exit "$failed"
