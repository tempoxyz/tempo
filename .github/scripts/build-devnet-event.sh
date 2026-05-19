#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 COMMENT_BODY [BRANCH REQUESTED_BY NAME]" >&2
}

ENVELOPE="false"
if [ "$#" -eq 1 ]; then
  ENVELOPE="true"
  COMMENT_BODY="$1"
  BRANCH="${PR_BRANCH:?PR_BRANCH is required}"
  REQUESTED_BY="${REQUESTED_BY:?REQUESTED_BY is required}"
  NAME="devnet-pr-${PR_NUMBER:?PR_NUMBER is required}"
  REPOSITORY="${GH_REPO:?GH_REPO is required}"
elif [ "$#" -eq 4 ]; then
  COMMENT_BODY="$1"
  BRANCH="$2"
  REQUESTED_BY="$3"
  NAME="$4"
  REPOSITORY=""
else
  usage
  exit 2
fi

NETWORK="mainnet"
STATE_ROOT_BACKEND="mpt"

for token in $COMMENT_BODY; do
  case "$token" in
    network=*)
      NETWORK="${token#network=}"
      ;;
    state-root.backend=*)
      STATE_ROOT_BACKEND="${token#state-root.backend=}"
      ;;
  esac
done

case "$NETWORK" in
  mainnet|moderato|testnet|mainnet-qmdb|moderato-qmdb) ;;
  *)
    echo "unsupported build-devnet network: $NETWORK" >&2
    exit 1
    ;;
esac

case "$STATE_ROOT_BACKEND" in
  mpt|qmdb) ;;
  *)
    echo "unsupported build-devnet state-root backend: $STATE_ROOT_BACKEND" >&2
    exit 1
    ;;
esac

case "$NETWORK" in
  mainnet-qmdb|moderato-qmdb)
    if [ "$STATE_ROOT_BACKEND" = "mpt" ]; then
      STATE_ROOT_BACKEND="qmdb"
    fi
    ;;
esac

DATA="$(jq -n \
  --arg name "$NAME" \
  --arg branch "$BRANCH" \
  --arg requested_by "$REQUESTED_BY" \
  --arg network "$NETWORK" \
  --arg state_root_backend "$STATE_ROOT_BACKEND" \
  '{
    name: $name,
    branch: $branch,
    requested_by: $requested_by,
    network: $network,
    state_root_backend: $state_root_backend
  }')"

if [ "$ENVELOPE" = "true" ]; then
  jq -n \
    --arg repository "$REPOSITORY" \
    --arg event "build_devnet" \
    --argjson data "$DATA" \
    '{repository: $repository, event: $event, data: $data}'
else
  printf '%s\n' "$DATA"
fi
