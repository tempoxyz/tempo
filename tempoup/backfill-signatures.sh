#!/usr/bin/env bash
set -euo pipefail

# Backfill GPG .asc signatures for all existing GitHub releases.
#
# Requirements: gh, gpg, curl
# Usage:
#   export GPG_PRIVATE_KEY="$(cat key.asc)"   # or base64-encoded
#   export GPG_PASSPHRASE="your-passphrase"
#   ./backfill-signatures.sh

REPO="tempoxyz/tempo"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}info${NC}: $1"; }
warn()  { echo -e "${YELLOW}warn${NC}: $1"; }
error() { echo -e "${RED}error${NC}: $1" >&2; exit 1; }

[[ -z "${GPG_PRIVATE_KEY:-}" ]] && error "GPG_PRIVATE_KEY env var is required"
[[ -z "${GPG_PASSPHRASE:-}" ]] && error "GPG_PASSPHRASE env var is required"

command -v gh  >/dev/null || error "gh CLI not found"
command -v gpg >/dev/null || error "gpg not found"

WORK_DIR=$(mktemp -d)
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap "rm -rf $WORK_DIR $GNUPGHOME" EXIT

info "Importing GPG key..."
if echo "$GPG_PRIVATE_KEY" | base64 --decode 2>/dev/null | gpg --batch --import 2>/dev/null; then
    true
elif echo "$GPG_PRIVATE_KEY" | gpg --batch --import 2>/dev/null; then
    true
else
    error "Failed to import GPG key (tried both base64 and raw)"
fi

KEY_ID=$(gpg --list-secret-keys --keyid-format long 2>/dev/null | grep sec | head -1 | awk '{print $2}' | cut -d'/' -f2)
info "Using key: $KEY_ID"

TAGS=$(gh release list --repo "$REPO" --limit 100 --json tagName -q '.[].tagName')

SIGNED=0
SKIPPED=0
FAILED=0

for TAG in $TAGS; do
    info "Processing $TAG..."

    ASSETS=$(gh release view "$TAG" --repo "$REPO" --json assets -q '.assets[].name')

    ARCHIVES=$(echo "$ASSETS" | grep '\.tar\.gz$' || true)
    [[ -z "$ARCHIVES" ]] && { warn "  No .tar.gz assets for $TAG, skipping"; continue; }

    TAG_DIR="$WORK_DIR/$TAG"
    mkdir -p "$TAG_DIR"

    for ARCHIVE in $ARCHIVES; do
        if echo "$ASSETS" | grep -qF "${ARCHIVE}.asc"; then
            warn "  ${ARCHIVE}.asc already exists, skipping"
            ((SKIPPED++))
            continue
        fi

        info "  Signing $ARCHIVE..."

        gh release download "$TAG" --repo "$REPO" -p "$ARCHIVE" -D "$TAG_DIR" --clobber

        if echo "$GPG_PASSPHRASE" | gpg \
            --batch --yes \
            --passphrase-fd 0 \
            --pinentry-mode loopback \
            -ab "$TAG_DIR/$ARCHIVE" 2>/dev/null; then

            gh release upload "$TAG" "$TAG_DIR/${ARCHIVE}.asc" --repo "$REPO" --clobber
            info "  Uploaded ${ARCHIVE}.asc"
            ((SIGNED++))
        else
            warn "  Failed to sign $ARCHIVE"
            ((FAILED++))
        fi

        rm -f "$TAG_DIR/$ARCHIVE" "$TAG_DIR/${ARCHIVE}.asc"
    done

    rm -rf "$TAG_DIR"
done

echo ""
info "Done. Signed: $SIGNED, Skipped (already exist): $SKIPPED, Failed: $FAILED"
