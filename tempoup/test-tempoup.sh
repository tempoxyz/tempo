#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

TEMPOUP_SOURCE="$TMP_ROOT/tempoup-source.sh"
INSTALL_SOURCE="$TMP_ROOT/install-source.sh"
sed '$d' "$ROOT_DIR/tempoup/tempoup" > "$TEMPOUP_SOURCE"
sed '$d' "$ROOT_DIR/tempoup/install" > "$INSTALL_SOURCE"

test_index=0

q() {
    printf '%q' "$1"
}

ok() {
    printf 'ok - %s\n' "$1"
}

fail() {
    printf 'not ok - %s\n' "$1" >&2
    exit 1
}

contains() {
    [[ "$1" == *"$2"* ]] || fail "expected output to contain $2"
}

log_contains() {
    if [[ ! -f "$1" ]] || ! grep -qF "$2" "$1"; then
        fail "expected $1 to contain $2"
    fi
}

log_lacks() {
    [[ ! -f "$1" ]] || ! grep -qF "$2" "$1" || fail "expected $1 not to contain $2"
}

run_source() {
    local source_file="$1"
    local snippet="$2"
    local runner="$TMP_ROOT/case-$((test_index += 1)).sh"

    {
        printf 'set -e\n'
        printf 'source %q\n' "$source_file"
        printf '%s\n' "$snippet"
    } > "$runner"

    bash "$runner"
}

run_tempoup() {
    run_source "$TEMPOUP_SOURCE" "$1"
}

run_install() {
    run_source "$INSTALL_SOURCE" "$1"
}

fake_otool() {
    mkdir -p "$1"
    cat > "$1/otool" <<'FAKE_OTOOL'
#!/usr/bin/env bash
printf '%s:\n' "${@: -1}"
if [[ -n "${REQUIRED_DYLIB:-}" ]]; then
    printf '\t%s (compatibility version 6.0.0, current version 6.0.0)\n' "$REQUIRED_DYLIB"
else
    printf '\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)\n'
fi
FAKE_OTOOL
    chmod +x "$1/otool"
}

fake_brew() {
    mkdir -p "$1"
    cat > "$1/brew" <<'FAKE_BREW'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$BREW_LOG"
case "$1 ${2:-}" in
    "--prefix libusb") printf '%s\n' "$LIBUSB_PREFIX" ;;
    "list --versions") [[ "${BREW_LIST_INSTALLED:-0}" == "1" ]] && printf 'libusb 1.0.30\n' || exit 1 ;;
    "install libusb"|"reinstall libusb") mkdir -p "$LIBUSB_PREFIX/lib"; : > "$LIBUSB_PREFIX/lib/libusb-1.0.0.dylib" ;;
    *) printf 'unexpected brew invocation: %s\n' "$*" >&2; exit 2 ;;
esac
FAKE_BREW
    chmod +x "$1/brew"
}

setup_case() {
    CASE_DIR="$TMP_ROOT/$1"
    FAKE_BIN="$CASE_DIR/bin"
    BREW_LOG="$CASE_DIR/brew.log"
    LIBUSB_PREFIX="$CASE_DIR/prefix"
    TEMPO_BINARY="$CASE_DIR/tempo"
    REQUIRED_DYLIB="$LIBUSB_PREFIX/lib/libusb-1.0.0.dylib"
    mkdir -p "$(dirname "$TEMPO_BINARY")"
    : > "$TEMPO_BINARY"
    fake_otool "$FAKE_BIN"
    if [[ "${2:-brew}" == "brew" ]]; then
        fake_brew "$FAKE_BIN"
    fi
}

check_darwin_deps() {
    REQUIRED_DYLIB="$1" BREW_LOG="$BREW_LOG" LIBUSB_PREFIX="$LIBUSB_PREFIX" \
        PATH="$FAKE_BIN:$PATH" run_tempoup "ensure_runtime_dependencies darwin $(q "$TEMPO_BINARY")"
}

setup_case linux
BREW_LOG="$BREW_LOG" LIBUSB_PREFIX="$LIBUSB_PREFIX" \
    PATH="$FAKE_BIN:$PATH" run_tempoup "ensure_runtime_dependencies linux $(q "$TEMPO_BINARY")"
[[ ! -f "$BREW_LOG" ]] || fail "linux runtime dependency check called brew"
ok "linux runtime dependency no-op"

setup_case darwin-no-link
check_darwin_deps ""
[[ ! -f "$BREW_LOG" ]] || fail "non-libusb darwin binary called brew"
ok "darwin binary without libusb link is no-op"

setup_case darwin-existing
mkdir -p "$LIBUSB_PREFIX/lib"
: > "$REQUIRED_DYLIB"
check_darwin_deps "$REQUIRED_DYLIB"
log_lacks "$BREW_LOG" "install libusb"
log_lacks "$BREW_LOG" "reinstall libusb"
ok "darwin existing libusb is no-op"

setup_case darwin-install
check_darwin_deps "$REQUIRED_DYLIB"
[[ -r "$REQUIRED_DYLIB" ]] || fail "libusb was not installed"
log_contains "$BREW_LOG" "install libusb"
ok "darwin missing libusb installs formula"

setup_case darwin-reinstall
mkdir -p "$LIBUSB_PREFIX/lib"
BREW_LIST_INSTALLED=1 check_darwin_deps "$REQUIRED_DYLIB"
[[ -r "$REQUIRED_DYLIB" ]] || fail "libusb was not reinstalled"
log_contains "$BREW_LOG" "reinstall libusb"
ok "darwin incomplete formula reinstalls"

setup_case darwin-no-brew none
if output="$(REQUIRED_DYLIB="$REQUIRED_DYLIB" PATH="$FAKE_BIN:/usr/bin:/bin" \
    run_tempoup "ensure_runtime_dependencies darwin $(q "$TEMPO_BINARY")" 2>&1)"; then
    printf '%s\n' "$output" >&2
    fail "missing Homebrew case succeeded"
fi
contains "$output" "Homebrew was not found"
contains "$output" "brew install libusb"
ok "darwin missing Homebrew fails clearly"

GOOD_TEMPO="$TMP_ROOT/tempo-good"
BAD_TEMPO="$TMP_ROOT/tempo-bad"
cat > "$GOOD_TEMPO" <<'GOOD'
#!/usr/bin/env bash
printf 'Tempo Version: test\n'
GOOD
cat > "$BAD_TEMPO" <<'BAD'
#!/usr/bin/env bash
printf 'dyld: Library not loaded: libusb-1.0.0.dylib\n' >&2
exit 134
BAD
chmod +x "$GOOD_TEMPO" "$BAD_TEMPO"

TEST_BINARY="$GOOD_TEMPO" run_tempoup 'verify_tempo_binary "$TEST_BINARY"'
if output="$(TEST_BINARY="$BAD_TEMPO" run_tempoup 'verify_tempo_binary "$TEST_BINARY"' 2>&1)"; then
    printf '%s\n' "$output" >&2
    fail "broken tempo binary verified successfully"
fi
contains "$output" "could not launch because libusb is missing"
ok "tempo launch verification catches libusb failure"

run_install '
    should_verify_tempo_after_tempoup
    should_verify_tempo_after_tempoup --unsafe-skip-verify
    should_verify_tempo_after_tempoup --unsafe-skip-verify -i v1.9.1
    ! should_verify_tempo_after_tempoup -i v1.9.1 --help
    ! should_verify_tempo_after_tempoup -i v1.9.1 --version
    ! should_verify_tempo_after_tempoup -i v1.9.1 --update
    ! should_verify_tempo_after_tempoup --help
    ! should_verify_tempo_after_tempoup -h
    ! should_verify_tempo_after_tempoup --version
    ! should_verify_tempo_after_tempoup -v
    ! should_verify_tempo_after_tempoup --update
    ! should_verify_tempo_after_tempoup -U
'
ok "bootstrap verification gating"

ROLLBACK_DIR="$TMP_ROOT/rollback-upgrade"
mkdir -p "$ROLLBACK_DIR"
printf 'old tempo\n' > "$ROLLBACK_DIR/tempo"
if output="$(ROLLBACK_DIR="$ROLLBACK_DIR" run_tempoup '
    TEMPOUP_INSTALL_TARGET="$ROLLBACK_DIR/tempo"
    TEMPOUP_OLD_BINARY="$TEMPOUP_INSTALL_TARGET.old"
    TEMPOUP_HAD_OLD_BINARY=1
    mv -f "$TEMPOUP_INSTALL_TARGET" "$TEMPOUP_OLD_BINARY"
    trap rollback_tempo_install EXIT
    printf "new tempo\n" > "$TEMPOUP_INSTALL_TARGET"
    false
' 2>&1)"; then
    printf '%s\n' "$output" >&2
    fail "failed upgrade rollback succeeded"
fi
[[ "$(cat "$ROLLBACK_DIR/tempo")" == "old tempo" ]] || fail "failed upgrade did not restore old tempo"
[[ ! -e "$ROLLBACK_DIR/tempo.old" ]] || fail "failed upgrade left backup behind"
ok "failed upgrade restores old tempo"
