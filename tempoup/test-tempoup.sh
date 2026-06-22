#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPOUP_SCRIPT="$ROOT_DIR/tempoup/tempoup"
INSTALL_SCRIPT="$ROOT_DIR/tempoup/install"
TMP_ROOT="$(mktemp -d)"
TEST_INDEX=0

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

TEMP_SOURCE="$TMP_ROOT/tempoup-source.sh"
INSTALL_SOURCE="$TMP_ROOT/install-source.sh"
sed '$d' "$TEMPOUP_SCRIPT" > "$TEMP_SOURCE"
sed '$d' "$INSTALL_SCRIPT" > "$INSTALL_SOURCE"

pass() {
    printf 'ok - %s\n' "$1"
}

fail() {
    printf 'not ok - %s\n' "$1" >&2
    exit 1
}

assert_file_contains() {
    local file="$1"
    local pattern="$2"
    if ! grep -qF "$pattern" "$file"; then
        printf 'expected %s to contain %s\n' "$file" "$pattern" >&2
        [[ -f "$file" ]] && cat "$file" >&2
        exit 1
    fi
}

assert_file_not_contains() {
    local file="$1"
    local pattern="$2"
    if [[ -f "$file" ]] && grep -qF "$pattern" "$file"; then
        printf 'expected %s not to contain %s\n' "$file" "$pattern" >&2
        cat "$file" >&2
        exit 1
    fi
}

assert_contains() {
    local value="$1"
    local pattern="$2"
    if [[ "$value" != *"$pattern"* ]]; then
        printf 'expected output to contain %s\noutput:\n%s\n' "$pattern" "$value" >&2
        exit 1
    fi
}

run_with_source() {
    local source_file="$1"
    local snippet="$2"
    TEST_INDEX=$((TEST_INDEX + 1))
    local runner="$TMP_ROOT/case-$TEST_INDEX.sh"

    {
        printf 'set -e\n'
        printf 'source %q\n' "$source_file"
        printf '%s\n' "$snippet"
    } > "$runner"

    bash "$runner"
}

run_with_tempoup() {
    run_with_source "$TEMP_SOURCE" "$1"
}

run_with_install() {
    run_with_source "$INSTALL_SOURCE" "$1"
}

make_fake_otool() {
    local fakebin="$1"
    mkdir -p "$fakebin"
    cat > "$fakebin/otool" <<'FAKE_OTOOL'
#!/usr/bin/env bash
binary="${@: -1}"
printf '%s:\n' "$binary"
if [[ -n "${REQUIRED_DYLIB:-}" ]]; then
    printf '\t%s (compatibility version 6.0.0, current version 6.0.0)\n' "$REQUIRED_DYLIB"
else
    printf '\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)\n'
fi
FAKE_OTOOL
    chmod +x "$fakebin/otool"
}

make_fake_brew() {
    local fakebin="$1"
    mkdir -p "$fakebin"
    cat > "$fakebin/brew" <<'FAKE_BREW'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$BREW_LOG"
case "$1 $2" in
    "--prefix libusb")
        printf '%s\n' "$LIBUSB_PREFIX"
        ;;
    "list --versions")
        if [[ "${BREW_LIST_INSTALLED:-0}" == "1" ]]; then
            printf 'libusb 1.0.30\n'
        else
            exit 1
        fi
        ;;
    "install libusb"|"reinstall libusb")
        mkdir -p "$LIBUSB_PREFIX/lib"
        : > "$LIBUSB_PREFIX/lib/libusb-1.0.0.dylib"
        ;;
    *)
        printf 'unexpected brew invocation: %s\n' "$*" >&2
        exit 2
        ;;
esac
FAKE_BREW
    chmod +x "$fakebin/brew"
}

test_detect_target_matrix() {
    run_with_tempoup '
        [[ "$(detect_target darwin arm64)" == "aarch64-apple-darwin" ]]
        [[ "$(detect_target linux amd64)" == "x86_64-unknown-linux-gnu" ]]
        [[ "$(detect_target linux arm64)" == "aarch64-unknown-linux-gnu" ]]
        [[ "$(detect_target win32 amd64)" == "x86_64-pc-windows-msvc" ]]
        [[ "$(detect_target win32 arm64)" == "aarch64-pc-windows-msvc" ]]
    '
}

test_linux_runtime_dependencies_are_noop() {
    local fakebin="$TMP_ROOT/linux-noop/bin"
    local brew_log="$TMP_ROOT/linux-noop/brew.log"
    make_fake_brew "$fakebin"

    BREW_LOG="$brew_log" LIBUSB_PREFIX="$TMP_ROOT/linux-noop/prefix" \
        PATH="$fakebin:$PATH" run_with_tempoup '
            ensure_runtime_dependencies linux "$TMP_ROOT/nonexistent-tempo"
        '

    [[ ! -f "$brew_log" ]] || fail "linux runtime dependency check called brew"
}

test_darwin_without_libusb_link_is_noop() {
    local fakebin="$TMP_ROOT/darwin-no-link/bin"
    local brew_log="$TMP_ROOT/darwin-no-link/brew.log"
    local binary="$TMP_ROOT/darwin-no-link/tempo"
    mkdir -p "$(dirname "$binary")"
    : > "$binary"
    make_fake_otool "$fakebin"
    make_fake_brew "$fakebin"

    BREW_LOG="$brew_log" LIBUSB_PREFIX="$TMP_ROOT/darwin-no-link/prefix" \
        PATH="$fakebin:$PATH" run_with_tempoup '
            ensure_runtime_dependencies darwin "'"$binary"'"
        '

    [[ ! -f "$brew_log" ]] || fail "non-libusb darwin binary called brew"
}

test_darwin_existing_libusb_is_noop() {
    local fakebin="$TMP_ROOT/darwin-existing/bin"
    local brew_log="$TMP_ROOT/darwin-existing/brew.log"
    local prefix="$TMP_ROOT/darwin-existing/prefix"
    local binary="$TMP_ROOT/darwin-existing/tempo"
    local dylib="$prefix/lib/libusb-1.0.0.dylib"
    mkdir -p "$(dirname "$binary")" "$prefix/lib"
    : > "$binary"
    : > "$dylib"
    make_fake_otool "$fakebin"
    make_fake_brew "$fakebin"

    REQUIRED_DYLIB="$dylib" BREW_LOG="$brew_log" LIBUSB_PREFIX="$prefix" \
        PATH="$fakebin:$PATH" run_with_tempoup '
            ensure_runtime_dependencies darwin "'"$binary"'"
        '

    assert_file_not_contains "$brew_log" "install libusb"
    assert_file_not_contains "$brew_log" "reinstall libusb"
}

test_darwin_missing_libusb_installs_formula() {
    local fakebin="$TMP_ROOT/darwin-install/bin"
    local brew_log="$TMP_ROOT/darwin-install/brew.log"
    local prefix="$TMP_ROOT/darwin-install/prefix"
    local binary="$TMP_ROOT/darwin-install/tempo"
    local dylib="$prefix/lib/libusb-1.0.0.dylib"
    mkdir -p "$(dirname "$binary")"
    : > "$binary"
    make_fake_otool "$fakebin"
    make_fake_brew "$fakebin"

    REQUIRED_DYLIB="$dylib" BREW_LOG="$brew_log" LIBUSB_PREFIX="$prefix" \
        PATH="$fakebin:$PATH" run_with_tempoup '
            ensure_runtime_dependencies darwin "'"$binary"'"
        '

    [[ -r "$dylib" ]]
    assert_file_contains "$brew_log" "install libusb"
}

test_darwin_incomplete_formula_reinstalls() {
    local fakebin="$TMP_ROOT/darwin-reinstall/bin"
    local brew_log="$TMP_ROOT/darwin-reinstall/brew.log"
    local prefix="$TMP_ROOT/darwin-reinstall/prefix"
    local binary="$TMP_ROOT/darwin-reinstall/tempo"
    local dylib="$prefix/lib/libusb-1.0.0.dylib"
    mkdir -p "$(dirname "$binary")" "$prefix/lib"
    : > "$binary"
    make_fake_otool "$fakebin"
    make_fake_brew "$fakebin"

    REQUIRED_DYLIB="$dylib" BREW_LOG="$brew_log" LIBUSB_PREFIX="$prefix" \
        BREW_LIST_INSTALLED=1 PATH="$fakebin:$PATH" run_with_tempoup '
            ensure_runtime_dependencies darwin "'"$binary"'"
        '

    [[ -r "$dylib" ]]
    assert_file_contains "$brew_log" "reinstall libusb"
}

test_darwin_missing_homebrew_fails_clearly() {
    local fakebin="$TMP_ROOT/darwin-no-brew/bin"
    local prefix="$TMP_ROOT/darwin-no-brew/prefix"
    local binary="$TMP_ROOT/darwin-no-brew/tempo"
    local dylib="$prefix/lib/libusb-1.0.0.dylib"
    mkdir -p "$(dirname "$binary")"
    : > "$binary"
    make_fake_otool "$fakebin"

    local output
    if output="$(REQUIRED_DYLIB="$dylib" PATH="$fakebin:/usr/bin:/bin" run_with_tempoup '
        ensure_runtime_dependencies darwin "'"$binary"'"
    ' 2>&1)"; then
        printf '%s\n' "$output" >&2
        fail "missing Homebrew case succeeded"
    fi

    assert_contains "$output" "Homebrew was not found"
    assert_contains "$output" "brew install libusb"
}

test_verify_tempo_binary_success_and_failure() {
    local good="$TMP_ROOT/verify/tempo-good"
    local bad="$TMP_ROOT/verify/tempo-bad"
    mkdir -p "$(dirname "$good")"
    cat > "$good" <<'GOOD'
#!/usr/bin/env bash
printf 'Tempo Version: test\n'
GOOD
    cat > "$bad" <<'BAD'
#!/usr/bin/env bash
printf 'dyld: Library not loaded: libusb-1.0.0.dylib\n' >&2
exit 134
BAD
    chmod +x "$good" "$bad"

    TEST_BINARY="$good" run_with_tempoup 'verify_tempo_binary "$TEST_BINARY"'

    local output
    if output="$(TEST_BINARY="$bad" run_with_tempoup 'verify_tempo_binary "$TEST_BINARY"' 2>&1)"; then
        printf '%s\n' "$output" >&2
        fail "broken tempo binary verified successfully"
    fi

    assert_contains "$output" "could not launch because libusb is missing"
}

test_bootstrap_verify_gating() {
    run_with_install '
        should_verify_tempo_after_tempoup
        should_verify_tempo_after_tempoup --unsafe-skip-verify
        should_verify_tempo_after_tempoup --unsafe-skip-verify -i v1.9.1
        ! should_verify_tempo_after_tempoup --help
        ! should_verify_tempo_after_tempoup -h
        ! should_verify_tempo_after_tempoup --version
        ! should_verify_tempo_after_tempoup -v
        ! should_verify_tempo_after_tempoup --update
        ! should_verify_tempo_after_tempoup -U
    '
}

tests=(
    test_detect_target_matrix
    test_linux_runtime_dependencies_are_noop
    test_darwin_without_libusb_link_is_noop
    test_darwin_existing_libusb_is_noop
    test_darwin_missing_libusb_installs_formula
    test_darwin_incomplete_formula_reinstalls
    test_darwin_missing_homebrew_fails_clearly
    test_verify_tempo_binary_success_and_failure
    test_bootstrap_verify_gating
)

for test_name in "${tests[@]}"; do
    "$test_name"
    pass "$test_name"
done
