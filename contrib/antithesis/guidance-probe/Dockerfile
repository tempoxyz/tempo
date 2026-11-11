FROM rust:1.96-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc AS builder
WORKDIR /probe
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY src/ src/

# Only formatting uses nightly; all compiled artifacts use stable 1.96.0.
RUN rustup component add clippy --toolchain 1.96.0 \
    && rustup toolchain install nightly-2026-11-10 --profile minimal --component rustfmt \
    && cargo +nightly-2026-11-10 fmt --all -- --check \
    && cargo +1.96.0 test --locked \
    && cargo +1.96.0 clippy --locked --all-targets -- -D warnings \
    && cargo +1.96.0 build --release --locked

# The same deterministic tape must produce identical states and only label-byte SDK differences.
RUN set -eu; \
    awk 'BEGIN { for (i = 0; i < 70; i++) print 1; for (i = 0; i < 7; i++) print i; print 3 }' > /tmp/tape; \
    awk '{ state = $1 % 4 == 0 ? 0 : (state < 63 ? state + 1 : 63); printf "{\"probe_step\":%d,\"actual_state\":%d}\n", NR - 1, state }' \
        /tmp/tape > /tmp/expected-stdout; \
    for mode in dynamic constant; do \
        start=$(date +%s%N); \
        PROBE_MODE="$mode" ANTITHESIS_SDK_LOCAL_OUTPUT="/tmp/$mode-sdk.jsonl" \
            timeout 30s target/release/guidance-probe --steps 78 --tape /tmp/tape > "/tmp/$mode-stdout"; \
        elapsed=$(( $(date +%s%N) - start )); \
        test "$elapsed" -ge 7750000000; \
        cmp /tmp/expected-stdout "/tmp/$mode-stdout"; \
        test "$(wc -l < "/tmp/$mode-sdk.jsonl")" -eq 83; \
        sed -n 's/^.*"guidance_data":{"label":"\([0-3][0-9a-f]\)"}.*$/\1/p' \
            "/tmp/$mode-sdk.jsonl" > "/tmp/$mode-labels"; \
        test "$(wc -l < "/tmp/$mode-labels")" -eq 78; \
        sed 's/"guidance_data":{"label":"[0-3][0-9a-f]"}/"guidance_data":{"label":"xx"}/g' \
            "/tmp/$mode-sdk.jsonl" > "/tmp/$mode-normalized"; \
        awk '/"antithesis_guidance"/ { if ($0 !~ /"guidance_type":"json"/ || $0 !~ /"maximize":false/ || $0 !~ /"message":"Probe state shape"/) exit 1; if ($0 ~ /"hit":false/) { catalog = NR; catalogs++ } } /"antithesis_setup"/ { setup = NR } END { if (catalogs != 1 || !setup || catalog >= setup) exit 1 }' \
            "/tmp/$mode-sdk.jsonl"; \
    done; \
    cmp /tmp/dynamic-stdout /tmp/constant-stdout; \
    cmp /tmp/dynamic-normalized /tmp/constant-normalized; \
    test "$(sort -u /tmp/dynamic-labels | wc -l)" -eq 64; \
    test "$(sort -u /tmp/constant-labels)" = 13

# Reject coverage hooks and state/mode-dependent jumps in the release binary.
RUN set -eu; \
    binary=target/release/guidance-probe; \
    nm -a "$binary" > /tmp/symbols; \
    readelf -SW "$binary" > /tmp/sections; \
    cargo +1.96.0 tree --locked > /tmp/dependencies; \
    if grep -E '__sanitizer_cov|__sancov|__llvm_profile|\.llvm_prf|\.sancov|antithesis[-_]instrumentation|__AFL' \
        /tmp/symbols /tmp/sections /tmp/dependencies; then exit 1; fi; \
    objdump -Cd "$binary" > /tmp/disassembly; \
    for symbol in transition 'Probe.*step'; do \
        awk -v symbol="$symbol" \
            '/^[[:xdigit:]]+ <.*>:/ { emit = ($0 ~ /guidance_probe::/ && $0 ~ symbol) } emit { print }' \
            /tmp/disassembly > /tmp/function; \
        test -s /tmp/function; \
        cat /tmp/function; \
        if grep -E '[[:space:]](j[a-z]+|loop[a-z]*)[[:space:]]' /tmp/function; then exit 1; fi; \
    done; \
    mkdir -p /rootfs/usr/local/bin /rootfs/opt/antithesis/test/v1/main /rootfs/tmp; \
    chmod 1777 /rootfs/tmp; \
    cp "$binary" /rootfs/usr/local/bin/guidance-probe; \
    cp "$binary" /rootfs/opt/antithesis/test/v1/main/first_start_workload; \
    cmp /rootfs/usr/local/bin/guidance-probe /rootfs/opt/antithesis/test/v1/main/first_start_workload; \
    ldd "$binary" > /tmp/runtime-libraries; \
    cat /tmp/runtime-libraries; \
    if grep 'not found' /tmp/runtime-libraries; then exit 1; fi; \
    awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i }' /tmp/runtime-libraries > /tmp/library-paths; \
    test -s /tmp/library-paths; \
    while IFS= read -r library; do cp --parents --dereference "$library" /rootfs; done < /tmp/library-paths

FROM scratch
COPY --from=builder /rootfs/ /
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/guidance-probe"]
