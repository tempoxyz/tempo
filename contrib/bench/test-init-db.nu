#!/usr/bin/env nu
source ../../tempo.nu
# Sourcing the CLI also defines main; the test should not print its help text.
hide main
use std/assert

def run-test [] {
    let temp_dir = (^mktemp -d | str trim)
    let tempo_stub = $"($temp_dir)/tempo"
    "#!/bin/sh\ncase \"$1\" in\n  init) exit 0 ;;\n  init-from-binary-dump) printf 'injected import failure\\n' >&2; exit 42 ;;\nesac\nexit 99\n" | save $tempo_stub
    ^chmod 700 $tempo_stub

    let failure = (try {
        bench-init-db $tempo_stub unused-genesis unused-datadir 1 unused-dump
        "unexpected success"
    } catch { |err| $err.msg })
    assert ($failure | str contains "state bloat load failed")

    let success_stub = $"($temp_dir)/tempo-success"
    "#!/bin/sh\ncase \"$1\" in\n  init|init-from-binary-dump) exit 0 ;;\nesac\nexit 99\n" | save $success_stub
    ^chmod 700 $success_stub
    bench-init-db $success_stub unused-genesis unused-datadir 1 unused-dump

    # Without bloat there is no import step to fail.
    bench-init-db $tempo_stub unused-genesis unused-datadir 0 unused-dump
    rm -rf $temp_dir
    print "Benchmark database initialization failure handling passed"
}

run-test
