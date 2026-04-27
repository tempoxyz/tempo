# Bootstrap stub for the txgen benchmark backend.
#
# This file exists on main so the benchmark workflow can reference a real
# entrypoint before the txgen harness lands on a PR branch.

def main [] {
    print "Tempo txgen benchmark helper"
    print ""
    print "Usage:"
    print "  nu contrib/bench/bench-txgen.nu run [flags]"
    print ""
    print "This is a bootstrap stub. The txgen harness is not implemented on this branch."
}

def "main run" [
    --preset: string = ""
    --mode: string = ""
    --bloat: string = ""
    --duration: string = ""
    --tps: string = ""
    --no-infra
    --baseline: string = ""
    --feature: string = ""
    --bench-datadir: string = ""
    --tune
    --gas-limit: string = ""
    --samply
    --tracy: string = ""
    --tracy-seconds: string = ""
    --tracy-offset: string = ""
    --baseline-args: string = ""
    --feature-args: string = ""
    --baseline-hardfork: string = ""
    --feature-hardfork: string = ""
    --force
    --bench-args: string = ""
    --bench-env: string = ""
    --baseline-env: string = ""
    --feature-env: string = ""
] {
    print "txgen benchmark backend is not implemented on this branch."
    print "Add the txgen harness in this branch to make `@decofe bench backend=txgen` runnable."
    exit 1
}
