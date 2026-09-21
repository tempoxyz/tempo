# This path never calls Cargo, the shared cache, or snapshot generators.
def prebuilt-select [directory: string, side: string, revision: string, features: string, profile: string, a_cpus: string, b_cpus: string] {
    let result = (^python3 contrib/bench/lifecycle/prebuilt_consumer.py select --directory $directory --arm $side --runtime $revision --features $features --profile $profile --no-default-features --cpus $a_cpus --cpus $b_cpus | complete)
    if $result.exit_code != 0 { error make {msg: "Prebuilt binary admission rejected"} }
    $result.stdout | from json
}

def prebuilt-require-snapshot [enabled: bool, ready: bool, force: bool, init_only: bool] {
    if $enabled and (not $ready or $force or $init_only) {
        error make {msg: "Prebuilt execution requires an existing snapshot; local generation is forbidden"}
    }
}
