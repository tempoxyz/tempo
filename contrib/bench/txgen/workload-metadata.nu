# Compact display metadata; the full spec remains the input to txgen.
export def txgen-workload-mix [spec_path: string, --seen: list<string> = []] {
    let path = ($spec_path | path expand)
    if $path in $seen { error make {msg: "Circular workload spec include"} }
    let spec = (open $path)
    let include = ($spec | get -o include | default ($spec | get -o includes) | default [])
    let includes = if ($include | describe) == string { [$include] } else { $include }
    mut mix = []
    for file in $includes {
        let inherited = (txgen-workload-mix ([($path | path dirname) $file] | path join) --seen ($seen | append $path))
        if not ($inherited | is-empty) { $mix = $inherited }
    }
    $mix = ($spec | get -o mix | default $mix)
    $mix = ($spec | get -o merge.mix | default $mix)
    $mix | append ($spec | get -o append.mix | default [])
}

export def txgen-workload-metadata [mix: list] {
    mut weights = {}
    for entry in $mix {
        let template = ($entry | get -o template | default "")
        let sequence = ($entry | get -o sequence | default "")
        let weight = ($entry | get -o weight)
        if (($template == "") == ($sequence == "")) or (($weight | describe) not-in [int float]) {
            error make {msg: "Workload mix entries require template or sequence and a numeric weight"}
        }
        if $weight < 0 or ($weight | into string) in [inf -inf NaN] {
            error make {msg: "Workload mix weights must be finite and non-negative"}
        }
        let name = (if $template != "" { $template } else { $sequence })
        if ($name | describe) != string { error make {msg: "Workload category must be a string"} }
        if ($name | str trim | is-empty) { error make {msg: "Workload category must not be blank"} }
        # Only the fixture-generated account suffixes have category semantics.
        let category = ($name | str replace --regex '^((?:zone|vault)_(?:deposit|withdraw))_[0-9]+$' '$1')
        let total = ($weights | get -o $category | default 0) + $weight
        if ($total | into string) in [inf -inf NaN] { error make {msg: "Workload category weight overflow"} }
        $weights = ($weights | upsert $category $total)
    }
    if ($weights | is-empty) or (($weights | values | math sum) <= 0) {
        error make {msg: "Workload mix must have positive total weight"}
    }
    if ($weights | values | math sum | into string) in [inf -inf NaN] { error make {msg: "Workload total weight overflow"} }
    {workload_mix_version: "1", workload_mix_weights: ($weights | sort | to json --raw)}
}
