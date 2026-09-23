# Keep each validator in its existing CPU group, reserving equal numbers of
# whole physical cores from each group for the generator, sender and scraper.
export def expand-cpu-list [cpus: string] {
    $cpus | split row ',' | each { |part|
        let bounds = ($part | split row '-' | into int)
        if ($bounds | length) == 1 {
            $bounds
        } else if ($bounds | length) == 2 and $bounds.0 <= $bounds.1 {
            $bounds.0..$bounds.1 | each { $in }
        } else {
            error make {msg: $"Invalid CPU range: ($part)"}
        }
    } | flatten | uniq | sort
}

export def read-cpu-topology [] {
    let allowed = (open /proc/self/status | lines | where { |line| $line starts-with 'Cpus_allowed_list:' } | first | split row ':' | last | str trim | expand-cpu-list $in)
    with-env {LC_ALL: 'C'} { ^lscpu --all --parse=CPU,CORE,SOCKET,ONLINE }
    | lines
    | where { |line| not ($line starts-with '#') and $line != '' }
    | each { |line|
        let fields = ($line | split row ',')
        let cpu = ($fields.0 | into int)
        {cpu: $cpu, core: $fields.1, socket: $fields.2, online: ($fields.3 == 'Y'), allowed: ($cpu in $allowed)}
    }
}

export def bench-cpu-layout [a: string, b: string, txgen_cores: int, topology: list<record>] {
    if $txgen_cores < 0 or ($txgen_cores mod 2) != 0 {
        error make {msg: 'txgen-cores must be a non-negative even number of physical cores'}
    }
    let a_ids = (expand-cpu-list $a)
    let b_ids = (expand-cpu-list $b)
    if ($a_ids | any { |cpu| $cpu in $b_ids }) {
        error make {msg: 'Validator CPU groups overlap'}
    }
    let reserved_per_node = $txgen_cores // 2
    let partitions = ([$a_ids $b_ids] | each { |ids|
        mut groups = []
        mut seen = []
        for cpu in $ids {
            let rows = ($topology | where cpu == $cpu)
            if ($rows | length) != 1 or not $rows.0.online {
                error make {msg: $"CPU ($cpu) is missing, duplicated or offline"}
            }
            if not ($rows.0 | get -o allowed | default true) {
                error make {msg: $"CPU ($cpu) is outside the runner's allowed CPU set"}
            }
            if $cpu in $seen { continue }
            let row = $rows.0
            let siblings = ($topology | where socket == $row.socket and core == $row.core | get cpu | sort)
            if ($siblings | any { |sibling| $sibling not-in $ids }) {
                error make {msg: $"CPU ($cpu) has SMT siblings outside its validator CPU group"}
            }
            $seen = ($seen | append $siblings)
            $groups = ($groups | append {cpus: $siblings})
        }
        if $reserved_per_node >= ($groups | length) {
            error make {msg: 'txgen-cores must leave at least one physical core per validator'}
        }
        let keep = ($groups | length) - $reserved_per_node
        {
            node: ($groups | first $keep | get cpus | flatten | sort | str join ',')
            txgen: ($groups | skip $keep | get cpus | flatten)
            node_cores: $keep
        }
    })
    {
        a: $partitions.0.node
        b: $partitions.1.node
        # Zero explicitly reproduces the previous unpinned sender behavior.
        txgen: ($partitions | get txgen | flatten | sort | str join ',')
        txgen_cores: $txgen_cores
        validator_cores: [$partitions.0.node_cores $partitions.1.node_cores]
    }
}
