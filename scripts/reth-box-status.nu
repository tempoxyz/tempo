#!/usr/bin/env nu

# Check the status of reth tailscale boxes for benchmarking
# Shows: hostname, reth version/commit, running nodes, benchmark status, tmux users

def ssh-cmd [box: string, cmd: string] {
    ^ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $"ubuntu@($box)" $cmd | str trim
}

# Look up commit info from GitHub
def lookup-commit [sha: string] {
    if ($sha | is-empty) or ($sha == "none") or ($sha == "unknown") {
        return { pr: "", msg: "" }
    }
    
    # Try paradigmxyz/reth first, then tempoxyz/tempo
    let result = try {
        let resp = (^curl -s $"https://api.github.com/repos/paradigmxyz/reth/commits/($sha)" | from json)
        let msg = ($resp.commit?.message? | default "" | lines | first | default "" | str substring 0..50)
        # Try to extract PR number from commit message
        let pr = ($msg | parse -r '\(#(?<pr>\d+)\)' | get pr? | first | default "")
        { pr: $pr, msg: $msg }
    } catch {
        { pr: "", msg: "" }
    }
    $result
}

def main [] {
    # Fetch chain tips once locally in parallel using reliable RPCs
    print "Fetching chain tips..."
    let mainnet_tip = try { ^cast block-number --rpc-url https://eth.llamarpc.com | str trim } catch { "?" }
    let sepolia_tip = try { ^cast block-number --rpc-url https://ethereum-sepolia-rpc.publicnode.com | str trim } catch { "?" }
    let holesky_tip = try { ^cast block-number --rpc-url https://holesky.drpc.org | str trim } catch { "?" }
    let base_sepolia_tip = try { ^cast block-number --rpc-url https://sepolia.base.org | str trim } catch { "?" }
    
    let tips = {
        mainnet: (if ($mainnet_tip =~ '^[0-9]+$') { $mainnet_tip } else { "?" })
        sepolia: (if ($sepolia_tip =~ '^[0-9]+$') { $sepolia_tip } else { "?" })
        holesky: (if ($holesky_tip =~ '^[0-9]+$') { $holesky_tip } else { "?" })
        base-sepolia: (if ($base_sepolia_tip =~ '^[0-9]+$') { $base_sepolia_tip } else { "?" })
    }
    
    let boxes = (^tailscale status | lines | where { $in =~ 'reth[0-9]+\s' } | each { |line|
        $line | split row -r '\s+' | get 1
    })

    # Single SSH call per box with all commands batched
    let box_data = $boxes | par-each { |box|
        let batch_cmd = "
echo 'SECTION_NODES'
ps aux | grep -E '(reth|tempo-node)' | grep -E ' node | node$' | grep -v 'op-node' | grep -v grep | grep -v bash | awk '{for(i=11;i<=NF;i++) printf \"%s \", $i; print \"\"}'
echo 'SECTION_VERSION'
(/data/bin/reth --version 2>/dev/null || /data/bin/reth-sepolia --version 2>/dev/null || reth --version 2>/dev/null || ~/.cargo/bin/reth --version 2>/dev/null) | head -5
echo 'SECTION_BENCH'
ps aux | grep -E '[t]empo-bench|[r]eth-bench' | grep -v grep | awk '{print $11}'
echo 'SECTION_USERS'
{ ps aux | grep '[t]mux: server' | awk '{print $1}'; who | awk '{print $1}'; } | sort -u | tr '\\n' ',' | sed 's/,$//'
echo ''
echo 'SECTION_DISK'
df -h / 2>/dev/null | tail -1 | awk '{print $3\"/\"$2\" (\"$5\")\"}'
echo 'SECTION_DBS'
# Search more locations for reth dbs
for dir in /data/*/reth /data/*/reth-* /data/*/*/reth /data/*/*/op-reth ~/.local/share/reth ~/.local/share/reth/*; do
  if [ -d \"$dir/db\" ] || [ -d \"$dir/static_files\" ]; then
    # Extract network name from path
    if echo \"$dir\" | grep -q '.local/share/reth'; then
      # For ~/.local/share/reth/mainnet or ~/.local/share/reth
      network=$(basename \"$dir\")
      if [ \"$network\" = \"reth\" ]; then
        network=\"local\"
      fi
    else
      # For /data/mainnet/reth or /data/base-sepolia/op-reth
      network=$(echo $dir | sed 's|/data/||' | sed 's|/reth.*||' | sed 's|/op-reth||')
    fi
    size=$(du -sh \"$dir\" 2>/dev/null | awk '{print $1}')
    if [ -d \"$dir/static_files\" ]; then
      highest=$(ls \"$dir/static_files/\" 2>/dev/null | grep 'static_file_headers' | sort -t_ -k4 -n | tail -1 | sed 's/static_file_headers_[0-9]*_//' | sed 's/\\.off//' || echo '?')
    else
      highest='?'
    fi
    # Include full path for clarity
    echo \"$network:$size:$highest:$dir\"
  fi
done | tr '\\n' '|' | sed 's/|$//'
echo ''
echo 'SECTION_TIP'
echo 'fetch_from_local'
echo 'SECTION_END'
"
        let output = try { ssh-cmd $box $batch_cmd } catch { "" }
        
        # Parse sections using line-based approach
        let lines = ($output | lines)
        
        let nodes_start = ($lines | enumerate | where { $in.item == "SECTION_NODES" } | get index | first | default 0)
        let version_start = ($lines | enumerate | where { $in.item == "SECTION_VERSION" } | get index | first | default 0)
        let bench_start = ($lines | enumerate | where { $in.item == "SECTION_BENCH" } | get index | first | default 0)
        let users_start = ($lines | enumerate | where { $in.item == "SECTION_USERS" } | get index | first | default 0)
        let disk_start = ($lines | enumerate | where { $in.item == "SECTION_DISK" } | get index | first | default 0)
        let dbs_start = ($lines | enumerate | where { $in.item == "SECTION_DBS" } | get index | first | default 0)
        let tip_start = ($lines | enumerate | where { $in.item == "SECTION_TIP" } | get index | first | default 0)
        let end_marker = ($lines | enumerate | where { $in.item == "SECTION_END" } | get index | first | default ($lines | length))
        
        let nodes_raw = ($lines | skip ($nodes_start + 1) | take ($version_start - $nodes_start - 1) | str join "\n")
        let version_raw = ($lines | skip ($version_start + 1) | take ($bench_start - $version_start - 1) | str join "\n")
        let bench_raw = ($lines | skip ($bench_start + 1) | take ($users_start - $bench_start - 1) | str join "\n")
        let users_raw = ($lines | skip ($users_start + 1) | take ($disk_start - $users_start - 1) | where { $in != "" and $in !~ "SECTION" } | str join "," | str trim)
        let disk_raw = ($lines | skip ($disk_start + 1) | take ($dbs_start - $disk_start - 1) | first | default "")
        let dbs_raw = ($lines | skip ($dbs_start + 1) | take ($tip_start - $dbs_start - 1) | where { $in != "" and $in !~ "SECTION" } | str join "" | str trim)
        let tips_raw = ($lines | skip ($tip_start + 1) | take ($end_marker - $tip_start - 1) | where { $in != "" and $in !~ "SECTION" } | str join "" | str trim)
        
        # Parse commit SHA
        let commit = if ($version_raw | is-empty) { 
            "none" 
        } else { 
            let sha = ($version_raw | lines | where { $in =~ 'Commit SHA' } | first | default "" | str replace 'Commit SHA: ' '' | str trim)
            if ($sha | is-empty) { "unknown" } else { $sha }
        }
        
        # Parse build profile
        let profile = if ($version_raw | is-empty) { 
            "" 
        } else { 
            $version_raw | lines | where { $in =~ 'Build Profile' } | first | default "" | str replace 'Build Profile: ' '' | str trim
        }
        
        # Parse benchmark type
        let has_tempo_bench = ($bench_raw =~ 'tempo-bench')
        let has_reth_bench_compare = ($bench_raw =~ 'reth-bench-compare')
        let has_reth_bench = ($bench_raw =~ 'reth-bench') and (not $has_reth_bench_compare)

        {
            box: $box
            running_nodes: $nodes_raw
            commit: $commit
            profile: $profile
            has_tempo_bench: $has_tempo_bench
            has_reth_bench: $has_reth_bench
            has_reth_bench_compare: $has_reth_bench_compare
            users: $users_raw
            disk: $disk_raw
            dbs: $dbs_raw
            tips: $tips_raw
        }
    }

    # Collect unique commits and look them up
    let unique_commits = ($box_data | get commit | uniq | where { $in != "none" and $in != "unknown" })
    let commit_info = $unique_commits | par-each { |sha|
        let info = (lookup-commit $sha)
        { sha: $sha, pr: $info.pr, msg: $info.msg }
    }

    # Print results
    print "═══════════════════════════════════════════════════════════════════════════════"
    print "RETH BOX STATUS"
    print "═══════════════════════════════════════════════════════════════════════════════"
    
    for data in ($box_data | sort-by box) {
        let box = $data.box
        let commit = $data.commit
        let profile = $data.profile
        let users = if ($data.users | is-empty) { "none" } else { $data.users }
        
        # Get PR info for this commit
        let pr_info = ($commit_info | where { $in.sha == $commit } | first | default { pr: "", msg: "" })
        let pr_str = if ($pr_info.pr | is-empty) { "" } else { $" PR#($pr_info.pr)" }
        
        let reth_str = if ($commit == "none") {
            "not installed"
        } else {
            let short_sha = ($commit | str substring 0..8)
            $"($short_sha) \(($profile))($pr_str)"
        }
        
        let bench_status = if $data.has_reth_bench_compare {
            "🔴 reth-bench-compare"
        } else if $data.has_reth_bench {
            "🔴 reth-bench"
        } else if $data.has_tempo_bench {
            "🔴 tempo-bench"
        } else {
            "none"
        }
        
        let nodes = ($data.running_nodes | lines | where { $in | str trim | is-not-empty })
        let node_count = ($nodes | length)
        let status_icon = if $node_count == 0 { "🟢" } else { "🔴" }
        
        let disk = if ($data.disk | is-empty) { "?" } else { $data.disk }
        
        print ""
        print $"($status_icon) ($box) | reth: ($reth_str) | bench: ($bench_status) | users: ($users) | disk used: ($disk)"
        
        # Show running nodes first
        if $node_count > 0 {
            print "   ▸ Running nodes:"
            for node_cmd in $nodes {
                # Extract key params: binary name, --chain, --datadir
                let binary = ($node_cmd | split row " " | first | default "" | path basename)
                let chain = ($node_cmd | parse -r '--chain[= ](?<chain>[^ ]+)' | get chain? | first | default "mainnet")
                let datadir = ($node_cmd | parse -r '--datadir[= ](?<dir>[^ ]+)' | get dir? | first | default "default")
                let instance = ($node_cmd | parse -r '--instance[= ](?<i>[^ ]+)' | get i? | first | default "")
                let metrics = ($node_cmd | parse -r '--metrics[= ](?<m>[^ ]+)' | get m? | first | default "")
                
                let instance_str = if ($instance | is-empty) { "" } else { $" inst=($instance)" }
                let metrics_str = if ($metrics | is-empty) { "" } else { $" metrics=($metrics)" }
                let datadir_str = if ($datadir == "default") { "" } else { $" datadir=($datadir)" }
                
                print $"     └─ ($binary) chain=($chain)($datadir_str)($instance_str)($metrics_str)"
            }
        }
        
        # Show databases
        if (not ($data.dbs | is-empty)) {
            print "   ▸ Databases:"
            let dbs = ($data.dbs | split row "|" | where { $in | str trim | is-not-empty } | each { |db|
                let parts = ($db | split row ":")
                let network = ($parts | get 0 | default "?" | str trim)
                let size = ($parts | get 1 | default "?" | str trim)
                let block = ($parts | get 2 | default "?" | str trim)
                let path = ($parts | get 3 | default "" | str trim)
                
                # Get tip for this network from global tips
                let tip = (try { $tips | get $network } catch { "?" })
                
                # Calculate delta
                let delta_str = if ($block == "?" or $tip == "?" or not ($block =~ '^[0-9]+$') or not ($tip =~ '^[0-9]+$')) { 
                    "" 
                } else {
                    let b = ($block | into int)
                    let t = ($tip | into int)
                    let delta = $t - $b
                    if $delta <= 0 { " ✓synced" } else if $delta < 1000 { $" -($delta) blocks behind" } else { $" -($delta / 1000 | math round --precision 1)K blocks behind" }
                }
                
                # Format block number with M suffix for millions
                let block_fmt = if ($block == "?" or not ($block =~ '^[0-9]+$')) { "?" } else {
                    let b = ($block | into int)
                    if $b >= 1000000 { $"($b / 1000000 | math round --precision 1)M" } else { $"($b)" }
                }
                
                # Short path
                let short_path = ($path | str replace '/home/ubuntu' '~' | str replace '/data/' '')
                
                $"($network) ($size) @block ($block_fmt)($delta_str) [($short_path)]"
            })
            for db in $dbs {
                print $"     📦 ($db)"
            }
        }
    }
    
    print ""
    print "═══════════════════════════════════════════════════════════════════════════════"
    print ""
    print "📋 RECOMMENDATIONS"
    print "───────────────────────────────────────────────────────────────────────────────"
    
    # Calculate scores for each box (lower = more available)
    let scored_boxes = $box_data | each { |data|
        let nodes = ($data.running_nodes | lines | where { $in | str trim | is-not-empty } | length)
        let has_bench = $data.has_tempo_bench or $data.has_reth_bench or $data.has_reth_bench_compare
        let users = if ($data.users | is-empty) { 0 } else { $data.users | split row "," | length }
        
        # Parse disk percentage
        let disk_pct = if ($data.disk | is-empty) { 100 } else {
            let pct_str = ($data.disk | parse -r '\((\d+)%\)' | get capture0? | first | default "100")
            $pct_str | into int | default 100
        }
        
        # Score: lower is better (0 = completely free)
        # nodes running: +50 each, bench: +100, users: +10 each, disk%: +1 per %
        let score = ($nodes * 50) + (if $has_bench { 100 } else { 0 }) + ($users * 10) + $disk_pct
        
        # Find synced networks
        let synced_nets = if ($data.dbs | is-empty) { [] } else {
            $data.dbs | split row "|" | where { $in | str trim | is-not-empty } | each { |db|
                let parts = ($db | split row ":")
                let network = ($parts | get 0 | default "" | str trim)
                let block = ($parts | get 2 | default "?" | str trim)
                let tip = (try { $tips | get $network } catch { "?" })
                
                if ($block =~ '^[0-9]+$' and $tip =~ '^[0-9]+$') {
                    let b = ($block | into int)
                    let t = ($tip | into int)
                    let delta = $t - $b
                    if $delta < 10000 { $network } else { null }
                } else { null }
            } | where { $in != null }
        }
        
        {
            box: $data.box
            score: $score
            nodes: $nodes
            users: $users
            disk_pct: $disk_pct
            has_bench: $has_bench
            synced: $synced_nets
        }
    } | sort-by score
    
    # Best boxes for fresh benchmarks (lowest score)
    print ""
    print "🆓 Best for fresh benchmarks (least allocated):"
    let top3 = ($scored_boxes | take 3)
    for box in $top3 {
        let status = if $box.nodes > 0 { "⚠️ nodes running" } else if $box.has_bench { "⚠️ bench running" } else { "✅ idle" }
        print $"   ($box.box): score=($box.score) | ($status) | users=($box.users) | disk=($box.disk_pct)%"
    }
    
    # Boxes with synced mainnet
    print ""
    print "⚡ Boxes with synced databases:"
    let networks = ["mainnet", "sepolia", "holesky", "base-sepolia"]
    for net in $networks {
        let synced_boxes = ($scored_boxes | where { $net in $in.synced } | get box | str join ", ")
        if (not ($synced_boxes | is-empty)) {
            print $"   ($net): ($synced_boxes)"
        }
    }
    
    print ""
    print "═══════════════════════════════════════════════════════════════════════════════"
}
