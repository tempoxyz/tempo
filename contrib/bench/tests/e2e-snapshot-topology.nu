#!/usr/bin/env nu
source ../../../bench-e2e.nu
use std/assert

# Run from the repository root: nu contrib/bench/tests/e2e-snapshot-topology.nu
let root = (mktemp -d)
let a = $"($root)/a"
let b = $"($root)/b"
let id_a = "51177dde89242d9121d787a681bd2a0bd6013428a6b83e684a253815db96d8b3bd42c409d2f0f0c805fb913f2066f597e0df65451bca3e81ca718afaa0763de3"
let id_b = "5b0ef8c9bd756af433edc3129975888f6f18b8185b2afbaabc8bb3029a00cf815252cfe424044db42f1c8c4fa805bec74438bdc1ad482c648cdf8807290a86c9"
let peer_a = $"enode://($id_a)@127.0.0.2:8001"
let peer_b = $"enode://($id_b)@127.0.0.3:8101"
let peers = $"($peer_a),($peer_b)"
try {
    for dir in [$a $b] {
        mkdir $"($dir)/.bench-meta" $"($dir)/db"
        { config: { chainId: 1337 } } | to json | save $"($dir)/.bench-meta/genesis.json"
        $peers | save $"($dir)/.bench-meta/trusted-peers.txt"
        for file in [signing.key signing.share enode.key db/sentinel] {
            $"unchanged-($dir)-($file)" | save $"($dir)/($file)"
        }
    }
    $id_a | save $"($a)/enode.identity"
    $id_b | save $"($b)/enode.identity"
    let normal = (e2e-snapshot-topology $a $b)
    assert equal $normal.a.consensus_port 8000
    assert equal $normal.b.consensus_port 8100

    # Peer-list order is irrelevant, but identity-to-address association is not.
    $"($peer_b),($peer_a)" | save -f $"($b)/.bench-meta/trusted-peers.txt"
    assert equal (e2e-snapshot-topology $a $b) $normal
    $id_b | save -f $"($a)/enode.identity"
    $id_a | save -f $"($b)/enode.identity"
    let swapped = (e2e-snapshot-topology $a $b)
    assert equal $swapped.a.ip "127.0.0.3"
    assert equal $swapped.a.consensus_port 8100
    assert equal $swapped.b.ip "127.0.0.2"
    assert equal $swapped.b.consensus_port 8000
    for dir in [$a $b] {
        for file in [signing.key signing.share enode.key db/sentinel] {
            assert equal (open --raw $"($dir)/($file)") $"unchanged-($dir)-($file)"
        }
    }

    $id_a | save -f $"($a)/enode.identity"
    assert (try { e2e-snapshot-topology $a $b | ignore; false } catch { true }) "duplicate identities must fail"
    "unknown" | save -f $"($a)/enode.identity"
    assert (try { e2e-snapshot-topology $a $b | ignore; false } catch { true }) "unlisted identities must fail"
    $id_b | save -f $"($a)/enode.identity"
    $peer_a | save -f $"($a)/.bench-meta/trusted-peers.txt"
    assert (try { e2e-snapshot-topology $a $b | ignore; false } catch { true }) "different peer configurations must fail"
    for dir in [$a $b] {
        ($peers | str replace "127.0.0.3" "127.0.0.4") | save -f $"($dir)/.bench-meta/trusted-peers.txt"
    }
    assert (try { e2e-snapshot-topology $a $b | ignore; false } catch { true }) "unexpected endpoints must fail"
    for dir in [$a $b] { $peers | save -f $"($dir)/.bench-meta/trusted-peers.txt" }
    { config: { chainId: 9999 } } | to json | save -f $"($b)/.bench-meta/genesis.json"
    assert (try { e2e-snapshot-topology $a $b | ignore; false } catch { true }) "different genesis configurations must fail"
} catch { |err|
    rm -rf $root
    error make $err
}
rm -rf $root
print "Local e2e snapshot topology checks passed"
exit 0
