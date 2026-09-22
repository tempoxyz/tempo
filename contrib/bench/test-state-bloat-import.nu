#!/usr/bin/env nu

source ../../bench-e2e.nu
use std/assert

def --wrapped checked [bin: string, ...args: string] {
    let result = (run-external $bin ...$args | complete)
    if $result.exit_code != 0 {
        error make { msg: $"Command failed: ($bin) ($args | str join ' ')\n($result.stdout)\n($result.stderr)" }
    }
    $result.stdout
}

def checksums [bin: string, genesis: string, datadir: string] {
    [
        [mdbx HashedAccounts]
        [mdbx HashedStorages]
        [mdbx AccountsTrie]
        [mdbx StoragesTrie]
        [rocksdb accounts-history]
        [rocksdb storages-history]
        [static-file account-change-sets]
        [static-file storage-change-sets]
    ] | each { |table|
        let output = (checked $bin db --chain $genesis --datadir $datadir checksum ...$table --color never)
        let checksum = ($output | parse --regex 'Checksum for [^\n]+: (?<hash>0x[0-9a-f]+) ' | get hash | first)
        { table: ($table | str join "/"), checksum: $checksum }
    }
}

# Compare an optimized importer against a pre-change binary using a real small database.
def "main verify" [
    --before: string
    --after: string
    --xtask: string
] {
    let before = ($before | path expand)
    let after = ($after | path expand)
    let xtask = ($xtask | path expand)
    let test_dir = (^mktemp -d -t tempo-state-import-test.XXXXXX | str trim)
    print $"Test artifacts: ($test_dir)"
    cd $test_dir
    let localnet = $"($test_dir)/localnet/e2e-local-init"
    let genesis = $"($localnet)/genesis.json"
    let dump = $"($test_dir)/state.bin"
    let a = $"($test_dir)/a"
    let b = $"($test_dir)/b"
    let original = $"($test_dir)/original"
    let address = "0x535441544541434345535342454e434800000000"

    checked $xtask generate-localnet -o $localnet --accounts 3 --validators "127.0.0.2:8000" --followers "127.0.0.3:8100" --seed 42 --state-access-benchmark | save $"($test_dir)/genesis.log"
    # Cover an overlapping genesis slot and an unrelated slot that must survive the import.
    let initial = (open $genesis)
    let storage = {
        "0x0000000000000000000000000000000000000000000000000000000000000000": "0x63"
        "0x0000000000000000000000000000000000000000000000000000000000004e20": "0x4d"
    }
    let account = ($initial.alloc | get $address | upsert storage $storage)
    $initial | upsert alloc ($initial.alloc | upsert $address $account) | to json | save -f $genesis
    checked $xtask generate-state-bloat --size 1 --state-access --out $dump | save $"($test_dir)/dump.log"
    # Duplicate the dump's block to exercise deduplication before history insertion.
    let contents = (open --raw $dump | into binary)
    $contents | bytes add --end $contents | save -f $dump

    checked $before init --chain $genesis --datadir $original | save $"($test_dir)/before-init.log"
    checked $before init-from-binary-dump --chain $genesis --datadir $original $dump | save $"($test_dir)/before-import.log"
    let peers = (trusted-peers-from-localnet $localnet)
    init-local-e2e-side a "" "" $a $a $"($localnet)/127.0.0.2:8000" $genesis $peers 1 $dump $after {} true

    # Exercise a follower rebuild with stale validator credentials present.
    mkdir $b
    "stale" | save $"($b)/signing.key"
    "stale" | save $"($b)/signing.share"
    init-local-e2e-side b "" "" $b $b $"($localnet)/127.0.0.3:8100" $genesis $peers 1 $dump "/must-not-run-an-import-for-b" {} false --copy-db-from $a
    assert (e2e-snapshots-ready $a $b true)
    assert not ($"($b)/signing.key" | path exists)
    assert not ($"($b)/signing.share" | path exists)
    assert equal (open --raw $"($b)/enode.key") (open --raw $"($localnet)/127.0.0.3:8100/enode.key")
    assert not ((open --raw $"($a)/enode.key") == (open --raw $"($b)/enode.key"))
    assert equal (open $"($a)/.bench-meta/marker.json" | get validator_role) a
    assert equal (open $"($b)/.bench-meta/marker.json" | get validator_role) b

    # Reject invalid copies before modifying the destination.
    assert (try { copy-e2e-db $a $a; false } catch { true })
    assert (try { copy-e2e-db $"($test_dir)/missing" $b; false } catch { true })
    let expected = (checksums $after $genesis $original)
    assert equal (checksums $after $genesis $a) $expected
    assert equal (checksums $after $genesis $b) $expected
    $expected | to json | save $"($test_dir)/checksums.json"
    print "PASS: state, trie, history, and changesets match the old importer and copied follower; identities remain separate."
}
