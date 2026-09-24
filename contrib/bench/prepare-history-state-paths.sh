#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
tool=${HISTORY_FIXTURE_TOOL:-$PWD/target/profiling/examples/prepare_history_state_paths}
checkpoint=${STATE_PATH_CHECKPOINT_TOOL:-$PWD/target/profiling/examples/read_finish_checkpoint}
count=${HISTORY_CODE_COUNT:-4266667}
[[ $count =~ ^[0-9]+$ && $count -ge 1024 && $count -le 8000000 ]] || exit 2
exec 9>/tmp/tempo-general-state-access-20260922.lock
flock -n 9
base=tempo_e2e_100000mb_state_access_isolated_roles
a=/reth-bench-a/${base}_history_paths
b=/reth-bench-b/${base}_history_paths
for side in a b; do
    root=/reth-bench-${side}
    test -d "$root/$base.virgin"
    test ! -e "$root/${base}_history_paths"
    test ! -e "$root/${base}_history_paths.virgin"
    "$checkpoint" "$root/$base.virgin/db" | node -e '
      let input="";process.stdin.on("data",c=>input+=c).on("end",()=>{
        require("node:assert/strict").equal(JSON.parse(input).block_number,0);
      });'
done
printf 'COPY_A_START %s\n' "$(date -u --iso-8601=seconds)"
cp -a --reflink=auto --sparse=always -T "/reth-bench-a/$base.virgin" "$a"
printf 'IMPORT_START %s\n' "$(date -u --iso-8601=seconds)"
"$tool" --datadir "$a" --chain "$a/.bench-meta/genesis.json" --code-count "$count" \
    --router-artifact "$PWD/contrib/bench/txgen/history-state-paths.json"
printf 'COPY_B_START %s\n' "$(date -u --iso-8601=seconds)"
cp -a --reflink=auto --sparse=always -T "$a" "$b"
for file in enode.key enode.identity; do cp "/reth-bench-b/$base.virgin/$file" "$b/$file"; done
# These are newly copied proposer keys, not keys in either original snapshot.
rm -f "$b/signing.key" "$b/signing.share"
cp "/reth-bench-b/$base.virgin/.bench-meta/marker.json" "$b/.bench-meta/marker.json"
node - "$a" "$b" <<'JS'
const fs=require('node:fs'),path=require('node:path');
for(const dir of process.argv.slice(2)) {
  const file=path.join(dir,'.bench-meta/marker.json');
  const marker=JSON.parse(fs.readFileSync(file));
  marker.bench_datadir=dir; marker.node_dir=dir; marker.history_state_paths=true;
  fs.writeFileSync(file,JSON.stringify(marker,null,2)+'\n');
}
JS
mv "$a" "$a.virgin"
mv "$b" "$b.virgin"
printf 'FIXTURE_READY %s\n' "$(date -u --iso-8601=seconds)"
