#!/usr/bin/env bash
# Bounded normal-file probes on one already mounted benchmark filesystem.
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
target=""; out=""; label=""; table=""
while (($#)); do
  case "$1" in
    --target) target="$2"; shift 2;;
    --out) out="$2"; shift 2;;
    --label) label="$2"; shift 2;;
    --table) table="$2"; shift 2;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done
[[ "$target" == /reth-bench-a || "$target" == /reth-bench-b ]] || exit 2
[[ -n "$out" && "$label" =~ ^[A-Za-z0-9_-]+$ && -f "$table" ]] || exit 2
mountpoint -q -- "$target"
[[ "$(findmnt -n -o FSTYPE --target "$target")" == ext4 ]] || exit 2
if pgrep -x 'tempo|tempo-baseline|tempo-feature|tempo-setup|txgen-tempo|txgen|bench|reth-bench|fio|mmap_flush_prob'; then
  echo 'Active workload detected immediately before controls; refusing.' >&2; exit 1
fi
mkdir -p -- "$out"
out=$(realpath -- "$out")
python3 - "$target" <<'SPACE'
import shutil,sys
if shutil.disk_usage(sys.argv[1]).free < 96*1024**3:
    raise SystemExit('Need 96 GiB free for 64 GiB file plus 32 GiB reserve')
SPACE
# dm-era's fifth field is its data device; the fourth is metadata/ramdisk.
# Resolve the existing data partition to its physical NVMe namespace read-only.
block_device=$(python3 - "$table" <<'DEVICE'
from pathlib import Path
import re,sys
rows=[line.split() for line in Path(sys.argv[1]).read_text().splitlines()]
assert len(rows)==1 and rows[0][2]=='era', 'Expected exactly one era table'
assert re.fullmatch(r'[0-9]+:[0-9]+',rows[0][4]), 'Invalid data major:minor'
p=(Path('/sys/dev/block')/rows[0][4]).resolve(strict=True)
if (p/'partition').exists(): p=p.parent
assert re.fullmatch(r'nvme[0-9]+n[0-9]+',p.name), 'Expected physical NVMe namespace'
assert not list((p/'slaves').glob('*')), 'Expected direct NVMe backing'
print(p.name)
DEVICE
)
printf '%s\n' "$block_device" > "$out/backing-nvme.txt"
python3 "$source_dir/capture_storage.py" metadata "$target" "$label" > "$out/metadata.json"
probe_dir=$(mktemp -d -- "$target/.tempo-storage-probe.XXXXXXXX")
sampler_pid=""
cleanup() {
  local rc=$?
  if [[ -n "$sampler_pid" ]]; then
    kill "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true
  fi
  if [[ -n "$probe_dir" && -d "$probe_dir" && "$(dirname -- "$probe_dir")" == "$target" && "$(basename -- "$probe_dir")" == .tempo-storage-probe.* ]]; then
    rm -rf -- "$probe_dir"
  fi
  python3 - "$out/cleanup.json" "$probe_dir" "$rc" <<'CLEAN'
from pathlib import Path
import json,sys,time,subprocess
listing=subprocess.run(['ps','-eo','pid=,args='],text=True,capture_output=True,check=True).stdout
owned=[line.strip() for line in listing.splitlines() if len(line.split(None,1))==2 and line.split(None,1)[1].startswith(sys.argv[2]+'/')]
Path(sys.argv[1]).write_text(json.dumps({'timestamp':time.time(),'owned_directory':sys.argv[2], 'owned_directory_exists':Path(sys.argv[2]).exists(),'owned_processes':owned,'exit_code':int(sys.argv[3])},indent=2))
CLEAN
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cc -O2 -Wall -Wextra -Werror -std=c11 "$source_dir/mmap_flush_probe.c" -o "$probe_dir/mmap_flush_probe"
sha256sum "$source_dir/mmap_flush_probe.c" > "$out/probe-source.sha256"
python3 "$source_dir/capture_storage.py" sample > "$out/system-samples.ndjson" &
sampler_pid=$!
run_case() {
  local name="$1"; local mib="$2"; local batches="$3"; shift 3
  printf '%s\n' "Running $label/$name backing=$block_device"
  timeout --signal=TERM --kill-after=30 600 "$probe_dir/mmap_flush_probe" \
    --file "$probe_dir/$name.bin" --size-mib "$mib" --dirty-mib 256 \
    --batches "$batches" --seed 42 --pattern spread --range full \
    --max-seconds 120 --block-device "$block_device" "$@" > "$out/$name.ndjson"
  python3 - "$out/$name.ndjson" "$batches" <<'VERIFY'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
assert rows[-1]['event']=='summary'
assert rows[-1]['batches_completed']==int(sys.argv[2]), 'Incomplete bounded control'
assert len([r for r in rows if r.get('event')=='batch'])==int(sys.argv[2])
VERIFY
  [[ ! -e "$probe_dir/$name.bin" ]] || { echo 'Probe did not clean owned file' >&2; exit 1; }
}
run_case spread_8g_default 8192 8
run_case spread_8g_mdbx 8192 8 --init-write-kib 4 --mdbx-advice
run_case spread_64g_default 65536 4
run_case spread_64g_mdbx 65536 4 --init-write-kib 4 --mdbx-advice
python3 "$source_dir/capture_storage.py" metadata "$target" "$label" > "$out/metadata-after.json"
printf '%s\n' 'All four mapping controls completed.'
