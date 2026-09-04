#!/usr/bin/env bash
# File-only storage comparison. Requires fio, Python 3, a C compiler, and Linux.
set -euo pipefail
PROBE_SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
target=""; out=""; label=""; size_gib=8; duration=20; fresh_era=""
while (($#)); do
  case "$1" in
    --target) target="$2"; shift 2;;
    --out) out="$2"; shift 2;;
    --label) label="$2"; shift 2;;
    --size-gib) size_gib="$2"; shift 2;;
    --duration) duration="$2"; shift 2;;
    --fresh-era) fresh_era="$2"; shift 2;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done
[[ -d "$target" && -n "$out" && "$label" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo 'Require existing --target directory, --out directory and simple --label' >&2; exit 2; }
[[ "$size_gib" =~ ^[0-9]+$ && "$duration" =~ ^[0-9]+$ ]] || exit 2
((size_gib >= 1 && size_gib <= 8 && duration >= 5 && duration <= 30)) || exit 2
[[ "$(uname -s)" == Linux ]] || { echo 'Linux probe only' >&2; exit 2; }
for dep in fio python3 cc timeout findmnt lsblk; do command -v "$dep" >/dev/null; done
[[ "$(fio --version)" == fio-* ]] || { echo 'Expected Flexible I/O Tester' >&2; exit 2; }
target="$(realpath -- "$target")"
case "$target" in /dev|/dev/*|/proc|/proc/*|/sys|/sys/*) echo 'Refusing virtual/device target' >&2; exit 2;; esac
if [[ -n "$fresh_era" ]]; then
  [[ "$fresh_era" =~ ^tempo_storage_probe_[a-zA-Z0-9_]+$ ]] || { echo 'Fresh-era mode only permits task-owned probe mapper names' >&2; exit 2; }
  [[ "$(findmnt -n -o SOURCE -T "$target")" == "/dev/mapper/$fresh_era" ]] || { echo 'Fresh-era mapper does not match target mount' >&2; exit 2; }
  [[ "$(dmsetup table "$fresh_era" | awk '{print $3}')" == era ]] || exit 2
fi
mkdir -p -- "$out"
out="$(realpath -- "$out")"
# The largest optional test file is 64 GiB. Retain at least 32 GiB free.
python3 - "$target" <<'PY'
import shutil,sys
free=shutil.disk_usage(sys.argv[1]).free
if free < 96*1024**3: raise SystemExit('Need 96 GiB free for largest test plus 32 GiB reserve')
PY
probe_dir="$(mktemp -d -- "$target/.tempo-storage-probe.XXXXXXXX")"
sampler_pid=""; fresh_pid=""
cleanup() {
  if [[ -n "$fresh_pid" ]]; then kill "$fresh_pid" 2>/dev/null || true; wait "$fresh_pid" 2>/dev/null || true; fi
  if [[ -n "$sampler_pid" ]]; then kill "$sampler_pid" 2>/dev/null || true; wait "$sampler_pid" 2>/dev/null || true; fi
  # Only a directory created by this invocation may be removed.
  if [[ -n "$probe_dir" && -d "$probe_dir" && "$(dirname -- "$probe_dir")" == "$target" && "$(basename -- "$probe_dir")" == .tempo-storage-probe.* ]]; then
    rm -rf -- "$probe_dir"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 "$PROBE_SOURCE_DIR/capture_storage.py" metadata "$target" "$label" > "$out/metadata.json"
python3 "$PROBE_SOURCE_DIR/capture_storage.py" sample > "$out/system-samples.ndjson" &
sampler_pid=$!
cc -O2 -Wall -Wextra -std=c11 "$PROBE_SOURCE_DIR/mmap_flush_probe.c" -o "$probe_dir/mmap_flush_probe"
fio_file="$probe_dir/fio-data.bin"
printf '%s\n' "Preparing $label: ${size_gib} GiB regular file at $target"
# Fully initialize data/extents before timed tests; never use sparse reads as device measurements.
timeout --signal=TERM --kill-after=30 300 fio --name=prepare --filename="$fio_file" --size="${size_gib}G" --rw=write --bs=1M --ioengine=libaio --iodepth=16 --direct=1 --end_fsync=1 --output-format=json --output="$out/fio-prepare.json" --eta=never
common=(--filename="$fio_file" --size="${size_gib}G" --time_based=1 --runtime="$duration" --ramp_time=2 --numjobs=1 --group_reporting=1 --randrepeat=1 --randseed=42 --norandommap=1 --invalidate=0 --end_fsync=1 --percentile_list=50:90:95:99:99.9 --output-format=json --eta=never)
run_fio() {
  local name="$1"; shift
  printf '%s\n' "Running $label/$name"
  timeout --signal=TERM --kill-after=30 120 fio --name="$name" "${common[@]}" "$@" --output="$out/fio-$name.json"
  python3 - "$out/fio-$name.json" <<'PY'
import json,sys
j=json.load(open(sys.argv[1]));assert j.get('jobs')
if any(x.get('error',0) for x in j['jobs']):raise SystemExit('fio job failed')
PY
}
run_fio randread_4k_q1 --rw=randread --bs=4k --ioengine=psync --iodepth=1 --direct=1
run_fio randwrite_4k_q1 --rw=randwrite --bs=4k --ioengine=psync --iodepth=1 --direct=1
run_fio randwrite_4k_q32 --rw=randwrite --bs=4k --ioengine=libaio --iodepth=32 --direct=1
run_fio seqwrite_1m_q16 --rw=write --bs=1M --ioengine=libaio --iodepth=16 --direct=1
run_fio fdatasync_4k --rw=randwrite --bs=4k --ioengine=psync --iodepth=1 --direct=0 --fdatasync=1
run_fio fdatasync_1m_batch --rw=randwrite --bs=4k --ioengine=psync --iodepth=1 --direct=0 --fdatasync=256
run_fio fdatasync_4k_repeat --rw=randwrite --bs=4k --ioengine=psync --iodepth=1 --direct=0 --fdatasync=1
run_fio randwrite_4k_q1_repeat --rw=randwrite --bs=4k --ioengine=psync --iodepth=1 --direct=1
rm -- "$fio_file"
run_mmap() {
  local name="$1"; shift
  printf '%s\n' "Running $label/$name"
  timeout --signal=TERM --kill-after=30 300 "$probe_dir/mmap_flush_probe" --file "$probe_dir/mmap-$name.bin" --dirty-mib 256 --seed 42 --max-seconds 120 "$@" > "$out/mmap-$name.ndjson"
  python3 - "$out/mmap-$name.ndjson" <<'PY'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
assert rows[-1]['event']=='summary' and rows[-1]['batches_completed']>0
PY
  rm -f -- "$probe_dir/mmap-$name.bin"
}
run_mmap spread_full_8g --size-mib 8192 --batches 8 --pattern spread --range full
run_mmap contiguous_full_8g --size-mib 8192 --batches 8 --pattern contiguous --range full
run_mmap contiguous_dirty_8g --size-mib 8192 --batches 8 --pattern contiguous --range dirty
run_mmap spread_full_64g --size-mib 65536 --batches 4 --pattern spread --range full
run_mmap pwrite_spread_8g --size-mib 8192 --batches 8 --pattern spread --range full --method pwrite
if [[ -n "$fresh_era" ]]; then
  name=spread_full_fresh_era_8g
  ready="$probe_dir/ready"; go="$probe_dir/go"
  printf '%s\n' "Running $label/$name on exclusive mapper $fresh_era"
  timeout --signal=TERM --kill-after=30 300 "$probe_dir/mmap_flush_probe" --file "$probe_dir/mmap-$name.bin" --size-mib 8192 --dirty-mib 256 --seed 42 --max-seconds 120 --batches 8 --pattern spread --range full --ready-file "$ready" --go-file "$go" > "$out/mmap-$name.ndjson" &
  fresh_pid=$!
  for ((i=0;i<180;i++)); do
    [[ -f "$ready" ]] && break
    kill -0 "$fresh_pid" 2>/dev/null || { wait "$fresh_pid"; exit 1; }
    sleep 1
  done
  [[ -f "$ready" ]] || { kill "$fresh_pid" 2>/dev/null || true; wait "$fresh_pid" || true; echo 'Probe initialization barrier timed out' >&2; exit 1; }
  dmsetup status "$fresh_era" > "$out/fresh-era-before.txt"
  before_era=$(awk '{print $6}' "$out/fresh-era-before.txt")
  dmsetup message "$fresh_era" 0 checkpoint
  changed=false
  for ((i=0;i<50;i++)); do
    dmsetup status "$fresh_era" > "$out/fresh-era-after.txt"
    after_era=$(awk '{print $6}' "$out/fresh-era-after.txt")
    if [[ "$before_era" =~ ^[0-9]+$ && "$after_era" =~ ^[0-9]+$ ]] && ((after_era > before_era)); then changed=true; break; fi
    sleep 0.1
  done
  [[ "$changed" == true ]] || { echo 'Fresh-era checkpoint did not advance' >&2; exit 1; }
  touch -- "$go"
  wait "$fresh_pid"
  fresh_pid=""
  python3 - "$out/mmap-$name.ndjson" <<'PYFRESH'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
assert rows[-1]['event']=='summary' and rows[-1]['batches_completed']>0
PYFRESH
  rm -f -- "$probe_dir/mmap-$name.bin" "$ready" "$go"
fi
python3 "$PROBE_SOURCE_DIR/capture_storage.py" metadata "$target" "$label" > "$out/metadata-after.json"
printf '%s\n' "Completed $label; results in $out"
