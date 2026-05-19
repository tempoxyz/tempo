#!/usr/bin/env bash
set -euo pipefail

out=${1:?usage: mem-debug.sh OUT SENTINEL [INTERVAL_SECS] [LABEL]}
sentinel=${2:?usage: mem-debug.sh OUT SENTINEL [INTERVAL_SECS] [LABEL]}
interval=${3:-5}
label=${4:-bench}

mkdir -p "$(dirname "$out")"

write_header() {
  cat >>"$out" <<'EOF'
# kind	ts_ms	label	fields...
# mem	ts_ms	label	key	value_kb
# pressure	ts_ms	label	resource	line
# proc	ts_ms	label	pid	ppid	pgid	etime	comm	rss_kb	vsz_kb	pss_kb	anon_kb	file_kb	cgroup_current_bytes	cgroup_peak_bytes	cmd
# top	ts_ms	label	pid	ppid	rss_kb	vsz_kb	comm	cmd
EOF
}

now_ms() {
  date +%s%3N
}

proc_field_kb() {
  local pid=$1 field=$2
  awk -v field="$field" '$1 == field ":" { print $2; found=1; exit } END { if (!found) print 0 }' \
    "/proc/$pid/smaps_rollup" 2>/dev/null || echo 0
}

cgroup_file_value() {
  local pid=$1 file=$2 cg rel
  rel=$(awk -F: 'NR == 1 { print $3 }' "/proc/$pid/cgroup" 2>/dev/null || true)
  [[ -n "$rel" ]] || { echo 0; return; }
  cg="/sys/fs/cgroup${rel}"
  [[ -r "$cg/$file" ]] || { echo 0; return; }
  cat "$cg/$file" 2>/dev/null || echo 0
}

interesting_process() {
  local comm=$1 cmd=$2
  case "$comm:$cmd" in
    tempo:*"tempo node "*|tempo:".bench-worktrees/"*" node "*|\
    bench:*"bench send "*|\
    txgen-tempo:*"txgen-tempo generate "*|\
    nu:*"bench-e2e.nu e2e"*|\
    Runner.Worker:*|Runner.Listener:*|\
    sccache:*|vector:*|vmagent:*|tailscaled:*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

sample_once() {
  local ts pid comm cmd ppid pgid etime rss vsz pss anon file current peak
  ts=$(now_ms)

  awk -v ts="$ts" -v label="$label" '
    /^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SReclaimable|SwapTotal|SwapFree|Dirty|Writeback):/ {
      gsub(":", "", $1);
      print "mem", ts, label, $1, $2;
    }
  ' OFS='\t' /proc/meminfo >>"$out"

  if [[ -r /proc/pressure/memory ]]; then
    while IFS= read -r line; do
      printf 'pressure\t%s\t%s\tmemory\t%s\n' "$ts" "$label" "$line" >>"$out"
    done </proc/pressure/memory
  fi

  ps -e -o pid=,ppid=,rss=,vsz=,comm=,args= --sort=-rss \
    | head -n 20 \
    | awk -v ts="$ts" -v label="$label" '
      {
        pid=$1; ppid=$2; rss=$3; vsz=$4; comm=$5;
        sub(/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]*/, "", $0);
        print "top", ts, label, pid, ppid, rss, vsz, comm, $0;
      }
    ' OFS='\t' >>"$out"

  for pid in /proc/[0-9]*; do
    pid=${pid##*/}
    [[ -r "/proc/$pid/comm" && -r "/proc/$pid/stat" ]] || continue
    comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
    cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
    [[ -n "$cmd" ]] || cmd="[$comm]"
    interesting_process "$comm" "$cmd" || continue

    read -r _ ppid pgid _ < <(awk '{ print $1, $4, $5, $0 }' "/proc/$pid/stat" 2>/dev/null || echo "0 0 0")
    read -r etime rss vsz < <(ps -o etime=,rss=,vsz= -p "$pid" 2>/dev/null || echo "- 0 0")
    pss=$(proc_field_kb "$pid" Pss)
    anon=$(proc_field_kb "$pid" Anonymous)
    file=$((rss > anon ? rss - anon : 0))
    current=$(cgroup_file_value "$pid" memory.current)
    peak=$(cgroup_file_value "$pid" memory.peak)
    printf 'proc\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$ts" "$label" "$pid" "$ppid" "$pgid" "$etime" "$comm" "$rss" "$vsz" \
      "$pss" "$anon" "$file" "$current" "$peak" "$cmd" >>"$out"
  done

  local avail used total
  read -r total avail < <(awk '
    $1 == "MemTotal:" { total=$2 }
    $1 == "MemAvailable:" { avail=$2 }
    END { print total, avail }
  ' /proc/meminfo)
  used=$((total - avail))
  printf 'BENCH_MEM_DEBUG ts=%s label=%s used_mib=%s available_mib=%s out=%s\n' \
    "$ts" "$label" "$((used / 1024))" "$((avail / 1024))" "$out"
}

write_header
while [[ -e "$sentinel" ]]; do
  sample_once
  sleep "$interval"
done
sample_once
