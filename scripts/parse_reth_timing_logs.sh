#!/bin/bash
# parse_logs.sh - Parse Reth logs and extract timing metrics per block
#
# Usage: ./parse_logs.sh <logfile>
#        cat logs.txt | ./parse_logs.sh
#
# Output: CSV with columns: block_number, state_root_elapsed_us, block_added_elapsed_us, builder_finish_elapsed_us

set -eo pipefail

# Read from file or stdin
if [ $# -gt 0 ]; then
    INPUT="$1"
else
    INPUT="/dev/stdin"
fi

# Print CSV header
echo "block_number,state_root_elapsed_us,block_added_elapsed_us,builder_finish_elapsed_us"

# Strip ANSI color codes and process with awk
sed 's/\x1b\[[0-9;]*m//g' < "$INPUT" | awk '
function time_to_us(time_str) {
    # Convert time string to microseconds
    if (time_str ~ /µs$/) {
        gsub(/µs/, "", time_str)
        return int(time_str + 0.5)
    } else if (time_str ~ /ms$/) {
        gsub(/ms/, "", time_str)
        return int(time_str * 1000 + 0.5)
    } else if (time_str ~ /ns$/) {
        gsub(/ns/, "", time_str)
        return int(time_str / 1000 + 0.5)
    } else if (time_str ~ /s$/ && time_str !~ /[mn]s$/) {
        gsub(/s/, "", time_str)
        return int(time_str * 1000000 + 0.5)
    }
    return 0
}

# Extract state root calculation time
/Calculated state root/ && /root_elapsed=/ && /number:/ {
    # Extract block number
    for (i = 1; i <= NF; i++) {
        if ($i == "number:") {
            block = $(i+1)
            gsub(/,/, "", block)
            break
        }
    }
    # Extract elapsed time
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^root_elapsed=/) {
            split($i, parts, "=")
            elapsed = parts[2]
            state_root[block] = time_to_us(elapsed)
            break
        }
    }
}

# Extract block added time
/Block added to canonical chain/ && /elapsed=/ {
    # Extract block number
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^number=/) {
            split($i, parts, "=")
            block = parts[2]
            break
        }
    }
    # Extract last elapsed time
    for (i = NF; i >= 1; i--) {
        if ($i ~ /^elapsed=/) {
            split($i, parts, "=")
            elapsed = parts[2]
            block_added[block] = time_to_us(elapsed)
            break
        }
    }
}

# Extract builder finish time - parent_number is in the log context part
/builder_finish_elapsed=/ && /parent_number=/ {
    # Extract parent_number using gsub
    line = $0
    # Remove everything before parent_number=
    sub(/.*parent_number=/, "", line)
    # Extract just the number (stop at first space)
    sub(/ .*/, "", line)
    parent_block = line
    block = parent_block + 1

    # Extract builder_finish_elapsed time
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^builder_finish_elapsed=/) {
            split($i, parts, "=")
            elapsed = parts[2]
            builder_finish[block] = time_to_us(elapsed)
            break
        }
    }
}

END {
    # Collect all unique block numbers and print
    for (block in state_root) {
        if (!(block in seen)) {
            seen[block] = 1
            sr = state_root[block]
            ba = (block in block_added) ? block_added[block] : ""
            bf = (block in builder_finish) ? builder_finish[block] : ""
            print block "," sr "," ba "," bf
        }
    }
    for (block in block_added) {
        if (!(block in seen)) {
            seen[block] = 1
            sr = ""
            ba = block_added[block]
            bf = (block in builder_finish) ? builder_finish[block] : ""
            print block "," sr "," ba "," bf
        }
    }
    for (block in builder_finish) {
        if (!(block in seen)) {
            seen[block] = 1
            sr = ""
            ba = ""
            bf = builder_finish[block]
            print block "," sr "," ba "," bf
        }
    }
}
' | sort -t, -k1 -n
