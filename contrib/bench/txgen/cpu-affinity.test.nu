use std assert
use ../cpu-layout.nu expand-cpu-list
source helpers.nu

# Check the real taskset inheritance path without starting nodes or sending RPCs.
let allowed = (open /proc/self/status | lines | where { |line| $line starts-with 'Cpus_allowed_list:' } | first | split row ':' | last | str trim)
let cpu = (expand-cpu-list $allowed | first | into string)
let result = (txgen-run-shell "awk '/Cpus_allowed_list/ { print $2 }' /proc/self/status | (read left; printf '%s\\n' \"$left\"; awk '/Cpus_allowed_list/ { print $2 }' /proc/self/status)" $cpu)
assert equal $result.exit_code 0
assert equal ($result.stdout | lines) [$cpu $cpu]
assert equal (txgen-run-shell 'exit 17' $cpu).exit_code 17
assert equal (txgen-run-shell 'printf unpinned' '').stdout 'unpinned'
assert equal (txgen-run-shell 'exit 19' '').exit_code 19
print 'txgen pipeline affinity tests passed'
