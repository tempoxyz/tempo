#!/usr/bin/env bash

set -eo pipefail

# List of crates to check for no_std compatibility.
# These crates are expected to build without std on bare-metal targets.
no_std_crates=(
    tempo-contracts
)

for crate in "${no_std_crates[@]}"; do
    echo "Checking $crate..."
    cargo +stable build -p "$crate" --target riscv32imac-unknown-none-elf --no-default-features
done

echo "All no_std checks passed!"
