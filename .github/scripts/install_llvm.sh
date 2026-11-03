#!/usr/bin/env bash
# Installs LLVM on Ubuntu and exports the paths llvm-sys reads.
set -eo pipefail

version=${1:-23}
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sudo "$script_dir/install_llvm_ubuntu.sh" "$version"
prefix="$(llvm-config --prefix)"
version_major_minor="$(llvm-config --version | awk -F. '{ print $1 $2 }')"
if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "LLVM_SYS_${version_major_minor}_PREFIX=${prefix}" >> "$GITHUB_ENV"
    echo "LLVM_CONFIG_PATH=$(which llvm-config)" >> "$GITHUB_ENV"
fi
