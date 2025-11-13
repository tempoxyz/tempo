#!/bin/bash

# Script to build cargo docs with the same flags as used in CI

# Navigate to the root directory
cd .. || exit 1

echo "Building cargo docs..."

# Build the documentation
export RUSTDOCFLAGS="--cfg docsrs --show-type-layout --generate-link-to-definition --enable-index-page -Zunstable-options"
cargo docs

echo "Cargo docs built successfully at ./target/doc"