#!/bin/sh
# LazyFS and fault patch from tempoxyz/bedrock at 0e92d1b1; immutable archives, byte hashes.
set -eu
OUT=${1:?expected build directory}
PATCH_DIR=$(realpath "$(dirname "$0")")
mkdir -p "$OUT"
cd "$OUT"
fetch() {
    name=$1 url=$2 hash=$3
    curl --fail --location --retry 3 "$url" -o "$name.tar.gz"
    echo "$hash  $name.tar.gz" | sha256sum -c -
    mkdir "$name"
    tar -xzf "$name.tar.gz" --strip-components=1 -C "$name"
}
fetch lazyfs https://codeload.github.com/dsrhaslab/lazyfs/tar.gz/fa7d32ee9710d55a7e529ac3c375f6616563c78b d6f5e82d580d0ec7f38c0e3a44ad0045a7ccf2b8cd68afdd61b1904900dc587f
fetch toml11 https://codeload.github.com/ToruNiina/toml11/tar.gz/dcfe39a783a94e8d52c885e5883a6fbb21529019 948b8bffc7cf3d10cbdcf718b2441943e599e61a92f1146a919de6a09cb912f9
fetch spdlog https://codeload.github.com/gabime/spdlog/tar.gz/76fb40d95455f249bd70824ecfcae7a8f0930fa3 4530d53b86d45228a5b8982a8f4fe7d95d3ba8e1944858d3f663732c7e949cb7
cd lazyfs
patch -p1 < "$PATCH_DIR/bedrock.patch"
patch -p1 < "$PATCH_DIR/adapter.patch"
c++ -std=c++17 -O2 -o lazyfs.bin \
    -Ilibs/libpcache/include -Ilazyfs/include -I../toml11 -I../spdlog/include \
    $(find libs/libpcache/src -name '*.cpp') \
    lazyfs/src/*.cpp lazyfs/include/lazyfs/fusepp/Fuse.cpp \
    $(pkg-config --cflags --libs fuse3) -lpthread
