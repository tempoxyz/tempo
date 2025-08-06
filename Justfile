cross_compile := "true"
cargo_build_binary := if cross_compile == "true" { "cross" } else { "cargo" }
act_debug_mode := env("ACT", "false")

[group('deps')]
install-cross:
    cargo install cross --git https://github.com/cross-rs/cross

[group('build')]
[doc('Builds all tempo binaries in cargo release mode')]
build-all-release extra_args="": (_build-release "tempo" extra_args)

[group('build')]
[doc('Builds all tempo binaries')]
build-all extra_args="": (_build "tempo" extra_args)

_build-release binary extra_args="": (_build binary "-r " + extra_args)

_build binary extra_args="":
    CROSS_CONTAINER_IN_CONTAINER={{act_debug_mode}} RUSTFLAGS="-C link-arg=-lgcc -Clink-arg=-static-libgcc" \
        {{cargo_build_binary}} build {{extra_args}} --target x86_64-unknown-linux-gnu --bin {{binary}}
