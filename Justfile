cross_compile := "false"
cargo_build_binary := if cross_compile == "true" { "cross" } else { "cargo" }
act_debug_mode := env("ACT", "false")

[group('deps')]
install-cross:
    cargo install cross --git https://github.com/cross-rs/cross

[group('build')]
[doc('Builds all tempo binaries in cargo release mode')]
build-all-release extra_args="": (build-release "tempo" extra_args)

[group('build')]
[doc('Builds all tempo binaries')]
build-all extra_args="": (build "tempo" extra_args)

build-release binary extra_args="": (build binary "-r " + extra_args)

build binary extra_args="":
    {{cargo_build_binary}} build {{extra_args}} --bin {{binary}}

mod scripts

[group('dev')]
tempo-dev-up: scripts::tempo-dev-up
tempo-dev-down: scripts::tempo-dev-down

[group('test')]
feature-test: scripts::auto-7702-delegation  scripts::basic-transfer scripts::registrar-delegation scripts::create-tip20-token scripts::fee-amm

fee-amm: scripts::fee-amm
