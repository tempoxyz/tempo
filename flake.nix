{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/25.11";
    utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    fenix.url = "github:nix-community/fenix";
  };

  outputs =
    {
      nixpkgs,
      utils,
      crane,
      fenix,
      ...
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        # A useful helper for folding a list of `prevSet -> newSet` functions
        # into an attribute set.
        composeAttrOverrides =
          defaultAttrs: overrides: builtins.foldl' (acc: f: acc // (f acc)) defaultAttrs overrides;

        cargoTarget = pkgs.stdenv.hostPlatform.rust.rustcTargetSpec;
        cargoTargetEnvVar = builtins.replaceStrings [ "-" ] [ "_" ] (pkgs.lib.toUpper cargoTarget);

        cargoTOML = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        packageVersion = cargoTOML.workspace.package.version;

        rustStable = fenix.packages.${system}.stable.withComponents [
          "cargo"
          "rustc"
          "rust-src"
        ];
        rustNightly = fenix.packages.${system}.latest;

        craneLib = (crane.mkLib pkgs).overrideToolchain rustStable;

        nativeBuildInputs = [
          pkgs.pkg-config
          pkgs.perl
        ];

        withLibgit2 = prev: {
          buildInputs = prev.buildInputs or [ ] ++ [
            pkgs.libgit2
          ];
          LD_LIBRARY_PATH = "${pkgs.libgit2}/lib";
        };

        withClang = prev: {
          buildInputs = prev.buildInputs or [ ] ++ [
            pkgs.clang
          ];
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        };

        withMaxPerf = prev: {
          cargoBuildCommand = "cargo build --profile=maxperf";
          RUSTFLAGS = prev.RUSTFLAGS or [ ] ++ [
            "-Ctarget-cpu=native"
          ];
        };

        withMold = prev: {
          buildInputs = prev.buildInputs or [ ] ++ [
            pkgs.mold
          ];
          "CARGO_TARGET_${cargoTargetEnvVar}_LINKER" = "${pkgs.llvmPackages.clangUseLLVM}/bin/clang";
          RUSTFLAGS = prev.RUSTFLAGS or [ ] ++ [
            "-Clink-arg=-fuse-ld=${pkgs.mold}/bin/mold"
          ];
        };

        mkTempo =
          overrides:
          craneLib.buildPackage (
            composeAttrOverrides {
              pname = "tempo";
              version = packageVersion;
              src = ./.;
              inherit nativeBuildInputs;
              doCheck = false;
              LD_LIBRARY_PATH = "${pkgs.libgit2}/lib";
            } overrides
          );

      in
      {
        packages = rec {
          tempo = mkTempo (
            [
              withClang
              withLibgit2
              withMaxPerf
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              withMold
            ]
          );

          default = tempo;
        };

        devShell =
          let
            overrides = [
              withClang
              withLibgit2
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              withMold
            ];
          in
          craneLib.devShell (
            composeAttrOverrides {
              packages = nativeBuildInputs ++ [
                rustNightly.rust-analyzer
                rustNightly.rustfmt
                pkgs.cargo-nextest
              ];

            } overrides
          );
      }
    );
}
