# Owned benchmark tool installation

bench-owned-install.py wraps the existing Cargo install invocation. It creates an
exclusive `.bench-txgen-install-<random>` directory in the validated checkout,
containing only this invocation's generated target/build and temporary files.
The install arguments, pinned git revision, feature/profile/toolchain/Rust flags,
Cargo installation root and Cargo registry/git cache are retained. Both compiler
wrapper variables are explicitly empty for this install only, preventing a shared
sccache daemon from inheriting a removed temporary directory. The helper accepts
only sccache/unset wrappers in environment and user Cargo configuration; custom
code-generation wrappers/config includes fail closed. This disables compiler-cache
use for this installation and can increase install build time. It neither stops
nor cleans shared caches. This contains generated files; shared
caches can still grow independently.

On ordinary success, failure, SIGINT or SIGTERM, the supervisor stops/reaps only
its Cargo process group before cleanup. Linux child-subreaper mode handles compiler
grandchildren left behind when Cargo exits. The group leader remains unreaped
until the last signal, preventing a reused process-group ID from being signaled.
Cleanup is relative to a held directory descriptor, requires the original owned
directory inode/device, and uses symlink-resistant rmtree. A replaced directory
or an unreaped process causes cleanup refusal rather than deleting unknown data.

An abrupt SIGKILL/power loss cannot guarantee cleanup. Existing historical
/tmp directories have no new ownership proof and are not touched. This helper
contains future ordinary install intermediates; it is not historical reclamation
or an assurance that the runner has sufficient free space.

Validation:

    python3 -m unittest discover -s .github/scripts -p test_bench_owned_install.py

The behavioral tests execute real synthetic Cargo processes, including nonzero
exit with a live grandchild, SIGTERM cancellation, path replacement, and preserved
arguments/settings. A separate tiny offline Cargo/Rust installation was also run:
the installed executable remained usable after generated files were removed.
