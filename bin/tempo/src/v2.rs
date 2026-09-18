//! Fixed T11 node. Historical execution is served by the external v1 binary.

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

fn main() -> eyre::Result<()> {
    tempo::tempo_main()
}
