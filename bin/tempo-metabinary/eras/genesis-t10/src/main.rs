//! Frozen Genesis through T10 worker for the Tempo metabinary.

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

fn main() -> eyre::Result<()> {
    tempo::tempo_main()
}
