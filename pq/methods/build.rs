//! Compile the guest and derive the exact image ID from its ELF.

fn main() {
    risc0_build::embed_methods();
}
