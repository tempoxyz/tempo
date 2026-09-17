// Release/LTO survival proof for a future opt-in collector registration hook.
// No native identity is passed or exported; the uprobe observes only an ordinal.
#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn reth_lifecycle_thread_register(ordinal: u64, epoch: u64) {
    std::hint::black_box((ordinal, epoch));
}

fn main() {
    reth_lifecycle_thread_register(std::hint::black_box(1), std::hint::black_box(123));
    reth_lifecycle_thread_register(std::hint::black_box(2), std::hint::black_box(123));
}
