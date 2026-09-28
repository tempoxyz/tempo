use reth_codecs::Compact;
use reth_primitives_traits::Bytecode;
use std::{hint::black_box, time::Instant};

#[cfg(jemalloc)]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn cpu_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

fn usage() -> libc::rusage {
    let mut value = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut value) }, 0);
    value
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: bytecode-codec-diagnostic RECORDS_FILE");
    let data = std::fs::read(path).unwrap();
    let mut input = data.as_slice();
    let mut records = Vec::new();
    while !input.is_empty() {
        let length = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
        records.push(input[4..4 + length].to_vec());
        input = &input[4 + length..];
    }
    assert_eq!(records.len(), 512);
    for i in 512..8192 {
        records.push(records[i % 512].clone());
    }
    let allocator = if cfg!(jemalloc) { "jemalloc" } else { "system" };
    for trial in 0..6 {
        for corpus in [512, 8192] {
            for retain in [false, true] {
                let mut held = Vec::with_capacity(2250);
                let mut decode_ns = 0;
                let mut drop_ns = 0;
                let before_usage = usage();
                let before_cpu = cpu_ns();
                let before = Instant::now();
                for batch in 0..32 {
                    let decode_start = Instant::now();
                    for i in 0..2250 {
                        let bytes = &records[((batch * 2250 + i) * 317 + trial * 73) % corpus];
                        let (code, tail) = Bytecode::from_compact(black_box(bytes), bytes.len());
                        assert!(tail.is_empty());
                        assert_eq!(code.len(), 24576);
                        black_box(&code);
                        if retain {
                            held.push(code);
                        }
                    }
                    decode_ns += decode_start.elapsed().as_nanos();
                    let drop_start = Instant::now();
                    held.clear();
                    drop_ns += drop_start.elapsed().as_nanos();
                }
                let wall_us = before.elapsed().as_nanos() as f64 / 1000.0;
                let cpu_us = (cpu_ns() - before_cpu) as f64 / 1000.0;
                let after_usage = usage();
                println!(
                    "{{\"kind\":\"codec\",\"allocator\":\"{allocator}\",\"trial\":{trial},\"corpus_records\":{corpus},\"retain_batch\":{retain},\"operations\":72000,\"wall_us\":{wall_us},\"cpu_us\":{cpu_us},\"decode_us\":{},\"drop_us\":{},\"major_faults\":{},\"minor_faults\":{}}}",
                    decode_ns as f64 / 1000.0,
                    drop_ns as f64 / 1000.0,
                    after_usage.ru_majflt - before_usage.ru_majflt,
                    after_usage.ru_minflt - before_usage.ru_minflt
                );
            }
        }
    }
}
