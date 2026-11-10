//! Binary entrypoint for the Tempo node.

#[global_allocator]
static ALLOC: exec_arenas::ArenaAlloc = exec_arenas::ArenaAlloc(reth_cli_util::allocator::new_allocator());

/// Compile-time jemalloc configuration for heap profiling.
///
/// tikv-jemallocator uses prefixed symbols, so the runtime `MALLOC_CONF` env var is ignored.
/// This exported symbol is read by jemalloc at init time to enable profiling unconditionally
/// when the `jemalloc-prof` feature is active.
///
/// See <https://github.com/jemalloc/jemalloc/wiki/Getting-Started>
#[cfg(all(feature = "jemalloc-prof", unix))]
#[unsafe(export_name = "_rjem_malloc_conf")]
static MALLOC_CONF: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

fn main() -> eyre::Result<()> {
    exec_arenas::init();
    tempo::tempo_main()
}

/// Experimental: Agave-style dedicated jemalloc arenas for execution threads (anza-xyz/agave#16374).
///
/// Env:
/// - TEMPO_EXEC_ARENAS=N            create N arenas and enable (unset/0 = off, stock behaviour)
/// - TEMPO_EXEC_ARENA_THREADS=a,b   thread-name prefixes to bind (default engine,payload-builder,prewarm)
/// - TEMPO_EXEC_ARENA_DECAY=never|default   dirty/muzzy decay for the arenas (default never, like Agave)
/// - TEMPO_EXEC_ARENA_TUNE=1|0      apply 16MiB oversize threshold + 64MiB retain grow limit (default 1)
mod exec_arenas {
    use reth_cli_util::allocator::Allocator;
    use std::{
        alloc::{GlobalAlloc, Layout},
        cell::Cell,
        ffi::{c_char, c_int, c_void},
        sync::{
            OnceLock,
            atomic::{AtomicBool, AtomicU32, Ordering},
        },
    };

    #[cfg(all(feature = "jemalloc", unix))]
    use reth_cli_util::allocator::tikv_jemalloc_sys::mallctl;

    pub struct ArenaAlloc(pub Allocator);

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static ARENAS: OnceLock<Vec<u32>> = OnceLock::new();
    static PREFIXES: OnceLock<Vec<Box<[u8]>>> = OnceLock::new();
    static NEXT: AtomicU32 = AtomicU32::new(0);
    pub static BOUND: AtomicU32 = AtomicU32::new(0);

    /// Re-check the thread name every CHECK_EVERY allocations, MAX_CHECKS times, because a new
    /// thread inherits its creator's comm until std renames it.
    const CHECK_EVERY: u32 = 1024;
    const MAX_CHECKS: u32 = 8;

    thread_local! {
        static ALLOCS: Cell<u32> = const { Cell::new(0) };
        static BUSY: Cell<bool> = const { Cell::new(false) };
        static BOUND_TO: Cell<u32> = const { Cell::new(u32::MAX) };
        static ORIG: Cell<u32> = const { Cell::new(0) };
    }

    unsafe extern "C" {
        fn prctl(option: c_int, ...) -> c_int;
    }
    const PR_GET_NAME: c_int = 16;

    #[cfg(all(feature = "jemalloc", unix))]
    unsafe fn ctl_write<T>(name: &[u8], mut v: T) -> c_int {
        unsafe {
            mallctl(
                name.as_ptr() as *const c_char,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut v as *mut T as *mut c_void,
                size_of::<T>(),
            )
        }
    }

    #[cfg(all(feature = "jemalloc", unix))]
    unsafe fn ctl_read<T: Default>(name: &[u8]) -> (c_int, T) {
        let mut v = T::default();
        let mut len = size_of::<T>();
        let rc = unsafe {
            mallctl(
                name.as_ptr() as *const c_char,
                &mut v as *mut T as *mut c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc, v)
    }

    pub fn init() {
        #[cfg(all(feature = "jemalloc", unix))]
        {
            let count: u32 =
                std::env::var("TEMPO_EXEC_ARENAS").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
            if std::env::var("TEMPO_EXEC_ARENA_REPORT").map(|v| v != "0").unwrap_or(true) {
                spawn_report();
            }
            if count == 0 {
                return;
            }
            let prefixes = std::env::var("TEMPO_EXEC_ARENA_THREADS")
                .unwrap_or_else(|_| "engine,payload-builder,prewarm".to_string());
            let decay_never = std::env::var("TEMPO_EXEC_ARENA_DECAY").map(|v| v != "default").unwrap_or(true);
            let tune = std::env::var("TEMPO_EXEC_ARENA_TUNE").map(|v| v != "0").unwrap_or(true);
            let mut arenas = Vec::new();
            for _ in 0..count {
                let (rc, id): (c_int, u32) = unsafe { ctl_read(b"arenas.create\0") };
                assert_eq!(rc, 0, "arenas.create failed: {rc}");
                let set = |k: &str, rc: c_int| assert_eq!(rc, 0, "mallctl arena.{id}.{k} failed: {rc}");
                if decay_never {
                    let d = format!("arena.{id}.dirty_decay_ms\0");
                    set("dirty_decay_ms", unsafe { ctl_write::<isize>(d.as_bytes(), -1) });
                    let m = format!("arena.{id}.muzzy_decay_ms\0");
                    set("muzzy_decay_ms", unsafe { ctl_write::<isize>(m.as_bytes(), -1) });
                }
                if tune {
                    let o = format!("arena.{id}.oversize_threshold\0");
                    set("oversize_threshold", unsafe { ctl_write::<usize>(o.as_bytes(), 16 << 20) });
                    let r = format!("arena.{id}.retain_grow_limit\0");
                    set("retain_grow_limit", unsafe { ctl_write::<usize>(r.as_bytes(), 64 << 20) });
                }
                arenas.push(id);
            }
            eprintln!(
                "exec-arenas: enabled arenas={arenas:?} threads={prefixes} decay_never={decay_never} tune={tune}"
            );
            let _ = ARENAS.set(arenas);
            let _ = PREFIXES.set(
                prefixes.split(',').filter(|p| !p.is_empty()).map(|p| p.as_bytes().into()).collect(),
            );
            ENABLED.store(true, Ordering::Release);

        }
    }

    #[cfg(all(feature = "jemalloc", unix))]
    fn spawn_report() {
        std::thread::Builder::new()
            .name("arena-report".into())
            .spawn(|| loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let _ = unsafe { ctl_write::<u64>(b"epoch\0", 1) };
                let mut line = String::from("exec-arenas: report");
                for id in ARENAS.get().map(|a| a.as_slice()).unwrap_or(&[]) {
                    let n = format!("stats.arenas.{id}.nthreads\0");
                    let (_, nthreads): (c_int, u32) = unsafe { ctl_read(n.as_bytes()) };
                    let r = format!("stats.arenas.{id}.resident\0");
                    let (_, resident): (c_int, usize) = unsafe { ctl_read(r.as_bytes()) };
                    line.push_str(&format!(" a{id}:threads={nthreads},resident_mib={}", resident >> 20));
                }
                let (_, res): (c_int, usize) = unsafe { ctl_read(b"stats.resident\0") };
                let (_, alloc): (c_int, usize) = unsafe { ctl_read(b"stats.allocated\0") };
                let (_, dp): (c_int, u64) = unsafe { ctl_read(b"stats.arenas.4096.dirty_purged\0") };
                let (_, mp): (c_int, u64) = unsafe { ctl_read(b"stats.arenas.4096.muzzy_purged\0") };
                let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
                let f: Vec<&str> = stat.rsplit(')').next().unwrap_or("").split_whitespace().collect();
                let minflt = f.get(7).copied().unwrap_or("0");
                let majflt = f.get(9).copied().unwrap_or("0");
                let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
                let rss = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap_or("").split_whitespace().nth(1).unwrap_or("0").to_string();
                line.push_str(&format!(
                    " total_resident_mib={} allocated_mib={} rss_kib={rss} dirty_purged_pages={dp} muzzy_purged_pages={mp} minflt={minflt} majflt={majflt} bound={}",
                    res >> 20, alloc >> 20, BOUND.load(Ordering::Relaxed)
                ));
                eprintln!("{line}");
            })
            .expect("spawn arena-report");
    }

    #[inline(always)]
    fn maybe_bind() {
        if !ENABLED.load(Ordering::Relaxed) {
            return;
        }
        let n = ALLOCS.with(|c| {
            let n = c.get();
            if n < CHECK_EVERY * MAX_CHECKS {
                c.set(n + 1);
            }
            n
        });
        if n >= CHECK_EVERY * MAX_CHECKS || n % CHECK_EVERY != 0 {
            return;
        }
        #[cfg(all(feature = "jemalloc", unix))]
        BUSY.with(|busy| {
            if busy.replace(true) {
                return;
            }
            let mut buf = [0u8; 17];
            unsafe { prctl(PR_GET_NAME, buf.as_mut_ptr()) };
            let len = buf.iter().position(|b| *b == 0).unwrap_or(16);
            let name = &buf[..len];
            let wants = PREFIXES.get().is_some_and(|ps| ps.iter().any(|p| name.starts_with(p)));
            let cur = BOUND_TO.with(|b| b.get());
            if wants && cur == u32::MAX {
                let arenas = ARENAS.get().unwrap();
                let idx = NEXT.fetch_add(1, Ordering::Relaxed) as usize % arenas.len();
                let arena = arenas[idx];
                let (_, orig): (c_int, u32) = unsafe { ctl_read(b"thread.arena\0") };
                ORIG.with(|o| o.set(orig));
                if unsafe { ctl_write::<u32>(b"thread.arena\0", arena) } == 0 {
                    BOUND_TO.with(|b| b.set(arena));
                    BOUND.fetch_add(1, Ordering::Relaxed);
                }
            } else if !wants && cur != u32::MAX {
                // Inherited the creator's name before std renamed us: restore the original arena.
                let orig = ORIG.with(|o| o.get());
                if unsafe { ctl_write::<u32>(b"thread.arena\0", orig) } == 0 {
                    BOUND_TO.with(|b| b.set(u32::MAX));
                    BOUND.fetch_sub(1, Ordering::Relaxed);
                }
            }
            busy.set(false);
        });
    }

    unsafe impl GlobalAlloc for ArenaAlloc {
        #[inline]
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            maybe_bind();
            unsafe { self.0.alloc(layout) }
        }
        #[inline]
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            maybe_bind();
            unsafe { self.0.alloc_zeroed(layout) }
        }
        #[inline]
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { self.0.dealloc(ptr, layout) }
        }
        #[inline]
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            maybe_bind();
            unsafe { self.0.realloc(ptr, layout, new_size) }
        }
    }
}
