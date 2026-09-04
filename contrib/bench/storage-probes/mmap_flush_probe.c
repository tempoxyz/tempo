/* File-only MS_SYNC probe. Compile: cc -O2 -std=c11 -Wall -Wextra -Werror ...
 * Linux measurement target; macOS is supported for correctness smoke runs.
 * O_EXCL prevents opening existing data. Every file byte is initialized and
 * fsynced before measurements. The owned file is removed on normal/error exit.
 * An external timeout must bound blocked I/O; max-seconds only stops admission
 * of new measured batches and excludes initialization.
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#ifdef __linux__
#define _DEFAULT_SOURCE
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#define MIB UINT64_C(1048576)
static const char *owned_path;
static const char *owned_ready;
static int owned_fd = -1;
static volatile sig_atomic_t interrupted;
static void cleanup(void) {
    if (owned_fd >= 0) close(owned_fd);
    if (owned_path) unlink(owned_path);
    if (owned_ready) unlink(owned_ready);
}
static void on_signal(int sig) { interrupted = sig; }
static void die(const char *what) {
    fprintf(stderr, "mmap_flush_probe: %s: %s\n", what, strerror(errno));
    exit(1);
}
static void invalid(const char *what) {
    fprintf(stderr, "mmap_flush_probe: %s\n", what); exit(2);
}
static double now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) die("clock_gettime");
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static uint64_t unix_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t)) die("clock_gettime realtime");
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static uint64_t number(const char *s) {
    char *end;
    if (!s[0] || s[0] == '-') invalid("expected an unsigned integer");
    errno = 0;
    uint64_t n = strtoull(s, &end, 10);
    if (errno || *end) invalid("invalid integer");
    return n;
}
static uint64_t random64(uint64_t *state) {
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}
static uint64_t below(uint64_t *state, uint64_t bound) {
    uint64_t x, threshold = (uint64_t)(-bound) % bound;
    do { x = random64(state); } while (x < threshold);
    return x % bound;
}
static void write_all(int fd, const void *buffer, size_t len, off_t offset) {
    const unsigned char *p = buffer;
    while (len) {
        if (interrupted) { errno = EINTR; die("interrupted"); }
        ssize_t n = pwrite(fd, p, len, offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; die("pwrite"); }
        p += (size_t)n; len -= (size_t)n; offset += n;
    }
}
static void sync_file(int fd) {
    while (fsync(fd)) {
        if (errno == EINTR && !interrupted) continue;
        die("fsync");
    }
}
static void sync_mapping(void *address, size_t length) {
    while (msync(address, length, MS_SYNC)) {
        if (errno == EINTR && !interrupted) continue;
        die("msync(MS_SYNC)");
    }
}
static double cpu_seconds(struct timeval t) {
    return (double)t.tv_sec + (double)t.tv_usec / 1e6;
}
struct process_io {
    int available;
    uint64_t read_bytes, write_bytes, cancelled_write_bytes;
};
static struct process_io read_process_io(void) {
    struct process_io result = {0};
#ifdef __linux__
    FILE *file = fopen("/proc/self/io", "r");
    if (!file) return result;
    char line[256], key[64];
    uint64_t value;
    unsigned found = 0;
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%63[^:]: %" SCNu64, key, &value) != 2) continue;
        if (!strcmp(key, "read_bytes")) { result.read_bytes = value; found |= 1; }
        if (!strcmp(key, "write_bytes")) { result.write_bytes = value; found |= 2; }
        if (!strcmp(key, "cancelled_write_bytes")) { result.cancelled_write_bytes = value; found |= 4; }
    }
    result.available = found == 7 && !ferror(file);
    fclose(file);
#endif
    return result;
}
struct mapping_smaps {
    int available;
    uint64_t vmas, kernel_page_kib_min, kernel_page_kib_max;
    uint64_t mmu_page_kib_min, mmu_page_kib_max, rss_kib;
    uint64_t file_pmd_mapped_kib, anon_huge_pages_kib;
    uint64_t shared_dirty_kib, private_dirty_kib, thp_eligible_vmas;
};
static struct mapping_smaps read_mapping_smaps(const void *mapping, size_t size) {
    struct mapping_smaps result = {0};
#ifdef __linux__
    if (!mapping) return result;
    FILE *file = fopen("/proc/self/smaps", "r");
    if (!file) return result;
    uintptr_t low = (uintptr_t)mapping, high = low + size, start, end;
    char line[1024], key[64];
    uint64_t value;
    int matches = 0;
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) == 2) {
            matches = start < high && end > low;
            if (matches) ++result.vmas;
            continue;
        }
        if (!matches || sscanf(line, "%63[^:]: %" SCNu64, key, &value) != 2) continue;
        if (!strcmp(key, "KernelPageSize")) {
            if (!result.kernel_page_kib_min || value < result.kernel_page_kib_min) result.kernel_page_kib_min = value;
            if (value > result.kernel_page_kib_max) result.kernel_page_kib_max = value;
        } else if (!strcmp(key, "MMUPageSize")) {
            if (!result.mmu_page_kib_min || value < result.mmu_page_kib_min) result.mmu_page_kib_min = value;
            if (value > result.mmu_page_kib_max) result.mmu_page_kib_max = value;
        } else if (!strcmp(key, "Rss")) result.rss_kib += value;
        else if (!strcmp(key, "FilePmdMapped")) result.file_pmd_mapped_kib += value;
        else if (!strcmp(key, "AnonHugePages")) result.anon_huge_pages_kib += value;
        else if (!strcmp(key, "Shared_Dirty")) result.shared_dirty_kib += value;
        else if (!strcmp(key, "Private_Dirty")) result.private_dirty_kib += value;
        else if (!strcmp(key, "THPeligible") && value) ++result.thp_eligible_vmas;
    }
    result.available = result.vmas > 0 && !ferror(file);
    fclose(file);
#else
    (void)mapping; (void)size;
#endif
    return result;
}
static void print_mapping_smaps(struct mapping_smaps s) {
    if (!s.available) { printf("null"); return; }
    printf("{\"vmas\":%" PRIu64 ",\"kernel_page_kib_min\":%" PRIu64
           ",\"kernel_page_kib_max\":%" PRIu64 ",\"mmu_page_kib_min\":%" PRIu64
           ",\"mmu_page_kib_max\":%" PRIu64 ",\"rss_kib\":%" PRIu64
           ",\"file_pmd_mapped_kib\":%" PRIu64 ",\"anon_huge_pages_kib\":%" PRIu64
           ",\"shared_dirty_kib\":%" PRIu64 ",\"private_dirty_kib\":%" PRIu64
           ",\"thp_eligible_vmas\":%" PRIu64 "}", s.vmas, s.kernel_page_kib_min,
           s.kernel_page_kib_max, s.mmu_page_kib_min, s.mmu_page_kib_max, s.rss_kib,
           s.file_pmd_mapped_kib, s.anon_huge_pages_kib, s.shared_dirty_kib,
           s.private_dirty_kib, s.thp_eligible_vmas);
}
static void print_process_io_delta(struct process_io before, struct process_io after) {
    if (!before.available || !after.available) { printf("null"); return; }
    /* Linux block-layer accounting, not internal SSD/NAND writes. Values are
     * tiny relative to int64 for this bounded probe, including cancellation. */
    printf("{\"read_bytes\":%" PRId64 ",\"write_bytes\":%" PRId64
           ",\"cancelled_write_bytes\":%" PRId64 "}",
           (int64_t)after.read_bytes - (int64_t)before.read_bytes,
           (int64_t)after.write_bytes - (int64_t)before.write_bytes,
           (int64_t)after.cancelled_write_bytes - (int64_t)before.cancelled_write_bytes);
}
struct block_io {
    int available;
    uint64_t read_ios, read_sectors, write_ios, write_sectors;
};
static struct block_io read_block_io(const char *name) {
    struct block_io result = {0};
#ifdef __linux__
    if (!name) return result;
    char path[256], line[1024];
    snprintf(path, sizeof(path), "/sys/class/block/%s/stat", name);
    FILE *file = fopen(path, "r");
    if (!file) return result;
    uint64_t merged_read, merged_write, read_ms;
    if (fgets(line, sizeof(line), file))
        result.available = sscanf(line, "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
                                  " %" SCNu64 " %" SCNu64 " %" SCNu64,
                                  &result.read_ios, &merged_read, &result.read_sectors,
                                  &read_ms, &result.write_ios, &merged_write, &result.write_sectors) == 7;
    fclose(file);
#else
    (void)name;
#endif
    return result;
}
static void print_block_io_delta(struct block_io before, struct block_io after) {
    if (!before.available || !after.available || after.read_ios < before.read_ios ||
        after.write_ios < before.write_ios || after.read_sectors < before.read_sectors ||
        after.write_sectors < before.write_sectors) { printf("null"); return; }
    /* Kernel diskstats sectors are always 512 bytes, independent of the LBA size.
     * Whole-device counters may include other processes, and are not NAND I/O. */
    printf("{\"read_ios\":%" PRIu64 ",\"write_ios\":%" PRIu64
           ",\"read_bytes\":%" PRIu64 ",\"write_bytes\":%" PRIu64 "}",
           after.read_ios - before.read_ios, after.write_ios - before.write_ios,
           (after.read_sectors - before.read_sectors) * UINT64_C(512),
           (after.write_sectors - before.write_sectors) * UINT64_C(512));
}
static void mapping_advice(void *mapping, size_t size) {
    printf("{\"event\":\"mapping_advice\",\"madv_nohugepage\":");
#ifdef MADV_NOHUGEPAGE
    errno = 0;
    int nohuge_rc = madvise(mapping, size, MADV_NOHUGEPAGE);
    int nohuge_errno = nohuge_rc ? errno : 0;
    printf("{\"result\":%d,\"errno\":%d}", nohuge_rc, nohuge_errno);
#else
    printf("null");
#endif
    errno = 0;
    int random_rc = madvise(mapping, size, MADV_RANDOM);
    int random_errno = random_rc ? errno : 0;
    printf(",\"madv_random\":{\"result\":%d,\"errno\":%d}}\n", random_rc, random_errno);
}
static void usage(FILE *f) {
    fprintf(f,
      "Usage: mmap_flush_probe --file NEW_PATH [options]\n"
      "  --size-mib N       initialized file MiB (default 8192, maximum 65536)\n"
      "  --dirty-mib N      unique full pages touched per batch (default 256)\n"
      "  --batches N        maximum measured batches (default 8, maximum 1000)\n"
      "  --seed N           deterministic PRNG seed (default 42)\n"
      "  --pattern NAME     spread (default) or contiguous\n"
      "  --range NAME       full (default) or dirty\n"
      "  --method NAME      mmap (default) or pwrite (fsync control)\n"
      "  --init-write-kib N initialization syscall size: 4 or 1024 (default)\n"
      "  --mdbx-advice      apply MADV_NOHUGEPAGE and MADV_RANDOM to own mapping\n"
      "  --block-device N   read /sys/class/block/N/stat around each batch\n"
      "  --max-seconds N    stop starting batches after N measured seconds\n"
      "                    (default 60, maximum 600; excludes initialization)\n"
      "  --ready-file PATH --go-file PATH   optional external checkpoint barrier\n"
      "  --barrier-seconds N maximum barrier wait (default 30, maximum 120)\n"
      "full: one MS_SYNC over the file; dirty: one MS_SYNC from first to\n"
      "last touched page, NOT one syscall per page. Spread samples unique\n"
      "pages across the file. Contiguous touches one random dirty-mib window\n"
      "in shuffled page order. Range never changes the selected pages.\n"
      "pwrite uses identical selected pages then fsync; range must be full.\n"
      "The new file is fully written/fsynced before timing, and removed on\n"
      "exit. No cache dropping or system setting changes are performed.\n");
}
int main(int argc, char **argv) {
    const char *path = NULL, *pattern = "spread", *range = "full", *method = "mmap";
    const char *ready = NULL, *go = NULL;
    const char *block_device = NULL;
    uint64_t size_mib = 8192, dirty_mib = 256, batches = 8, seed = 42, max_seconds = 60;
    uint64_t barrier_seconds = 30, init_write_kib = 1024;
    int mdbx_advice = 0;
    static const struct option opts[] = {
      {"file", required_argument, NULL, 'f'}, {"size-mib", required_argument, NULL, 's'},
      {"dirty-mib", required_argument, NULL, 'd'}, {"batches", required_argument, NULL, 'b'},
      {"seed", required_argument, NULL, 'S'}, {"pattern", required_argument, NULL, 'p'},
      {"range", required_argument, NULL, 'r'}, {"max-seconds", required_argument, NULL, 't'},
      {"method", required_argument, NULL, 'm'}, {"help", no_argument, NULL, 'h'},
      {"ready-file", required_argument, NULL, 'R'}, {"go-file", required_argument, NULL, 'G'},
      {"barrier-seconds", required_argument, NULL, 'B'},
      {"init-write-kib", required_argument, NULL, 'I'},
      {"mdbx-advice", no_argument, NULL, 'A'},
      {"block-device", required_argument, NULL, 'D'},
      {NULL, 0, NULL, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (opt) {
          case 'f': path = optarg; break;
          case 's': size_mib = number(optarg); break;
          case 'd': dirty_mib = number(optarg); break;
          case 'b': batches = number(optarg); break;
          case 'S': seed = number(optarg); break;
          case 'p': pattern = optarg; break;
          case 'r': range = optarg; break;
          case 't': max_seconds = number(optarg); break;
          case 'm': method = optarg; break;
          case 'R': ready = optarg; break;
          case 'G': go = optarg; break;
          case 'B': barrier_seconds = number(optarg); break;
          case 'I': init_write_kib = number(optarg); break;
          case 'A': mdbx_advice = 1; break;
          case 'D': block_device = optarg; break;
          case 'h': usage(stdout); return 0;
          default: usage(stderr); return 2;
        }
    }
    if (!path || !path[0] || optind != argc) invalid("--file NEW_PATH is required");
    if (!size_mib || size_mib > 65536 || !dirty_mib || dirty_mib > size_mib)
        invalid("require 0 < dirty-mib <= size-mib <= 65536");
    if (!batches || batches > 1000 || !max_seconds || max_seconds > 600)
        invalid("require batches 1..1000 and max-seconds 1..600");
    if (init_write_kib != 4 && init_write_kib != 1024) invalid("init-write-kib must be 4 or 1024");
    if (block_device) {
        if (!block_device[0] || strlen(block_device) > 128 || !isalnum((unsigned char)block_device[0]))
            invalid("block-device must be a simple device name");
        for (const unsigned char *c = (const unsigned char *)block_device; *c; ++c)
            if (!isalnum(*c) && *c != '-' && *c != '_' && *c != '.')
                invalid("block-device must not contain paths or special characters");
    }
    if ((ready == NULL) != (go == NULL) || !barrier_seconds || barrier_seconds > 120)
        invalid("barrier requires both ready/go paths and seconds 1..120");
    if (ready) {
        if (!strcmp(ready, go) || !strcmp(ready, path) || !strcmp(go, path))
            invalid("data, ready and go paths must differ");
        struct stat existing;
        if (!lstat(go, &existing)) invalid("go file must not exist before initialization");
        if (errno != ENOENT) die("check go file");
    }
    int contiguous = !strcmp(pattern, "contiguous"), narrow = !strcmp(range, "dirty");
    int use_pwrite = !strcmp(method, "pwrite");
    if ((!contiguous && strcmp(pattern, "spread")) || (!narrow && strcmp(range, "full")) ||
        (!use_pwrite && strcmp(method, "mmap"))) invalid("unknown pattern, range, or method");
    if (use_pwrite && narrow) invalid("pwrite control requires --range full");
    if (use_pwrite && mdbx_advice) invalid("mdbx-advice requires method mmap");
    long os_page = sysconf(_SC_PAGESIZE);
    if (os_page <= 0 || MIB % (uint64_t)os_page || (uint64_t)os_page % sizeof(uint64_t))
        invalid("unsupported OS page size");
    uint64_t size = size_mib * MIB, dirty = dirty_mib * MIB, page = (uint64_t)os_page;
    uint64_t pages = size / page, count = dirty / page;
    if (size > SIZE_MAX || size > INT64_MAX) invalid("file does not fit address space");
    if (atexit(cleanup)) invalid("could not register cleanup");
    struct sigaction action;
    memset(&action, 0, sizeof(action)); action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) die("sigaction");
    owned_fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (owned_fd < 0) die("create NEW_PATH (existing files are refused)");
    owned_path = path;
    struct statvfs space;
    if (fstatvfs(owned_fd, &space)) die("fstatvfs");
    uint64_t available = (uint64_t)space.f_bavail * (uint64_t)space.f_frsize;
    if (available < size + 64 * MIB) invalid("insufficient space for file plus 64 MiB");
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("{\"event\":\"configuration\",\"version\":1,\"file_bytes\":%" PRIu64
           ",\"os_page_bytes\":%" PRIu64 ",\"dirty_bytes\":%" PRIu64
           ",\"dirty_pages\":%" PRIu64 ",\"batches_requested\":%" PRIu64
           ",\"seed\":%" PRIu64 ",\"pattern\":\"%s\",\"range\":\"%s\",\"method\":\"%s\","
           "\"max_measured_seconds\":%" PRIu64 ",\"init_write_kib\":%" PRIu64
           ",\"mdbx_advice\":%s,\"block_device\":",
           size, page, dirty, count, batches, seed, pattern, range, method, max_seconds,
           init_write_kib, mdbx_advice ? "true" : "false");
    if (block_device) printf("\"%s\"", block_device); else printf("null");
    printf(",\"cleanup\":true}\n");

    /* Every byte is written: fallocate/ftruncate alone can leave unwritten extents. */
    double init_start = now();
    size_t chunk = (size_t)MIB;
    uint64_t *buffer = malloc(chunk);
    if (!buffer) die("allocate initialization buffer");
    uint64_t init_rng = seed ^ UINT64_C(0x3c6ef372fe94f82b);
    for (size_t i = 0; i < chunk / sizeof(*buffer); ++i) buffer[i] = random64(&init_rng);
    for (uint64_t offset = 0; offset < size; offset += chunk)
        for (size_t within = 0; within < chunk; within += (size_t)init_write_kib * 1024)
            write_all(owned_fd, (unsigned char *)buffer + within, (size_t)init_write_kib * 1024,
                      (off_t)(offset + within));
    double init_write_end = now();
    sync_file(owned_fd);
    double init_end = now();
    struct stat st;
    if (fstat(owned_fd, &st)) die("fstat");
    if (!S_ISREG(st.st_mode) || (uint64_t)st.st_size != size) invalid("unexpected created file");
    printf("{\"event\":\"initialized\",\"file_bytes\":%" PRIu64
           ",\"allocated_bytes\":%" PRIu64 ",\"write_seconds\":%.9f,\"fsync_seconds\":%.9f}\n",
           size, (uint64_t)st.st_blocks * UINT64_C(512), init_write_end - init_start, init_end - init_write_end);
    unsigned char *mapping = NULL;
    if (!use_pwrite) {
        mapping = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE, MAP_SHARED, owned_fd, 0);
        if (mapping == MAP_FAILED) die("mmap");
        if (mdbx_advice) mapping_advice(mapping, (size_t)size);
    }
    uint64_t *selected = malloc((size_t)count * sizeof(*selected));
    size_t bitmap_bytes = (size_t)((pages + 7) / 8);
    unsigned char *bitmap = malloc(bitmap_bytes);
    if (!selected || !bitmap) die("allocate page selection");
    if (ready) {
        int ready_fd = open(ready, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (ready_fd < 0) die("create new ready file");
        owned_ready = ready;
        if (close(ready_fd)) die("close ready file");
        printf("{\"event\":\"barrier_ready\",\"timeout_seconds\":%" PRIu64 "}\n", barrier_seconds);
        double barrier_start = now();
        for (;;) {
            if (interrupted) { errno = EINTR; die("interrupted at barrier"); }
            int go_fd = open(go, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (go_fd >= 0) {
                struct stat flag;
                if (fstat(go_fd, &flag)) die("stat go file");
                if (!S_ISREG(flag.st_mode)) invalid("go flag must be a regular file");
                if (close(go_fd)) die("close go file");
                break;
            }
            if (errno != ENOENT) die("read go file");
            if (now() - barrier_start >= (double)barrier_seconds)
                invalid("timed out waiting for go file");
            struct timespec delay = {0, 50000000};
            while (nanosleep(&delay, &delay) && errno == EINTR && !interrupted) {}
        }
        printf("{\"event\":\"barrier_released\",\"wait_seconds\":%.9f}\n", now() - barrier_start);
    }
    uint64_t completed = 0;
    double measured_start = now(), total_touch = 0, total_sync = 0;
    for (uint64_t batch = 0; batch < batches && !interrupted; ++batch) {
        if (now() - measured_start >= (double)max_seconds) break;
        double prep_start = now();
        uint64_t rng = seed ^ ((batch + 1) * UINT64_C(0x9e3779b97f4a7c15));
        if (contiguous) {
            uint64_t base = below(&rng, pages - count + 1);
            for (uint64_t i = 0; i < count; ++i) selected[i] = base + i;
        } else {
            /* Floyd's uniform sampling without replacement: bounded O(count). */
            memset(bitmap, 0, bitmap_bytes);
            uint64_t i = 0;
            for (uint64_t j = pages - count; j < pages; ++j) {
                uint64_t t = below(&rng, j + 1);
                if (bitmap[t >> 3] & (1u << (t & 7))) t = j;
                bitmap[t >> 3] |= (unsigned char)(1u << (t & 7));
                selected[i++] = t;
            }
        }
        for (uint64_t i = count; i > 1; --i) {
            uint64_t j = below(&rng, i), swap = selected[i - 1];
            selected[i - 1] = selected[j]; selected[j] = swap;
        }
        uint64_t lo = pages, hi = 0, fingerprint = UINT64_C(1469598103934665603);
        for (uint64_t i = 0; i < count; ++i) {
            if (selected[i] < lo) lo = selected[i];
            if (selected[i] > hi) hi = selected[i];
            fingerprint = (fingerprint ^ selected[i]) * UINT64_C(1099511628211);
        }
        uint64_t sync_offset = narrow ? lo * page : 0;
        uint64_t sync_bytes = narrow ? (hi - lo + 1) * page : size;
        /* Observe outside the timed touch/sync and rusage window. No mapping,
         * cache, allocation or durability policy is changed by these reads. */
        struct mapping_smaps smaps_before = read_mapping_smaps(mapping, (size_t)size);
        struct process_io io_before = read_process_io();
        struct block_io block_before = read_block_io(block_device);
        struct rusage before, after;
        if (getrusage(RUSAGE_SELF, &before)) die("getrusage");
        uint64_t start_unix_ms = unix_ms();
        double touch_start = now();
        for (uint64_t i = 0; i < count; ++i) {
            if (interrupted) { errno = EINTR; die("interrupted during dirtying"); }
            uint64_t value = (batch + 1) ^ selected[i] ^ UINT64_C(0xa5a5a5a5a5a5a5a5);
            uint64_t *dest = use_pwrite ? buffer : (uint64_t *)(mapping + selected[i] * page);
            for (uint64_t word = 0; word < page / sizeof(uint64_t); ++word)
                dest[word] = value + word * UINT64_C(0x9e3779b97f4a7c15);
            if (use_pwrite) write_all(owned_fd, dest, (size_t)page, (off_t)(selected[i] * page));
        }
        double sync_start = now();
        uint64_t sync_start_unix_ms = unix_ms();
        if (use_pwrite) sync_file(owned_fd);
        else sync_mapping(mapping + sync_offset, (size_t)sync_bytes);
        double sync_end = now();
        uint64_t end_unix_ms = unix_ms();
        if (getrusage(RUSAGE_SELF, &after)) die("getrusage");
        struct process_io io_after = read_process_io();
        struct block_io block_after = read_block_io(block_device);
        struct mapping_smaps smaps_after = read_mapping_smaps(mapping, (size_t)size);
        total_touch += sync_start - touch_start; total_sync += sync_end - sync_start;
        ++completed;
        printf("{\"event\":\"batch\",\"batch\":%" PRIu64 ",\"file_bytes\":%" PRIu64
               ",\"start_unix_ms\":%" PRIu64 ",\"sync_start_unix_ms\":%" PRIu64 ",\"end_unix_ms\":%" PRIu64
               ",\"dirty_pages\":%" PRIu64 ",\"dirty_bytes\":%" PRIu64
               ",\"sync_offset\":%" PRIu64 ",\"sync_range_bytes\":%" PRIu64
               ",\"page_sequence_hash\":\"%016" PRIx64 "\",\"prepare_seconds\":%.9f,"
               "\"touch_seconds\":%.9f,\"sync_seconds\":%.9f,\"sync_call\":\"%s\","
               "\"user_seconds\":%.9f,\"system_seconds\":%.9f,\"minor_faults\":%ld,"
               "\"major_faults\":%ld,\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld",
               batch + 1, size, start_unix_ms, sync_start_unix_ms, end_unix_ms,
               count, dirty, sync_offset, sync_bytes, fingerprint,
               touch_start - prep_start, sync_start - touch_start, sync_end - sync_start,
               use_pwrite ? "fsync" : "msync_MS_SYNC",
               cpu_seconds(after.ru_utime) - cpu_seconds(before.ru_utime),
               cpu_seconds(after.ru_stime) - cpu_seconds(before.ru_stime),
               after.ru_minflt - before.ru_minflt, after.ru_majflt - before.ru_majflt,
               after.ru_nvcsw - before.ru_nvcsw, after.ru_nivcsw - before.ru_nivcsw);
        printf(",\"proc_self_io_delta\":"); print_process_io_delta(io_before, io_after);
        printf(",\"block_device_io_delta\":"); print_block_io_delta(block_before, block_after);
        printf(",\"mapping_smaps_before\":"); print_mapping_smaps(smaps_before);
        printf(",\"mapping_smaps_after\":"); print_mapping_smaps(smaps_after);
        printf("}\n");
    }
    if (mapping && munmap(mapping, (size_t)size)) die("munmap");
    printf("{\"event\":\"summary\",\"batches_completed\":%" PRIu64
           ",\"touch_seconds\":%.9f,\"sync_seconds\":%.9f,\"measured_seconds\":%.9f,"
           "\"stopped_by\":\"%s\",\"signal\":%d}\n",
           completed, total_touch, total_sync, now() - measured_start,
           interrupted ? "signal" : completed == batches ? "batches" : "max_seconds", (int)interrupted);
    free(bitmap); free(selected); free(buffer);
    return interrupted ? 128 + interrupted : 0;
}
