/* File-only MS_SYNC probe. Compile: cc -O2 -std=c11 -Wall -Wextra -Werror ...
 * Linux measurement target; macOS is supported for correctness smoke runs.
 * O_EXCL prevents opening existing data. Every file byte is initialized and
 * fsynced before measurements. The owned file is removed on normal/error exit.
 * An external timeout must bound blocked I/O; max-seconds only stops admission
 * of new measured batches and excludes initialization.
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include <errno.h>
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
    uint64_t size_mib = 8192, dirty_mib = 256, batches = 8, seed = 42, max_seconds = 60;
    uint64_t barrier_seconds = 30;
    static const struct option opts[] = {
      {"file", required_argument, NULL, 'f'}, {"size-mib", required_argument, NULL, 's'},
      {"dirty-mib", required_argument, NULL, 'd'}, {"batches", required_argument, NULL, 'b'},
      {"seed", required_argument, NULL, 'S'}, {"pattern", required_argument, NULL, 'p'},
      {"range", required_argument, NULL, 'r'}, {"max-seconds", required_argument, NULL, 't'},
      {"method", required_argument, NULL, 'm'}, {"help", no_argument, NULL, 'h'},
      {"ready-file", required_argument, NULL, 'R'}, {"go-file", required_argument, NULL, 'G'},
      {"barrier-seconds", required_argument, NULL, 'B'},
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
          case 'h': usage(stdout); return 0;
          default: usage(stderr); return 2;
        }
    }
    if (!path || !path[0] || optind != argc) invalid("--file NEW_PATH is required");
    if (!size_mib || size_mib > 65536 || !dirty_mib || dirty_mib > size_mib)
        invalid("require 0 < dirty-mib <= size-mib <= 65536");
    if (!batches || batches > 1000 || !max_seconds || max_seconds > 600)
        invalid("require batches 1..1000 and max-seconds 1..600");
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
           "\"max_measured_seconds\":%" PRIu64 ",\"cleanup\":true}\n",
           size, page, dirty, count, batches, seed, pattern, range, method, max_seconds);

    /* Every byte is written: fallocate/ftruncate alone can leave unwritten extents. */
    double init_start = now();
    size_t chunk = (size_t)MIB;
    uint64_t *buffer = malloc(chunk);
    if (!buffer) die("allocate initialization buffer");
    uint64_t init_rng = seed ^ UINT64_C(0x3c6ef372fe94f82b);
    for (size_t i = 0; i < chunk / sizeof(*buffer); ++i) buffer[i] = random64(&init_rng);
    for (uint64_t offset = 0; offset < size; offset += chunk)
        write_all(owned_fd, buffer, chunk, (off_t)offset);
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
        total_touch += sync_start - touch_start; total_sync += sync_end - sync_start;
        ++completed;
        printf("{\"event\":\"batch\",\"batch\":%" PRIu64 ",\"file_bytes\":%" PRIu64
               ",\"start_unix_ms\":%" PRIu64 ",\"sync_start_unix_ms\":%" PRIu64 ",\"end_unix_ms\":%" PRIu64
               ",\"dirty_pages\":%" PRIu64 ",\"dirty_bytes\":%" PRIu64
               ",\"sync_offset\":%" PRIu64 ",\"sync_range_bytes\":%" PRIu64
               ",\"page_sequence_hash\":\"%016" PRIx64 "\",\"prepare_seconds\":%.9f,"
               "\"touch_seconds\":%.9f,\"sync_seconds\":%.9f,\"sync_call\":\"%s\","
               "\"user_seconds\":%.9f,\"system_seconds\":%.9f,\"minor_faults\":%ld,"
               "\"major_faults\":%ld,\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld}\n",
               batch + 1, size, start_unix_ms, sync_start_unix_ms, end_unix_ms,
               count, dirty, sync_offset, sync_bytes, fingerprint,
               touch_start - prep_start, sync_start - touch_start, sync_end - sync_start,
               use_pwrite ? "fsync" : "msync_MS_SYNC",
               cpu_seconds(after.ru_utime) - cpu_seconds(before.ru_utime),
               cpu_seconds(after.ru_stime) - cpu_seconds(before.ru_stime),
               after.ru_minflt - before.ru_minflt, after.ru_majflt - before.ru_majflt,
               after.ru_nvcsw - before.ru_nvcsw, after.ru_nivcsw - before.ru_nivcsw);
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
