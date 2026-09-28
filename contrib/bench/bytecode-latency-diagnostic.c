#define main page_diagnostic_main
#include "bytecode-page-diagnostic.c"
#undef main
#include <sched.h>
#include <sys/prctl.h>

/* The early-prefetch control uses saved offsets, not a proposed provider API.
 * It isolates the first-page dependency without modifying the node or MDBX. */
enum { LATENCY_TRIALS = 9, STAGES = 4 };
typedef struct { uint64_t wall, cpu; } Stamp;
typedef struct { uint64_t wall[STAGES], cpu[STAGES]; } Times;
static off_t offsets[RECORDS];
static const char *stage_names[] = {"early_hint", "lookup_or_read", "late_hint", "copy"};
static const char *mode_names[] = {
    "prefix", "serial_full", "late_prefetch", "early_prefetch",
    "pread_4k", "pread_28k", "pread_4k_then_24k",
    "direct_4k", "direct_28k", "direct_4k_then_24k"
};
static const char *trace_names[] = {
    "lat-prefix", "lat-serial", "lat-late", "lat-early", "lat-pread4",
    "lat-pread28", "lat-pread2", "lat-direct4", "lat-direct28", "lat-direct2"
};

static uint64_t ns(clockid_t clock) {
    struct timespec t;
    require(clock_gettime(clock, &t) == 0, "clock_gettime failed");
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static Stamp stamp(void) {
    Stamp s = {.wall = ns(CLOCK_MONOTONIC), .cpu = ns(CLOCK_THREAD_CPUTIME_ID)};
    return s;
}
static void add_time(Times *times, int stage, Stamp start) {
    Stamp end = stamp();
    times->wall[stage] += end.wall - start.wall;
    times->cpu[stage] += end.cpu - start.cpu;
}
static double timeval_us(struct timeval t) { return t.tv_sec * 1e6 + t.tv_usec; }
static void hint(const void *ptr, size_t length) {
    uintptr_t start = (uintptr_t)ptr & ~(uintptr_t)(PAGE_BYTES - 1);
    size_t bytes = ((uintptr_t)ptr - start + length + PAGE_BYTES - 1) / PAGE_BYTES * PAGE_BYTES;
    require(madvise((void *)start, bytes, MADV_WILLNEED) == 0, "madvise failed");
}
static void output_measurement(const char *mode, const char *temperature, int trial,
                               unsigned count, Sample a, Sample b, Times times) {
    require(b.rios >= a.rios && b.cgroup_read_bytes >= a.cgroup_read_bytes, "I/O counter reset");
    double wall = (b.time.tv_sec - a.time.tv_sec) * 1e6 + (b.time.tv_nsec - a.time.tv_nsec) / 1e3;
    double user = timeval_us(b.usage.ru_utime) - timeval_us(a.usage.ru_utime);
    double sys = timeval_us(b.usage.ru_stime) - timeval_us(a.usage.ru_stime);
    printf("{\"kind\":\"latency\",\"mode\":\"%s\",\"temperature\":\"%s\",\"trial\":%d,"
           "\"records\":%u,\"wall_us\":%.3f,\"user_us\":%.3f,\"system_us\":%.3f,"
           "\"read_ios\":%" PRIu64 ",\"read_bytes\":%" PRIu64 ",\"major_faults\":%ld,"
           "\"minor_faults\":%ld,\"voluntary_switches\":%ld,\"involuntary_switches\":%ld,\"stages\":{",
           mode, temperature, trial, count, wall, user, sys,
           b.rios - a.rios, b.cgroup_read_bytes - a.cgroup_read_bytes,
           b.usage.ru_majflt - a.usage.ru_majflt, b.usage.ru_minflt - a.usage.ru_minflt,
           b.usage.ru_nvcsw - a.usage.ru_nvcsw, b.usage.ru_nivcsw - a.usage.ru_nivcsw);
    for (int s = 0; s < STAGES; ++s)
        printf("%s\"%s\":{\"wall_us\":%.3f,\"cpu_us\":%.3f}", s ? "," : "", stage_names[s],
               times.wall[s] / 1e3, times.cpu[s] / 1e3);
    puts("}}");
    fflush(stdout);
}
static void create_fixture(const char *path, const char *export_path) {
    MDBX_env *env = open_control(path, 0);
    MDBX_txn *txn;
    MDBX_dbi dbi;
    DB(mdbx_txn_begin(env, NULL, 0, &txn));
    DB(mdbx_dbi_open(txn, "Bytecodes", MDBX_CREATE, &dbi));
    FILE *export = fopen(export_path, "wbx");
    require(export != NULL, "export must be a new file");
    for (unsigned i = 0; i < RECORDS; ++i) {
        MDBX_val key = {.iov_base = records[i].key, .iov_len = 32};
        MDBX_val value = {.iov_base = records[i].value, .iov_len = records[i].length};
        DB(mdbx_put(txn, dbi, &key, &value, MDBX_NOOVERWRITE));
        uint32_t length = (uint32_t)value.iov_len;
        require(fwrite(&length, sizeof(length), 1, export) == 1 &&
                fwrite(value.iov_base, length, 1, export) == 1, "export failed");
    }
    require(fclose(export) == 0, "export close failed");
    DB(mdbx_txn_commit(txn));
    DB(mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn));
    void *base;
    size_t bytes;
    /* Discover offsets without relying on private MDBX struct layouts. */
    FILE *maps = fopen("/proc/self/maps", "r");
    require(maps != NULL, "maps unavailable");
    char line[8192], filename[4096];
    require(snprintf(filename, sizeof(filename), "%s/mdbx.dat", path) < (int)sizeof(filename), "path too long");
    base = NULL; bytes = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end, offset;
        char permissions[8];
        if (strstr(line, filename) && sscanf(line, "%lx-%lx %7s %lx", &start, &end, permissions, &offset) == 4 && offset == 0) {
            base = (void *)start; bytes = end - start;
        }
    }
    require(fclose(maps) == 0 && base && bytes, "MDBX map not found");
    for (unsigned i = 0; i < RECORDS; ++i) {
        MDBX_val key = {.iov_base = records[i].key, .iov_len = 32}, value;
        DB(mdbx_get(txn, dbi, &key, &value));
        offsets[i] = (unsigned char *)value.iov_base - (unsigned char *)base;
        require(offsets[i] >= 0 && (size_t)offsets[i] + value.iov_len <= bytes, "value not mapped");
        require(offsets[i] % PAGE_BYTES == 20 &&
                (20 + value.iov_len + PAGE_BYTES - 1) / PAGE_BYTES == 7, "unexpected overflow layout");
    }
    DB(mdbx_txn_abort(txn));
    DB(mdbx_env_close(env));
}
static void run_pass(const char *path, int mode, int trial, int warm) {
    require(prctl(PR_SET_NAME, trace_names[mode]) == 0, "thread name failed");
    MDBX_env *env = open_control(path, 0);
    MDBX_txn *txn;
    MDBX_dbi dbi;
    DB(mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn));
    DB(mdbx_dbi_open(txn, "Bytecodes", 0, &dbi));
    char file[4096];
    require(snprintf(file, sizeof(file), "%s/mdbx.dat", path) < (int)sizeof(file), "path too long");
    int fd = open(file, O_RDONLY | (mode >= 7 ? O_DIRECT : 0));
    struct stat st;
    require(fd >= 0 && fstat(fd, &st) == 0, "fixture open failed");
    unsigned char *map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    require(map != MAP_FAILED && madvise(map, st.st_size, MADV_RANDOM) == 0, "map failed");
    require(posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM) == 0, "fadvise failed");
    void *buffer;
    require(posix_memalign(&buffer, PAGE_BYTES, 32768) == 0, "aligned allocation failed");
    memset(buffer, 0, 32768);
    Times times = {0};
    Sample before = sample();
    for (unsigned i = 0; i < RECORDS; ++i) {
        unsigned index = (i * 317u + trial * 73u) % RECORDS;
        Record *r = &records[index];
        off_t page = offsets[index] & ~(off_t)(PAGE_BYTES - 1);
        MDBX_val key = {.iov_base = r->key, .iov_len = 32}, value = {0};
        Stamp start;
        if (mode == 3) {
            start = stamp();
            hint(map + offsets[index], r->length);
            add_time(&times, 0, start);
        }
        start = stamp();
        if (mode < 4) {
            DB(mdbx_get(txn, dbi, &key, &value));
        } else {
            int layout = (mode - 4) % 3;
            size_t length = layout == 1 ? 7 * PAGE_BYTES : PAGE_BYTES;
            require(pread(fd, buffer, length, page) == (ssize_t)length, "pread failed");
        }
        add_time(&times, 1, start);
        if (mode == 2) {
            start = stamp();
            hint(value.iov_base, value.iov_len);
            add_time(&times, 2, start);
        }
        start = stamp();
        if (mode < 4) {
            require(value.iov_len == r->length, "wrong length");
            size_t offset = mode == 0 ? 5 : 0;
            size_t length = mode == 0 ? 32 : r->length;
            memcpy(buffer, (unsigned char *)value.iov_base + offset, length);
        } else if ((mode - 4) % 3 == 2) {
            require(pread(fd, (unsigned char *)buffer + PAGE_BYTES, 6 * PAGE_BYTES,
                          page + PAGE_BYTES) == 6 * PAGE_BYTES, "second pread failed");
        }
        add_time(&times, 3, start);
        size_t offset = mode == 0 ? 5 : 0;
        size_t length = mode == 0 || (mode >= 4 && (mode - 4) % 3 == 0) ? 32 : r->length;
        unsigned char *data = (unsigned char *)buffer + (mode >= 4 ? 20 : 0);
        require(memcmp(data, r->value + offset, length) == 0, "read mismatch");
        checksum += data[0] + data[length - 1];
    }
    output_measurement(mode_names[mode], warm ? (mode >= 7 ? "uncached_repeat" : "warm") : "cold",
                       trial, RECORDS, before, sample(), times);
    free(buffer);
    require(munmap(map, st.st_size) == 0 && close(fd) == 0, "close failed");
    DB(mdbx_txn_abort(txn));
    DB(mdbx_env_close(env));
}
static void hot_source(const char *path) {
    require(prctl(PR_SET_NAME, "lat-source") == 0, "thread name failed");
    MDBX_env *env = open_source(path);
    MDBX_txn *txn;
    MDBX_dbi code, accounts;
    MDBX_cursor *cursor;
    unsigned char keys[RECORDS][32];
    DB(mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn));
    DB(mdbx_dbi_open(txn, "Bytecodes", 0, &code));
    DB(mdbx_dbi_open(txn, "HashedAccounts", 0, &accounts));
    DB(mdbx_cursor_open(txn, accounts, &cursor));
    for (unsigned i = 0; i < RECORDS; ++i) {
        MDBX_val key = {.iov_base = records[i].key, .iov_len = 32}, value;
        DB(mdbx_cursor_get(cursor, &key, &value, MDBX_SET_RANGE));
        require(key.iov_len == 32, "invalid account key");
        memcpy(keys[i], key.iov_base, 32);
    }
    mdbx_cursor_close(cursor);
    unsigned char buffer[32768];
    for (int trial = 0; trial < 6; ++trial) for (int mode = 0; mode < 3; ++mode) {
        Sample before = sample();
        for (unsigned round = 0; round < 128; ++round) for (unsigned i = 0; i < RECORDS; ++i) {
            unsigned index = (i * 317u + round * 73u) % RECORDS;
            MDBX_val key = {.iov_base = mode == 0 ? keys[index] : records[index].key, .iov_len = 32}, value;
            DB(mdbx_get(txn, mode == 0 ? accounts : code, &key, &value));
            if (mode == 2) {
                memcpy(buffer, value.iov_base, value.iov_len);
                require(memcmp(buffer, records[index].value, value.iov_len) == 0, "source mismatch");
                checksum += buffer[value.iov_len - 1];
            } else checksum += ((unsigned char *)value.iov_base)[0];
        }
        const char *names[] = {"source_account_lookup", "source_code_lookup", "source_code_lookup_copy_verify"};
        output_measurement(names[mode], trial ? "warm" : "conditioning", trial, RECORDS * 128,
                           before, sample(), (Times){0});
    }
    DB(mdbx_txn_abort(txn));
    DB(mdbx_env_close(env));
}
static void wide_source(const char *path) {
    enum { KEYS = 65536, ROUNDS = 8 };
    unsigned char (*keys)[32] = malloc(KEYS * 32);
    require(keys != NULL, "key allocation failed");
    MDBX_env *env = open_source(path);
    MDBX_txn *txn;
    DB(mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn));
    const char *tables[] = {"HashedAccounts", "Bytecodes"};
    for (int mode = 0; mode < 2; ++mode) {
        require(prctl(PR_SET_NAME, mode ? "lat-wide-code" : "lat-wide-acct") == 0, "thread name failed");
        MDBX_dbi dbi;
        MDBX_cursor *cursor;
        DB(mdbx_dbi_open(txn, tables[mode], 0, &dbi));
        DB(mdbx_cursor_open(txn, dbi, &cursor));
        for (unsigned i = 0; i < KEYS; ++i) {
            for (int j = 0; j < 32; j += 8) {
                uint64_t word = random_word();
                memcpy(keys[i] + j, &word, 8);
            }
            MDBX_val key = {.iov_base = keys[i], .iov_len = 32}, value;
            int rc = mdbx_cursor_get(cursor, &key, &value, MDBX_SET_RANGE);
            if (rc == MDBX_NOTFOUND) rc = mdbx_cursor_get(cursor, &key, &value, MDBX_FIRST);
            DB(rc);
            require(key.iov_len == 32, "wrong source key length");
            memcpy(keys[i], key.iov_base, 32);
            checksum += ((unsigned char *)value.iov_base)[0];
        }
        mdbx_cursor_close(cursor);
        for (int trial = 0; trial < 6; ++trial) {
            Sample before = sample();
            for (unsigned round = 0; round < ROUNDS; ++round) for (unsigned i = 0; i < KEYS; ++i) {
                unsigned index = (i * 317u + round * 73u + trial * 19u) % KEYS;
                MDBX_val key = {.iov_base = keys[index], .iov_len = 32}, value;
                DB(mdbx_get(txn, dbi, &key, &value));
                checksum += ((unsigned char *)value.iov_base)[0];
            }
            output_measurement(mode ? "wide_source_code_lookup" : "wide_source_account_lookup",
                               trial ? "warm" : "conditioning", trial, KEYS * ROUNDS,
                               before, sample(), (Times){0});
        }
    }
    DB(mdbx_txn_abort(txn));
    DB(mdbx_env_close(env));
    free(keys);
}
int main(int argc, char **argv) {
    require(argc == 4, "usage: bytecode-latency-diagnostic SOURCE_DB TEMP_PARENT EXPORT_FILE");
    require(sysconf(_SC_PAGESIZE) == PAGE_BYTES, "4 KiB pages required");
    configure_io(argv[2]);
    printf("{\"kind\":\"latency_metadata\",\"records\":%u,\"trials\":%u,\"cpu\":%d,\"device\":\"%u:%u\"}\n",
           RECORDS, LATENCY_TRIALS, sched_getcpu(), device_major, device_minor);
    if (getenv("BYTECODE_WIDE_ONLY")) {
        wide_source(argv[1]);
        return 0;
    }
    extract_records(argv[1]);
    char control[4096];
    require(snprintf(control, sizeof(control), "%s/bytecode-latency-XXXXXX", argv[2]) < (int)sizeof(control), "path too long");
    require(mkdtemp(control) != NULL, "mkdtemp failed");
    create_fixture(control, argv[3]);
    Times calibration = {0};
    for (int i = 0; i < 100000; ++i) { Stamp start = stamp(); add_time(&calibration, 0, start); }
    printf("{\"kind\":\"timer_calibration\",\"wall_ns\":%.3f,\"cpu_ns\":%.3f}\n",
           calibration.wall[0] / 100000.0, calibration.cpu[0] / 100000.0);
    for (int trial = 0; trial < LATENCY_TRIALS; ++trial) for (int m = 0; m < 10; ++m) {
        int mode = (m * 3 + trial * 7) % 10;
        evict_private_control(control, trial, 0, mode_names[mode]);
        run_pass(control, mode, trial, 0);
        run_pass(control, mode, trial, 1);
    }
    hot_source(argv[1]);
    DB(mdbx_env_delete(control, MDBX_ENV_JUST_DELETE));
    if (rmdir(control) != 0) require(errno == ENOENT, "cleanup failed");
    for (unsigned i = 0; i < RECORDS; ++i) free(records[i].value);
    return 0;
}
