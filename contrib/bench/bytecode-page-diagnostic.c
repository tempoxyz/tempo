#define _GNU_SOURCE
#include "mdbx.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

/* Actual serialized Bytecodes, copied into a disposable storage-engine control.
 * Never evict or modify the source database. This is not an EVM throughput test. */
enum { RECORDS = 512, TRIALS = 3, PAGE_BYTES = 4096 };
typedef struct { unsigned char key[32]; unsigned char *value; size_t length; } Record;
typedef struct {
    struct rusage usage;
    struct timespec time;
    uint64_t read_bytes, rios, cgroup_read_bytes;
} Sample;
static Record records[RECORDS];
static char cgroup_io[4096];
static unsigned device_major, device_minor;
static volatile uint64_t checksum;

static void require(int ok, const char *message) {
    if (!ok) { fprintf(stderr, "%s\n", message); exit(1); }
}
static void check(int rc, const char *operation) {
    if (rc != MDBX_SUCCESS) {
        fprintf(stderr, "%s: %s (%d)\n", operation, mdbx_strerror(rc), rc);
        exit(1);
    }
}
#define DB(call) check((call), #call)

static uint64_t be(const unsigned char *p, size_t n) {
    uint64_t result = 0;
    for (size_t i = 0; i < n; ++i) result = (result << 8) | p[i];
    return result;
}
static uint64_t random_word(void) {
    static uint64_t state = UINT64_C(0xd4740bd84755c991);
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return state;
}
static MDBX_env *open_source(const char *path) {
    char file[4096];
    require(snprintf(file, sizeof(file), "%s/mdbx.dat", path) < (int)sizeof(file), "path too long");
    require(access(file, R_OK) == 0, "source must already exist");
    MDBX_env *env;
    DB(mdbx_env_create(&env));
    DB(mdbx_env_set_maxdbs(env, 256));
    DB(mdbx_env_open(env, path, MDBX_RDONLY | MDBX_NORDAHEAD, 0));
    return env;
}
static MDBX_env *open_control(const char *path, int readahead) {
    MDBX_env *env;
    DB(mdbx_env_create(&env));
    DB(mdbx_env_set_geometry(env, 0, 0, 128 * 1024 * 1024, 4 * 1024 * 1024, 0, PAGE_BYTES));
    DB(mdbx_env_set_maxdbs(env, 2));
    DB(mdbx_env_open(env, path, MDBX_WRITEMAP | MDBX_COALESCE |
                    (readahead ? 0 : MDBX_NORDAHEAD), 0600));
    return env;
}
static void table_stats(MDBX_txn *txn, const char *name, const char *scope) {
    MDBX_dbi dbi;
    MDBX_stat s;
    DB(mdbx_dbi_open(txn, name, 0, &dbi));
    DB(mdbx_dbi_stat(txn, dbi, &s, sizeof(s)));
    printf("{\"kind\":\"table\",\"scope\":\"%s\",\"table\":\"%s\","
           "\"page_bytes\":%u,\"entries\":%" PRIu64 ",\"depth\":%u,"
           "\"branch_pages\":%" PRIu64 ",\"leaf_pages\":%" PRIu64 ",\"overflow_pages\":%" PRIu64 "}\n",
           scope, name, s.ms_psize, s.ms_entries, s.ms_depth,
           s.ms_branch_pages, s.ms_leaf_pages, s.ms_overflow_pages);
}
static void extract_records(const char *source) {
    MDBX_env *env = open_source(source);
    MDBX_txn *txn;
    MDBX_dbi dbi;
    MDBX_cursor *cursor;
    DB(mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn));
    const char *tables[] = {"Bytecodes", "HashedAccounts", "HashedStorages", "StoragesTrie"};
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); ++i)
        table_stats(txn, tables[i], "source_read_only");
    DB(mdbx_dbi_open(txn, "Bytecodes", 0, &dbi));
    DB(mdbx_cursor_open(txn, dbi, &cursor));
    for (unsigned i = 0; i < RECORDS;) {
        unsigned char seek[32];
        for (unsigned j = 0; j < 32; j += 8) {
            uint64_t word = random_word();
            memcpy(seek + j, &word, sizeof(word));
        }
        MDBX_val key = { .iov_base = seek, .iov_len = sizeof(seek) }, value;
        int rc = mdbx_cursor_get(cursor, &key, &value, MDBX_SET_RANGE);
        if (rc == MDBX_NOTFOUND) continue;
        DB(rc);
        require(key.iov_len == 32, "unexpected Bytecodes key length");
        const unsigned char *p = value.iov_base;
        if (value.iov_len < 24576) continue;
        size_t padded = be(p, 4);
        require(padded <= value.iov_len - 13, "invalid bytecode length");
        require(p[4 + padded] == 2, "expected analyzed legacy bytecode");
        size_t original = be(p + 5 + padded, 8);
        if (original != 24576 || p[4] != 0) continue;
        int duplicate = 0;
        for (unsigned j = 0; j < i; ++j)
            if (memcmp(records[j].key, key.iov_base, 32) == 0) duplicate = 1;
        if (duplicate) continue;
        memcpy(records[i].key, key.iov_base, 32);
        records[i].length = value.iov_len;
        records[i].value = malloc(value.iov_len);
        require(records[i].value != NULL, "allocation failed");
        memcpy(records[i].value, p, value.iov_len);
        size_t offset = (uintptr_t)p % PAGE_BYTES;
        printf("{\"kind\":\"record\",\"index\":%u,\"runtime_bytes\":%zu,"
               "\"padded_code_bytes\":%zu,\"jump_table_bytes\":%zu,\"encoded_bytes\":%zu,"
               "\"value_page_offset\":%zu,\"value_pages\":%zu}\n",
               i, original, padded, value.iov_len - padded - 13, value.iov_len,
               offset, (offset + value.iov_len + PAGE_BYTES - 1) / PAGE_BYTES);
        ++i;
    }
    mdbx_cursor_close(cursor);
    DB(mdbx_txn_abort(txn));
    DB(mdbx_env_close(env));
}
static void configure_io(const char *parent) {
    struct stat st;
    require(stat(parent, &st) == 0, "temporary parent must exist");
    device_major = major(st.st_dev); device_minor = minor(st.st_dev);
    FILE *f = fopen("/proc/self/cgroup", "r");
    require(f != NULL, "cgroup unavailable");
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::", 3) != 0) continue;
        line[strcspn(line, "\n")] = 0;
        require(strstr(line, "tempo-bytecode-io-") != NULL, "run in a dedicated tempo-bytecode-io-* systemd scope");
        require(snprintf(cgroup_io, sizeof(cgroup_io), "/sys/fs/cgroup%s/io.stat", line + 3)
                < (int)sizeof(cgroup_io), "cgroup path too long");
    }
    require(fclose(f) == 0 && cgroup_io[0], "cgroup v2 required");
}
static Sample sample(void) {
    Sample result = {0};
    require(getrusage(RUSAGE_SELF, &result.usage) == 0, "getrusage failed");
    require(clock_gettime(CLOCK_MONOTONIC, &result.time) == 0, "clock failed");
    FILE *f = fopen("/proc/self/io", "r");
    require(f != NULL, "process I/O unavailable");
    char key[64]; uint64_t value; int seen = 0;
    while (fscanf(f, "%63s %" SCNu64, key, &value) == 2)
        if (!strcmp(key, "read_bytes:")) { result.read_bytes = value; seen = 1; }
    require(fclose(f) == 0 && seen, "missing process read counter");
    f = fopen(cgroup_io, "r");
    require(f != NULL, "cgroup I/O unavailable");
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        unsigned major_id, minor_id;
        if (sscanf(line, "%u:%u", &major_id, &minor_id) != 2 ||
            major_id != device_major || minor_id != device_minor) continue;
        char *part = strstr(line, "rbytes=");
        require(part && sscanf(part + 7, "%" SCNu64, &result.cgroup_read_bytes) == 1, "missing rbytes");
        part = strstr(line, "rios=");
        require(part && sscanf(part + 5, "%" SCNu64, &result.rios) == 1, "missing rios");
    }
    require(fclose(f) == 0, "cgroup close failed");
    return result;
}
static void evict_private_control(const char *path, int trial, int ra, const char *mode) {
    char file[4096];
    require(snprintf(file, sizeof(file), "%s/mdbx.dat", path) < (int)sizeof(file), "path too long");
    int fd = open(file, O_RDWR);
    require(fd >= 0 && fsync(fd) == 0, "private fixture sync failed");
    check(posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED), "private fixture eviction");
    struct stat st;
    require(fstat(fd, &st) == 0 && st.st_size > 0, "stat failed");
    size_t pages = ((size_t)st.st_size + PAGE_BYTES - 1) / PAGE_BYTES;
    unsigned char *resident = malloc(pages);
    require(resident != NULL, "allocation failed");
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    require(map != MAP_FAILED && mincore(map, st.st_size, resident) == 0, "mincore failed");
    size_t present = 0;
    for (size_t i = 0; i < pages; ++i) present += !!(resident[i] & 1);
    printf("{\"kind\":\"residency\",\"trial\":%d,\"readahead\":%s,\"mode\":\"%s\",\"resident_pages\":%zu}\n",
           trial, ra ? "true" : "false", mode, present);
    require(present == 0, "cold fixture still resident");
    require(munmap(map, st.st_size) == 0 && close(fd) == 0, "close failed");
    free(resident);
}
static void read_records(MDBX_env *env, int mode) {
    MDBX_txn *txn;
    MDBX_dbi dbi;
    DB(mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn));
    DB(mdbx_dbi_open(txn, "Bytecodes", 0, &dbi));
    unsigned char copied[32768];
    uint64_t sum = 0;
    for (unsigned i = 0; i < RECORDS; ++i) {
        Record *record = &records[(i * 317u) % RECORDS];
        MDBX_val key = { .iov_base = record->key, .iov_len = 32 }, value;
        DB(mdbx_get(txn, dbi, &key, &value));
        require(value.iov_len == record->length && value.iov_len <= sizeof(copied), "incorrect record");
        if (mode == 2) {
            /* Hint only this value's extent, not neighboring records or tables. */
            uintptr_t start = (uintptr_t)value.iov_base & ~(uintptr_t)(PAGE_BYTES - 1);
            size_t length = ((uintptr_t)value.iov_base - start + value.iov_len + PAGE_BYTES - 1)
                            / PAGE_BYTES * PAGE_BYTES;
            require(madvise((void *)start, length, MADV_WILLNEED) == 0, "value prefetch failed");
        }
        int full = mode != 0;
        size_t offset = full ? 0 : 5;
        size_t length = full ? value.iov_len : 32;
        memcpy(copied, (unsigned char *)value.iov_base + offset, length);
        require(memcmp(copied, record->value + offset, length) == 0, "incorrect value bytes");
        sum += copied[0] + copied[length - 1];
    }
    checksum = sum;
    DB(mdbx_txn_abort(txn));
}
static void emit(const char *mode, const char *temperature, int trial, int ra, Sample a, Sample b) {
    require(b.read_bytes >= a.read_bytes && b.rios >= a.rios &&
            b.cgroup_read_bytes >= a.cgroup_read_bytes, "counter reset");
    double ms = (b.time.tv_sec - a.time.tv_sec) * 1000.0 + (b.time.tv_nsec - a.time.tv_nsec) / 1e6;
    printf("{\"kind\":\"sample\",\"mode\":\"%s\",\"temperature\":\"%s\","
           "\"trial\":%d,\"readahead\":%s,\"records\":%u,\"ms\":%.6f,"
           "\"major_faults\":%ld,\"minor_faults\":%ld,\"process_read_bytes\":%" PRIu64 ","
           "\"read_ios\":%" PRIu64 ",\"cgroup_read_bytes\":%" PRIu64 "}\n",
           mode, temperature, trial, ra ? "true" : "false", RECORDS, ms,
           b.usage.ru_majflt - a.usage.ru_majflt, b.usage.ru_minflt - a.usage.ru_minflt,
           b.read_bytes - a.read_bytes, b.rios - a.rios, b.cgroup_read_bytes - a.cgroup_read_bytes);
    fflush(stdout);
}
int main(int argc, char **argv) {
    require(argc == 3, "usage: bytecode-page-diagnostic SOURCE_DB_DIRECTORY TEMP_PARENT");
    require(sysconf(_SC_PAGESIZE) == PAGE_BYTES, "4 KiB OS pages required");
    configure_io(argv[2]);
    printf("{\"kind\":\"metadata\",\"records\":%u,\"trials\":%u,\"device\":\"%u:%u\","
           "\"mdbx\":\"%u.%u.%u\",\"source_read_only\":true,\"global_eviction\":false}\n",
           RECORDS, TRIALS, device_major, device_minor,
           mdbx_version.major, mdbx_version.minor, mdbx_version.patch);
    extract_records(argv[1]);
    char control[4096];
    require(snprintf(control, sizeof(control), "%s/bytecode-pages-XXXXXX", argv[2]) < (int)sizeof(control), "path too long");
    require(mkdtemp(control) != NULL, "mkdtemp failed");
    MDBX_env *env = open_control(control, 0);
    MDBX_txn *txn;
    MDBX_dbi dbi;
    DB(mdbx_txn_begin(env, NULL, 0, &txn));
    DB(mdbx_dbi_open(txn, "Bytecodes", MDBX_CREATE, &dbi));
    for (unsigned i = 0; i < RECORDS; ++i) {
        MDBX_val key = { .iov_base = records[i].key, .iov_len = 32 };
        MDBX_val value = { .iov_base = records[i].value, .iov_len = records[i].length };
        DB(mdbx_put(txn, dbi, &key, &value, MDBX_NOOVERWRITE));
    }
    DB(mdbx_txn_commit(txn));
    DB(mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn));
    table_stats(txn, "Bytecodes", "private_control");
    DB(mdbx_txn_abort(txn));
    DB(mdbx_env_close(env));
    for (int trial = 1; trial <= TRIALS; ++trial) {
        for (int ra = 0; ra <= 1; ++ra) for (int mode = 0; mode < 3; ++mode) {
            const char *names[] = {"prefix_32_bytes", "full_serialized_value", "full_value_targeted_prefetch"};
            const char *name = names[mode];
            evict_private_control(control, trial, ra, name);
            Sample before = sample();
            env = open_control(control, ra);
            read_records(env, mode);
            emit(name, "cold_including_open", trial, ra, before, sample());
            before = sample();
            read_records(env, mode);
            emit(name, "warm", trial, ra, before, sample());
            DB(mdbx_env_close(env));
        }
    }
    DB(mdbx_env_delete(control, MDBX_ENV_JUST_DELETE));
    if (rmdir(control) != 0) require(errno == ENOENT, "private directory cleanup failed");
    for (unsigned i = 0; i < RECORDS; ++i) free(records[i].value);
    return 0;
}
