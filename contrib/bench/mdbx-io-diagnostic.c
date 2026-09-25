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
#include <time.h>
#include <unistd.h>

/* Small storage-engine controls, not EVM workloads or per-gas measurements. */
enum { RECORDS = 2048, BATCH = 128, ROUNDS = 8, TRIALS = 3 };
static volatile uint64_t checksum_sink;

static void check(int rc, const char *operation) {
    if (rc != MDBX_SUCCESS) {
        fprintf(stderr, "%s: %s (%d)\n", operation, mdbx_strerror(rc), rc);
        exit(1);
    }
}
#define DB(call) check((call), #call)

static void require(int valid, const char *message) {
    if (!valid) { fprintf(stderr, "%s\n", message); exit(1); }
}

typedef struct {
    struct rusage usage;
    struct timespec time;
    uint64_t read_bytes, write_bytes;
} Sample;

static Sample sample(void) {
    Sample s = {0};
    FILE *f = fopen("/proc/self/io", "r");
    require(f != NULL, "cannot open process I/O counters");
    char key[64];
    uint64_t value;
    int seen = 0;
    while (fscanf(f, "%63s %" SCNu64, key, &value) == 2) {
        if (!strcmp(key, "read_bytes:")) { s.read_bytes = value; seen |= 1; }
        if (!strcmp(key, "write_bytes:")) { s.write_bytes = value; seen |= 2; }
    }
    require(fclose(f) == 0 && seen == 3, "missing process I/O counters");
    require(getrusage(RUSAGE_SELF, &s.usage) == 0, "getrusage failed");
    require(clock_gettime(CLOCK_MONOTONIC, &s.time) == 0, "clock failed");
    return s;
}

static void emit(const char *phase, unsigned bytes, int readahead, int trial,
                 int round, Sample a, Sample b) {
    require(b.read_bytes >= a.read_bytes && b.write_bytes >= a.write_bytes,
            "I/O counters decreased");
    double ms = (b.time.tv_sec - a.time.tv_sec) * 1000.0 +
                (b.time.tv_nsec - a.time.tv_nsec) / 1000000.0;
    printf("{\"kind\":\"sample\",\"phase\":\"%s\",\"record_bytes\":%u,"
           "\"records\":%u,\"readahead\":%s,\"trial\":%d,\"round\":%d,"
           "\"ms\":%.6f,\"major_faults\":%ld,\"minor_faults\":%ld,"
           "\"read_bytes\":%" PRIu64 ",\"write_bytes\":%" PRIu64 "}\n",
           phase, bytes, RECORDS, readahead ? "true" : "false", trial, round,
           ms, b.usage.ru_majflt - a.usage.ru_majflt,
           b.usage.ru_minflt - a.usage.ru_minflt,
           b.read_bytes - a.read_bytes, b.write_bytes - a.write_bytes);
    fflush(stdout);
}

static MDBX_env *open_env(const char *path, int readahead) {
    MDBX_env *env;
    DB(mdbx_env_create(&env));
    DB(mdbx_env_set_geometry(env, 0, 0, 256 * 1024 * 1024,
                             4 * 1024 * 1024, 0, 4096));
    DB(mdbx_env_set_maxdbs(env, 2));
    DB(mdbx_env_open(env, path, MDBX_WRITEMAP | MDBX_COALESCE |
                    (readahead ? 0 : MDBX_NORDAHEAD), 0600));
    return env;
}

static void fill(unsigned char *value, unsigned length, uint64_t id, int round) {
    for (unsigned j = 0; j < length; ++j)
        value[j] = (unsigned char)((id + j + round) % 251);
}

static void create_fixture(const char *path, unsigned bytes, int trial) {
    MDBX_env *env = open_env(path, 0);
    MDBX_txn *txn;
    MDBX_dbi dbi;
    DB(mdbx_txn_begin(env, NULL, 0, &txn));
    DB(mdbx_dbi_open(txn, "records", MDBX_CREATE, &dbi));
    unsigned char *buffer = malloc(bytes);
    require(buffer != NULL, "allocation failed");
    for (uint64_t id = 0; id < RECORDS; ++id) {
        fill(buffer, bytes, id, 0);
        MDBX_val key = { .iov_base = &id, .iov_len = sizeof(id) };
        MDBX_val val = { .iov_base = buffer, .iov_len = bytes };
        DB(mdbx_put(txn, dbi, &key, &val, 0));
    }
    DB(mdbx_txn_commit(txn));
    DB(mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn));
    MDBX_stat stat;
    DB(mdbx_dbi_stat(txn, dbi, &stat, sizeof(stat)));
    printf("{\"kind\":\"fixture\",\"trial\":%d,\"record_bytes\":%u,"
           "\"page_bytes\":%u,\"branch_pages\":%" PRIu64 ","
           "\"leaf_pages\":%" PRIu64 ",\"overflow_pages\":%" PRIu64 "}\n",
           trial, bytes, stat.ms_psize, stat.ms_branch_pages,
           stat.ms_leaf_pages, stat.ms_overflow_pages);
    DB(mdbx_txn_abort(txn));
    DB(mdbx_env_close(env));
    free(buffer);
}

/* Evict only this freshly created, closed fixture, never host-wide caches. */
static void cold_fixture(const char *path, unsigned bytes, int trial, int ra) {
    char file[1024];
    require(snprintf(file, sizeof(file), "%s/mdbx.dat", path) < (int)sizeof(file),
            "path too long");
    int fd = open(file, O_RDWR);
    require(fd >= 0, "fixture open failed");
    require(fsync(fd) == 0, "fixture fsync failed");
    check(posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED), "fixture fadvise");
    struct stat st;
    require(fstat(fd, &st) == 0 && st.st_size > 0, "fixture stat failed");
    long page = sysconf(_SC_PAGESIZE);
    require(page > 0, "invalid OS page size");
    size_t count = ((size_t)st.st_size + page - 1) / page;
    unsigned char *resident = malloc(count);
    require(resident != NULL, "allocation failed");
    void *mapping = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    require(mapping != MAP_FAILED, "fixture mmap failed");
    require(mincore(mapping, st.st_size, resident) == 0, "mincore failed");
    size_t present = 0;
    for (size_t i = 0; i < count; ++i) present += !!(resident[i] & 1);
    printf("{\"kind\":\"residency\",\"trial\":%d,\"record_bytes\":%u,"
           "\"readahead\":%s,\"resident_pages\":%zu,\"file_pages\":%zu}\n",
           trial, bytes, ra ? "true" : "false", present, count);
    require(present == 0, "cold control failed: fixture still resident");
    require(munmap(mapping, st.st_size) == 0 && close(fd) == 0, "close failed");
    free(resident);
}

static void read_records(MDBX_env *env, unsigned bytes, int ra, int trial,
                         const char *phase, int expected_round,
                         const Sample *opening_start) {
    Sample before = sample();
    MDBX_txn *txn;
    MDBX_dbi dbi;
    DB(mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn));
    DB(mdbx_dbi_open(txn, "records", 0, &dbi));
    uint64_t sum = 0;
    for (unsigned i = 0; i < RECORDS; ++i) {
        uint64_t id = (i * 1031u) % RECORDS;
        MDBX_val key = { .iov_base = &id, .iov_len = sizeof(id) }, val;
        DB(mdbx_get(txn, dbi, &key, &val));
        require(val.iov_len == bytes, "incorrect record length");
        const unsigned char *p = val.iov_base;
        for (unsigned j = 0; j < bytes; ++j) {
            require(p[j] == (unsigned char)((id + j + expected_round) % 251),
                    "incorrect stored value");
            sum += p[j];
        }
    }
    DB(mdbx_txn_abort(txn));
    checksum_sink = sum;
    Sample after = sample();
    emit(phase, bytes, ra, trial, expected_round, before, after);
    if (opening_start) {
        emit("cold_open", bytes, ra, trial, 0, *opening_start, before);
        emit("cold_total", bytes, ra, trial, 0, *opening_start, after);
    }
}

static void update_records(MDBX_env *env, int trial, int round) {
    unsigned char buffer[32];
    Sample before = sample();
    for (unsigned start = 0; start < RECORDS; start += BATCH) {
        MDBX_txn *txn;
        MDBX_dbi dbi;
        DB(mdbx_txn_begin(env, NULL, 0, &txn));
        DB(mdbx_dbi_open(txn, "records", 0, &dbi));
        for (unsigned i = start; i < start + BATCH; ++i) {
            uint64_t id = (i * 1031u) % RECORDS;
            MDBX_val key = { .iov_base = &id, .iov_len = sizeof(id) }, old;
            DB(mdbx_get(txn, dbi, &key, &old));
            require(old.iov_len == sizeof(buffer), "incorrect update length");
            fill(buffer, sizeof(buffer), id, round - 1);
            require(memcmp(old.iov_base, buffer, sizeof(buffer)) == 0,
                    "incorrect pre-update value");
            fill(buffer, sizeof(buffer), id, round);
            MDBX_val val = { .iov_base = buffer, .iov_len = sizeof(buffer) };
            DB(mdbx_put(txn, dbi, &key, &val, 0));
        }
        /* Default durable commits are inside the measured interval. */
        DB(mdbx_txn_commit(txn));
    }
    emit("durable_update", sizeof(buffer), 0, trial, round, before, sample());
}

int main(int argc, char **argv) {
    require(argc == 2, "usage: mdbx-io-diagnostic TEMP_PARENT_DIRECTORY");
    printf("{\"kind\":\"metadata\",\"mdbx\":\"%u.%u.%u\",\"pid\":%d,"
           "\"writemap\":true,\"durability\":\"default_durable\","
           "\"records\":%u,\"batch\":%u,\"rounds\":%u,\"trials\":%u}\n",
           mdbx_version.major, mdbx_version.minor, mdbx_version.patch, getpid(),
           RECORDS, BATCH, ROUNDS, TRIALS);
    const unsigned sizes[] = {32, 1024, 24576};
    for (int trial = 1; trial <= TRIALS; ++trial) {
        for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
            char path[1024];
            require(snprintf(path, sizeof(path), "%s/mdbx-io-diag-XXXXXX", argv[1])
                    < (int)sizeof(path), "parent path too long");
            require(mkdtemp(path) != NULL, "temporary fixture creation failed");
            create_fixture(path, sizes[s], trial);
            for (int ra = 0; ra <= 1; ++ra) {
                cold_fixture(path, sizes[s], trial, ra);
                Sample opening_start = sample();
                MDBX_env *env = open_env(path, ra);
                read_records(env, sizes[s], ra, trial, "cold_read", 0, &opening_start);
                read_records(env, sizes[s], ra, trial, "warm_read", 0, NULL);
                DB(mdbx_env_close(env));
            }
            if (sizes[s] == 32) {
                cold_fixture(path, sizes[s], trial, 0);
                MDBX_env *env = open_env(path, 0);
                for (int round = 1; round <= ROUNDS; ++round)
                    update_records(env, trial, round);
                DB(mdbx_env_close(env));
                env = open_env(path, 0);
                read_records(env, sizes[s], 0, trial, "verify_updates", ROUNDS, NULL);
                DB(mdbx_env_close(env));
            }
            /* The directory is exclusively owned by this invocation. */
            DB(mdbx_env_delete(path, MDBX_ENV_JUST_DELETE));
            if (rmdir(path) != 0) require(errno == ENOENT, "temporary cleanup failed");
        }
    }
    return 0;
}
