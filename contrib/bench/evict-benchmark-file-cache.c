#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static uint64_t resident_pages(int fd, size_t length, size_t page_size) {
    void *mapping = mmap(NULL, length, PROT_READ, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) { perror("mmap"); exit(1); }
    size_t count = (length + page_size - 1) / page_size;
    unsigned char *pages = calloc(count, 1);
    if (!pages) { perror("calloc"); exit(1); }
    if (mincore(mapping, length, pages)) { perror("mincore"); exit(1); }
    uint64_t resident = 0;
    for (size_t i = 0; i < count; ++i) resident += pages[i] & 1;
    free(pages);
    munmap(mapping, length);
    return resident;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: evict-benchmark-file-cache STOPPED_SCRATCH_FILE\n"); return 2; }
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { perror("open"); return 1; }
    struct stat st;
    if (fstat(fd, &st)) { perror("fstat"); return 1; }
    if (!S_ISREG(st.st_mode) || st.st_size <= 0) return 2;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uint64_t before = resident_pages(fd, (size_t)st.st_size, page_size);
    // Flush only this restored file; never drop the host's global caches.
    if (fsync(fd)) { perror("fsync"); return 1; }
    int error = posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    if (error) { errno = error; perror("posix_fadvise"); return 1; }
    uint64_t after = resident_pages(fd, (size_t)st.st_size, page_size);
    close(fd);
    printf("{\"bytes\":%" PRIu64 ",\"page_size\":%zu,\"resident_before\":%" PRIu64
           ",\"resident_after\":%" PRIu64 "}\n", (uint64_t)st.st_size, page_size, before, after);
    // A mapped/in-use file can resist eviction even when fadvise succeeds.
    return after <= 16 ? 0 : 1;
}
