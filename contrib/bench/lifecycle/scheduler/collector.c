/* Private fixed-width records only; never receives native process/thread IDs. */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct event { uint64_t ts; uint32_t ordinal; uint16_t kind, state; };
_Static_assert(sizeof(struct event) == 16, "fixed binary scheduler schema");
struct buffer {
    size_t retained, capacity, invalid, overflow, io_error, received;
    uint64_t first_ts, last_ts;
    int fd;
    size_t pending;
    unsigned char bytes[64 * 1024];
};

void *allocate_capacity(int fd, size_t capacity) {
    struct stat status;
    if (!capacity || capacity > (1024UL * 1024 * 1024) / sizeof(struct event) ||
        fstat(fd, &status) || !S_ISREG(status.st_mode) || status.st_nlink || status.st_size) return NULL;
    struct buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer) return NULL;
    buffer->capacity = capacity;
    buffer->fd = fd;
    return buffer;
}
void *allocate(int fd) { return allocate_capacity(fd, (1024UL * 1024 * 1024) / sizeof(struct event)); }

void finalize(void *context) {
    struct buffer *buffer = context;
    size_t done = 0;
    while (!buffer->io_error && done < buffer->pending) {
        ssize_t wrote = write(buffer->fd, buffer->bytes + done, buffer->pending - done);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) { buffer->io_error = 1; break; }
        done += wrote;
    }
    buffer->pending = 0;
}
int collect(void *context, void *data, size_t size) {
    struct buffer *buffer = context;
    if (size != sizeof(struct event)) { buffer->invalid++; return 0; }
    struct event *event = data;
    if (!event->ordinal || event->ordinal > 8192 || event->kind > 5 ||
        (event->kind != 1 && event->state) || event->state > 256) {
        buffer->invalid++;
        return 0;
    }
    if (!buffer->received || event->ts < buffer->first_ts) buffer->first_ts = event->ts;
    if (event->ts > buffer->last_ts) buffer->last_ts = event->ts;
    buffer->received++;
    if (buffer->retained == buffer->capacity) { buffer->overflow++; return 0; }
    if (buffer->io_error) return 0;
    memcpy(buffer->bytes + buffer->pending, data, size);
    buffer->pending += size;
    buffer->retained++;
    if (buffer->pending == sizeof(buffer->bytes)) finalize(context);
    return 0;
}
size_t metric(void *context, int index) {
    struct buffer *buffer = context;
    switch (index) {
        case 0: return buffer->retained;
        case 1: return buffer->invalid;
        case 2: return buffer->overflow;
        case 3: return buffer->io_error;
        case 4: return buffer->received;
        default: return buffer->last_ts - buffer->first_ts;
    }
}
void release(void *context) { free(context); }

/* Query only the miss count. Native program metadata stays on this stack. */
#include <stddef.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
int probe_misses(int fd, uint64_t *result) {
    struct bpf_prog_info info = {0};
    union bpf_attr attr = {0};
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uintptr_t)&info;
    if (syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) ||
        attr.info.info_len < offsetof(struct bpf_prog_info, recursion_misses) + sizeof(info.recursion_misses)) return -1;
    *result = info.recursion_misses;
    return 0;
}
