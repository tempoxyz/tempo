/* Private fixed-width records only; never receives native process/thread IDs. */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct event { uint64_t ts; uint32_t ordinal; uint16_t kind, state; };
_Static_assert(sizeof(struct event) == 16, "fixed binary scheduler schema");
struct wait_event { struct event event; int32_t stack_id; uint32_t reserved; };
_Static_assert(sizeof(struct wait_event)==24,"private kernel stack protocol");
typedef int (*wait_resolver)(int);
struct buffer {
    size_t retained, capacity, invalid, overflow, io_error, received;
    uint64_t first_ts, last_ts;
    int fd;
    wait_resolver resolve;
    uint16_t categories[1024];
    int wait_enabled;
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
int configure_waits(void *context, wait_resolver resolve) {
    struct buffer *buffer=context;
    if(!resolve||buffer->received||buffer->retained)return -1;
    buffer->resolve=resolve;buffer->wait_enabled=1;return 0;
}
static int valid_category(unsigned code,int sleeping) {
    unsigned reason=(code>>9)&7,status=code>>12;
    return !(code&511)&&reason<=5&&status>=1&&status<=9&&
      ((status==1)==(reason!=0))&&((status!=9)==sleeping);
}
int collect(void *context, void *data, size_t size) {
    struct buffer *buffer = context;
    size_t expected=buffer->wait_enabled?sizeof(struct wait_event):sizeof(struct event);
    if (size != expected) { buffer->invalid++; return 0; }
    struct event safe=*(struct event*)data;
    struct event *event=&safe;
    if (!event->ordinal || event->ordinal > 8192 || event->kind > 5 ||
        (event->kind != 1 && event->state) || event->state > 256) {
        buffer->invalid++;
        return 0;
    }
    if(buffer->wait_enabled) {
        struct wait_event *raw=data;
        if(raw->reserved){buffer->invalid++;return 0;}
        int sleeping=event->kind==1&&(event->state==1||event->state==2);
        unsigned code=0;
        if(sleeping) {
            int id=raw->stack_id;
            if(id<0)code=(id==-EEXIST?4:id==-ENOMEM?5:3)<<12;
            else if(id>=1024){buffer->invalid++;return 0;}
            else {
                code=buffer->categories[id];
                if(!code){code=buffer->resolve(id);if(!valid_category(code,1)){buffer->invalid++;return 0;}buffer->categories[id]=code;}
            }
        } else {
            if(raw->stack_id!=INT32_MIN){buffer->invalid++;return 0;}
            if(event->kind==1&&event->state!=0&&event->state!=256)code=9<<12;
        }
        if(code) {if(!valid_category(code,sleeping)){buffer->invalid++;return 0;}event->state|=code;}
    }
    if (!buffer->received || event->ts < buffer->first_ts) buffer->first_ts = event->ts;
    if (event->ts > buffer->last_ts) buffer->last_ts = event->ts;
    buffer->received++;
    if (buffer->retained == buffer->capacity) { buffer->overflow++; return 0; }
    if (buffer->io_error) return 0;
    memcpy(buffer->bytes + buffer->pending, event, sizeof(*event));
    buffer->pending += sizeof(*event);
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
