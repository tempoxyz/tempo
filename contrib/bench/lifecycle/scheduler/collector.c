/* Private fixed-width records only; never receives native process/thread IDs. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct event {
    uint64_t ts;
    uint32_t ordinal;
    uint16_t kind;
    uint16_t state;
};
_Static_assert(sizeof(struct event) == 16, "fixed binary scheduler schema");
struct buffer {
    size_t used, capacity, invalid, overflow;
    struct event *data;
};

void *allocate_capacity(size_t capacity) {
    if (!capacity || capacity > (256UL * 1024 * 1024) / sizeof(struct event)) return NULL;
    struct buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer) return NULL;
    buffer->capacity = capacity;
    buffer->data = malloc(capacity * sizeof(struct event));
    if (!buffer->data) { free(buffer); return NULL; }
    return buffer;
}
void *allocate(void) { return allocate_capacity((256UL * 1024 * 1024) / sizeof(struct event)); }

int collect(void *context, void *data, size_t size) {
    struct buffer *buffer = context;
    if (size != sizeof(struct event)) { buffer->invalid++; return 0; }
    struct event *event = data;
    if (!event->ordinal || event->ordinal > 8192 || event->kind > 5 ||
        (event->kind != 1 && event->state) || event->state > 256) {
        buffer->invalid++;
        return 0;
    }
    if (buffer->used == buffer->capacity) { buffer->overflow++; return 0; }
    memcpy(buffer->data + buffer->used++, data, size);
    return 0;
}
size_t metric(void *context, int index) {
    struct buffer *buffer = context;
    return index == 0 ? buffer->used : index == 1 ? buffer->invalid : buffer->overflow;
}
void *records(void *context) { return ((struct buffer *)context)->data; }
void release(void *context) {
    struct buffer *buffer = context;
    free(buffer->data);
    free(buffer);
}
