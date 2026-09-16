#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

__attribute__((noinline, noipa)) void lifecycle_thread_register(uint64_t ordinal) {
    __asm__ volatile("" : : "r"(ordinal) : "memory");
}
__attribute__((noinline, noipa)) void lifecycle_cutoff(uint64_t timestamp) {
    __asm__ volatile("" : : "r"(timestamp) : "memory");
}
static uint64_t now_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void *worker(void *opaque) {
    lifecycle_thread_register((uintptr_t)opaque);
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (!sched_getaffinity(0, sizeof(allowed), &allowed)) {
        for (int cpu=0;cpu<CPU_SETSIZE;cpu++) if (CPU_ISSET(cpu,&allowed)) {
            cpu_set_t one; CPU_ZERO(&one); CPU_SET(cpu,&one);
            pthread_setaffinity_np(pthread_self(),sizeof(one),&one); break;
        }
    }
    volatile uint64_t x=1;
    for (int i=0;i<8;i++) {
        uint64_t end=now_ns()+60000000ULL;
        while(now_ns()<end) x=x*3+1;
        usleep(10000);
    }
    return 0;
}
int main(void) {
    lifecycle_thread_register(1);
    pthread_t a,b;
    if(pthread_create(&a,0,worker,(void*)2)||pthread_create(&b,0,worker,(void*)3))return 1;
    usleep(350000);
    lifecycle_cutoff(now_ns());
    pthread_join(a,0); pthread_join(b,0);
    return 0;
}
