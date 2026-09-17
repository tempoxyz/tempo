#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <time.h>
#include <stdint.h>
static int word;
static int channel[2];
__attribute__((noinline)) void reth_lifecycle_thread_register(uint64_t ordinal, uint64_t epoch) {
    asm volatile("" : : "r"(ordinal), "r"(epoch) : "memory");
}
static void *worker(void *argument) {
    uintptr_t role=(uintptr_t)argument;
    reth_lifecycle_thread_register(role,1);
    struct timespec delay={.tv_nsec=5000000};
    for(int i=0;i<24;i++) {
        if(role==1)nanosleep(&delay,0);
        if(role==2)syscall(SYS_futex,&word,FUTEX_WAIT_PRIVATE,0,&delay,0,0);
        if(role==3){char byte; if(read(channel[0],&byte,1)!=1)return (void*)1;}
    }
    return 0;
}
int main(void) {
    pthread_t tasks[3];if(pipe(channel))return 1;
    for(uintptr_t i=1;i<=3;i++)if(pthread_create(&tasks[i-1],0,worker,(void*)i))return 2;
    struct timespec delay={.tv_nsec=5000000};
    for(int i=0;i<24;i++){nanosleep(&delay,0);if(write(channel[1],"x",1)!=1)return 3;}
    for(int i=0;i<3;i++){void *result;if(pthread_join(tasks[i],&result)||result)return 4;}
    close(channel[0]);close(channel[1]);return 0;
}
