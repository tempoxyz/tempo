#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#define LENGTH (32u * 1024u * 1024u)
static int owned_fd;
static volatile unsigned char sink;
static long major_faults[2];
__attribute__((noinline)) void reth_lifecycle_thread_register(uint64_t ordinal, uint64_t epoch) {
    asm volatile("" : : "r"(ordinal), "r"(epoch) : "memory");
}
static void *worker(void *argument) {
    uintptr_t role=(uintptr_t)argument;
    struct rusage before,after;
    reth_lifecycle_thread_register(role,1);
    if(getrusage(RUSAGE_THREAD,&before))return (void*)1;
    for(int cycle=0;cycle<2;cycle++) {
        /* This fd names only our parent's freshly created, fsynced tempfile. */
        if(posix_fadvise(owned_fd,0,LENGTH,POSIX_FADV_DONTNEED))return (void*)2;
        if(role==1) {
            unsigned char *p=mmap(0,LENGTH,PROT_READ,MAP_PRIVATE,owned_fd,0);
            if(p==MAP_FAILED)return (void*)3;
            if(madvise(p,LENGTH,MADV_RANDOM))return (void*)4;
            for(size_t page=0;page<LENGTH/4096;page++)sink^=p[((page*8191)%(LENGTH/4096))*4096];
            if(munmap(p,LENGTH))return (void*)5;
        } else {
            unsigned char buffer[4096];
            for(size_t page=0;page<LENGTH/4096;page++) {
                off_t offset=((page*8191)%(LENGTH/4096))*4096;
                if(pread(owned_fd,buffer,sizeof(buffer),offset)!=sizeof(buffer))return (void*)6;
                sink^=buffer[0];
            }
        }
    }
    if(getrusage(RUSAGE_THREAD,&after))return (void*)7;
    major_faults[role-1]=after.ru_majflt-before.ru_majflt;
    return 0;
}
int main(int argc,char **argv) {
    if(argc!=2)return 1;owned_fd=atoi(argv[1]);
    if(owned_fd<3)return 2;
    for(uintptr_t role=1;role<=2;role++) {
        pthread_t task;void *result;
        if(pthread_create(&task,0,worker,(void*)role)||pthread_join(task,&result)||result)return 3;
    }
    /* Numeric fixture evidence only, no file/native identity or payload. */
    printf("%ld %ld\n",major_faults[0],major_faults[1]);
    return 0;
}
