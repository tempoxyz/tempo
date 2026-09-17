/* Baseline x86-64 only: run before any portable-v3 application binary. */
#define _GNU_SOURCE
#include <cpuid.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static bool feature_set(unsigned ecx1, unsigned edx1, unsigned ebx7,
                        unsigned extended_ecx, uint64_t xcr0) {
    const unsigned c1 = (1U<<0)|(1U<<9)|(1U<<12)|(1U<<13)|(1U<<19)|
        (1U<<20)|(1U<<22)|(1U<<23)|(1U<<26)|(1U<<27)|(1U<<28)|(1U<<29);
    const unsigned d1 = (1U<<0)|(1U<<8)|(1U<<15)|(1U<<23)|(1U<<24)|(1U<<25)|(1U<<26);
    const unsigned b7 = (1U<<3)|(1U<<5)|(1U<<8);
    const unsigned ex = (1U<<0)|(1U<<5);
    return (ecx1 & c1)==c1 && (edx1 & d1)==d1 && (ebx7 & b7)==b7 &&
           (extended_ecx & ex)==ex && (xcr0 & 6)==6;
}

static bool current_supported(void) {
    unsigned a,b,c,d,c1,d1,b7,extended;
    if (__get_cpuid_max(0,0)<7 || __get_cpuid_max(0x80000000,0)<0x80000001) return false;
    __cpuid_count(1,0,a,b,c,d); c1=c; d1=d;
    /* XGETBV is legal only after XSAVE and OSXSAVE admission. */
    if ((c1 & ((1U<<26)|(1U<<27))) != ((1U<<26)|(1U<<27))) return false;
    unsigned xlo,xhi;
    __asm__ volatile("xgetbv" : "=a"(xlo), "=d"(xhi) : "c"(0));
    __cpuid_count(7,0,a,b,c,d); b7=b;
    __cpuid_count(0x80000001,0,a,b,c,d); extended=c;
    return feature_set(c1,d1,b7,extended,((uint64_t)xhi<<32)|xlo);
}

int main(void) {
    cpu_set_t original,one;
    unsigned total=0,checked=0;
    bool supported=true;
    CPU_ZERO(&original);
    if (sched_getaffinity(0,sizeof(original),&original)) supported=false;
    if (supported) {
        total=(unsigned)CPU_COUNT(&original);
        if (!total) supported=false;
        for (int cpu=0; cpu<CPU_SETSIZE; ++cpu) {
            if (!CPU_ISSET(cpu,&original)) continue;
            CPU_ZERO(&one); CPU_SET(cpu,&one);
            if (sched_setaffinity(0,sizeof(one),&one)) { supported=false; break; }
            ++checked;
            if (!current_supported()) supported=false;
        }
        if (sched_setaffinity(0,sizeof(original),&original)) supported=false;
    }
    printf("{\"schema\":1,\"supported\":%s,\"checked\":%u,\"total\":%u}\n",
        supported && checked==total && total ? "true" : "false",checked,total);
    return supported && checked==total && total ? 0 : 1;
}
