#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pool.h"


Pool::Pool(size_t capacity, size_t max_alloc_size) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    auto round_up = [page_size](size_t n) -> size_t {
        return (n + page_size - 1) / page_size * page_size;
    };

    // max_alloc_size should be rounded up to page size
    guard_size = round_up(max_alloc_size);
    if (guard_size == 0)
        guard_size = page_size; // guard_size must be at least one page in size
    size_t rounded_capacity = round_up(capacity); // Similarly, round up the requested capacity to page size

    total_size = rounded_capacity + guard_size;
    base_addr = (char*)mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (base_addr == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }
    if (mprotect(base_addr, guard_size, PROT_NONE) == -1) {
        perror("mprotect failed");
        exit(EXIT_FAILURE);
    }

    first_free = base_addr + total_size;
}
