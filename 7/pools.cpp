#include <iostream>
#include <unistd.h>
#include <sys/mman.h>
#include <csignal>
#include <cstring>
#include <cassert>

#include "pools.hpp"
#include "sigsegv_handler.hpp"


LockFreePool::LockFreePool(size_t capacity, size_t max_alloc_size, const char* name) : pool_name(name) {
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
    base_addr = static_cast<char *>(mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0));
    if (base_addr == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }
    if (mprotect(base_addr, guard_size, PROT_NONE) == -1) {
        perror("mprotect failed");
        exit(EXIT_FAILURE);
    }

    first_free.store(base_addr + total_size, std::memory_order_relaxed);

    pool_id = lock_free_pool_count.fetch_add(1, std::memory_order_acq_rel);
    active_lock_free_pools[pool_id].store(this, std::memory_order_release);
}

LockFreePool::~LockFreePool() {
    active_lock_free_pools[pool_id].store(nullptr, std::memory_order_release);
    munmap(base_addr, total_size);
}


Pool::Pool(size_t capacity, size_t max_alloc_size, const char* name) : pool_name(name) {
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
    base_addr = static_cast<char *>(mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0));
    if (base_addr == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }
    if (mprotect(base_addr, guard_size, PROT_NONE) == -1) {
        perror("mprotect failed");
        exit(EXIT_FAILURE);
    }

    first_free = base_addr + total_size;

    pool_id = pool_count.fetch_add(1, std::memory_order_acq_rel);
    active_pools[pool_id].store(this, std::memory_order_release);
}

Pool::~Pool() {
    active_pools[pool_id].store(nullptr, std::memory_order_release);
    munmap(base_addr, total_size);
}
