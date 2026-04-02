#include <iostream>
#include <unistd.h>
#include <sys/mman.h>
#include <csignal>
#include <cstring>
#include <cassert>

#include "pools.hpp"
#include "sigsegv_handler.hpp"


static const size_t page_size = sysconf(_SC_PAGESIZE);

BasePool::BasePool(size_t capacity, size_t max_alloc_size) {
    auto round_up = [](size_t n) -> size_t {
        return (n + page_size - 1) & ~(page_size - 1);
    };
    size_t guard_size = round_up(max_alloc_size);
    size_t rounded_capacity = round_up(capacity);

    total_size = rounded_capacity + guard_size;
    base_addr = static_cast<char *>(mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0));
    if (base_addr == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }
    if (guard_size > 0 && mprotect(base_addr, guard_size, PROT_NONE) == -1) {
        perror("mprotect failed");
        exit(EXIT_FAILURE);
    }

    pool_id = PoolRegistry::getInstance().register_pool(base_addr, base_addr + guard_size);
}
BasePool::~BasePool() {
    PoolRegistry::getInstance().unregister_pool(pool_id);
    munmap(base_addr, total_size);
}

Pool::Pool(size_t capacity, size_t max_alloc_size) : BasePool(capacity, max_alloc_size) {
    first_free = base_addr + total_size;
}
LockFreePool::LockFreePool(size_t capacity, size_t max_alloc_size) : BasePool(capacity, max_alloc_size) {
    first_free.store(base_addr + total_size, std::memory_order_relaxed);
}
MutexedPool::MutexedPool(size_t capacity, size_t max_alloc_size) : Pool(capacity, max_alloc_size) {}