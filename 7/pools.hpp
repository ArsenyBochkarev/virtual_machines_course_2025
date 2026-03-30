#ifndef POOLS_HPP
#define POOLS_HPP

#include <cstddef>
#include <atomic>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/mman.h>


class LockFreePool {
    char *base_addr;
    std::atomic<char*> first_free;
    size_t total_size;
    size_t guard_size;
    const char *pool_name;
    int pool_id;

public:
    LockFreePool(size_t capacity, size_t max_alloc_size, const char* name);
    ~LockFreePool();

    inline void* allocate(size_t size) {
        // fetch_sub returns old value
        return first_free.fetch_sub(size, std::memory_order_acq_rel) - size;
    }

    bool is_in_guard_zone(void* addr) const {
        return addr >= base_addr && addr < (base_addr + guard_size);
    }
    const char* get_name() const {
        return pool_name;
    }
};

class Pool {
    char *base_addr;
    char *first_free;
    size_t total_size;
    size_t guard_size;
    const char *pool_name;
    int pool_id;

public:
    Pool(size_t capacity, size_t max_alloc_size, const char* name);
    ~Pool();

    inline void *allocate(size_t size) {
        return (first_free -= size);
    }

    bool is_in_guard_zone(void* addr) const {
        return addr >= base_addr && addr < (base_addr + guard_size);
    }
    const char* get_name() const {
        return pool_name;
    }
};

#endif // POOLS_HPP