#ifndef POOLS_HPP
#define POOLS_HPP

#include <cstddef>
#include <atomic>
#include <mutex>

class BasePool {
public:
    char* base_addr;
    size_t total_size;
    int pool_id;

    BasePool(size_t capacity, size_t max_alloc_size);
    ~BasePool();
};

class Pool : public BasePool {
    char* first_free;
public:
    Pool(size_t capacity, size_t max_alloc_size);
    inline void* allocate(size_t size) {
        return first_free -= size;
    }
};

class LockFreePool : public BasePool {
    std::atomic<char*> first_free;
public:
    LockFreePool(size_t capacity, size_t max_alloc_size);
    inline void* allocate(size_t size) {
        return first_free.fetch_sub(size, std::memory_order_relaxed) - size;
    }
};

class MutexedPool : public Pool {
    std::mutex mtx;
public:
    MutexedPool(size_t capacity, size_t max_alloc_size);
    inline void* allocate(size_t size) {
        std::lock_guard<std::mutex> lock(mtx);
        return Pool::allocate(size);
    }
};

#endif // POOLS_HPP