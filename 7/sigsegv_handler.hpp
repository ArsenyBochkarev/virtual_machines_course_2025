#ifndef SIGSEGV_HANDLER_HPP
#define SIGSEGV_HANDLER_HPP

#include <atomic>
#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <stdlib.h>
#include <csignal>
#include <cstring>
#include <cassert>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pools.hpp"


constexpr int MAX_POOLS = 128;
class PoolRegistry {
    PoolRegistry();
    ~PoolRegistry() = default;

    std::mutex registry_mtx;
    std::atomic<bool> active_pools[MAX_POOLS];
    std::atomic<char *> guard_starts[MAX_POOLS];
    std::atomic<char *> guard_ends[MAX_POOLS];
public:
    static PoolRegistry& getInstance();
    int register_pool(char* guard_start, char* guard_end);
    void unregister_pool(int id);
    int find_pool_id(char *addr);
};

#endif // SIGSEGV_HANDLER_HPP