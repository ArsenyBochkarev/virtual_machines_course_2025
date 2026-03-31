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
public:
    static inline std::atomic<BasePool *> active_pools[MAX_POOLS];
    static void register_pool(BasePool *p);
    static void unregister_pool(BasePool *p);
    static void register_sigsegv_handler();
};

#endif // SIGSEGV_HANDLER_HPP