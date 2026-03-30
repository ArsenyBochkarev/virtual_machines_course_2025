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

extern std::atomic<LockFreePool *> active_lock_free_pools[MAX_POOLS];
extern std::atomic<int> lock_free_pool_count;

extern std::atomic<Pool *> active_pools[MAX_POOLS];
extern std::atomic<int> pool_count;

void register_sigsegv_handler();

#endif // SIGSEGV_HANDLER_HPP