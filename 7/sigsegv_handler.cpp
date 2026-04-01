#include "sigsegv_handler.hpp"
#include "pools.hpp"


static struct sigaction prev_handler;

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    char *mem_hit = static_cast<char *>(info->si_addr);
    int pool_id = -1;

    for (int i = 0; i < MAX_POOLS; ++i) {
        BasePool *p = PoolRegistry::active_pools[i].load(std::memory_order_acquire);
        if (p && p->is_in_guard_zone(mem_hit)) {
            pool_id = i;
            break;
        }
    }

    if (pool_id != -1) {
        const char msg1[] = "SIGSEGV for pool with ID: ";
        const char msg3[] = "\n";
        write(STDERR_FILENO, msg1, strlen(msg1));
        int64_t msg2 = 0x0a30303030 | (pool_id / 1000) 
                                    | (pool_id / 100 % 10) << 8 
                                    | (pool_id / 10 % 10) << 16 
                                    | (pool_id % 10) << 24;
        write(STDERR_FILENO, reinterpret_cast<char *>(&msg2), 5);
        write(STDERR_FILENO, msg3, strlen(msg3));
        _exit(EXIT_FAILURE);
    }

    if (prev_handler.sa_handler == SIG_DFL) {
        sigaction(sig, &prev_handler, NULL);
        raise(sig);
    } else if (prev_handler.sa_handler != SIG_IGN) {
        prev_handler.sa_sigaction(sig, info, ucontext);
    }
}

void PoolRegistry::register_pool(BasePool* pool) {
    for (int i = 0; i < MAX_POOLS; ++i) {
        BasePool* expected = nullptr;
        // nullptr -> pool
        if (active_pools[i].compare_exchange_strong(expected, pool, std::memory_order_release))
            return;
    }
    assert(false && "Too many pools");
}

void PoolRegistry::unregister_pool(BasePool* pool) {
    for (int i = 0; i < MAX_POOLS; ++i) {
        BasePool* expected = pool;
        // pool -> nullptr
        if (active_pools[i].compare_exchange_strong(expected, nullptr, std::memory_order_release))
            return;
    }
    assert(false && "Pool not found");
}

PoolRegistry::PoolRegistry() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigsegv_handler;
    sigemptyset(&sa.sa_mask);
    assert(sigaction(SIGSEGV, &sa, &prev_handler) == 0);
}

PoolRegistry& PoolRegistry::getInstance() {
    static PoolRegistry instance;
    return instance;
}
