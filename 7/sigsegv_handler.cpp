#include "sigsegv_handler.hpp"
#include "pools.hpp"


static struct sigaction prev_handler;

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    char *mem_hit = static_cast<char *>(info->si_addr);
    int pool_id = PoolRegistry::getInstance().find_pool_id(mem_hit);

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

int PoolRegistry::register_pool(char* guard_start, char* guard_end) {
    std::lock_guard<std::mutex> lock(registry_mtx); // To ensure no race for pool_id happens
    for (int i = 0; i < MAX_POOLS; ++i) {
        bool expected = false;
        // Lock first non-true slot
        if (!active_pools[i].load(std::memory_order_relaxed)) {
            guard_starts[i].store(guard_start, std::memory_order_release);
            guard_ends[i].store(guard_end, std::memory_order_release);
            active_pools[i].store(true, std::memory_order_release);
            return i; // pool_id
        }
    }
    assert(false && "Too many pools");
}

void PoolRegistry::unregister_pool(int id) {
    assert(id >= 0 && id < MAX_POOLS && "Ill-formed pool ID");
    active_pools[id].store(false, std::memory_order_release);
}

int PoolRegistry::find_pool_id(char *addr) {
    for (int i = 0; i < MAX_POOLS; ++i) {
        if (active_pools[i].load(std::memory_order_acquire)) {
            char *start = guard_starts[i].load(std::memory_order_acquire);
            char *end = guard_ends[i].load(std::memory_order_acquire);
            if (addr >= start && addr < end)
                // We don't care if here active_pools[i].load == false,
                // we've found memory that got hit by pool of this guard,
                // so return it as we should
                return i;
        }
    }
    return -1;
}

PoolRegistry::PoolRegistry() {
    for (int i = 0; i < MAX_POOLS; ++i)
        active_pools[i].store(false, std::memory_order_relaxed);
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
