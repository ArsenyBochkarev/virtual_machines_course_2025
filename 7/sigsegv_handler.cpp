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
    for (int i = 0; i < MAX_POOLS; ++i) {
        char *expected = nullptr;
        if (guard_starts[i].compare_exchange_strong(expected, guard_start, std::memory_order_release, std::memory_order_relaxed)) {
            guard_ends[i].store(guard_end, std::memory_order_relaxed);
            return i;
        }
    }
    assert(false && "Too many pools");
}

void PoolRegistry::unregister_pool(int id) {
    assert(id >= 0 && id < MAX_POOLS && "Ill-formed pool ID");
    guard_starts[id].store(nullptr, std::memory_order_release);
}

int PoolRegistry::find_pool_id(char *addr) {
    for (int i = 0; i < MAX_POOLS; ++i) {
        if (char *start = guard_starts[i].load(std::memory_order_acquire)) {
            char *end = guard_ends[i].load(std::memory_order_acquire);
            if (addr >= start && addr < end)
                return i;
        }
    }
    return -1;
}

PoolRegistry::PoolRegistry() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigsegv_handler;
    sigemptyset(&sa.sa_mask);
    assert(sigaction(SIGSEGV, &sa, &prev_handler) == 0);
}
