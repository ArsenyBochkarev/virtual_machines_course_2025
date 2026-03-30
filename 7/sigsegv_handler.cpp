#include "sigsegv_handler.hpp"


std::atomic<LockFreePool *> active_lock_free_pools[MAX_POOLS];
std::atomic<int> lock_free_pool_count{0};

std::atomic<Pool *> active_pools[MAX_POOLS];
std::atomic<int> pool_count{0};

static struct sigaction prev_handler;
static bool handler_registered = false;

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    char *mem_hit = static_cast<char *>(info->si_addr);
    const char *faulted_pool_name = nullptr;

    int count = lock_free_pool_count.load(std::memory_order_acquire);
    for (int i = 0; i < count; ++i) {
        LockFreePool *p = active_lock_free_pools[i].load(std::memory_order_acquire);
        if (p && p->is_in_guard_zone(mem_hit)) {
            faulted_pool_name = p->get_name();
            break;
        }
    }
    if (!faulted_pool_name) {
        count = pool_count.load(std::memory_order_acquire);
        for (int i = 0; i < count; ++i) {
            Pool *p = active_pools[i].load(std::memory_order_acquire);
            if (p && p->is_in_guard_zone(mem_hit)) {
                faulted_pool_name = p->get_name();
                break;
            }
        }
    }

    if (faulted_pool_name) {
        const char msg1[] = "SIGSEGV for pool: \"";
        const char msg2[] = "\"\n";
        write(STDERR_FILENO, msg1, strlen(msg1));
        write(STDERR_FILENO, faulted_pool_name, strlen(faulted_pool_name));
        write(STDERR_FILENO, msg2, strlen(msg2));
    }

    if (prev_handler.sa_handler == SIG_DFL) {
        sigaction(sig, &prev_handler, NULL);
        raise(sig);
    } else if (prev_handler.sa_handler != SIG_IGN) {
        prev_handler.sa_sigaction(sig, info, ucontext);
    }
}

void register_sigsegv_handler() {
    if (!handler_registered) {
        struct sigaction sa;
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = sigsegv_handler;
        sigemptyset(&sa.sa_mask);
        assert(sigaction(SIGSEGV, &sa, &prev_handler) == 0);
        handler_registered = true;
    }
}
