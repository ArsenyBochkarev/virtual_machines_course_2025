#ifndef SAFE_READ_BYTE_HPP
#define SAFE_READ_BYTE_HPP

#include <csetjmp>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <optional>
#include <signal.h>
#include <setjmp.h>


inline std::optional<uintptr_t> remembered_addr = std::nullopt;
inline struct sigaction prev_sigsegv_handler;
inline struct sigaction prev_sigbus_handler;
inline sigjmp_buf env;
inline void sig_handler(int sig, siginfo_t *info, void *ucontext) {
    uintptr_t mem_hit = reinterpret_cast<uintptr_t>(info->si_addr);
    bool is_sigsegv = (sig == SIGSEGV);

    // Return back only if signal occured in desired memory
    if (remembered_addr.has_value() && remembered_addr.value() == mem_hit) {
#ifdef SAFE_READ_BYTE_DEBUG
        const char msg1[] = "Custom handler for signal: ";
        write(STDOUT_FILENO, msg1, strlen(msg1));
        const char* msg2 = (is_sigsegv) ? "SIGSEGV\n" : "SIGBUS\n";
        write(STDOUT_FILENO, msg2, strlen(msg2));
#endif
        siglongjmp(env, 1);
    }

    // Otherwise call previous handler
    struct sigaction sa = (is_sigsegv) ? prev_sigsegv_handler : prev_sigbus_handler;
    if (sa.sa_handler == SIG_DFL) {
        sigaction(sig, &sa, NULL);
        raise(sig);
    } else if (sa.sa_handler != SIG_IGN) {
        sa.sa_sigaction(sig, info, ucontext);
    }
}

inline bool is_canonical(uintptr_t addr) {
    int64_t saddr = static_cast<int64_t>(addr);
    // Others should be the same
    return (saddr << 16) >> 16 == saddr;
}

inline std::optional<uint8_t> safe_read_uint8(const uint8_t *p) {
    uintptr_t addr = reinterpret_cast<uintptr_t>(p);
    // We're unable to detect address in sig_handler if address isn't canonical
    if (!is_canonical(addr))
        return std::nullopt;

    struct sigaction sigsegv_action;
    sigsegv_action.sa_flags = SA_SIGINFO; 
    sigsegv_action.sa_sigaction = sig_handler;
    sigemptyset(&sigsegv_action.sa_mask);
    if (sigaction(SIGSEGV, &sigsegv_action, &prev_sigsegv_handler) != 0 || sigaction(SIGBUS, &sigsegv_action, &prev_sigbus_handler))
        return std::nullopt;

    remembered_addr = addr;
    std::optional<uint8_t> result = std::nullopt;
    if (sigsetjmp(env, 1) == 0)
        result = *p;
    else
        result = std::nullopt;

    // We also need to restore handlers
    if (sigaction(SIGSEGV, &prev_sigsegv_handler, NULL) != 0 || sigaction(SIGBUS, &prev_sigbus_handler, NULL) != 0)
        return std::nullopt;
    return result;
}

#endif // SAFE_READ_BYTE_HPP
