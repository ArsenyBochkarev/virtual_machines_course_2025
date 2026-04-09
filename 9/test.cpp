#include <cassert>
#include <functional>
#include <iostream>
#include <string>
#include <sys/mman.h>

#define SAFE_READ_BYTE_DEBUG
#include "safe_read_byte.hpp"
#undef SAFE_READ_BYTE_DEBUG


void test(std::string test_name, std::function<void()> test_func) {
    std::cout << "=== test " + test_name + " begin ===\n";
    test_func();
    std::cout << "=== test " + test_name + " end ===\n\n\n";
}

void simple_tests() {
    int n = 123;
    assert(safe_read_uint8(reinterpret_cast<const uint8_t *>(&n)).value() == 123);
    const char* msg = "Hello";
    assert(safe_read_uint8(reinterpret_cast<const uint8_t *>(msg)).value() == 'H');
    for (int i = 0; i < 10; i++)
        assert(safe_read_uint8(reinterpret_cast<const uint8_t *>(&n)).value() == 123);

    assert(safe_read_uint8(reinterpret_cast<const uint8_t *>(0)) == std::nullopt);
    assert(safe_read_uint8(reinterpret_cast<const uint8_t *>(0x12345)) == std::nullopt);
    // Two signal handlers should be called
}

void non_canonical_addresses_test() {
    assert(safe_read_uint8(reinterpret_cast<const uint8_t *>(0x0000FFFF0000FFFF0000)) == std::nullopt);
    assert(safe_read_uint8(reinterpret_cast<const uint8_t *>(0x033FF00000000000)) == std::nullopt);
    // No signal handlers should be called
}


#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif

void handlers_restore_test() {
    // Save current handlers
    struct sigaction old_segv, old_bus;
    sigaction(SIGSEGV, nullptr, &old_segv);
    sigaction(SIGBUS, nullptr, &old_bus);

    int dummy = 42;
    auto res = safe_read_uint8(reinterpret_cast<const uint8_t*>(&dummy));
    assert(res.has_value() && res.value() == 42);

    struct sigaction new_segv, new_bus;
    sigaction(SIGSEGV, nullptr, &new_segv);
    sigaction(SIGBUS, nullptr, &new_bus);
    assert(new_segv.sa_sigaction == old_segv.sa_sigaction);
    assert((new_segv.sa_flags & ~SA_RESTORER) == (old_segv.sa_flags & ~SA_RESTORER));
    assert(new_bus.sa_sigaction == old_bus.sa_sigaction);
    assert((new_bus.sa_flags & ~SA_RESTORER) == (old_bus.sa_flags & ~SA_RESTORER));
    // No signal should fire in this test
}

static sigjmp_buf external_env;
static bool external_handler_called = false;
static void external_sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    external_handler_called = true;
    const char msg[] = "External handler\n";
    write(STDOUT_FILENO, msg, strlen(msg));
    siglongjmp(external_env, 1);
}

void external_handler_test() {
    struct sigaction prev_handler;
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = external_sigsegv_handler;
    sigemptyset(&sa.sa_mask);
    assert(sigaction(SIGSEGV, &sa, &prev_handler) == 0);

    const auto *fault_addr = reinterpret_cast<const uint8_t *>(0x12345);
    std::optional<uint8_t> res1 = std::nullopt;
    external_handler_called = false;
    if (sigsetjmp(external_env, 1) == 0) {
        res1 = *fault_addr;
        std::cout << "res1 = " << res1.value() << "\n";
    } else
        res1 = std::nullopt;
    assert(external_handler_called);
    assert(res1 == std::nullopt);
    // External handler should be triggered

    external_handler_called = false;
    auto res2 = safe_read_uint8(fault_addr);
    assert(res2 == std::nullopt);
    assert(!external_handler_called);

    sigaction(SIGSEGV, &prev_handler, nullptr);
    // External handler should not be triggered
    // `sig_handler` from `safe_read_byte` should be triggered
}

int main() {
    test("simple_tests", simple_tests);
    test("non_canonical_addresses_test", non_canonical_addresses_test);
    test("handlers_restore_test", handlers_restore_test);
    test("external_handler_test", external_handler_test);
    return 0;
}