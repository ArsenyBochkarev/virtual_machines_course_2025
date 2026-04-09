#ifndef SAFE_READ_BYTE_HPP
#define SAFE_READ_BYTE_HPP

#include <csetjmp>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <optional>
#include <signal.h>
#include <setjmp.h>


std::optional<uint8_t> safe_read_uint8(const uint8_t *p);

#endif // SAFE_READ_BYTE_HPP
