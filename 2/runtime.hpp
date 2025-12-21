#ifndef RUNTIME_HPP
#define RUNTIME_HPP

extern "C" {
#define _Noreturn [[noreturn]]

#include "./Lama/runtime/gc.h"
#include "./Lama/runtime/runtime.h"
}

#endif // RUNTIME_HPP