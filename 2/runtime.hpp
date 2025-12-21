#ifndef RUNTIME_HPP
#define RUNTIME_HPP

extern "C" {
#define _Noreturn [[noreturn]]

#include "./Lama/runtime/gc.h"
#include "./Lama/runtime/runtime.h"

extern aint Bstring_patt (void *x, void *y);
extern aint Bstring_tag_patt (void *x);
extern aint Barray_tag_patt (void *x);
extern aint Bsexp_tag_patt (void *x);
extern aint Bboxed_patt (void *x);
extern aint Bunboxed_patt (void *x);
extern aint Bclosure_tag_patt (void *x);
}

#endif // RUNTIME_HPP