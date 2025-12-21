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
extern aint Barray_patt (void *d, aint n);
extern aint Bclosure_tag_patt (void *x);

extern void push_extra_root (void **p);
extern void pop_extra_root (void **p);

extern void *LmakeArray (aint length);
extern void *Barray (aint* args, aint bn);
extern void *Bstring (aint* args);
extern aint LtagHash (char *);
extern void *Bsexp (aint* args, aint bn);
extern aint Btag (void *d, aint t, aint n);
extern void *Bclosure (aint* args, aint bn);

extern aint Lread ();
extern aint Lwrite (aint n);
extern aint Llength (void *p);
extern void *Lstring (aint* args);

extern void *Bsta (void *x, aint i, void *v);
extern void *Belem (void *p, aint i);
extern void Bmatch_failure (void *v, char *fname, aint line, aint col);
}

#endif // RUNTIME_HPP