#ifndef LAMAV_HPP
#define LAMAV_HPP

typedef struct bytefile_t bytefile;
void verify_bytecode(size_t enter_pt, auint *stack, bytefile_t *bf);

#endif // LAMAV_HPP
