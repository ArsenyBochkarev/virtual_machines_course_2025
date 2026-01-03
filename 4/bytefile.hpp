#ifndef BYTEFILE_HPP
#define BYTEFILE_HPP

#include "lamai.hpp"
#include "runtime.hpp"

extern int32_t code_size;

void check(bool condition, char *msg, int32_t offset);

/* The unpacked representation of bytecode file */
typedef struct bytefile_t {
    char *string_ptr;                  /* A pointer to the beginning of the string table */
    int32_t  *public_ptr;              /* A pointer to the beginning of publics table    */
    char *code_ptr;                    /* A pointer to the bytecode itself               */
    int32_t   stringtab_size;          /* The size (in bytes) of the string table        */
    int32_t   global_area_size;        /* The size (in words) of global area             */
    int32_t   public_symbols_number;   /* The number of public symbols                   */
    char  buffer[MAX_FILE_SIZE];
} bytefile;

/* Gets a string from a string table by an index */
char* get_string(bytefile *f, int pos);

/* Reads a binary bytecode file by name and unpacks it */
bytefile* read_file(char *fname, bytefile *file);

#endif // BYTEFILE_HPP