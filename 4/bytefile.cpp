#include "bytefile.hpp"

int32_t code_size = -1;

void check(bool condition, char *msg, int32_t offset) {
    if (!condition)
        failure(msg, offset);
}

/* Gets a string from a string table by an index */
char* get_string(bytefile *f, int pos) {
    return &f->string_ptr[pos];
}

/* Reads a binary bytecode file by name and unpacks it */
bytefile* read_file(char *fname, bytefile *file) {
    FILE *f = fopen (fname, "rb");
    long size;

    if (!f)
        failure("%s\n", strerror(errno));

    if (fseek (f, 0, SEEK_END) == -1) {
        fclose(f);
        failure("%s\n", strerror(errno));
    }

    size = ftell (f);
    if (size == -1) {
        fclose(f);
        failure("%s\n", strerror(errno));
    }

    rewind (f);
    if (size != fread (&file->stringtab_size, 1, size, f)) {
        fclose(f);
        failure("%s\n", strerror(errno));
    }
    fclose (f);

    check(file->public_symbols_number > 0, "corrupted public_symbols_number in file. Offset: 0x%x", 0);
    check(size + sizeof(int32_t)*4 < MAX_FILE_SIZE, "Input file too big. Offset: 0x%x", 0);
    file->string_ptr = &file->buffer [file->public_symbols_number * 2 * sizeof(int32_t)];
    file->public_ptr = (int32_t*) file->buffer;
    file->code_ptr = &file->string_ptr [file->stringtab_size];

    code_size = size - file->public_symbols_number * 2 * sizeof(int32_t) + file->stringtab_size;

    return file;
}