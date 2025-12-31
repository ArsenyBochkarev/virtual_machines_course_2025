/* Lama SM Bytecode interpreter */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

void *__start_custom_data;
void *__stop_custom_data;

void failure (char *s, ...) {
  printf("FAIL");
  exit(255);
}

/* The unpacked representation of bytecode file */
typedef struct
{
  char *string_ptr;          /* A pointer to the beginning of the string table */
  int *public_ptr;           /* A pointer to the beginning of publics table    */
  char *code_ptr;            /* A pointer to the bytecode itself               */
  int *global_ptr;           /* A pointer to the global area                   */
  int stringtab_size;        /* The size (in bytes) of the string table        */
  int global_area_size;      /* The size (in words) of global area             */
  int public_symbols_number; /* The number of public symbols                   */
  char buffer[0];
} bytefile;

bytefile* read_file(char *fname);
char* get_string(bytefile *f, int pos);

// /* Gets a name for a public symbol */
char *get_public_name(bytefile *f, int i)
{
  return get_string(f, f->public_ptr[i * 2]);
}

// /* Gets an offset for a publie symbol */
int get_public_offset(bytefile *f, int i)
{
  return f->public_ptr[i * 2 + 1];
}

/* Disassembles a single instruction */
unsigned disassemble_instruction(const bytefile* bf, unsigned offset, FILE* f)
{
    static const char *ops[] = {"+", "-", "*", "/", "%", "<", "<=", ">", ">=", "==", "!=", "&&", "!!"};
    static const char *pats[] = {"=str", "#string", "#array", "#sexp", "#ref", "#val", "#fun"};
    static const char *lds[] = {"LD", "LDA", "ST"};
    
    const char *ip = bf->code_ptr + offset;
    const char *start_ip = ip;
    char x = *ip++;
    char h = (x & 0xF0) >> 4;
    char l = x & 0x0F;
    
    // fprintf(f, "0x%.8x: ", offset);
    
    if (h == 15) {
        fprintf(f, "<end>\n");
        return 1;
    }
    
    switch (h) {
    case 0:
        fprintf(f, "BINOP%s", ops[l - 1]);
        break;
        
    case 1:
        switch (l) {
        case 0:
            fprintf(f, "CONST %d", *(int*)ip);
            ip += sizeof(int);
            break;
        case 1:
            fprintf(f, "STRING %s", get_string((bytefile*)bf, *(int*)ip));
            ip += sizeof(int);
            break;
        case 2:
            fprintf(f, "SEXP %s ", get_string((bytefile*)bf, *(int*)ip));
            ip += sizeof(int);
            fprintf(f, "%d", *(int*)ip);
            ip += sizeof(int);
            break;
        case 3:
            fprintf(f, "STI");
            break;
        case 4:
            fprintf(f, "STA");
            break;
        case 5:
            fprintf(f, "JMP 0x%.8x", *(int*)ip);
            ip += sizeof(int);
            break;
        case 6:
            fprintf(f, "END");
            break;
        case 7:
            fprintf(f, "RET");
            break;
        case 8:
            fprintf(f, "DROP");
            break;
        case 9:
            fprintf(f, "DUP");
            break;
        case 10:
            fprintf(f, "SWAP");
            break;
        case 11:
            fprintf(f, "ELEM");
            break;
        default:
            failure("ERROR: invalid opcode %d-%d\n", h, l);
        }
        break;
        
    case 2:
    case 3:
    case 4:
        fprintf(f, "%s ", lds[h - 2]);
        switch (l) {
        case 0:
            fprintf(f, "G(%d)", *(int*)ip);
            ip += sizeof(int);
            break;
        case 1:
            fprintf(f, "L(%d)", *(int*)ip);
            ip += sizeof(int);
            break;
        case 2:
            fprintf(f, "A(%d)", *(int*)ip);
            ip += sizeof(int);
            break;
        case 3:
            fprintf(f, "C(%d)", *(int*)ip);
            ip += sizeof(int);
            break;
        default:
            failure("ERROR: invalid opcode %d-%d\n", h, l);
        }
        break;
        
    case 5:
        switch (l) {
        case 0:
            fprintf(f, "CJMPz 0x%.8x", *(int*)ip);
            ip += sizeof(int);
            break;
        case 1:
            fprintf(f, "CJMPnz 0x%.8x", *(int*)ip);
            ip += sizeof(int);
            break;
        case 2:
            fprintf(f, "BEGIN %d ", *(int*)ip);
            ip += sizeof(int);
            fprintf(f, "%d", *(int*)ip);
            ip += sizeof(int);
            break;
        case 3:
            fprintf(f, "CBEGIN %d ", *(int*)ip);
            ip += sizeof(int);
            fprintf(f, "%d", *(int*)ip);
            ip += sizeof(int);
            break;
        case 4: {
            fprintf(f, "CLOSURE 0x%.8x", *(int*)ip);
            ip += sizeof(int);
            int n = *(int*)ip;
            ip += sizeof(int);
            for (int i = 0; i < n; i++) {
                switch (*ip++) {
                case 0:
                    fprintf(f, "G(%d)", *(int*)ip);
                    ip += sizeof(int);
                    break;
                case 1:
                    fprintf(f, "L(%d)", *(int*)ip);
                    ip += sizeof(int);
                    break;
                case 2:
                    fprintf(f, "A(%d)", *(int*)ip);
                    ip += sizeof(int);
                    break;
                case 3:
                    fprintf(f, "C(%d)", *(int*)ip);
                    ip += sizeof(int);
                    break;
                default:
                    failure("ERROR: invalid opcode %d-%d\n", h, l);
                }
            }
            break;
        }
        case 5:
            fprintf(f, "CALLC %d", *(int*)ip);
            ip += sizeof(int);
            break;
        case 6:
            fprintf(f, "CALL 0x%.8x ", *(int*)ip);
            ip += sizeof(int);
            fprintf(f, "%d", *(int*)ip);
            ip += sizeof(int);
            break;
        case 7:
            fprintf(f, "TAG %s ", get_string((bytefile*)bf, *(int*)ip));
            ip += sizeof(int);
            fprintf(f, "%d", *(int*)ip);
            ip += sizeof(int);
            break;
        case 8:
            fprintf(f, "ARRAY %d", *(int*)ip);
            ip += sizeof(int);
            break;
        case 9:
            fprintf(f, "FAIL %d", *(int*)ip);
            ip += sizeof(int);
            fprintf(f, "%d", *(int*)ip);
            ip += sizeof(int);
            break;
        case 10:
            fprintf(f, "LINE %d", *(int*)ip);
            ip += sizeof(int);
            break;
        default:
            failure("ERROR: invalid opcode %d-%d\n", h, l);
        }
        break;
        
    case 6:
        fprintf(f, "PATT %s", pats[l]);
        break;
        
    case 7:
        switch (l) {
        case 0:
            fprintf(f, "CALL Lread");
            break;
        case 1:
            fprintf(f, "CALL Lwrite");
            break;
        case 2:
            fprintf(f, "CALL Llength");
            break;
        case 3:
            fprintf(f, "CALL Lstring");
            break;
        case 4:
            fprintf(f, "CALL Barray %d", *(int*)ip);
            ip += sizeof(int);
            break;
        default:
            failure("ERROR: invalid opcode %d-%d\n", h, l);
        }
        break;
        
    default:
        failure("ERROR: invalid opcode %d-%d\n", h, l);
    }
    
    return ip - start_ip;
}

/* Disassembles the bytecode pool */
void disassemble(FILE *f, bytefile *bf)
{
    unsigned offset = 0;
    while (1) {
        unsigned size = disassemble_instruction(bf, offset, f);
        if (size == 0) break;
        offset += size;
        
        const char *ip = bf->code_ptr + offset - size;
        char h = (*ip & 0xF0) >> 4;
        if (h == 15) break;
    }
}

/* Dumps the contents of the file */
void dump_file(FILE *f, bytefile *bf)
{
  int i;

  fprintf(f, "String table size       : %d\n", bf->stringtab_size);
  fprintf(f, "Global area size        : %d\n", bf->global_area_size);
  fprintf(f, "Number of public symbols: %d\n", bf->public_symbols_number);
  fprintf(f, "Public symbols          :\n");

  for (i = 0; i < bf->public_symbols_number; i++)
    fprintf(f, "   0x%.8x: %s\n", get_public_offset(bf, i), get_public_name(bf, i));

  fprintf(f, "Code:\n");
  disassemble(f, bf);
}

// int main(int argc, char *argv[])
// {
//   bytefile *f = read_file(argv[1]);
//   dump_file(stdout, f);
//   return 0;
// }