#include <cassert>
#include <iostream>
#include <fstream>
#include <functional>
#include <vector>
#include <tuple>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <set>

#include "lamaa.hpp"

using namespace Bytecode;

class RuntimeError : public std::exception {
private:
    std::string message;
    int32_t bytecode_offset;

public:
    RuntimeError(const std::string& msg, int32_t offset)
        : message(msg), bytecode_offset(offset) {
            std::stringstream str_stream;
            str_stream << std::hex << bytecode_offset;
            message += ". Bytecode offset: 0x" + str_stream.str();
    }

    const char* what() const noexcept override {
        return message.c_str();
    }
};

static inline void check(bool condition, const char *msg, int32_t offset) {
    if (!condition)
        throw RuntimeError(msg, offset);
}

/* The unpacked representation of bytecode file */
typedef struct {
    char *string_ptr;                  /* A pointer to the beginning of the string table */
    int32_t  *public_ptr;              /* A pointer to the beginning of publics table    */
    char *code_ptr;                    /* A pointer to the bytecode itself               */
    int32_t   stringtab_size;          /* The size (in bytes) of the string table        */
    int32_t   global_area_size;        /* The size (in words) of global area             */
    int32_t   public_symbols_number;   /* The number of public symbols                   */
    char  buffer[0];               
} bytefile;

unsigned disassemble_instruction(const bytefile* bf, unsigned offset, FILE* f);

/* Gets a string from a string table by an index */
char* get_string(bytefile *f, int pos) {
    return &f->string_ptr[pos];
}

static int32_t code_size = -1;

/* Reads a binary bytecode file by name and unpacks it */
bytefile* read_file(char *fname) {
    FILE *f = fopen (fname, "rb");
    long size;
    bytefile *file;

    if (!f) {
        fprintf(stderr, "%s\n", strerror (errno));
        perror(fname);
        exit(1);
    }

    if (fseek (f, 0, SEEK_END) == -1) {
        perror("fseek");
        fclose(f);
        exit(1);
    }

    size = ftell (f);
    if (size == -1) {
        perror("ftell");
        fprintf(stderr, "%s\n", strerror(errno));
        fclose(f);
        exit(1);
    }

    file = (bytefile*) malloc (sizeof(int32_t)*4 + size);
    if (!file) {
        perror("unable to allocate memory");
        fclose(f);
        exit(1);
    }

    rewind (f);
    if (size != fread (&file->stringtab_size, 1, size, f)) {
        perror("fread");
        free(file);
        fclose(f);
        exit(1);
    }
    fclose (f);

    check(file->public_symbols_number > 0, "corrupted public_symbols_number in file", 0);
    file->string_ptr = &file->buffer [file->public_symbols_number * 2 * sizeof(int32_t)];
    file->public_ptr = (int32_t*) file->buffer;
    file->code_ptr = &file->string_ptr [file->stringtab_size];

    code_size = size - file->public_symbols_number * 2 * sizeof(int32_t) + file->stringtab_size;

    return file;
}

int32_t read_int32(const char* data, size_t pos, size_t buffer_size) {
    check(pos + sizeof(int32_t) <= buffer_size, "reading int32 value beyond buffer bounds", pos);
    int32_t value;
    std::memcpy(&value, data + pos, sizeof(int32_t));
    return value;
}

class IdiomAnalyzer {
private:
    bytefile* bf;
    std::vector<bool> reachable;
    std::vector<bool> jump_targets;
    std::vector<std::tuple<size_t, uint32_t, uint32_t, uint32_t>> idioms_vec; // (hash, freq, len, pos)

    size_t instr_length(size_t start) {
        return disassemble_instruction(bf, start, stdin);
    }

public:
    IdiomAnalyzer(bytefile* bytefile) : bf(bytefile) {}

    void analyze_reachability() {
        if (!bf)
            return;

        reachable.resize(code_size, false);
        jump_targets.resize(code_size, false);

        std::vector<size_t> workset;
        // Starting from public symbols
        for (int i = 0; i < bf->public_symbols_number; i++) {
            size_t addr = bf->public_ptr[i * 2 + 1]; // index for code_ptr (like vm.ip in lamai)
            check(addr < code_size, "addr from public_symbols overflows code_size", addr);
            if (reachable[addr])
                continue;
            reachable[addr] = true;
            jump_targets[addr] = true; // public_symbol is also a jump target
            workset.push_back(addr);
        }

        while(!workset.empty()) {
            size_t addr = workset.back();
            workset.pop_back();

            uint8_t opcode = static_cast<uint8_t>(bf->code_ptr[addr]);
            size_t len = instr_length(addr);
            check(addr + len <= code_size, "len overflows code_size", addr);

            // Add a target to CFG, if it's jump/call
            if (is_jump(opcode) || is_call(opcode)) {
                int32_t target = read_int32(bf->code_ptr, addr + 1, code_size);
                check(target < code_size, "JMP/CJMPZ/CJMPNZ/CALL/CALLC: target overflows code_size", addr);
                jump_targets[target] = true;
                if (!reachable[target]) {
                    reachable[target] = true;
                    workset.push_back(target);
                }
            }

            // Add next instruction to CFG, if we haven't been there yet
            if (!is_terminal(opcode)) {
                size_t next_addr = addr + len;
                if (!reachable[next_addr]) {
                    reachable[next_addr] = true;
                    workset.push_back(next_addr);
                }
            }
        }
    }

    void remember_idiom(size_t addr, const std::string &str, size_t sz, const std::hash<std::string> &hasher) {
        auto instr_hash = hasher(str);
        auto it = std::find_if(idioms_vec.begin(), idioms_vec.end(), [instr_hash](const auto& t) {
            return std::get<0>(t) == instr_hash;
        });
        if (it != idioms_vec.end()) // Idiom is in idioms_vec
            std::get<1>(*it) += 1;
        else
            idioms_vec.push_back({instr_hash, 1, sz, addr});
    }

    void find_idioms() {
        if (!bf)
            return;

        std::hash<std::string> hasher;
        size_t addr = 0;
        while (addr < code_size) {
            uint8_t opcode = static_cast<uint8_t>(bf->code_ptr[addr]);
            if (!reachable[addr]) {
                // Code here may be ill-formed, but it's OK since interpreter won't execute it anyway
                // Skip this code byte-by-byte
                addr += 1;
                continue;
            }

            size_t len1 = instr_length(addr);
            check(addr + len1 <= code_size, "len overflows code_size", addr);

            // 1-instr idiom always counts
            std::string instr1(bf->code_ptr + addr, len1);
            remember_idiom(addr, instr1, len1, hasher);

            if (!is_terminal(opcode) && !is_call(opcode)) { // non-terminal && non-call -> we shouldn't split idiom
                size_t next_addr = addr + len1;
                uint8_t next_opcode = static_cast<uint8_t>(bf->code_ptr[next_addr]);
                if (reachable[next_addr] && !jump_targets[next_addr]) {
                    size_t len2 = instr_length(next_addr);
                    check(next_addr + len2 <= code_size, "len overflows code_size", addr);
                    std::string instr2(bf->code_ptr + addr, len1 + len2);
                    remember_idiom(addr, instr2, len1 + len2, hasher);
                }
            }

            addr += len1;
        }
    }

    void print_results() {
        // Sort by freq
        std::sort(idioms_vec.begin(), idioms_vec.end(), [](const auto& a, const auto& b) {
            return std::get<1>(a) > std::get<1>(b);
        });
        // Bytes to text
        for (const auto& [idiom_hash, idiom_freq, idiom_size, idiom_offset] : idioms_vec) {
            std::string text;
            size_t pos_in_idiom = 0;
            std::cout << idiom_freq << " ";
            while (pos_in_idiom < idiom_size) {
                auto pos = idiom_offset + pos_in_idiom;
                size_t len = instr_length(pos);
                check(pos_in_idiom + len <= idiom_size, "ill-formed idiom", idiom_offset);
                disassemble_instruction(bf, pos, stdout);
                std::cout << "; ";
                pos_in_idiom += len;
            }
            std::cout << std::endl;
        }
    }

    void run() {
        analyze_reachability();
        find_idioms();
        print_results();
    }
};

int main(int argc, char* argv[]) {
    bytefile* bf = read_file(argv[1]);
    if (!bf)
        return 1;

    try {
        IdiomAnalyzer analyzer(bf);
        analyzer.run();
        free(bf);
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        free(bf);
    }

    return 0;
}