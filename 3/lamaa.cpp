#include <cassert>
#include <iostream>
#include <fstream>
#include <functional>
#include <vector>
#include <unordered_map>
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

    std::unordered_map<size_t, uint32_t> idioms; // idiom hash -> freq
    std::unordered_map<size_t, std::pair<uint32_t, uint32_t>> idioms_info; // idiom hash -> (idiom len, idiom position in bf->code_ptr)

    bool should_split_after(uint8_t opcode) {
        return opcode == JMP || opcode == CALL || opcode == CALLC || opcode == RET || opcode == END || opcode == FAIL;
    }

    size_t get_instr_length(uint8_t opcode, size_t pos, const char *code, size_t sz) {
        switch (opcode)
        {
        // Instrs with one 4-byte param
        case CONST:
        case STRING:
        case JMP:
        case LD_GLOBAL:
        case LD_LOCAL:
        case LD_ARGUMENT:
        case LD_CAPTURED:
        case LDA_GLOBAL:
        case LDA_LOCAL:
        case LDA_ARGUMENT:
        case LDA_CAPTURED:
        case ST_GLOBAL:
        case ST_LOCAL:
        case ST_ARGUMENT:
        case ST_CAPTURED:
        case CJMPZ:
        case CJMPNZ:
        case CALLC:
        case ARRAY:
        case LINE:
        case CALL_BARRAY:
            return 5; // 1 + 4

        // Instrs with two 4-byte params
        case SEXP:
        case BEGIN:
        case CBEGIN:
        case CALL:
        case TAG:
        case FAIL:
            return 9; // 1 + 4 + 4

        case CLOSURE: {
            // CLOSURE is variable-length instr
            int32_t n = read_int32(code, pos + 5, sz);
            check(n >= 0, "CLOSURE: invalid n", pos);
            size_t length = 9 + 5 * n; // 1 (opcode) + 4 (addr) + 4 (n) + 5 * n, where 5 is a value of varspec
            return length;
        }

        default:
            return 1;
        }
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
            workset.push_back(addr);
        }

        // BFS
        for (size_t idx = 0; idx < workset.size(); ++idx) {
            size_t addr = workset[idx];

            uint8_t opcode = static_cast<uint8_t>(bf->code_ptr[addr]);
            size_t len = get_instr_length(opcode, addr, bf->code_ptr, code_size);
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
                if (next_addr < code_size && !reachable[next_addr]) {
                    reachable[next_addr] = true;
                    workset.push_back(next_addr);
                }
            }
        }
    }

    void remember_idiom(size_t addr, const std::string &str, size_t sz, const std::hash<std::string> &hasher) {
        auto instr1_hash = hasher(str);
        idioms[instr1_hash]++;
        idioms_info[instr1_hash] = std::make_pair(sz, addr);
    }

    void find_idioms() {
        if (!bf)
            return;

        std::hash<std::string> hasher;
        size_t addr = 0;
        while (addr < code_size) {
            uint8_t opcode = static_cast<uint8_t>(bf->code_ptr[addr]);
            if (!reachable[addr]) {
                size_t len = get_instr_length(opcode, addr, bf->code_ptr, code_size);
                addr += len;
                continue;
            }

            size_t len1 = get_instr_length(opcode, addr, bf->code_ptr, code_size);
            check(addr + len1 <= code_size, "len overflows code_size", addr);

            // 1-instr idiom always counts
            std::string instr1(bf->code_ptr + addr, len1);
            remember_idiom(addr, instr1, len1, hasher);

            if (!should_split_after(opcode)) {
                size_t next_addr = addr + len1;
                uint8_t next_opcode = static_cast<uint8_t>(bf->code_ptr[next_addr]);
                if (next_addr < code_size && reachable[next_addr] && !jump_targets[next_addr]) {
                    size_t len2 = get_instr_length(next_opcode, next_addr, bf->code_ptr, code_size);
                    check(next_addr + len2 <= code_size, "len overflows code_size", addr);
                    std::string instr2(bf->code_ptr + addr, len1 + len2);
                    remember_idiom(addr, instr2, len1 + len2, hasher);
                }
            }

            addr += len1;
        }
    }

    std::string format_instruction(const char* code, size_t start, size_t end) {
        if (start >= end)
            return "";

        auto sz = end;
        uint8_t opcode = static_cast<uint8_t>(code[start]);
        std::string result = get_opcode_name(opcode);
        switch (opcode) {
            case CONST:
            case STRING:
            case JMP:
            case LD_GLOBAL:
            case LD_LOCAL:
            case LD_ARGUMENT:
            case LD_CAPTURED:
            case LDA_GLOBAL:
            case LDA_LOCAL:
            case LDA_ARGUMENT:
            case LDA_CAPTURED:
            case ST_GLOBAL:
            case ST_LOCAL:
            case ST_ARGUMENT:
            case ST_CAPTURED:
            case CJMPZ:
            case CJMPNZ:
            case CALLC:
            case ARRAY:
            case LINE:
            case CALL_BARRAY:
                if (end - start >= 5) {
                    int32_t param = read_int32(code, start + 1, sz);
                    result += " " + std::to_string(param);
                }
                break;

            case SEXP:
            case BEGIN:
            case CBEGIN:
            case CALL:
            case TAG:
            case FAIL:
                if (end - start >= 9) {
                    int32_t param1 = read_int32(code, start + 1, sz);
                    int32_t param2 = read_int32(code, start + 5, sz);
                    result += " " + std::to_string(param1) + " " + std::to_string(param2);
                }
                break;

            case CLOSURE:
                if (end - start >= 9) {
                    int32_t target = read_int32(code, start + 1, sz);
                    int32_t n = read_int32(code, start + 5, sz);
                    result += " " + std::to_string(target) + " " + std::to_string(n);

                    size_t pos = start + 9;
                    for (int i = 0; i < n && pos + 5 <= end; i++) {
                        uint8_t type = code[pos];
                        int32_t addr = read_int32(code, pos + 1, sz);

                        std::string type_str;
                        switch (type) {
                            case 0: type_str = "G"; break;
                            case 1: type_str = "L"; break;
                            case 2: type_str = "A"; break;
                            case 3: type_str = "C"; break;
                            default: type_str = "?";
                        }

                        result += " " + type_str + "(" + std::to_string(addr) + ")";
                        pos += 5;
                    }
                }
                break;
            default:
                break;
        }
        return result;
    }

    void print_results() {
        check(idioms.size() == idioms_info.size(), "idioms and idioms_info sizes should be same", 0);

        std::vector<std::pair<size_t, uint32_t>> sorted_idioms(idioms.begin(), idioms.end());
        std::sort(sorted_idioms.begin(), sorted_idioms.end(), [](const auto& a, const auto& b) {
            return a.second > b.second; 
        });

        // Bytes to text
        for (const auto& [idiom_key, idiom_freq] : sorted_idioms) {
            std::string text;
            size_t pos_in_idiom = 0;
            size_t idiom_size = idioms_info[idiom_key].first;
            size_t idiom_offset = idioms_info[idiom_key].second;

            while (pos_in_idiom < idiom_size) {
                uint8_t opcode = static_cast<uint8_t>(bf->code_ptr[idiom_offset + pos_in_idiom]);
                size_t len = get_instr_length(opcode, idiom_offset + pos_in_idiom, bf->code_ptr, idiom_size);
                check(pos_in_idiom + len <= idiom_size, "ill-formed idiom", idiom_offset);
                std::string instr_str = format_instruction(bf->code_ptr, idiom_offset + pos_in_idiom, idiom_offset + pos_in_idiom + len);
                if (!text.empty())
                    text += "; ";
                text += instr_str;
                pos_in_idiom += len;
            }

            std::cout << idiom_freq << " " << text << std::endl;
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