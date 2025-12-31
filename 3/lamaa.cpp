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
    std::vector<std::tuple<size_t, uint32_t, uint32_t, uint32_t>> idioms_vec; // (hash, freq, len, pos)

    enum class InstrState {
        is_jump,
        is_cond_jump,
        is_call,
        is_terminal,
        other
    };
    using instruction_info_tuple = std::tuple<std::string, size_t, InstrState>;
    bool instr_is_jump(const instruction_info_tuple &instr_info) {
        return (std::get<2>(instr_info) == InstrState::is_jump) || (std::get<2>(instr_info) == InstrState::is_cond_jump);
    }
    bool instr_is_call(const instruction_info_tuple &instr_info) {
        return std::get<2>(instr_info) == InstrState::is_call;
    }
    bool instr_is_terminal(const instruction_info_tuple &instr_info) {
        return (std::get<2>(instr_info) == InstrState::is_terminal) ||
            (std::get<2>(instr_info) == InstrState::is_jump); // regular jump is also a terminal instruction
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
            auto instr_info = instruction_info(bf->code_ptr, addr, code_size);
            size_t len = std::get<1>(instr_info);
            check(addr + len <= code_size, "len overflows code_size", addr);

            // Add a target to CFG, if it's jump/call
            if (instr_is_jump(instr_info) || instr_is_call(instr_info)) {
                int32_t target = read_int32(bf->code_ptr, addr + 1, code_size);
                check(target < code_size, "JMP/CJMPZ/CJMPNZ/CALL/CALLC: target overflows code_size", addr);
                jump_targets[target] = true;
                if (!reachable[target]) {
                    reachable[target] = true;
                    workset.push_back(target);
                }
            }

            // Add next instruction to CFG, if we haven't been there yet
            if (!instr_is_terminal(instr_info)) {
                size_t next_addr = addr + len;
                if (next_addr < code_size && !reachable[next_addr]) {
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

            auto instr_info = instruction_info(bf->code_ptr, addr, code_size);
            size_t len1 = std::get<1>(instr_info);
            check(addr + len1 <= code_size, "len overflows code_size", addr);

            // 1-instr idiom always counts
            std::string instr1(bf->code_ptr + addr, len1);
            remember_idiom(addr, instr1, len1, hasher);

            if (!instr_is_terminal(instr_info) && !instr_is_call(instr_info)) { // non-terminal && non-call -> we shouldn't split idiom
                size_t next_addr = addr + len1;
                uint8_t next_opcode = static_cast<uint8_t>(bf->code_ptr[next_addr]);
                if (next_addr < code_size && reachable[next_addr] && !jump_targets[next_addr]) {
                    auto instr_info2 = instruction_info(bf->code_ptr, next_addr, code_size);
                    size_t len2 = std::get<1>(instr_info2);
                    check(next_addr + len2 <= code_size, "len overflows code_size", addr);
                    std::string instr2(bf->code_ptr + addr, len1 + len2);
                    remember_idiom(addr, instr2, len1 + len2, hasher);
                }
            }

            addr += len1;
        }
    }

    // (instruction string, instruction length, State)
    std::tuple<std::string, size_t, InstrState> instruction_info(const char* code, size_t start, size_t end) {
        uint8_t x = static_cast<uint8_t>(code[start]);

        const char *ops[] = {" +", "-", "*", "/", "%", "<", "<=", ">", ">=", "==", "!=", "&&", "!!"};
        const char *pats[] = {"=str", "#string", "#array", "#sexp", "#ref", "#val", "#fun"};
        const char *lds[] = {"LD", "LDA", "ST"};
        const char h = (x & 0xF0) >> 4, l = x & 0x0F;

        auto sz = end;
        switch (h) {
            case 15:
                return {"STOP", 1, InstrState::is_terminal};
            case 0:
                return {std::string("BINOP ") + ops[l - 1], 1, InstrState::other};
            case 1: {
                switch (l) {
                    case 0:
                        return {"CONST " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::other};
                    case 1:
                        return {std::string("STRING ") + get_string(bf, read_int32(code, start + 1, sz)), 5, InstrState::other};
                    case 2:
                        return {std::string("SEXP ") + get_string(bf, read_int32(code, start + 1, sz)), 9, InstrState::other};
                    case 3:
                        return {"STI", 1, InstrState::other};
                    case 4:
                        return {"STA", 1, InstrState::other};
                    case 5:
                        return {"JMP " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::is_jump};
                    case 6:
                        return {"END", 1, InstrState::is_terminal};
                    case 7:
                        return {"RET", 1, InstrState::is_terminal};
                    case 8:
                        return {"DROP", 1, InstrState::other};
                    case 9:
                        return {"DUP", 1, InstrState::other};
                    case 10:
                        return {"SWAP", 1, InstrState::other};
                    case 11:
                        return {"ELEM", 1, InstrState::other};

                    default:
                        check(false, "unknown instruction", start);
                }
            }
            case 2:
            case 3:
            case 4: {
                std::string res = lds[h - 2];
                switch (l) {
                    case 0:
                        return {res + " G " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::other};
                    case 1:
                        return {res + " L " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::other};
                    case 2:
                        return {res + " A " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::other};
                    case 3:
                        return {res + " C " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::other};
                    default:
                        check(false, "unknown instruction", start);
                }
            }
            case 5: {
                switch (l) {
                    case 0:
                        return {"CJMPz " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::is_cond_jump};
                    case 1:
                        return {"CJMPnz " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::is_cond_jump};
                    case 2:
                        return {"BEGIN  " + std::to_string(read_int32(code, start + 1, sz)), 9, InstrState::other};
                    case 3:
                        return {"CBEGIN  " + std::to_string(read_int32(code, start + 1, sz)), 9, InstrState::other};
                    case 4: {
                        std::string result = "CLOSURE";
                        size_t length = 9; // 1 (opcode) + 4 (addr) + 4 (n) + 5 * n, where 5 is a value of varspec
                        if (end - start >= 9) {
                            int32_t target = read_int32(code, start + 1, sz);
                            int32_t n = read_int32(code, start + 5, sz);
                            length += 5 * n;
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
                            return {result, length, InstrState::other};
                        }
                        break;
                    }
                    case 5:
                        return {"CALLC " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::is_call};
                    case 6:
                        return {"CALL " + std::to_string(read_int32(code, start + 1, sz)), 9, InstrState::is_call};
                    case 7:
                        return {std::string("TAG ") + get_string(bf, read_int32(code, start + 1, sz)), 9, InstrState::other};
                    case 8:
                        return {"ARRAY " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::other};
                    case 9:
                        return {"FAIL " + std::to_string(read_int32(code, start + 1, sz)), 9, InstrState::is_terminal};
                    case 10:
                        return {"LINE " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::other};

                    default:
                        check(false, "unknown instruction", start);
                }
            }
            case 6:
                return {std::string("PATT ") + pats[l], 1, InstrState::other};
            case 7: {
                switch (l) {
                    case 0:
                        return {"CALL Lread", 1, InstrState::other};
                    case 1:
                        return {"CALL Lwrite", 1, InstrState::other};
                    case 2:
                        return {"CALL Llength", 1, InstrState::other};
                    case 3:
                        return {"CALL Lstring", 1, InstrState::other};
                    case 4:
                        return {"CALL Barray " + std::to_string(read_int32(code, start + 1, sz)), 5, InstrState::other};

                    default:
                        check(false, "unknown instruction", start);
                }
            }

            default:
                check(false, "unknown instruction", start);
        }
        return {"", 0, InstrState::other};
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
            while (pos_in_idiom < idiom_size) {
                auto pos = idiom_offset + pos_in_idiom;
                auto instr_info = instruction_info(bf->code_ptr, pos, code_size);
                size_t len = std::get<1>(instr_info);
                check(pos_in_idiom + len <= idiom_size, "ill-formed idiom", idiom_offset);
                std::string instr_str = std::get<0>(instr_info);
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