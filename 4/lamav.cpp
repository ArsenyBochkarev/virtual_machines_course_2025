#include <array>
#include <cstring>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <tuple>
#include <vector>

#include "bytefile.hpp"
#include "lamai.hpp"
#include "lamav.hpp"
#include "runtime.hpp"
#include "utility.hpp"

using namespace Closure;

struct VMState;
unsigned disassemble_instruction(const bytefile* bf, unsigned offset, FILE* f);

int32_t read_int32(const char* data, size_t pos) {
    check(pos + sizeof(int32_t) <= code_size, "reading int32 value beyond buffer bounds. Offset: 0x%x\n", pos);
    int32_t value;
    std::memcpy(&value, data + pos, sizeof(int32_t));
    return value;
}
int8_t read_int8(const char* data, size_t pos) {
    check(pos + sizeof(int8_t) <= code_size, "reading int8 value beyond buffer bounds. Offset: 0x%x\n", pos);
    int8_t value;
    std::memcpy(&value, data + pos, sizeof(int8_t));
    return value;
}

class Verifier {
private:
    bytefile* bf;
    char* code;

    auint *stack;
    auint *procedures_stack_ptr;
    auint *instructions_stack_ptr;

    int32_t global_area_size;
    int32_t stringtab_size;

    size_t proc_num = 0;
    std::array<int32_t, MAX_FILE_SIZE> stack_heights;

    size_t instr_length(size_t start) {
        return disassemble_instruction(bf, start, stdin);
    }

    void push_proc(int32_t proc_start_offset, int32_t proc_max_stack_sz) {
        *procedures_stack_ptr = proc_start_offset;
        *(procedures_stack_ptr + 1) = proc_max_stack_sz;
        procedures_stack_ptr += 2;
        proc_num++;
    }
    // (procedure start offset, max stack size)
    std::pair<int32_t, int32_t> pop_proc() {
        auto offset = *(procedures_stack_ptr - 2);
        auto stack_sz = *(procedures_stack_ptr - 1);
        procedures_stack_ptr -= 2;
        proc_num--;
        return std::make_pair(offset, stack_sz);
    }
    std::pair<int32_t, int32_t> peek_proc(int32_t offset = 0) {
        auto start_offset = *(procedures_stack_ptr - 2 - 2*offset);
        auto stack_sz = *(procedures_stack_ptr - 1 - 2*offset);
        return std::make_pair(start_offset, stack_sz);
    }
    int32_t proc_stack_size() {
        return (procedures_stack_ptr - stack) / 2;
    }

    void push_instr(int32_t offset, int32_t height, int32_t proc) {
        *instructions_stack_ptr = offset;
        *(instructions_stack_ptr + 1) = height;
        *(instructions_stack_ptr + 2) = proc;
        instructions_stack_ptr += 3;
    }
    // (offset, height, procedure)
    std::tuple<int32_t, int32_t, int32_t> pop_instr() {
        auto offset = *(instructions_stack_ptr - 3);
        auto height = *(instructions_stack_ptr - 2);
        auto proc = *(instructions_stack_ptr - 1);
        instructions_stack_ptr -= 3;
        return std::make_tuple(offset, height, proc);
    }
    std::tuple<int32_t, int32_t, int32_t> peek_instr(int32_t offset = 0) {
        auto instr_offset = *(instructions_stack_ptr - 3 - 3*offset);
        auto height = *(instructions_stack_ptr - 2 - 3*offset);
        auto proc = *(instructions_stack_ptr - 1 - 3*offset);
        return std::make_tuple(instr_offset, height, proc);
    }
    int32_t instr_stack_size() {
        return ((instructions_stack_ptr - stack) - PROC_STACK_MAP)/3;
    }

    void traverse() {
        stack_heights.fill(NO_STACK_HEIGHT_VAL);
        int32_t current_stack_height = 0;
        int32_t start_pt = 0; // Same starting point as in lamai
        push_instr(start_pt, current_stack_height, proc_num);
        while (instr_stack_size()) {
            auto [offset, current_stack_height, current_proc] = pop_instr();

            uint8_t opcode = static_cast<uint8_t>(code[offset]);
            int32_t length = instr_length(offset);
            check(offset + length <= code_size, "len overflows code_size", offset);

            auto stack_effect = get_stack_effect(code, offset);
            check(current_stack_height >= stack_effect.first, "stack underflow. Offset: 0x%x\n", offset);
            current_stack_height += (stack_effect.second - stack_effect.first);
            check(current_stack_height <= MAX_STACK_SIZE, "stack overflow. Offset: 0x%x\n", offset);

            // Skip already visited instructions
            if (stack_heights[offset] != NO_STACK_HEIGHT_VAL) {
                check(stack_heights[offset] == current_stack_height, "stack height mismatch at merge point. Offset: 0x%x\n", offset);
                continue;
            }
            stack_heights[offset] = current_stack_height;
            if (proc_stack_size())
                *(procedures_stack_ptr - 1) = std::max(current_stack_height > 0 ? static_cast<auint>(current_stack_height) : 0, *(procedures_stack_ptr - 1));

            if (opcode == Bytecode::BEGIN || opcode == Bytecode::CBEGIN)
                push_proc(offset, current_stack_height);

            check(proc_stack_size(), "ill-formed procedure: no BEGIN/CBEGIN. Offset: 0x%x\n", offset);
            auto [proc_start, proc_max_stack_size] = peek_proc();

            if (opcode == Bytecode::JMP || opcode == Bytecode::CJMPZ || opcode == Bytecode::CJMPNZ) {
                int32_t target = read_int32(code, offset + 1);
                check(target >= 0 && target < code_size, "jump/call target out of bounds. Offset: 0x%x\n", offset);
                push_instr(target, current_stack_height, proc_num);

                // Unconditional jump have single successor
                if (opcode == Bytecode::JMP)
                    continue;
            }

            verify_instruction(proc_start, offset, opcode);

            if (opcode == Bytecode::END || opcode == Bytecode::RET || opcode == Bytecode::FAIL) {
                // Check whether we need to dispose of current procedure or not
                // If workset contains current procedure instructions, don't pop from proc_stack
                if (instr_stack_size() > 1 && std::get<2>(peek_instr(1)) != current_proc)
                    pop_proc();

                // Use higher half-word from BEGIN/CBEGIN's local_count to save proc_max_stack_size
                int32_t arg_count_offset = proc_start + /*BEGIN/CBEGIN instruction size =*/1;
                int32_t local_count_offset = arg_count_offset + sizeof(int32_t);
                int32_t local_count = read_int32(code, local_count_offset);

                int32_t new_local_count_value = (proc_max_stack_size << 16) | (local_count & 0xFFFF);
                std::memcpy(code + local_count_offset, &new_local_count_value, sizeof(int32_t));
                continue;
            }

            auto next_offset = offset + length;
            push_instr(next_offset, current_stack_height, proc_num);
        }
    }

    void verify_instruction(int32_t current_proc_start_offset, int32_t offset, uint8_t opcode) {
        auto incr_offset = offset + 1;
        check(is_valid_opcode(opcode), "unknown instruction. Offset: 0x%x\n", offset);
        switch(opcode) {
            case Bytecode::CALL: {
                int32_t target = read_int32(code, incr_offset);
                int32_t n = read_int32(code, incr_offset + sizeof(int32_t));
                check(n >= 0, "CALL: negative arguments number. Offset: 0x%x\n", offset);
                break;
            }
            case Bytecode::CALLC: {
                int32_t n = read_int32(code, incr_offset + sizeof(int32_t));
                check(n >= 0, "CALLC: negative arguments number. Offset: 0x%x\n", offset);
                break;
            }
            // Jumps should already be verified in `traverse`

            // Global indexes
            case Bytecode::LD_GLOBAL:
            case Bytecode::LDA_GLOBAL:
            case Bytecode::ST_GLOBAL: {
                int32_t index = read_int32(code, incr_offset);
                check(index >= 0 && index < global_area_size, "global index out of bounds. Offset: 0x%x\n", offset);
                break;
            }
            // Local indexes
            case Bytecode::LD_LOCAL:
            case Bytecode::LDA_LOCAL:
            case Bytecode::ST_LOCAL: {
                int32_t index = read_int32(code, incr_offset);
                int32_t local_count = read_int32(code, current_proc_start_offset + /*BEGIN/CBEGIN instruction length=*/1 + sizeof(int32_t));
                check(index >= 0 && index < local_count, "local index out of bounds. Offset: 0x%x\n", offset);
                break;
            }
            // Argument indexes
            case Bytecode::LD_ARGUMENT:
            case Bytecode::LDA_ARGUMENT:
            case Bytecode::ST_ARGUMENT: {
                int32_t index = read_int32(code, incr_offset);
                int32_t arg_count = read_int32(code, current_proc_start_offset + /*BEGIN/CBEGIN instruction length=*/1);
                check(index >= 0 && index < arg_count, "argument index out of bounds. Offset: 0x%x\n", offset);
                break;
            }

            // String indexes
            case Bytecode::STRING: {
                int32_t str_index = read_int32(code, incr_offset);
                check(str_index >= 0 && str_index < stringtab_size, "string index out of bounds. Offset: 0x%x\n", offset);
                break;
            }

            case Bytecode::SEXP: {
                int32_t tag_index = read_int32(code, incr_offset);
                check(tag_index >= 0 && tag_index < stringtab_size, "SEXP: tag index out of bounds. Offset: 0x%x\n", offset);
                int32_t elem_count = read_int32(code, incr_offset + sizeof(int32_t));
                check(elem_count >= 0, "SEXP: negative element count. Offset: 0x%x\n", offset);
                break;
            }

            case Bytecode::TAG: {
                int32_t tag_index = read_int32(code, incr_offset);
                check(tag_index >= 0 && tag_index < bf->stringtab_size, "TAG: string index out of bounds. Offset: 0x%x\n", offset);
                int32_t expected_elem_count = read_int32(code, incr_offset + sizeof(int32_t));
                check(expected_elem_count >= 0, "TAG: negative element count. Offset: 0x%x\n", offset);
                break;
            }

            case Bytecode::CALL_BARRAY: {
                int32_t n = read_int32(code, incr_offset);
                check(n >= 0, "BARRAY: negative arguments number. Offset: 0x%x\n", offset);
                break;
            }

            case Bytecode::CONST:
            case Bytecode::ARRAY:
            case Bytecode::LINE: { // Check only out-of-bounds read
                read_int32(code, incr_offset);
                break;
            }
            case Bytecode::FAIL: { // Check only out-of-bounds reads
                read_int32(code, incr_offset);
                read_int32(code, incr_offset + sizeof(int32_t));
                break;
            }

            case Bytecode::CLOSURE: {
                int32_t target = read_int32(code, incr_offset);
                check(target >= 0 && target < code_size, "CLOSURE: invalid target address. Offset: 0x%x\n", offset);
                int32_t n = read_int32(code, incr_offset + sizeof(int32_t));
                check(n >= 0, "CLOSURE: negative capture count. Offset: 0x%x\n", offset);

                auto type_offset = incr_offset + sizeof(int32_t) + sizeof(int32_t);
                for (int i = 0; i < n; i++) {
                    int8_t type = read_int8(code, type_offset);
                    int32_t addr = read_int32(code, incr_offset + sizeof(int8_t));
                    check(type >= 0 && type <= 3, "CLOSURE: invalid varspec type. Offset: 0x%x\n", offset);

                    switch (type) {
                        case G:
                            check(addr >= 0 && addr < global_area_size, "CLOSURE: global index out of bounds. Offset: 0x%x\n", offset);
                            break;
                        case L: {
                            int32_t local_count = read_int32(code, current_proc_start_offset + /*BEGIN/CBEGIN instruction length=*/1 + sizeof(int32_t));
                            check(addr >= 0 && addr < local_count, "CLOSURE: local index out of bounds. Offset: 0x%x\n", offset);
                            break;
                        }
                        case A: {
                            int32_t arg_count = read_int32(code, current_proc_start_offset + /*BEGIN/CBEGIN instruction length=*/1);
                            check(addr >= 0 && addr < arg_count, "CLOSURE: argument index out of bounds. Offset: 0x%x\n", offset);
                            break;
                        }
                        case C:
                            // Can't check captured statically
                            break;
                        default:
                            check(false, "invalid varspec for CLOSURE. Offset: 0x%x\n", offset);
                    }
                }
                break;
            }
        }
    }

public:
    Verifier(bytefile* bytefile, auint *st) : bf(bytefile), stack(st), code(bf->code_ptr),
                                   global_area_size(bf->global_area_size),
                                   stringtab_size(bf->stringtab_size) {
        stack_heights.fill(NO_STACK_HEIGHT_VAL);
        procedures_stack_ptr = &st[0];
        instructions_stack_ptr = &st[PROC_STACK_MAP];
    }

    void verify() {
        check(bf->public_symbols_number > 0, "corrupted public_symbols_number in file. Offset: 0x%x\n", 0);
        traverse();
    }
};

void verify_bytecode(auint *stack, bytefile *bf) {
    Verifier verifier(bf, stack);
    verifier.verify();
}
