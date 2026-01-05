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
    check(pos + sizeof(int32_t) < code_size, "reading int32 value beyond buffer bounds. Offset: 0x%x\n", pos);
    int32_t value;
    std::memcpy(&value, data + pos, sizeof(int32_t));
    return value;
}
int8_t read_int8(const char* data, size_t pos) {
    check(pos + sizeof(int8_t) < code_size, "reading int8 value beyond buffer bounds. Offset: 0x%x\n", pos);
    int8_t value;
    std::memcpy(&value, data + pos, sizeof(int8_t));
    return value;
}

class Verifier {
private:
    bytefile* bf;
    char* code;
    size_t enter_pt;

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

    void push(int32_t val) {
        *(procedures_stack_ptr++) = val;
    }
    int32_t pop() {
        auto res = *(procedures_stack_ptr-1);
        procedures_stack_ptr--;
        return res;
    }
    int32_t peek(int32_t offset = 0) {
        return *(procedures_stack_ptr - 1 - offset);
    }
    int32_t stack_size() {
        return (procedures_stack_ptr - stack);
    }
    int32_t get_or_remember_height(int32_t h) {
        return (-1) * h - 2; // We need to distinguish this from NO_STACK_HEIGHT_VAL and known (non-negative) stack height
    }
    int32_t remember_proc_start_offset(int32_t offset) {
        return MAX_FILE_SIZE + offset; // We need to distinguish it from regular offsets
    }
    int32_t get_remembered_proc_start_offset(int32_t offset) {
        return offset - MAX_FILE_SIZE; // We need to distinguish it from regular offsets
    }
    bool guard_next() {
        return peek() >= MAX_FILE_SIZE;
    }

    void traverse() {
        auint current_max_proc_stack = 0;
        int32_t current_stack_height = 0;
        int32_t start_offset = enter_pt;
        push(enter_pt);
        while (stack_size()) {
            auto offset = pop();
            if (offset >= MAX_FILE_SIZE) {
                current_max_proc_stack = pop();
                start_offset = get_remembered_proc_start_offset(offset);
                proc_num--;
                continue;
            }

            uint8_t opcode = static_cast<uint8_t>(code[offset]);
            int32_t length = instr_length(offset);
            check(offset + length < code_size, "len overflows code_size", offset);

            if (stack_heights[offset] < NO_STACK_HEIGHT_VAL) // It's a jump target
                current_stack_height = get_or_remember_height(stack_heights[offset]);

            auto stack_effect = get_stack_effect(code, offset);
            current_stack_height += (stack_effect.second - stack_effect.first);
            check(current_stack_height >= 0, "stack underflow. Offset: 0x%x\n", offset);
            check(current_stack_height < MAX_STACK_SIZE, "stack overflow. Offset: 0x%x\n", offset);

            // Skip already visited instructions
            if (stack_heights[offset] > NO_STACK_HEIGHT_VAL) {
                if (!stack_size() || guard_next())
                    continue;

                auto next_instr = peek();
                // We need to set up next instruction
                current_stack_height = stack_heights[next_instr];
                check(stack_heights[next_instr] != NO_STACK_HEIGHT_VAL, "ill-formed control-flow. Offset: 0x%x\n", next_instr);
                if (stack_heights[next_instr] > NO_STACK_HEIGHT_VAL) // stack_heights[next_instr] == NO_STACK_HEIGHT_VAL isn't valid scenario
                    stack_heights[next_instr] = get_or_remember_height(current_stack_height);
                continue;
            }
            stack_heights[offset] = current_stack_height;
            current_max_proc_stack = std::max(current_stack_height > 0 ? static_cast<auint>(current_stack_height) : 0, current_max_proc_stack);

            if (opcode == Bytecode::BEGIN || opcode == Bytecode::CBEGIN) {
                push(current_max_proc_stack);
                push(remember_proc_start_offset(start_offset));
                start_offset = offset;
                proc_num++;
            }
            check(proc_num, "ill-formed procedure: no BEGIN/CBEGIN. Offset: 0x%x\n", offset);

            if (opcode == Bytecode::JMP || opcode == Bytecode::CJMPZ || opcode == Bytecode::CJMPNZ) {
                int32_t target = read_int32(code, offset + 1);
                check(target >= 0 && target < code_size, "jump/call target out of bounds. Offset: 0x%x\n", offset);
                if (stack_heights[target] != NO_STACK_HEIGHT_VAL) {
                    check(stack_heights[offset] == current_stack_height, "stack height mismatch at merge point. Offset: 0x%x\n", offset);
                } else {
                    stack_heights[target] = get_or_remember_height(current_stack_height);
                    push(target);
                }

                // Unconditional jump have single successor
                if (opcode == Bytecode::JMP)
                    continue;
            }
            if (opcode == Bytecode::CALL) {
                int32_t target = read_int32(code, offset + 1);
                check(target >= 0 && target < code_size, "jump/call target out of bounds. Offset: 0x%x\n", offset);
                stack_heights[target] = get_or_remember_height(current_stack_height);
                push(target);
            }

            verify_instruction(start_offset, offset, opcode);

            if (opcode == Bytecode::END || opcode == Bytecode::RET || opcode == Bytecode::FAIL) {
                // Check whether we need to dispose of current procedure or not
                // If workset contains current procedure instructions, don't pop from proc_stack
                if (guard_next()) {
                    pop(); // current_max_proc_stack
                    pop(); // start_offset
                    proc_num--;
                }

                // Use higher half-word from BEGIN/CBEGIN's local_count to save current_max_proc_stack
                int32_t arg_count_offset = start_offset + /*BEGIN/CBEGIN instruction size =*/1;
                int32_t local_count_offset = arg_count_offset + sizeof(int32_t);
                int32_t local_count = read_int32(code, local_count_offset);

                int32_t new_local_count_value = (current_max_proc_stack << 16) | (local_count & 0xFFFF);
                std::memcpy(code + local_count_offset, &new_local_count_value, sizeof(int32_t));
                if (!stack_size() || guard_next())
                    continue;

                auto next_instr = peek();
                // We need to set up next instruction
                current_stack_height = stack_heights[next_instr];
                if (stack_heights[next_instr] > NO_STACK_HEIGHT_VAL) // stack_heights[next_instr] == NO_STACK_HEIGHT_VAL isn't valid scenario
                    stack_heights[next_instr] = get_or_remember_height(current_stack_height);
                continue;
            }

            auto next_offset = offset + length;
            push(next_offset);
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
                    int32_t addr = read_int32(code, type_offset + sizeof(int8_t));
                    type_offset += (sizeof(int32_t) + sizeof(int8_t));
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
    Verifier(size_t enter, bytefile* bytefile, auint *st) : enter_pt(enter), bf(bytefile), stack(st), code(bf->code_ptr),
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

void verify_bytecode(size_t enter_pt, auint *stack, bytefile *bf) {
    Verifier verifier(enter_pt, bf, stack);
    verifier.verify();
}
