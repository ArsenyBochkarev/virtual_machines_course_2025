#include <array>
#include <cstring>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

#include "bytefile.hpp"
#include "lamai.hpp"
#include "lamav.hpp"
#include "runtime.hpp"
#include "utility.hpp"

using namespace Closure;

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
    int32_t global_area_size;
    int32_t stringtab_size;

    struct BasicBlock {
        int32_t start_offset;
        int32_t end_offset;
        std::array<int32_t, MAX_BB_SUCCESSORS> successors;
    };
    struct ProcedureInfo {
        int32_t start_offset;
        bool is_closure;
        int32_t arg_count;
        int32_t local_count;
        BasicBlock head_bb;
    };

    std::array<ProcedureInfo, MAX_PROCEDURES> procedures;
    size_t proc_num = 0;

    std::array<BasicBlock, MAX_FILE_SIZE> basic_blocks;
    std::array<int32_t, MAX_FILE_SIZE> stack_heights;

    std::array<bool, MAX_FILE_SIZE> reachable;
    std::array<bool, MAX_FILE_SIZE> jump_targets;

    size_t instr_length(size_t start) {
        return disassemble_instruction(bf, start, stdin);
    }

    void build_basic_blocks() {
        reachable.fill(false);
        jump_targets.fill(false);

        std::vector<int32_t> workset;
        for (int i = 0; i < bf->public_symbols_number; i++) {
            size_t addr = bf->public_ptr[i * 2 + 1]; // index for code_ptr (like vm.ip in lamai)
            check(addr < code_size, "addr from public_symbols overflows code_size", addr);
            if (reachable[addr])
                continue;
            reachable[addr] = true;
            jump_targets[addr] = true; // public_symbol is also a jump target
            workset.push_back(addr);
        }

        while (!workset.empty()) {
            size_t offset = workset.back();
            workset.pop_back();

            BasicBlock block;
            block.start_offset = offset;
            block.successors.fill(NO_SUCCESSOR_OFFSET);
            int32_t current_offset = offset;
            // Traverse instructions in BB
            while (true) {
                // Skip already visited instructions
                if (current_offset != offset && reachable[current_offset])
                    break;

                // We shouldn't be able to jump in the middle of BB
                if (current_offset != offset && jump_targets[current_offset]) {
                    block.end_offset = current_offset;
                    break;
                }

                uint8_t opcode = static_cast<uint8_t>(code[current_offset]);
                int32_t length = instr_length(current_offset);
                check(current_offset + length <= code_size, "len overflows code_size", offset);

                if (opcode == Bytecode::BEGIN || opcode == Bytecode::CBEGIN) {
                    check(proc_num + 1 <= MAX_PROCEDURES, "too many procedures. Offset: 0x%x\n", current_offset);
                    proc_num++;
                }
                basic_blocks[current_offset] = block;

                // Add a target to CFG, if it's jump/call
                if (opcode == Bytecode::JMP || opcode == Bytecode::CJMPZ ||
                    opcode == Bytecode::CJMPNZ || opcode == Bytecode::CALL ||
                    opcode == Bytecode::CALLC) {

                    if (opcode != Bytecode::CALLC) { // We can't get target for CALLC statically
                        int32_t target = read_int32(code, current_offset + 1);
                        check(target < code_size, "jump/call target out of bounds. Offset: 0x%x\n", current_offset);
                        jump_targets[target] = true;
                        if (!reachable[target]) {
                            reachable[target] = true;
                            block.successors[0] = target;
                            workset.push_back(target);
                        }
                    }

                    // Conditional jumps have multiple successors
                    if (opcode == Bytecode::CJMPZ || opcode == Bytecode::CJMPNZ) {
                        int32_t next_offset = current_offset + length;
                        if (!reachable[next_offset]) {
                            reachable[next_offset] = true;
                            block.successors[1] = next_offset;
                            workset.push_back(next_offset);
                        }
                    }

                    // End of BB
                    block.end_offset = current_offset + length;
                    break;
                }

                // Basic block also ends when procedure ends
                if (opcode == Bytecode::END || opcode == Bytecode::RET || 
                    opcode == Bytecode::FAIL) {
                    block.end_offset = current_offset + length;
                    break;
                }

                current_offset += length;
                reachable[current_offset] = true;
                check(current_offset < code_size, "basic blocks overflows exceeds code size. Offset: 0x%x\n", current_offset);
            }
        }
    }

    void build_procedures() {
        size_t addr = 0;
        size_t proc = 0;
        while (addr < code_size) {
            uint8_t opcode = static_cast<uint8_t>(bf->code_ptr[addr]);
            if (!reachable[addr]) {
                // Code here may be ill-formed, but it's OK since interpreter won't execute it anyway
                // Skip this code byte-by-byte
                addr += 1;
                continue;
            }

            size_t len = instr_length(addr);
            check(addr + len <= code_size, "len overflows code_size", addr);
            if (opcode != Bytecode::BEGIN && opcode != Bytecode::CBEGIN) {
                addr += len;
                continue;
            }

            ProcedureInfo current_proc;
            current_proc.head_bb = basic_blocks[addr];
            current_proc.start_offset = current_proc.head_bb.start_offset;
            current_proc.is_closure = (opcode == Bytecode::CBEGIN);

            int32_t arg_count_offset = current_proc.start_offset + /*BEGIN/CBEGIN instruction size =*/1;
            int32_t local_count_offset = arg_count_offset + sizeof(int32_t);
            int32_t local_count = read_int32(code, local_count_offset);
            current_proc.arg_count = read_int32(code, arg_count_offset);
            current_proc.local_count = read_int32(code, local_count);
            check(current_proc.arg_count >= 0 && current_proc.local_count >= 0, "negative argument or local count. Offset: 0x%x\n", addr);
            check(current_proc.local_count <= MAX_LOCAL_COUNT, "local count too large. Offset: 0x%x\n", addr);

            procedures[proc++] = current_proc;
        }
    }

    void verify_stack(const ProcedureInfo& proc) {
        stack_heights.fill(NO_STACK_HEIGHT_VAL);
        int32_t max_stack = 0;
        
        int32_t initial_height = proc.arg_count; // Procedure shouldn't know about stack outside arguments
        if (proc.is_closure)
            initial_height += 1; // +1 for CLOSURE

        stack_heights[proc.start_offset] = initial_height;
        std::vector<BasicBlock> workset;
        workset.push_back(proc.head_bb);
        while (!workset.empty()) {
            BasicBlock bb = workset.back();
            workset.pop_back();
            int32_t offset = bb.start_offset;

            int32_t current_height = stack_heights[offset];
            int32_t block_max_height = current_height;
            int32_t current_offset = offset;
            while (current_offset < bb.end_offset) {
                auto stack_effect = get_stack_effect(code, current_offset);
                int32_t pop_count = stack_effect.first;
                check(current_height >= pop_count, "stack underflow. Offset: 0x%x\n", current_offset);

                int32_t push_count = stack_effect.second;
                current_height = current_height - pop_count + push_count;
                check(current_height <= MAX_STACK_SIZE, "stack overflow. Offset: 0x%x\n", current_offset);

                block_max_height = std::max(current_height, block_max_height);
                current_offset += instr_length(current_offset);
            }
            max_stack = std::max(max_stack, block_max_height);

            for (int32_t succ_offset : bb.successors) {
                if (stack_heights[succ_offset] != NO_STACK_HEIGHT_VAL) {
                    // If successor's height was already calculated, check it's the same as current
                    check(stack_heights[succ_offset] == current_height, "stack height mismatch at merge point. Offset: 0x%x\n", succ_offset);
                } else {
                    stack_heights[succ_offset] = current_height;
                    workset.push_back(basic_blocks[succ_offset]);
                }
            }
        }
        check(max_stack <= MAX_STACK_SIZE, "max_stack overflows MAX_STACK_SIZE. Offset: 0x%x\n", proc.start_offset);

        // Use higher half-word from BEGIN/CBEGIN's local_count to save max_stack
        int32_t arg_count_offset = proc.start_offset + /*BEGIN/CBEGIN instruction size =*/1;
        int32_t local_count_offset = arg_count_offset + sizeof(int32_t);
        int32_t local_count = read_int32(code, local_count_offset);

        int32_t new_local_count_value = (max_stack << 16) | (local_count & 0xFFFF);
        std::memcpy(code + local_count_offset, &new_local_count_value, sizeof(int32_t));
    }

    void verify_instructions(const ProcedureInfo& proc) {
        std::vector<BasicBlock> workset;
        workset.push_back(proc.head_bb);
        while (!workset.empty()) {
            BasicBlock bb = workset.back();
            workset.pop_back();
            int32_t offset = bb.start_offset;
            uint8_t opcode = static_cast<uint8_t>(code[offset]);
            auto incr_offset = offset + 1;
            check(is_valid_opcode(opcode), "unknown instruction. Offset: 0x%x\n", offset);

            switch(opcode) {
                // Jumps/calls
                case Bytecode::JMP:
                case Bytecode::CJMPZ:
                case Bytecode::CJMPNZ: {
                    int32_t target = read_int32(code, incr_offset);
                    check(target >= 0 && target < code_size, "jump target out of bounds. Offset: 0x%x\n", offset);
                    // Target should be valid instruction. We can do it via `jump_targets`
                    check(jump_targets[target], "jump target not at instruction boundary. Offset: 0x%x\n", offset);
                }
                case Bytecode::CALL: {
                    int32_t target = read_int32(code, incr_offset);
                    check(target >= 0 && target < code_size, "call target out of bounds. Offset: 0x%x\n", offset);
                    // Target should be valid instruction. We can do it via `jump_targets`
                    check(jump_targets[target], "call target not at instruction boundary. Offset: 0x%x\n", offset);

                    int32_t n = read_int32(code, incr_offset + sizeof(int32_t));
                    check(n >= 0, "CALL: negative arguments number. Offset: 0x%x\n", offset);
                }
                case Bytecode::CALLC: {
                    int32_t n = read_int32(code, incr_offset + sizeof(int32_t));
                    check(n >= 0, "CALLC: negative arguments number. Offset: 0x%x\n", offset);
                }

                // Global indexes
                case Bytecode::LD_GLOBAL:
                case Bytecode::LDA_GLOBAL:
                case Bytecode::ST_GLOBAL: {
                    int32_t index = read_int32(code, incr_offset);
                    check(index >= 0 && index < global_area_size, "global index out of bounds. Offset: 0x%x\n", offset);
                }
                // Local indexes
                case Bytecode::LD_LOCAL:
                case Bytecode::LDA_LOCAL:
                case Bytecode::ST_LOCAL: {
                    int32_t index = read_int32(code, incr_offset);
                    check(index >= 0 && index < proc.local_count, "local index out of bounds. Offset: 0x%x\n", offset);
                }
                // Argument indexes
                case Bytecode::LD_ARGUMENT:
                case Bytecode::LDA_ARGUMENT:
                case Bytecode::ST_ARGUMENT: {
                    int32_t index = read_int32(code, incr_offset);
                    check(index >= 0 && index < proc.arg_count, "argument index out of bounds. Offset: 0x%x\n", offset);
                }

                // String indexes
                case Bytecode::STRING: {
                    int32_t str_index = read_int32(code, incr_offset);
                    check(str_index >= 0 && str_index < stringtab_size, "string index out of bounds. Offset: 0x%x\n", offset);
                }

                case Bytecode::SEXP: {
                    int32_t tag_index = read_int32(code, incr_offset);
                    check(tag_index >= 0 && tag_index < stringtab_size, "SEXP: tag index out of bounds. Offset: 0x%x\n", offset);
                    int32_t elem_count = read_int32(code, incr_offset + sizeof(int32_t));
                    check(elem_count >= 0, "SEXP: negative element count. Offset: 0x%x\n", offset);
                }

                case Bytecode::TAG: {
                    int32_t tag_index = read_int32(code, incr_offset);
                    check(tag_index >= 0 && tag_index < bf->stringtab_size, "TAG: string index out of bounds. Offset: 0x%x\n", offset);
                    int32_t expected_elem_count = read_int32(code, incr_offset + sizeof(int32_t));
                    check(expected_elem_count >= 0, "TAG: negative element count. Offset: 0x%x\n", offset);
                }

                case Bytecode::CALL_BARRAY: {
                    int32_t n = read_int32(code, incr_offset);
                    check(n >= 0, "BARRAY: negative arguments number. Offset: 0x%x\n", offset);
                }

                case Bytecode::CONST:
                case Bytecode::ARRAY:
                case Bytecode::LINE: { // Check only out-of-bounds read
                    read_int32(code, incr_offset);
                }
                case Bytecode::FAIL: { // Check only out-of-bounds reads
                    read_int32(code, incr_offset);
                    read_int32(code, incr_offset + sizeof(int32_t));
                }

                case Bytecode::CLOSURE: {
                    int32_t target = read_int32(code, incr_offset);
                    check(target >= 0 && target <= code_size, "CLOSURE: invalid target address. Offset: 0x%x\n", offset);
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
                            case L:
                                check(addr >= 0 && addr < proc.local_count, "CLOSURE: local index out of bounds. Offset: 0x%x\n", offset);
                                break;
                            case A:
                                check(addr >= 0 && addr < proc.arg_count, "CLOSURE: argument index out of bounds. Offset: 0x%x\n", offset);
                                break;
                            case C:
                                // Can't check captured statically
                                break;
                            default:
                                check(false, "invalid varspec for CLOSURE. Offset: 0x%x\n", offset);
                        }
                    }
                }
            }
        }
    }

public:
    Verifier(bytefile* bytefile) : bf(bytefile), code(bf->code_ptr),
                                   global_area_size(bf->global_area_size),
                                   stringtab_size(bf->stringtab_size) {
        stack_heights.fill(NO_STACK_HEIGHT_VAL);
    }

    void verify() {
        check(bf->public_symbols_number > 0, "corrupted public_symbols_number in file. Offset: 0x%x\n", 0);
        build_basic_blocks();
        for (int i = 0; i < proc_num; i++)
            verify_stack(procedures[i]);
        for (int i = 0; i < proc_num; i++)
            verify_instructions(procedures[i]);
    }
};

void verify_bytecode(bytefile *bf) {
    Verifier verifier(bf);
    verifier.verify();
}
