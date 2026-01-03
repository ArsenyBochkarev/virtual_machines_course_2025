#ifndef STACK_EFFECT_HPP
#define STACK_EFFECT_HPP

#include <utility>

constexpr uint32_t MAX_LOCAL_COUNT = 65535; // 0xFFFF
constexpr uint32_t MAX_PROCEDURES = 20;
constexpr uint32_t MAX_BB_SUCCESSORS = 2;
constexpr uint32_t NO_SUCCESSOR_OFFSET = -1;
constexpr uint32_t NO_STACK_HEIGHT_VAL = -1;

void check(bool condition, char *msg, int32_t offset);
int32_t read_int32(const char* data, size_t pos);
// (pop_count, push_count)
std::pair<int32_t, int32_t> get_stack_effect(const char *code, int32_t offset) {
    uint8_t opcode = static_cast<uint8_t>(code[offset]);
    switch (opcode) {
        case Bytecode::BEGIN:
        case Bytecode::CBEGIN:
        case Bytecode::JMP:
        case Bytecode::LINE:
            return {0, 0};

        case Bytecode::CONST:
        case Bytecode::STRING:
        case Bytecode::LD_GLOBAL:
        case Bytecode::LD_LOCAL:
        case Bytecode::LD_ARGUMENT:
        case Bytecode::LD_CAPTURED:
        case Bytecode::LDA_GLOBAL:
        case Bytecode::LDA_LOCAL:
        case Bytecode::LDA_ARGUMENT:
        case Bytecode::LDA_CAPTURED:
        case Bytecode::CALL_LREAD:
            return {0, 1};

        case Bytecode::CJMPZ:
        case Bytecode::CJMPNZ:
        case Bytecode::DROP:
        case Bytecode::FAIL:
            return {1, 0};

        case Bytecode::END:
        case Bytecode::RET:
        case Bytecode::ST_GLOBAL:
        case Bytecode::ST_LOCAL:
        case Bytecode::ST_ARGUMENT:
        case Bytecode::ST_CAPTURED:
        case Bytecode::TAG:
        case Bytecode::ARRAY:
        case Bytecode::PATT_STRING:
        case Bytecode::PATT_ARRAY:
        case Bytecode::PATT_SEXP:
        case Bytecode::PATT_REF:
        case Bytecode::PATT_VAL:
        case Bytecode::PATT_FUN:
        case Bytecode::CALL_LWRITE:
        case Bytecode::CALL_LLENGTH:
        case Bytecode::CALL_LSTRING:
            return {1, 1};

        case Bytecode::DUP:
            return {1, 2};

        case Bytecode::STI:
        case Bytecode::ELEM:
        case Bytecode::PATT_STR:
            return {2, 1};

        case Bytecode::SWAP:
            return {2, 2};

        case Bytecode::STA:
            return {3, 1}; // Conservatively assume worst-case scenario of 3 operands popped

        case Bytecode::CLOSURE:{
            int32_t n = read_int32(code, offset + /*size of CLOSURE instruction=*/1 + sizeof(int32_t));
            return {n + 1, 1};
        }

        case Bytecode::CALLC: {
            int32_t n = read_int32(code, offset + /*size of CALLC instruction=*/1);
            return {n + 1, 1};
        }

        case Bytecode::SEXP:
        case Bytecode::CALL: {
            int32_t n = read_int32(code, offset + /*size of CALL/SEXP instruction=*/1 + sizeof(int32_t));
            return {n, 1};
        }

        case Bytecode::CALL_BARRAY: {
            int32_t n = read_int32(code, offset + /*size of CALL Barray instruction=*/1);
            return {n, 1};
        }

        default: {
            int high = opcode & 0xF0;
            // We also need to check BINOP
            if (high == Bytecode::BINOP_HIGH)
                return {2, 1};
            else {
                check(false, "unknown instruction. Offset: 0x%x\n", offset);
                return {-1, -1};
            }
        }
    }
}

bool is_valid_opcode(uint8_t opcode) {
    return ((opcode >= 0x00 && opcode <= 0x0D) ||
            (opcode >= 0x10 && opcode <= 0x1B) ||
            (opcode >= 0x20 && opcode <= 0x23) ||
            (opcode >= 0x30 && opcode <= 0x33) ||
            (opcode >= 0x40 && opcode <= 0x43) ||
            (opcode >= 0x50 && opcode <= 0x5A) ||
            (opcode >= 0x60 && opcode <= 0x66) ||
            (opcode >= 0x70 && opcode <= 0x74) ||
             opcode == 0xF0);
}

#endif // STACK_EFFECT_HPP
