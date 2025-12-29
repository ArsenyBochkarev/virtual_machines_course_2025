#ifndef LAMAA_HPP
#define LAMAA_HPP

#include <cstdint>
#include <string>

namespace Bytecode {
    constexpr uint8_t BINOP_HIGH   = 0x00;
    namespace Binop {
        constexpr uint8_t LOW_ADD = 0x01;
        constexpr uint8_t LOW_SUB = 0x02;
        constexpr uint8_t LOW_MUL = 0x03;
        constexpr uint8_t LOW_DIV = 0x04;
        constexpr uint8_t LOW_MOD = 0x05;
        constexpr uint8_t LOW_LT  = 0x06;
        constexpr uint8_t LOW_LE  = 0x07;
        constexpr uint8_t LOW_GT  = 0x08;
        constexpr uint8_t LOW_GE  = 0x09;
        constexpr uint8_t LOW_EQ  = 0x0A;
        constexpr uint8_t LOW_NE  = 0x0B;
        constexpr uint8_t LOW_AND = 0x0C;
        constexpr uint8_t LOW_OR  = 0x0D;
    } // namespace Binop
    constexpr uint8_t CONST  = 0x10;
    constexpr uint8_t STRING = 0x11;
    constexpr uint8_t SEXP   = 0x12;
    constexpr uint8_t STI    = 0x13;
    constexpr uint8_t STA    = 0x14;
    constexpr uint8_t JMP    = 0x15;
    constexpr uint8_t END    = 0x16;
    constexpr uint8_t RET    = 0x17;
    constexpr uint8_t DROP   = 0x18;
    constexpr uint8_t DUP    = 0x19;
    constexpr uint8_t SWAP   = 0x1A;
    constexpr uint8_t ELEM   = 0x1B;

    constexpr uint8_t LD_GLOBAL   = 0x20;
    constexpr uint8_t LD_LOCAL    = 0x21;
    constexpr uint8_t LD_ARGUMENT = 0x22;
    constexpr uint8_t LD_CAPTURED = 0x23;

    constexpr uint8_t LDA_GLOBAL   = 0x30;
    constexpr uint8_t LDA_LOCAL    = 0x31;
    constexpr uint8_t LDA_ARGUMENT = 0x32;
    constexpr uint8_t LDA_CAPTURED = 0x33;

    constexpr uint8_t ST_GLOBAL   = 0x40;
    constexpr uint8_t ST_LOCAL    = 0x41;
    constexpr uint8_t ST_ARGUMENT = 0x42;
    constexpr uint8_t ST_CAPTURED = 0x43;

    constexpr uint8_t CJMPZ   = 0x50;
    constexpr uint8_t CJMPNZ  = 0x51;
    constexpr uint8_t BEGIN   = 0x52;
    constexpr uint8_t CBEGIN  = 0x53;
    constexpr uint8_t CLOSURE = 0x54;
    constexpr uint8_t CALLC   = 0x55;
    constexpr uint8_t CALL    = 0x56;

    constexpr uint8_t TAG     = 0x57;
    constexpr uint8_t ARRAY   = 0x58;
    constexpr uint8_t FAIL    = 0x59;
    constexpr uint8_t LINE    = 0x5A;

    constexpr uint8_t PATT_STR    = 0x60;
    constexpr uint8_t PATT_STRING = 0x61;
    constexpr uint8_t PATT_ARRAY  = 0x62;
    constexpr uint8_t PATT_SEXP   = 0x63;
    constexpr uint8_t PATT_REF    = 0x64;
    constexpr uint8_t PATT_VAL    = 0x65;
    constexpr uint8_t PATT_FUN    = 0x66;

    constexpr uint8_t CALL_LREAD   = 0x70;
    constexpr uint8_t CALL_LWRITE  = 0x71;
    constexpr uint8_t CALL_LLENGTH = 0x72;
    constexpr uint8_t CALL_LSTRING = 0x73;
    constexpr uint8_t CALL_BARRAY  = 0x74;

    constexpr uint8_t STOP = 0xF0;

    bool is_jump(uint8_t opcode) {
        return opcode == JMP || opcode == CJMPNZ || opcode == CJMPZ;
    }
    bool is_call(uint8_t opcode) {
        return opcode == CALL || opcode == CALLC;
    }
    bool is_terminal(uint8_t opcode) {
        return opcode == END || opcode == RET || opcode == STOP || opcode == FAIL || opcode == JMP;
    }

    std::string get_opcode_name(uint8_t opcode) {
        switch (opcode) {
        case CONST:
            return "CONST";
        case STRING:
            return "STRING";
        case SEXP:
            return "SEXP";
        case STI:
            return "STI";
        case STA:
            return "STA";
        case JMP:
            return "JMP";
        case END:
            return "END";
        case RET:
            return "RET";
        case DROP:
            return "DROP";
        case DUP:
            return "DUP";
        case SWAP:
            return "SWAP";
        case ELEM:
            return "ELEM";

        case LD_GLOBAL:
            return "LD(G)";
        case LD_LOCAL:
            return "LD(L)";
        case LD_ARGUMENT:
            return "LD(A)";
        case LD_CAPTURED:
            return "LD(C)";

        case LDA_GLOBAL:
            return "LDA(G)";
        case LDA_LOCAL:
            return "LDA(L)";
        case LDA_ARGUMENT:
            return "LDA(A)";
        case LDA_CAPTURED:
            return "LDA(C)";

        case ST_GLOBAL:
            return "ST(G)";
        case ST_LOCAL:
            return "ST(L)";
        case ST_ARGUMENT:
            return "ST(A)";
        case ST_CAPTURED:
            return "ST(A)";

        case CJMPZ:
            return "CJMPZ";
        case CJMPNZ:
            return "CJMPNZ";
        case BEGIN:
            return "BEGIN";
        case CBEGIN:
            return "CBEGIN";
        case CLOSURE:
            return "CLOSURE";
        case CALLC:
            return "CALLC";
        case CALL:
            return "CALL";

        case TAG:
            return "TAG";
        case ARRAY:
            return "ARRAY";
        case FAIL:
            return "FAIL";
        case LINE:
            return "LINE";

        case PATT_STR:
            return "PATT_STR";
        case PATT_STRING:
            return "PATT_STRING";
        case PATT_ARRAY:
            return "PATT_ARRAY";
        case PATT_SEXP:
            return "PATT_SEXP";
        case PATT_REF:
            return "PATT_REF";
        case PATT_VAL:
            return "PATT_VAL";
        case PATT_FUN:
            return "PATT_FUN";

        case CALL_LREAD:
            return "CALL_LREAD";
        case CALL_LWRITE:
            return "CALL_LWRITE";
        case CALL_LLENGTH:
            return "CALL_LLENGTH";
        case CALL_LSTRING:
            return "CALL_LSTRING";
        case CALL_BARRAY:
            return "CALL_BARRAY";

        case Bytecode::STOP:
            return "STOP";

        default:
            if (opcode >= 0x01 && opcode <= 0x0F) {
                switch (opcode) {
                    case Binop::LOW_ADD:
                        return "BINOP+";
                    case Binop::LOW_SUB:
                        return "BINOP-";
                    case Binop::LOW_MUL:
                        return "BINOP*";
                    case Binop::LOW_DIV:
                        return "BINOP/";
                    case Binop::LOW_MOD:
                        return "BINOP%";
                    case Binop::LOW_LT:
                        return "BINOP<";
                    case Binop::LOW_LE:
                        return "BINOP<=";
                    case Binop::LOW_GT:
                        return "BINOP>";
                    case Binop::LOW_GE:
                        return "BINOP>=";
                    case Binop::LOW_EQ:
                        return "BINOP==";
                    case Binop::LOW_NE:
                        return "BINOP!=";
                    case Binop::LOW_AND:
                        return "BINOP&&";
                    case Binop::LOW_OR:
                        return "BINOP!!";
                    default:
                        return "BINOP?";
                }
            }
            return "UNKNOWN";
        }
    }
} // namespace Bytecode

#endif // LAMAA_HPP