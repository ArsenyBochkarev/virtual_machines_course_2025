#ifndef LAMAI_HPP
#define LAMAI_HPP

#include <cstdint>

constexpr uint32_t MAX_STACK_SIZE = 0x7fffffffU;

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
} // namespace Bytecode

#endif // LAMAI_HPP