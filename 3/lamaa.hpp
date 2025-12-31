#ifndef LAMAA_HPP
#define LAMAA_HPP

#include <cstdint>

namespace Bytecode {
    constexpr uint8_t JMP    = 0x15;
    constexpr uint8_t END    = 0x16;
    constexpr uint8_t RET    = 0x17;
    constexpr uint8_t CJMPZ  = 0x50;
    constexpr uint8_t CJMPNZ = 0x51;
    constexpr uint8_t CALLC  = 0x55;
    constexpr uint8_t CALL   = 0x56;
    constexpr uint8_t FAIL   = 0x59;
    constexpr uint8_t STOP   = 0xF0;
    bool is_jump(uint8_t opcode) {
        return opcode == JMP || opcode == CJMPNZ || opcode == CJMPZ;
    }
    bool is_call(uint8_t opcode) {
        return opcode == CALL || opcode == CALLC;
    }
    bool is_terminal(uint8_t opcode) {
        return opcode == END || opcode == RET || opcode == STOP || opcode == FAIL || opcode == JMP;
    }
} // namespace Bytecode

#endif // LAMAA_HPP