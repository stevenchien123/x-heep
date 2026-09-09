#ifndef ASCON_COPROC_H_
#define ASCON_COPROC_H_

#include <stdbool.h>
#include <stdint.h>

/*
 *  Ascon Coprocessor
 *
 *  Custom instructions:
 *    Machine code: (OPCODE = 0x0B = 7'b0001011)
 *    R4-type:
 *    31       27 26 25 24       20 19        15  14    12 11      7 6       0
 *    +-----------+-----+-----------+-----------+--------+----------+---------+
 *    |    rs3    | 00  |    rs2    |    rs1    | funct3 |    rd    | 0001011 |
 *    +-----------+-----+-----------+-----------+--------+----------+---------+
 *
 *    R-type:
 *    31       25 24       20 19       15 14    12 11         7 6       0
 *    +-----------+-----------+-----------+--------+-----------+---------+
 *    |   func7   |    rs2    |    rs1    | func3  |    rd     | 0001011 |
 *    +-----------+-----------+-----------+--------+-----------+---------+
 *
 *    1. CONFIG:
 *      * R-type, send metadata to coproc (mode, ED, hash_len)
 *      * func3=3'b000, func7=7'b0000001
 *      * rs1[1:0] = mode, rs1[2] = ED, rs2[31:0] = hash_len
 *    2. PUSH  :
 *      * R4-type, send data into coproc (Key, Nonce, AD, PT/CT, message), rs1 and rs2 send data, rs3 send metadata (data_keep, data_last)
 *      * func3=3'b001
 *      * rs1[31:0] & rs2[31:0] = data, rs3[7:0] = data_keep, rs3[8:9] = data_last
 *    3. POP   :
 *      * R-type,  receive coproc output (CT/PT, tag, hash message), read 32-bit output
 *      * func3=3'b010, func7=7'b0000001
 *      * rd[31:0] = data
 *    4. CLEAR :
 *      * R-type,  clear Ascon state
 *      * func3=3'b011, func7=7'b0000001
 *      * nothing to send or receive
 *    5. STATUS:
 *      * R-type,  read Ascon error output
 *      * func3=3'b100, func7=7'b0000001
 *
 *
 */

typedef enum ascon_coproc_mode {
    ASCON_AEAD128 = 0,
    ASCON_HASH256 = 1,
    ASCON_XOF128  = 2,
    ASCON_CXOF128 = 3,
} ascon_coproc_mode_t;

typedef enum ascon_aead128_op {
    ENC = 0,
    DEC = 1,
} ascon_aead128_op_t;

/*
 * CONFIG (R-type)
 *   rs1[1:0] = mode
 *   rs1[2]   = decrypt (0: encryption, 1: decryption)
 *   rs2      = XOF/CXOF output length in bytes, Hash256 ignores this (fixed 256-bit output)
 */
static inline void ascon_coproc_config(ascon_coproc_mode_t mode,
                                       bool decrypt,
                                       uint32_t hash_len)
{
    const uint32_t control = ((uint32_t)mode & UINT32_C(0x3)) |
                             ((uint32_t)decrypt << 2);

    asm volatile(
        ".insn r 0x0b, 0x0, 0x01, x0, %[control], %[hash_len]\n"
        :
        : [control] "r"(control), [hash_len] "r"(hash_len)
        : "memory");
}

/*
 * PUSH (R4-type)
 *   rs1       = first 32-bit data word
 *   rs2       = second 32-bit data word
 *   rs3[3:0]  = keep for the first word
 *   rs3[7:4]  = keep for the second word
 *   rs3[8]    = last for the first word
 *   rs3[9]    = last for the second word
 */
static inline void ascon_coproc_push(uint32_t data0,
                                     uint32_t data1,
                                     uint8_t keep0,
                                     uint8_t keep1,
                                     bool last0,
                                     bool last1)
{
    const uint32_t metadata = ((uint32_t)keep0 & UINT32_C(0x0f)) |
                              (((uint32_t)keep1 & UINT32_C(0x0f)) << 4) |
                              ((uint32_t)last0 << 8) |
                              ((uint32_t)last1 << 9);

    asm volatile(
        ".insn r4 0x0b, 0x1, 0x0, x0, %[data0], %[data1], %[metadata]\n"
        :
        : [data0] "r"(data0), [data1] "r"(data1),
          [metadata] "r"(metadata)
        : "memory");
}

/* POP (R-type): wait for and return one 32-bit output word. */
static inline uint32_t ascon_coproc_pop(void)
{
    uint32_t data;

    asm volatile(
        ".insn r 0x0b, 0x2, 0x01, %[data], x0, x0\n"
        : [data] "=r"(data)
        :
        : "memory");

    return data;
}

/* CLEAR (R-type): reset the internal Ascon state. */
static inline void ascon_coproc_clear(void)
{
    asm volatile(
        ".insn r 0x0b, 0x3, 0x01, x0, x0, x0\n"
        :
        :
        : "memory");
}

/* STATUS (R-type): wait for completion and return bit 0 of the error status. */
static inline uint32_t ascon_coproc_status(void)
{
    uint32_t status;

    asm volatile(
        ".insn r 0x0b, 0x4, 0x01, %[status], x0, x0\n"
        : [status] "=r"(status)
        :
        : "memory");

    return status;
}

#endif  // ASCON_COPROC_H_
