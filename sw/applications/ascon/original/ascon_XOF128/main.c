#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "csr.h"

/* NIST SP 800-232 Ascon-XOF128 parameters. */
#define ASCON_XOF128_RATE 8U
#define ASCON_XOF128_TEST_OUTPUT_SIZE 32U

/*
 * Precomputed state from NIST SP 800-232, Appendix A, Table 12.
 * It is P12(0x0000080000cc0003 || 0^256), so the fixed initialization
 * permutation does not need to be executed at run time.
 */
#define ASCON_XOF128_INITIAL_X0 UINT64_C(0xda82ce768d9447eb)
#define ASCON_XOF128_INITIAL_X1 UINT64_C(0xcc7ce6c75f1ef969)
#define ASCON_XOF128_INITIAL_X2 UINT64_C(0xe7508fd780085631)
#define ASCON_XOF128_INITIAL_X3 UINT64_C(0x0ee0ea53416b58cc)
#define ASCON_XOF128_INITIAL_X4 UINT64_C(0xe0547524db6f0bde)

typedef struct {
    uint64_t x[5];
} ascon_state_t;

static inline uint64_t rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64U - n));
}

/* SP 800-232 maps the first byte to the least-significant byte of a lane. */
static uint64_t load64_le(const uint8_t *src, size_t len)
{
    uint64_t value = 0;

    for (size_t i = 0; i < len; ++i) {
        value |= (uint64_t)src[i] << (8U * i);
    }

    return value;
}

static void store64_le(uint8_t *dst, uint64_t value, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        dst[i] = (uint8_t)(value >> (8U * i));
    }
}

/* The 0x01 padding byte follows len valid bytes in the current lane. */
static inline uint64_t pad64(size_t len)
{
    return UINT64_C(1) << (8U * len);
}

static inline void ascon_round(ascon_state_t *state, uint8_t round_constant)
{
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t t3;
    uint64_t t4;

    /* Add round constant. */
    state->x[2] ^= round_constant;

    /* Substitution layer. */
    state->x[0] ^= state->x[4];
    state->x[4] ^= state->x[3];
    state->x[2] ^= state->x[1];

    t0 = state->x[0] ^ (~state->x[1] & state->x[2]);
    t1 = state->x[1] ^ (~state->x[2] & state->x[3]);
    t2 = state->x[2] ^ (~state->x[3] & state->x[4]);
    t3 = state->x[3] ^ (~state->x[4] & state->x[0]);
    t4 = state->x[4] ^ (~state->x[0] & state->x[1]);

    t1 ^= t0;
    t0 ^= t4;
    t3 ^= t2;
    t2 = ~t2;

    /* Linear diffusion layer. */
    state->x[0] = t0 ^ rotr64(t0, 19U) ^ rotr64(t0, 28U);
    state->x[1] = t1 ^ rotr64(t1, 61U) ^ rotr64(t1, 39U);
    state->x[2] = t2 ^ rotr64(t2, 1U) ^ rotr64(t2, 6U);
    state->x[3] = t3 ^ rotr64(t3, 10U) ^ rotr64(t3, 17U);
    state->x[4] = t4 ^ rotr64(t4, 7U) ^ rotr64(t4, 41U);
}

/* Keep P12 explicitly expanded, matching the CHIMERA reference code. */
static inline void ascon_p12(ascon_state_t *state)
{
    ascon_round(state, 0xf0U);
    ascon_round(state, 0xe1U);
    ascon_round(state, 0xd2U);
    ascon_round(state, 0xc3U);
    ascon_round(state, 0xb4U);
    ascon_round(state, 0xa5U);
    ascon_round(state, 0x96U);
    ascon_round(state, 0x87U);
    ascon_round(state, 0x78U);
    ascon_round(state, 0x69U);
    ascon_round(state, 0x5aU);
    ascon_round(state, 0x4bU);
}

/* Pure-CPU implementation of NIST SP 800-232 Ascon-XOF128. */
static __attribute__((noinline)) int ascon_xof128(
    uint8_t *output,
    size_t output_len,
    const uint8_t *message,
    uint64_t message_len)
{
    ascon_state_t state;
    const uint8_t *message_ptr = message;
    uint8_t *output_ptr = output;
    uint64_t message_remaining = message_len;
    size_t output_remaining = output_len;

    /* Load the precomputed initialization state from SP 800-232 Table 12. */
    state.x[0] = ASCON_XOF128_INITIAL_X0;
    state.x[1] = ASCON_XOF128_INITIAL_X1;
    state.x[2] = ASCON_XOF128_INITIAL_X2;
    state.x[3] = ASCON_XOF128_INITIAL_X3;
    state.x[4] = ASCON_XOF128_INITIAL_X4;

    /* Absorb complete 8-byte message blocks. */
    while (message_remaining >= ASCON_XOF128_RATE) {
        state.x[0] ^= load64_le(message_ptr, ASCON_XOF128_RATE);
        ascon_p12(&state);

        message_ptr += ASCON_XOF128_RATE;
        message_remaining -= ASCON_XOF128_RATE;
    }

    /* Absorb and pad the final, possibly empty, message block. */
    state.x[0] ^= load64_le(message_ptr, (size_t)message_remaining);
    state.x[0] ^= pad64((size_t)message_remaining);
    ascon_p12(&state);

    /*
     * Squeeze as many output bytes as requested. A P12 is needed between
     * output blocks, but not after the final block.
     */
    while (output_remaining > ASCON_XOF128_RATE) {
        store64_le(output_ptr, state.x[0], ASCON_XOF128_RATE);
        ascon_p12(&state);

        output_ptr += ASCON_XOF128_RATE;
        output_remaining -= ASCON_XOF128_RATE;
    }
    store64_le(output_ptr, state.x[0], output_remaining);

    return 0;
}

int main(void)
{
    /* NIST Ascon-XOF128 KAT No. 10: 9-byte message, 256-bit output. */
    static const uint8_t message[9] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    static const uint8_t expected[ASCON_XOF128_TEST_OUTPUT_SIZE] = {
        0xdb, 0x30, 0x13, 0xbf, 0xbb, 0xd1, 0x32, 0xdc,
        0x1d, 0x31, 0x52, 0xfd, 0x95, 0x5e, 0xd4, 0x8f,
        0x7c, 0xbb, 0x67, 0x5e, 0x9a, 0xd2, 0xa2, 0xfe,
        0xcf, 0x92, 0xb7, 0x4c, 0x95, 0x75, 0x92, 0xe0,
    };
    uint8_t output[ASCON_XOF128_TEST_OUTPUT_SIZE] = {0};
    uint32_t cycles;
    int errors = 0;

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    ascon_xof128(output, sizeof(output), message, sizeof(message));

    CSR_READ(CSR_REG_MCYCLE, &cycles);

    for (size_t i = 0; i < ASCON_XOF128_TEST_OUTPUT_SIZE; ++i) {
        if (output[i] != expected[i]) {
            printf("Mismatch at byte %u: expected %02x, got %02x\n",
                   (unsigned int)i, (unsigned int)expected[i],
                   (unsigned int)output[i]);
            errors = 1;
        }
    }

    printf("Ascon-XOF128 pure-CPU cycles: %u\n", (unsigned int)cycles);
    printf(errors == 0 ? "test passed!\n" : "test failed.\n");

    return errors;
}
