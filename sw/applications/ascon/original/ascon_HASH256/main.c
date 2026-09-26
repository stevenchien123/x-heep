#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "csr.h"

/* NIST SP 800-232 Ascon-Hash256 parameters. */
#define ASCON_HASH256_RATE 8U
#define MESSAGE_LENGTH 1536U
#define ASCON_HASH256_SIZE 32U

/*
 * Precomputed state from NIST SP 800-232, Appendix A, Table 12.
 * It is P12(0x0000080100cc0002 || 0^256), so the fixed initialization
 * permutation does not need to be executed at run time.
 */
#define ASCON_HASH256_INITIAL_X0 UINT64_C(0x9b1e5494e934d681)
#define ASCON_HASH256_INITIAL_X1 UINT64_C(0x4bc3a01e333751d2)
#define ASCON_HASH256_INITIAL_X2 UINT64_C(0xae65396c6b34b81a)
#define ASCON_HASH256_INITIAL_X3 UINT64_C(0x3c7fd4a4d56a4db3)
#define ASCON_HASH256_INITIAL_X4 UINT64_C(0x1a5c464906c5976d)

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

/* Pure-CPU implementation of NIST SP 800-232 Ascon-Hash256. */
static __attribute__((noinline)) int crypto_hash(
    uint8_t output[ASCON_HASH256_SIZE],
    const uint8_t *message,
    uint64_t message_len)
{
    ascon_state_t state;
    const uint8_t *message_ptr = message;
    uint8_t *output_ptr = output;
    uint64_t message_remaining = message_len;
    size_t output_remaining = ASCON_HASH256_SIZE;

    /* Load the precomputed initialization state from SP 800-232 Table 12. */
    state.x[0] = ASCON_HASH256_INITIAL_X0;
    state.x[1] = ASCON_HASH256_INITIAL_X1;
    state.x[2] = ASCON_HASH256_INITIAL_X2;
    state.x[3] = ASCON_HASH256_INITIAL_X3;
    state.x[4] = ASCON_HASH256_INITIAL_X4;

    /* Absorb complete 8-byte message blocks. */
    while (message_remaining >= ASCON_HASH256_RATE) {
        state.x[0] ^= load64_le(message_ptr, ASCON_HASH256_RATE);
        ascon_p12(&state);

        message_ptr += ASCON_HASH256_RATE;
        message_remaining -= ASCON_HASH256_RATE;
    }

    /* Absorb and pad the final, possibly empty, message block. */
    state.x[0] ^= load64_le(message_ptr, (size_t)message_remaining);
    state.x[0] ^= pad64((size_t)message_remaining);
    ascon_p12(&state);

    /*
     * Squeeze four 8-byte output blocks. A P12 is needed between blocks,
     * but not after the final block because it cannot affect the digest.
     */
    while (output_remaining > ASCON_HASH256_RATE) {
        store64_le(output_ptr, state.x[0], ASCON_HASH256_RATE);
        ascon_p12(&state);

        output_ptr += ASCON_HASH256_RATE;
        output_remaining -= ASCON_HASH256_RATE;
    }
    store64_le(output_ptr, state.x[0], output_remaining);

    return 0;
}

static unsigned char message[(MESSAGE_LENGTH > 0U) ? MESSAGE_LENGTH : 1U];

void init_buffer(unsigned char* buffer, unsigned long long numbytes);

void init_buffer(unsigned char* buffer, unsigned long long numbytes) {
  unsigned long long i;
  for (i = 0; i < numbytes; i++) buffer[i] = (unsigned char)i;
}

int main(void)
{
    /* NIST Ascon-Hash256 KAT No. 10: message bytes 0x00 through 0x08. */
    // static const uint8_t message[9] = {
    //     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    // };
    // static const uint8_t expected[ASCON_HASH256_SIZE] = {
    //     0x94, 0x26, 0x9c, 0x30, 0xe0, 0x29, 0x6e, 0x1e,
    //     0xc8, 0x66, 0x55, 0x04, 0x18, 0x41, 0x82, 0x3e,
    //     0xfa, 0x19, 0x27, 0xf5, 0x20, 0xfd, 0x58, 0xc8,
    //     0xe9, 0xbc, 0xe6, 0x19, 0x78, 0x78, 0xc1, 0xa6,
    // };
    init_buffer(message, sizeof(message));
    uint8_t output[ASCON_HASH256_SIZE] = {0};
    uint32_t cycles;
    int errors = 0;

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    crypto_hash(output, message, sizeof(message));

    CSR_READ(CSR_REG_MCYCLE, &cycles);

    // for (size_t i = 0; i < ASCON_HASH256_SIZE; ++i) {
    //     if (output[i] != expected[i]) {
    //         printf("Mismatch at byte %u: expected %02x, got %02x\n",
    //                (unsigned int)i, (unsigned int)expected[i],
    //                (unsigned int)output[i]);
    //         errors = 1;
    //     }
    // }

    printf("Ascon-Hash256 pure-CPU cycles: %u\n", (unsigned int)cycles);
    printf(errors == 0 ? "test finished!\n" : "test failed.\n");

    return errors;
}
