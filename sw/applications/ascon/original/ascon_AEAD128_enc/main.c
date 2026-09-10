#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "csr.h"

/* NIST SP 800-232 Ascon-AEAD128 parameters. */
#define ASCON_AEAD128_RATE 16U
#define ASCON_AEAD128_TAG_SIZE 16U
#define ASCON_AEAD128_IV UINT64_C(0x00001000808c0001)

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

/* Keep the rounds explicitly expanded, matching the CHIMERA reference code. */
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

static inline void ascon_p8(ascon_state_t *state)
{
    ascon_round(state, 0xb4U);
    ascon_round(state, 0xa5U);
    ascon_round(state, 0x96U);
    ascon_round(state, 0x87U);
    ascon_round(state, 0x78U);
    ascon_round(state, 0x69U);
    ascon_round(state, 0x5aU);
    ascon_round(state, 0x4bU);
}

/*
 * Pure-CPU implementation of NIST SP 800-232 Ascon-AEAD128 encryption.
 * The output buffer contains ciphertext followed by the 16-byte tag.
 */
static __attribute__((noinline)) int crypto_aead_encrypt(
    uint8_t *ciphertext,
    uint64_t *ciphertext_len,
    const uint8_t *plaintext,
    uint64_t plaintext_len,
    const uint8_t *associated_data,
    uint64_t associated_data_len,
    const uint8_t *nonce,
    const uint8_t *key)
{
    ascon_state_t state;
    const uint64_t key0 = load64_le(key, 8U);
    const uint64_t key1 = load64_le(key + 8U, 8U);
    const uint64_t nonce0 = load64_le(nonce, 8U);
    const uint64_t nonce1 = load64_le(nonce + 8U, 8U);
    uint8_t *ciphertext_ptr = ciphertext;
    const uint8_t *plaintext_ptr = plaintext;
    const uint8_t *associated_data_ptr = associated_data;
    uint64_t plaintext_remaining = plaintext_len;
    uint64_t associated_data_remaining = associated_data_len;

    *ciphertext_len = plaintext_len + ASCON_AEAD128_TAG_SIZE;

    /* Initialization: IV || K || N, followed by P12 and the key XOR. */
    state.x[0] = ASCON_AEAD128_IV;
    state.x[1] = key0;
    state.x[2] = key1;
    state.x[3] = nonce0;
    state.x[4] = nonce1;
    ascon_p12(&state);
    state.x[3] ^= key0;
    state.x[4] ^= key1;

    /* Absorb associated data, including a separate padding block if needed. */
    if (associated_data_remaining != 0U) {
        while (associated_data_remaining >= ASCON_AEAD128_RATE) {
            state.x[0] ^= load64_le(associated_data_ptr, 8U);
            state.x[1] ^= load64_le(associated_data_ptr + 8U, 8U);
            ascon_p8(&state);

            associated_data_ptr += ASCON_AEAD128_RATE;
            associated_data_remaining -= ASCON_AEAD128_RATE;
        }

        if (associated_data_remaining >= 8U) {
            const size_t upper_len = (size_t)associated_data_remaining - 8U;

            state.x[0] ^= load64_le(associated_data_ptr, 8U);
            state.x[1] ^= load64_le(associated_data_ptr + 8U, upper_len);
            state.x[1] ^= pad64(upper_len);
        } else {
            state.x[0] ^=
                load64_le(associated_data_ptr,
                          (size_t)associated_data_remaining);
            state.x[0] ^= pad64((size_t)associated_data_remaining);
        }
        ascon_p8(&state);
    }

    /* Domain separation is the most-significant bit of the last lane. */
    state.x[4] ^= UINT64_C(1) << 63;

    /* Encrypt all complete plaintext rate blocks. */
    while (plaintext_remaining >= ASCON_AEAD128_RATE) {
        state.x[0] ^= load64_le(plaintext_ptr, 8U);
        state.x[1] ^= load64_le(plaintext_ptr + 8U, 8U);
        store64_le(ciphertext_ptr, state.x[0], 8U);
        store64_le(ciphertext_ptr + 8U, state.x[1], 8U);
        ascon_p8(&state);

        plaintext_ptr += ASCON_AEAD128_RATE;
        ciphertext_ptr += ASCON_AEAD128_RATE;
        plaintext_remaining -= ASCON_AEAD128_RATE;
    }

    /* Encrypt and pad the final, possibly empty, plaintext block. */
    if (plaintext_remaining >= 8U) {
        const size_t upper_len = (size_t)plaintext_remaining - 8U;

        state.x[0] ^= load64_le(plaintext_ptr, 8U);
        state.x[1] ^= load64_le(plaintext_ptr + 8U, upper_len);
        store64_le(ciphertext_ptr, state.x[0], 8U);
        store64_le(ciphertext_ptr + 8U, state.x[1], upper_len);
        state.x[1] ^= pad64(upper_len);
    } else {
        state.x[0] ^= load64_le(plaintext_ptr, (size_t)plaintext_remaining);
        store64_le(ciphertext_ptr, state.x[0], (size_t)plaintext_remaining);
        state.x[0] ^= pad64((size_t)plaintext_remaining);
    }
    ciphertext_ptr += plaintext_remaining;

    /* Finalization and tag generation. */
    state.x[2] ^= key0;
    state.x[3] ^= key1;
    ascon_p12(&state);
    state.x[3] ^= key0;
    state.x[4] ^= key1;
    store64_le(ciphertext_ptr, state.x[3], 8U);
    store64_le(ciphertext_ptr + 8U, state.x[4], 8U);

    return 0;
}

int main(void)
{
    /* NIST Ascon-AEAD128 KAT No. 579: 17-byte AD and 17-byte plaintext. */
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    static const uint8_t nonce[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    static const uint8_t associated_data[17] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    };
    static const uint8_t plaintext[17] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    };
    static const uint8_t expected[33] = {
        /* Ciphertext. */
        0x98, 0x13, 0xb7, 0x01, 0x30, 0x89, 0xdb, 0x86,
        0x3a, 0x74, 0x2a, 0x4c, 0x13, 0xf1, 0x40, 0x8e,
        0x97,
        /* Tag. */
        0x81, 0xd4, 0x69, 0x86, 0xcb, 0xc0, 0x3b, 0x3e,
        0x6a, 0x33, 0x55, 0x81, 0xeb, 0x9d, 0xa9, 0x54,
    };
    uint8_t output[sizeof(expected)] = {0};
    uint64_t output_len = 0;
    uint32_t cycles;
    int errors = 0;

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    crypto_aead_encrypt(output, &output_len, plaintext, sizeof(plaintext),
                        associated_data, sizeof(associated_data), nonce, key);

    CSR_READ(CSR_REG_MCYCLE, &cycles);

    if (output_len != sizeof(expected)) {
        printf("Incorrect output length: expected %u, got %u\n",
               (unsigned int)sizeof(expected), (unsigned int)output_len);
        errors = 1;
    }

    for (size_t i = 0; i < sizeof(expected); ++i) {
        if (output[i] != expected[i]) {
            printf("Mismatch at byte %u: expected %02x, got %02x\n",
                   (unsigned int)i, (unsigned int)expected[i],
                   (unsigned int)output[i]);
            errors = 1;
        }
    }

    printf("Ascon-AEAD128 pure-CPU encryption cycles: %u\n",
           (unsigned int)cycles);
    printf(errors == 0 ? "test passed!\n" : "test failed.\n");

    return errors;
}
