#include "ascon_aead128.h"

#include <stddef.h>
#include <stdint.h>

#define ASCON_AEAD128_RATE 16U
#define ASCON_AEAD128_IV UINT64_C(0x00001000808c0001)

typedef struct {
    uint64_t x[5];
} ascon_state_t;

static inline uint64_t rotr64(uint64_t value, unsigned int shift)
{
    return (value >> shift) | (value << (64U - shift));
}

static uint64_t load64_le(const unsigned char *src, size_t len)
{
    uint64_t value = 0;

    for (size_t i = 0; i < len; ++i) {
        value |= (uint64_t)src[i] << (8U * i);
    }
    return value;
}

static void store64_le(unsigned char *dst, uint64_t value, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        dst[i] = (unsigned char)(value >> (8U * i));
    }
}

static uint64_t clear64_le(uint64_t value, size_t len)
{
    if (len == 0U) {
        return value;
    }
    if (len >= 8U) {
        return 0;
    }
    return value & ~((UINT64_C(1) << (8U * len)) - UINT64_C(1));
}

static inline uint64_t pad64(size_t len)
{
    return UINT64_C(1) << (8U * len);
}

static inline void ascon_round(ascon_state_t *state, uint8_t constant)
{
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t t3;
    uint64_t t4;

    state->x[2] ^= constant;
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

    state->x[0] = t0 ^ rotr64(t0, 19U) ^ rotr64(t0, 28U);
    state->x[1] = t1 ^ rotr64(t1, 61U) ^ rotr64(t1, 39U);
    state->x[2] = t2 ^ rotr64(t2, 1U) ^ rotr64(t2, 6U);
    state->x[3] = t3 ^ rotr64(t3, 10U) ^ rotr64(t3, 17U);
    state->x[4] = t4 ^ rotr64(t4, 7U) ^ rotr64(t4, 41U);
}

/* Keep one expanded copy of each permutation so ENC and DEC fit in ram0. */
static __attribute__((noinline)) void ascon_p12(ascon_state_t *state)
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

static __attribute__((noinline)) void ascon_p8(ascon_state_t *state)
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

static void initialize(ascon_state_t *state, const unsigned char *nonce,
                       const unsigned char *key)
{
    const uint64_t key0 = load64_le(key, 8U);
    const uint64_t key1 = load64_le(key + 8U, 8U);

    state->x[0] = ASCON_AEAD128_IV;
    state->x[1] = key0;
    state->x[2] = key1;
    state->x[3] = load64_le(nonce, 8U);
    state->x[4] = load64_le(nonce + 8U, 8U);
    ascon_p12(state);
    state->x[3] ^= key0;
    state->x[4] ^= key1;
}

static void absorb_associated_data(ascon_state_t *state,
                                   const unsigned char *associated_data,
                                   unsigned long long associated_data_len)
{
    if (associated_data_len != 0U) {
        while (associated_data_len >= ASCON_AEAD128_RATE) {
            state->x[0] ^= load64_le(associated_data, 8U);
            state->x[1] ^= load64_le(associated_data + 8U, 8U);
            ascon_p8(state);
            associated_data += ASCON_AEAD128_RATE;
            associated_data_len -= ASCON_AEAD128_RATE;
        }

        if (associated_data_len >= 8U) {
            const size_t upper_len = (size_t)associated_data_len - 8U;
            state->x[0] ^= load64_le(associated_data, 8U);
            state->x[1] ^= load64_le(associated_data + 8U, upper_len);
            state->x[1] ^= pad64(upper_len);
        } else {
            state->x[0] ^= load64_le(associated_data,
                                     (size_t)associated_data_len);
            state->x[0] ^= pad64((size_t)associated_data_len);
        }
        ascon_p8(state);
    }

    state->x[4] ^= UINT64_C(1) << 63;
}

static void finalize(ascon_state_t *state, const unsigned char *key,
                     unsigned char tag[ASCON_AEAD128_TAG_SIZE])
{
    const uint64_t key0 = load64_le(key, 8U);
    const uint64_t key1 = load64_le(key + 8U, 8U);

    state->x[2] ^= key0;
    state->x[3] ^= key1;
    ascon_p12(state);
    state->x[3] ^= key0;
    state->x[4] ^= key1;
    store64_le(tag, state->x[3], 8U);
    store64_le(tag + 8U, state->x[4], 8U);
}

__attribute__((noinline)) int ascon_aead128_encrypt(
    unsigned char *ciphertext, unsigned long long *ciphertext_len,
    const unsigned char *plaintext, unsigned long long plaintext_len,
    const unsigned char *associated_data,
    unsigned long long associated_data_len, const unsigned char *nonce,
    const unsigned char *key)
{
    ascon_state_t state;
    unsigned long long remaining = plaintext_len;

    *ciphertext_len = plaintext_len + ASCON_AEAD128_TAG_SIZE;
    initialize(&state, nonce, key);
    absorb_associated_data(&state, associated_data, associated_data_len);

    while (remaining >= ASCON_AEAD128_RATE) {
        state.x[0] ^= load64_le(plaintext, 8U);
        state.x[1] ^= load64_le(plaintext + 8U, 8U);
        store64_le(ciphertext, state.x[0], 8U);
        store64_le(ciphertext + 8U, state.x[1], 8U);
        ascon_p8(&state);
        plaintext += ASCON_AEAD128_RATE;
        ciphertext += ASCON_AEAD128_RATE;
        remaining -= ASCON_AEAD128_RATE;
    }

    if (remaining >= 8U) {
        const size_t upper_len = (size_t)remaining - 8U;
        state.x[0] ^= load64_le(plaintext, 8U);
        state.x[1] ^= load64_le(plaintext + 8U, upper_len);
        store64_le(ciphertext, state.x[0], 8U);
        store64_le(ciphertext + 8U, state.x[1], upper_len);
        state.x[1] ^= pad64(upper_len);
    } else {
        state.x[0] ^= load64_le(plaintext, (size_t)remaining);
        store64_le(ciphertext, state.x[0], (size_t)remaining);
        state.x[0] ^= pad64((size_t)remaining);
    }
    ciphertext += remaining;

    finalize(&state, key, ciphertext);
    return 0;
}

__attribute__((noinline)) int ascon_aead128_decrypt(
    unsigned char *plaintext, unsigned long long *plaintext_len,
    const unsigned char *ciphertext, unsigned long long ciphertext_len,
    const unsigned char *associated_data,
    unsigned long long associated_data_len, const unsigned char *nonce,
    const unsigned char *key)
{
    ascon_state_t state;
    unsigned char expected_tag[ASCON_AEAD128_TAG_SIZE];
    const unsigned char *tag;
    unsigned long long remaining;
    uint32_t difference = 0;

    if (ciphertext_len < ASCON_AEAD128_TAG_SIZE) {
        *plaintext_len = 0;
        return -1;
    }

    *plaintext_len = ciphertext_len - ASCON_AEAD128_TAG_SIZE;
    remaining = *plaintext_len;
    tag = ciphertext + remaining;
    initialize(&state, nonce, key);
    absorb_associated_data(&state, associated_data, associated_data_len);

    while (remaining >= ASCON_AEAD128_RATE) {
        const uint64_t ciphertext0 = load64_le(ciphertext, 8U);
        const uint64_t ciphertext1 = load64_le(ciphertext + 8U, 8U);

        store64_le(plaintext, state.x[0] ^ ciphertext0, 8U);
        store64_le(plaintext + 8U, state.x[1] ^ ciphertext1, 8U);
        state.x[0] = ciphertext0;
        state.x[1] = ciphertext1;
        ascon_p8(&state);
        plaintext += ASCON_AEAD128_RATE;
        ciphertext += ASCON_AEAD128_RATE;
        remaining -= ASCON_AEAD128_RATE;
    }

    if (remaining >= 8U) {
        const size_t upper_len = (size_t)remaining - 8U;
        const uint64_t ciphertext0 = load64_le(ciphertext, 8U);
        const uint64_t ciphertext1 = load64_le(ciphertext + 8U, upper_len);

        store64_le(plaintext, state.x[0] ^ ciphertext0, 8U);
        store64_le(plaintext + 8U, state.x[1] ^ ciphertext1, upper_len);
        state.x[0] = ciphertext0;
        state.x[1] = clear64_le(state.x[1], upper_len) ^ ciphertext1;
        state.x[1] ^= pad64(upper_len);
    } else {
        const uint64_t ciphertext0 =
            load64_le(ciphertext, (size_t)remaining);

        store64_le(plaintext, state.x[0] ^ ciphertext0, (size_t)remaining);
        state.x[0] = clear64_le(state.x[0], (size_t)remaining) ^ ciphertext0;
        state.x[0] ^= pad64((size_t)remaining);
    }

    finalize(&state, key, expected_tag);
    for (size_t i = 0; i < ASCON_AEAD128_TAG_SIZE; ++i) {
        difference |= (uint32_t)(expected_tag[i] ^ tag[i]);
    }

    return (int)(((difference - 1U) >> 8) & 1U) - 1;
}
