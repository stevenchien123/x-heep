#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "ascon_coproc.h"

/* Change this value to benchmark a different message length. */
#ifndef MESSAGE_LENGTH
#define MESSAGE_LENGTH 16U
#endif

#define ASCON_HASH256_SIZE 32U
#define HASH_OUTPUT_WORDS  (ASCON_HASH256_SIZE / 4U)
#define WORDS_FOR_BYTES(n) (((n) + 3U) / 4U)
#define STORAGE_WORDS(n) \
    ((WORDS_FOR_BYTES(n) > 0U) ? WORDS_FOR_BYTES(n) : 1U)

/*
 * Keep benchmark data in .bss instead of the small X-HEEP stack. Filling the
 * word array byte-by-byte produces the little-endian PUSH words expected by
 * the coprocessor: bytes 00,01,02,03 become 0x03020100.
 */
static uint32_t message[STORAGE_WORDS(MESSAGE_LENGTH)];
static uint32_t hash_output[HASH_OUTPUT_WORDS];

int main(void)
{
    const uint32_t mlen = MESSAGE_LENGTH;
    uint8_t *const message_bytes = (uint8_t *)message;
    uint32_t cycles;

    /* Test-vector generation is outside the measured region. */
    for (uint32_t i = 0U; i < mlen; ++i) {
        message_bytes[i] = (uint8_t)i;
    }

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    ascon_coproc_clear();
    ascon_coproc_config(ASCON_HASH256, false, ASCON_HASH256_SIZE);

    /* Absorb every complete 8-byte Hash256 rate block. */
    uint32_t message_offset = 0U;
    for (; message_offset + 8U <= mlen; message_offset += 8U) {
        const uint32_t word = message_offset >> 2;

        ascon_coproc_push(message[word], message[word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
    }

    /*
     * Send the final partial block. An exact multiple of the 8-byte rate
     * requires an empty final block so that the hardware absorbs the 0x01
     * padding byte in a new block.
     */
    const uint32_t message_remaining = mlen - message_offset;
    const uint32_t message_word = message_offset >> 2;

    if (message_remaining == 0U) {
        ascon_coproc_push(UINT32_C(0), UINT32_C(0), UINT8_C(0), UINT8_C(0),
                         true, false);
    } else if (message_remaining <= 4U) {
        const uint8_t keep0 =
            (uint8_t)((UINT32_C(1) << message_remaining) - 1U);
        ascon_coproc_push(message[message_word], UINT32_C(0), keep0,
                         UINT8_C(0), true, false);
    } else {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) << (message_remaining - 4U)) - 1U);
        ascon_coproc_push(message[message_word], message[message_word + 1U],
                         UINT8_C(0xf), keep1, false, true);
    }

    /* Hash256 always returns a 32-byte digest. */
    hash_output[0] = ascon_coproc_pop();
    hash_output[1] = ascon_coproc_pop();
    hash_output[2] = ascon_coproc_pop();
    hash_output[3] = ascon_coproc_pop();
    hash_output[4] = ascon_coproc_pop();
    hash_output[5] = ascon_coproc_pop();
    hash_output[6] = ascon_coproc_pop();
    hash_output[7] = ascon_coproc_pop();

    CSR_READ(CSR_REG_MCYCLE, &cycles);

    /* Keep the digest observable without including checking in cycle count. */
    uint32_t output_xor = 0U;
    for (uint32_t i = 0U; i < HASH_OUTPUT_WORDS; ++i) {
        output_xor ^= hash_output[i];
    }

    printf("Ascon-Hash256 coprocessor cycles (message=%u): %u\n",
           (unsigned int)mlen, (unsigned int)cycles);
    printf("benchmark finished (output xor = 0x%08x)\n",
           (unsigned int)output_xor);

    return 0;
}
