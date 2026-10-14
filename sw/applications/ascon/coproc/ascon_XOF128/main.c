#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "ascon_coproc.h"

/* Change these two values to benchmark different input/output lengths. */
#ifndef MESSAGE_LENGTH
#define MESSAGE_LENGTH 1536U
#endif
#ifndef OUTPUT_LENGTH
#define OUTPUT_LENGTH  1536U
#endif

#define WORDS_FOR_BYTES(n) (((n) + 3U) / 4U)
#define STORAGE_WORDS(n) \
    ((WORDS_FOR_BYTES(n) > 0U) ? WORDS_FOR_BYTES(n) : 1U)
#define OUTPUT_WORDS WORDS_FOR_BYTES(OUTPUT_LENGTH)

/*
 * Keep large benchmark buffers in .bss instead of the small X-HEEP stack.
 * Filling message byte-by-byte gives the coprocessor the sequence 00,01,02...
 * in its expected little-endian word layout.
 */
static uint32_t message[STORAGE_WORDS(MESSAGE_LENGTH)];
static uint32_t xof_output[STORAGE_WORDS(OUTPUT_LENGTH)];

int main(void)
{
    const uint32_t mlen = MESSAGE_LENGTH;
    const uint32_t output_len = OUTPUT_LENGTH;
    uint8_t *const message_bytes = (uint8_t *)message;
    uint32_t cycles;

    /* Test-vector generation is outside the measured region. */
    for (uint32_t i = 0U; i < mlen; ++i) {
        message_bytes[i] = (uint8_t)i;
    }

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    ascon_coproc_clear();
    ascon_coproc_config(ASCON_XOF128, false, output_len);

    /* Absorb every complete 8-byte XOF128 rate block. */
    uint32_t message_offset = 0U;
    for (; message_offset + 8U <= mlen; message_offset += 8U) {
        const uint32_t word = message_offset >> 2;

        ascon_coproc_push(message[word], message[word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
    }

    /*
     * Absorb the last 0--7 bytes. Exact multiples of the 8-byte rate need an
     * empty final block so the hardware inserts padding in a new rate block.
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

    /*
     * Pop both 32-bit halves of each 64-bit XOF rate block before storing
     * them, so the second POP is not delayed by the store and loop overhead.
     */
    uint32_t i = 0U;
    for (; i + 1U < OUTPUT_WORDS; i += 2U) {
        uint32_t word0 = ascon_coproc_pop();
        uint32_t word1 = ascon_coproc_pop();

        xof_output[i]      = word0;
        xof_output[i + 1U] = word1;
    }

    /* Handle a final partial 64-bit block containing one 32-bit word. */
    if (i < OUTPUT_WORDS) {
        xof_output[i] = ascon_coproc_pop();
    }

    CSR_READ(CSR_REG_MCYCLE, &cycles);

    /* Keep the generated output observable without adding to cycle count. */
    uint32_t output_xor = 0U;
    for (uint32_t i = 0U; i < OUTPUT_WORDS; ++i) {
        output_xor ^= xof_output[i];
    }

    printf("Ascon-XOF128 coprocessor cycles (message=%u, output=%u): %u\n",
           (unsigned int)mlen, (unsigned int)output_len,
           (unsigned int)cycles);
    printf("benchmark finished (output xor = 0x%08x)\n",
           (unsigned int)output_xor);

    return 0;
}
