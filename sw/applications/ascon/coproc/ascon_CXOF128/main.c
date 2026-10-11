#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "ascon_coproc.h"

/* Change these values to benchmark different Z, message and output lengths. */
#define CUSTOMIZATION_LENGTH 256U
#define MESSAGE_LENGTH       1536U
#define OUTPUT_LENGTH        1536U

#define ASCON_CXOF128_MAX_CUSTOMIZATION_LENGTH 256U
#define WORDS_FOR_BYTES(n) (((n) + 3U) / 4U)
#define STORAGE_WORDS(n) \
    ((WORDS_FOR_BYTES(n) > 0U) ? WORDS_FOR_BYTES(n) : 1U)
#define OUTPUT_WORDS WORDS_FOR_BYTES(OUTPUT_LENGTH)

// _Static_assert(CUSTOMIZATION_LENGTH <=
//                    ASCON_CXOF128_MAX_CUSTOMIZATION_LENGTH,
//                "Ascon-CXOF128 customization string exceeds 256 bytes");

/* Large benchmark buffers stay in .bss instead of the X-HEEP stack. */
static uint32_t customization[STORAGE_WORDS(CUSTOMIZATION_LENGTH)];
static uint32_t message[STORAGE_WORDS(MESSAGE_LENGTH)];
static uint32_t cxof_output[STORAGE_WORDS(OUTPUT_LENGTH)];

int main(void)
{
    const uint32_t zlen = CUSTOMIZATION_LENGTH;
    const uint32_t mlen = MESSAGE_LENGTH;
    const uint32_t output_len = OUTPUT_LENGTH;
    uint8_t *const customization_bytes = (uint8_t *)customization;
    uint8_t *const message_bytes = (uint8_t *)message;
    uint32_t cycles;

    /* Generate the 00,01,02... test vectors outside the measured region. */
    for (uint32_t i = 0U; i < zlen; ++i) {
        customization_bytes[i] = (uint8_t)i;
    }
    for (uint32_t i = 0U; i < mlen; ++i) {
        message_bytes[i] = (uint8_t)i;
    }

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    ascon_coproc_clear();
    ascon_coproc_config(ASCON_CXOF128, false, output_len);

    /*
     * Customization starts with a 64-bit little-endian encoding of the Z
     * length in bits, followed by Z itself and its padding block.
     */
    const uint64_t customization_bits = (uint64_t)zlen * UINT64_C(8);
    ascon_coproc_push((uint32_t)customization_bits,
                     (uint32_t)(customization_bits >> 32), UINT8_C(0xf),
                     UINT8_C(0xf), false, false);

    uint32_t customization_offset = 0U;
    for (; customization_offset + 8U <= zlen;
         customization_offset += 8U) {
        const uint32_t word = customization_offset >> 2;

        ascon_coproc_push(customization[word], customization[word + 1U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);
    }

    const uint32_t customization_remaining = zlen - customization_offset;
    const uint32_t customization_word = customization_offset >> 2;

    if (customization_remaining == 0U) {
        ascon_coproc_push(UINT32_C(0), UINT32_C(0), UINT8_C(0), UINT8_C(0),
                         true, false);
    } else if (customization_remaining <= 4U) {
        const uint8_t keep0 =
            (uint8_t)((UINT32_C(1) << customization_remaining) - 1U);
        ascon_coproc_push(customization[customization_word], UINT32_C(0),
                         keep0, UINT8_C(0), true, false);
    } else {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) <<
                       (customization_remaining - 4U)) - 1U);
        ascon_coproc_push(customization[customization_word],
                         customization[customization_word + 1U],
                         UINT8_C(0xf), keep1, false, true);
    }

    /* Absorb every complete 8-byte message rate block. */
    uint32_t message_offset = 0U;
    for (; message_offset + 8U <= mlen; message_offset += 8U) {
        const uint32_t word = message_offset >> 2;

        ascon_coproc_push(message[word], message[word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
    }

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
     * Pop both 32-bit halves of each 64-bit CXOF rate block before storing
     * them, so the second POP is not delayed by the store and loop overhead.
     */
    uint32_t i = 0U;
    for (; i + 1U < OUTPUT_WORDS; i += 2U) {
        uint32_t word0 = ascon_coproc_pop();
        uint32_t word1 = ascon_coproc_pop();

        cxof_output[i]      = word0;
        cxof_output[i + 1U] = word1;
    }

    /* Handle a final partial 64-bit block containing one 32-bit word. */
    if (i < OUTPUT_WORDS) {
        cxof_output[i] = ascon_coproc_pop();
    }

    CSR_READ(CSR_REG_MCYCLE, &cycles);

    /* Keep the output observable without including checking in cycle count. */
    uint32_t output_xor = 0U;
    for (uint32_t i = 0U; i < OUTPUT_WORDS; ++i) {
        output_xor ^= cxof_output[i];
    }

    printf("Ascon-CXOF128 coprocessor cycles "
           "(Z=%u, message=%u, output=%u): %u\n",
           (unsigned int)zlen, (unsigned int)mlen,
           (unsigned int)output_len, (unsigned int)cycles);
    printf("benchmark finished (output xor = 0x%08x)\n",
           (unsigned int)output_xor);

    return 0;
}
