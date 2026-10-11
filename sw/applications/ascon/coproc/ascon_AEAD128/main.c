#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "ascon_coproc.h"

/* Change these two values to benchmark different AD/PT lengths. */
#define AD_LENGTH      10000U
#define MESSAGE_LENGTH 10000U

#define WORDS_FOR_BYTES(length) (((length) + 3U) / 4U)
#define STORAGE_WORDS(length) \
    ((WORDS_FOR_BYTES(length) > 0U) ? WORDS_FOR_BYTES(length) : 1U)
#define TEXT_WORDS   WORDS_FOR_BYTES(MESSAGE_LENGTH)
#define TAG_WORDS    4U
#define OUTPUT_WORDS (TEXT_WORDS + TAG_WORDS)

/*
 * X-HEEP is little-endian. Filling these word arrays byte-by-byte before the
 * timed region makes bytes 00,01,02,03 appear to PUSH as 0x03020100.
 */
static uint32_t associated_data[STORAGE_WORDS(AD_LENGTH)];
static uint32_t plaintext[STORAGE_WORDS(MESSAGE_LENGTH)];
static uint32_t ascon_output[OUTPUT_WORDS];
static uint32_t recovered_plaintext[STORAGE_WORDS(MESSAGE_LENGTH)];

int main(void)
{
    const uint32_t adlen = AD_LENGTH;
    const uint32_t mlen = MESSAGE_LENGTH;
    uint8_t *const ad_bytes = (uint8_t *)associated_data;
    uint8_t *const plaintext_bytes = (uint8_t *)plaintext;
    uint32_t enc_cycles;
    uint32_t dec_cycles;
    uint32_t error_flag;

    /* Input generation is intentionally outside the measured region. */
    for (uint32_t i = 0; i < adlen; ++i) {
        ad_bytes[i] = (uint8_t)i;
    }
    for (uint32_t i = 0; i < mlen; ++i) {
        plaintext_bytes[i] = (uint8_t)i;
    }

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    /* Clear, configure and start the Ascon coprocessor. */
    ascon_coproc_clear();
    ascon_coproc_config(ASCON_AEAD128, ENC, UINT32_C(0));

    /* Key: bytes 00..0f. */
    ascon_coproc_push(UINT32_C(0x03020100), UINT32_C(0x07060504),
                     UINT8_C(0xf), UINT8_C(0xf), false, false);
    ascon_coproc_push(UINT32_C(0x0b0a0908), UINT32_C(0x0f0e0d0c),
                     UINT8_C(0xf), UINT8_C(0xf), false, true);

    /* Nonce: bytes 00..0f. */
    ascon_coproc_push(UINT32_C(0x03020100), UINT32_C(0x07060504),
                     UINT8_C(0xf), UINT8_C(0xf), false, false);
    ascon_coproc_push(UINT32_C(0x0b0a0908), UINT32_C(0x0f0e0d0c),
                     UINT8_C(0xf), UINT8_C(0xf), false, true);

    /*
     * Associated-data fast path. Unlike TEXT_LOAD, the current RTL does not
     * synthesize an empty padding block after a full final AD block. Therefore
     * every complete AD block is sent without last, and a zero-byte final
     * block below terminates lengths that are exact multiples of 16 bytes.
     */
    uint32_t ad_offset = 0U;
    for (; ad_offset + 16U <= adlen; ad_offset += 16U) {
        const uint32_t word = ad_offset >> 2;

        ascon_coproc_push(associated_data[word], associated_data[word + 1U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);
        ascon_coproc_push(associated_data[word + 2U],
                         associated_data[word + 3U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
    }

    /* Final partial AD block, or the required empty padding block. */
    const uint32_t ad_remaining = adlen - ad_offset;
    const uint32_t ad_word = ad_offset >> 2;

    if (ad_remaining == 0U) {
        ascon_coproc_push(UINT32_C(0), UINT32_C(0), UINT8_C(0), UINT8_C(0),
                         true, false);
    } else if (ad_remaining <= 4U) {
        const uint8_t keep0 = (uint8_t)((UINT32_C(1) << ad_remaining) - 1U);
        ascon_coproc_push(associated_data[ad_word], UINT32_C(0), keep0,
                         UINT8_C(0), true, false);
    } else if (ad_remaining <= 8U) {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) << (ad_remaining - 4U)) - 1U);
        ascon_coproc_push(associated_data[ad_word],
                         associated_data[ad_word + 1U], UINT8_C(0xf), keep1,
                         false, true);
    } else if (ad_remaining <= 12U) {
        const uint8_t keep0 =
            (uint8_t)((UINT32_C(1) << (ad_remaining - 8U)) - 1U);
        ascon_coproc_push(associated_data[ad_word],
                         associated_data[ad_word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
        ascon_coproc_push(associated_data[ad_word + 2U], UINT32_C(0), keep0,
                         UINT8_C(0), true, false);
    } else {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) << (ad_remaining - 12U)) - 1U);
        ascon_coproc_push(associated_data[ad_word],
                         associated_data[ad_word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
        ascon_coproc_push(associated_data[ad_word + 2U],
                         associated_data[ad_word + 3U], UINT8_C(0xf), keep1,
                         false, true);
    }

    /*
     * Plaintext fast path. Each complete 16-byte block produces four
     * 32-bit ciphertext words, which are popped before the next block.
     */
    uint32_t output_index = 0U;
    uint32_t text_offset = 0U;
    for (; text_offset + 16U < mlen; text_offset += 16U) {
        const uint32_t word = text_offset >> 2;

        ascon_coproc_push(plaintext[word], plaintext[word + 1U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);
        ascon_coproc_push(plaintext[word + 2U], plaintext[word + 3U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);

        ascon_output[output_index++] = ascon_coproc_pop();
        ascon_output[output_index++] = ascon_coproc_pop();
        ascon_output[output_index++] = ascon_coproc_pop();
        ascon_output[output_index++] = ascon_coproc_pop();
    }

    /* Final plaintext block, including the zero-length empty block. */
    const uint32_t text_remaining = mlen - text_offset;
    const uint32_t text_word = text_offset >> 2;

    if (text_remaining == 0U) {
        ascon_coproc_push(UINT32_C(0), UINT32_C(0), UINT8_C(0), UINT8_C(0),
                         true, false);
    } else if (text_remaining == 16U) {
        ascon_coproc_push(plaintext[text_word], plaintext[text_word + 1U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);
        ascon_coproc_push(plaintext[text_word + 2U],
                         plaintext[text_word + 3U], UINT8_C(0xf),
                         UINT8_C(0xf), false, true);
    } else if (text_remaining <= 4U) {
        const uint8_t keep0 =
            (uint8_t)((UINT32_C(1) << text_remaining) - 1U);
        ascon_coproc_push(plaintext[text_word], UINT32_C(0), keep0,
                         UINT8_C(0), true, false);
    } else if (text_remaining <= 8U) {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) << (text_remaining - 4U)) - 1U);
        ascon_coproc_push(plaintext[text_word], plaintext[text_word + 1U],
                         UINT8_C(0xf), keep1, false, true);
    } else if (text_remaining <= 12U) {
        const uint8_t keep0 =
            (uint8_t)((UINT32_C(1) << (text_remaining - 8U)) - 1U);
        ascon_coproc_push(plaintext[text_word], plaintext[text_word + 1U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);
        ascon_coproc_push(plaintext[text_word + 2U], UINT32_C(0), keep0,
                         UINT8_C(0), true, false);
    } else {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) << (text_remaining - 12U)) - 1U);
        ascon_coproc_push(plaintext[text_word], plaintext[text_word + 1U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);
        ascon_coproc_push(plaintext[text_word + 2U],
                         plaintext[text_word + 3U], UINT8_C(0xf), keep1,
                         false, true);
    }

    /* Pop the final full/partial ciphertext block. */
    if (text_remaining > 0U) {
        ascon_output[output_index++] = ascon_coproc_pop();
    }
    if (text_remaining > 4U) {
        ascon_output[output_index++] = ascon_coproc_pop();
    }
    if (text_remaining > 8U) {
        ascon_output[output_index++] = ascon_coproc_pop();
    }
    if (text_remaining > 12U) {
        ascon_output[output_index++] = ascon_coproc_pop();
    }

    /* Tag: always 16 bytes. */
    ascon_output[output_index++] = ascon_coproc_pop();
    ascon_output[output_index++] = ascon_coproc_pop();
    ascon_output[output_index++] = ascon_coproc_pop();
    ascon_output[output_index++] = ascon_coproc_pop();

    CSR_READ(CSR_REG_MCYCLE, &enc_cycles);

    /*
     * Decryption is measured independently.  Reconfigure the coprocessor and
     * feed it the ciphertext and tag that were produced above; no data copy or
     * software Ascon operation is inserted in the measured region.
     */
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));
    ascon_coproc_clear();
    ascon_coproc_config(ASCON_AEAD128, DEC, UINT32_C(0));

    /* Key: bytes 00..0f. */
    ascon_coproc_push(UINT32_C(0x03020100), UINT32_C(0x07060504),
                     UINT8_C(0xf), UINT8_C(0xf), false, false);
    ascon_coproc_push(UINT32_C(0x0b0a0908), UINT32_C(0x0f0e0d0c),
                     UINT8_C(0xf), UINT8_C(0xf), false, true);

    /* Nonce: bytes 00..0f. */
    ascon_coproc_push(UINT32_C(0x03020100), UINT32_C(0x07060504),
                     UINT8_C(0xf), UINT8_C(0xf), false, false);
    ascon_coproc_push(UINT32_C(0x0b0a0908), UINT32_C(0x0f0e0d0c),
                     UINT8_C(0xf), UINT8_C(0xf), false, true);

    /* Send the same associated data again for authentication. */
    uint32_t dec_ad_offset = 0U;
    for (; dec_ad_offset + 16U <= adlen; dec_ad_offset += 16U) {
        const uint32_t word = dec_ad_offset >> 2;

        ascon_coproc_push(associated_data[word], associated_data[word + 1U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);
        ascon_coproc_push(associated_data[word + 2U],
                         associated_data[word + 3U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
    }

    const uint32_t dec_ad_remaining = adlen - dec_ad_offset;
    const uint32_t dec_ad_word = dec_ad_offset >> 2;

    if (dec_ad_remaining == 0U) {
        ascon_coproc_push(UINT32_C(0), UINT32_C(0), UINT8_C(0), UINT8_C(0),
                         true, false);
    } else if (dec_ad_remaining <= 4U) {
        const uint8_t keep0 =
            (uint8_t)((UINT32_C(1) << dec_ad_remaining) - 1U);
        ascon_coproc_push(associated_data[dec_ad_word], UINT32_C(0), keep0,
                         UINT8_C(0), true, false);
    } else if (dec_ad_remaining <= 8U) {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) << (dec_ad_remaining - 4U)) - 1U);
        ascon_coproc_push(associated_data[dec_ad_word],
                         associated_data[dec_ad_word + 1U], UINT8_C(0xf),
                         keep1, false, true);
    } else if (dec_ad_remaining <= 12U) {
        const uint8_t keep0 =
            (uint8_t)((UINT32_C(1) << (dec_ad_remaining - 8U)) - 1U);
        ascon_coproc_push(associated_data[dec_ad_word],
                         associated_data[dec_ad_word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
        ascon_coproc_push(associated_data[dec_ad_word + 2U], UINT32_C(0),
                         keep0, UINT8_C(0), true, false);
    } else {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) << (dec_ad_remaining - 12U)) - 1U);
        ascon_coproc_push(associated_data[dec_ad_word],
                         associated_data[dec_ad_word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
        ascon_coproc_push(associated_data[dec_ad_word + 2U],
                         associated_data[dec_ad_word + 3U], UINT8_C(0xf),
                         keep1, false, true);
    }

    /* Push ciphertext and pop the recovered plaintext block-by-block. */
    uint32_t recovered_index = 0U;
    uint32_t ciphertext_offset = 0U;
    for (; ciphertext_offset + 16U < mlen; ciphertext_offset += 16U) {
        const uint32_t word = ciphertext_offset >> 2;

        ascon_coproc_push(ascon_output[word], ascon_output[word + 1U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);
        ascon_coproc_push(ascon_output[word + 2U], ascon_output[word + 3U],
                         UINT8_C(0xf), UINT8_C(0xf), false, false);

        recovered_plaintext[recovered_index++] = ascon_coproc_pop();
        recovered_plaintext[recovered_index++] = ascon_coproc_pop();
        recovered_plaintext[recovered_index++] = ascon_coproc_pop();
        recovered_plaintext[recovered_index++] = ascon_coproc_pop();
    }

    const uint32_t ciphertext_remaining = mlen - ciphertext_offset;
    const uint32_t ciphertext_word = ciphertext_offset >> 2;

    if (ciphertext_remaining == 0U) {
        ascon_coproc_push(UINT32_C(0), UINT32_C(0), UINT8_C(0), UINT8_C(0),
                         true, false);
    } else if (ciphertext_remaining == 16U) {
        ascon_coproc_push(ascon_output[ciphertext_word],
                         ascon_output[ciphertext_word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
        ascon_coproc_push(ascon_output[ciphertext_word + 2U],
                         ascon_output[ciphertext_word + 3U], UINT8_C(0xf),
                         UINT8_C(0xf), false, true);
    } else if (ciphertext_remaining <= 4U) {
        const uint8_t keep0 =
            (uint8_t)((UINT32_C(1) << ciphertext_remaining) - 1U);
        ascon_coproc_push(ascon_output[ciphertext_word], UINT32_C(0), keep0,
                         UINT8_C(0), true, false);
    } else if (ciphertext_remaining <= 8U) {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) << (ciphertext_remaining - 4U)) - 1U);
        ascon_coproc_push(ascon_output[ciphertext_word],
                         ascon_output[ciphertext_word + 1U], UINT8_C(0xf),
                         keep1, false, true);
    } else if (ciphertext_remaining <= 12U) {
        const uint8_t keep0 =
            (uint8_t)((UINT32_C(1) << (ciphertext_remaining - 8U)) - 1U);
        ascon_coproc_push(ascon_output[ciphertext_word],
                         ascon_output[ciphertext_word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
        ascon_coproc_push(ascon_output[ciphertext_word + 2U], UINT32_C(0),
                         keep0, UINT8_C(0), true, false);
    } else {
        const uint8_t keep1 =
            (uint8_t)((UINT32_C(1) << (ciphertext_remaining - 12U)) - 1U);
        ascon_coproc_push(ascon_output[ciphertext_word],
                         ascon_output[ciphertext_word + 1U], UINT8_C(0xf),
                         UINT8_C(0xf), false, false);
        ascon_coproc_push(ascon_output[ciphertext_word + 2U],
                         ascon_output[ciphertext_word + 3U], UINT8_C(0xf),
                         keep1, false, true);
    }

    if (ciphertext_remaining > 0U) {
        recovered_plaintext[recovered_index++] = ascon_coproc_pop();
    }
    if (ciphertext_remaining > 4U) {
        recovered_plaintext[recovered_index++] = ascon_coproc_pop();
    }
    if (ciphertext_remaining > 8U) {
        recovered_plaintext[recovered_index++] = ascon_coproc_pop();
    }
    if (ciphertext_remaining > 12U) {
        recovered_plaintext[recovered_index++] = ascon_coproc_pop();
    }

    /* Authentication tag follows the ciphertext and is not part of mlen. */
    ascon_coproc_push(ascon_output[TEXT_WORDS],
                     ascon_output[TEXT_WORDS + 1U], UINT8_C(0xf),
                     UINT8_C(0xf), false, false);
    ascon_coproc_push(ascon_output[TEXT_WORDS + 2U],
                     ascon_output[TEXT_WORDS + 3U], UINT8_C(0xf),
                     UINT8_C(0xf), false, true);

    error_flag = ascon_coproc_status();
    CSR_READ(CSR_REG_MCYCLE, &dec_cycles);

    printf("Ascon AEAD128 encryption cycles (AD=%u, PT=%u): %u\n",
           (unsigned int)adlen, (unsigned int)mlen,
           (unsigned int)enc_cycles);
    printf("Ascon AEAD128 decryption cycles (AD=%u, CT=%u): %u\n",
           (unsigned int)adlen, (unsigned int)mlen,
           (unsigned int)dec_cycles);

    int test_passed = 1;

    if (error_flag != 0U) {
        printf("Decryption authentication failed (status = 0x%08x)\n",
               (unsigned int)error_flag);
        test_passed = 0;
    }

    const uint8_t *const recovered_bytes =
        (const uint8_t *)recovered_plaintext;
    for (uint32_t i = 0; i < mlen; ++i) {
        if (recovered_bytes[i] != plaintext_bytes[i]) {
            printf("Decryption failed at byte %u: expected 0x%02x, "
                   "got 0x%02x\n",
                   (unsigned int)i, (unsigned int)plaintext_bytes[i],
                   (unsigned int)recovered_bytes[i]);
            test_passed = 0;
            break;
        }
    }

    printf(test_passed ? "encryption/decryption test passed!\n"
                       : "encryption/decryption test failed.\n");
    return test_passed ? 0 : 1;
}
