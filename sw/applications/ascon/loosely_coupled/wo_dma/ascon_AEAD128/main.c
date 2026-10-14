#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "../ascon_accelerator.h"

/* Change these two values to benchmark different AD/PT lengths. */
#ifndef AD_LENGTH
#define AD_LENGTH 16U
#endif
#ifndef MESSAGE_LENGTH
#define MESSAGE_LENGTH 0U
#endif

#define WORDS_FOR_BYTES(length) (((length) + 3U) / 4U)
#define STORAGE_WORDS(length) \
    ((WORDS_FOR_BYTES(length) > 0U) ? WORDS_FOR_BYTES(length) : 1U)
#define TEXT_WORDS   WORDS_FOR_BYTES(MESSAGE_LENGTH)
#define TAG_WORDS    4U
#define OUTPUT_WORDS (TEXT_WORDS + TAG_WORDS)

/* These arrays reside in SRAM and are accessed by the CPU. */
static uint32_t key[4] = {
    UINT32_C(0x03020100), UINT32_C(0x07060504),
    UINT32_C(0x0b0a0908), UINT32_C(0x0f0e0d0c),
};
static uint32_t nonce[4] = {
    UINT32_C(0x03020100), UINT32_C(0x07060504),
    UINT32_C(0x0b0a0908), UINT32_C(0x0f0e0d0c),
};
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
    const ascon_accel_t accelerator =
        ascon_accel_init(ASCON_ACCELERATOR_START_ADDRESS);
    uint32_t enc_cycles;
    uint32_t dec_cycles;

    /* Test-vector generation stays outside the measured region. */
    for (uint32_t i = 0U; i < adlen; ++i) {
        ad_bytes[i] = (uint8_t)i;
    }
    for (uint32_t i = 0U; i < mlen; ++i) {
        plaintext_bytes[i] = (uint8_t)i;
    }

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    ascon_accel_start(&accelerator, ASCON_ACCEL_AEAD128, false,
                      UINT32_C(0), adlen, mlen, UINT32_C(0));
    ascon_accel_push_words(&accelerator, key, 16U);
    ascon_accel_push_words(&accelerator, nonce, 16U);
    ascon_accel_push_words(&accelerator, associated_data, adlen);

    /* AEAD input/output is transferred one 16-byte rate block at a time. */
    uint32_t text_offset = 0U;
    uint32_t output_index = 0U;
    while (text_offset < mlen) {
        uint32_t block_bytes = mlen - text_offset;
        if (block_bytes > 16U) block_bytes = 16U;

        const uint32_t block_words = WORDS_FOR_BYTES(block_bytes);
        const uint32_t input_word = text_offset >> 2;

        for (uint32_t word = 0U; word < block_words; ++word) {
            ascon_accel_push(&accelerator, plaintext[input_word + word]);
        }
        for (uint32_t word = 0U; word < block_words; ++word) {
            ascon_output[output_index++] = ascon_accel_pop(&accelerator);
        }
        text_offset += block_bytes;
    }

    /* The wrapper handles a zero-length text terminator; CPU only pops tag. */
    for (uint32_t word = 0U; word < TAG_WORDS; ++word) {
        ascon_output[output_index++] = ascon_accel_pop(&accelerator);
    }

    (void)ascon_accel_wait_done(&accelerator);
    CSR_READ(CSR_REG_MCYCLE, &enc_cycles);

    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    ascon_accel_start(&accelerator, ASCON_ACCEL_AEAD128, true,
                      UINT32_C(0), adlen, mlen, UINT32_C(0));
    ascon_accel_push_words(&accelerator, key, 16U);
    ascon_accel_push_words(&accelerator, nonce, 16U);
    ascon_accel_push_words(&accelerator, associated_data, adlen);

    uint32_t ciphertext_offset = 0U;
    uint32_t recovered_index = 0U;
    while (ciphertext_offset < mlen) {
        uint32_t block_bytes = mlen - ciphertext_offset;
        if (block_bytes > 16U) block_bytes = 16U;

        const uint32_t block_words = WORDS_FOR_BYTES(block_bytes);
        const uint32_t input_word = ciphertext_offset >> 2;

        for (uint32_t word = 0U; word < block_words; ++word) {
            ascon_accel_push(&accelerator, ascon_output[input_word + word]);
        }
        for (uint32_t word = 0U; word < block_words; ++word) {
            recovered_plaintext[recovered_index++] =
                ascon_accel_pop(&accelerator);
        }
        ciphertext_offset += block_bytes;
    }

    /* Authentication tag is an actual 16-byte input phase. */
    for (uint32_t word = 0U; word < TAG_WORDS; ++word) {
        ascon_accel_push(&accelerator, ascon_output[TEXT_WORDS + word]);
    }

    const uint32_t dec_status = ascon_accel_wait_done(&accelerator);
    CSR_READ(CSR_REG_MCYCLE, &dec_cycles);

    uint32_t output_xor = 0U;
    for (uint32_t word = 0U; word < OUTPUT_WORDS; ++word) {
        output_xor ^= ascon_output[word];
    }

    printf("Ascon AEAD128 accelerator encryption cycles (AD=%u, PT=%u): %u\n",
           (unsigned int)adlen, (unsigned int)mlen,
           (unsigned int)enc_cycles);
    printf("Ascon AEAD128 accelerator decryption cycles (AD=%u, CT=%u): %u\n",
           (unsigned int)adlen, (unsigned int)mlen,
           (unsigned int)dec_cycles);
    printf("benchmark finished (output xor = 0x%08x)\n",
           (unsigned int)output_xor);

    int test_passed = 1;
    if ((dec_status & ASCON_ACCEL_STATUS_ERROR) != 0U) {
        printf("Decryption authentication failed (status = 0x%08x)\n",
               (unsigned int)dec_status);
        test_passed = 0;
    }

    const uint8_t *const recovered_bytes =
        (const uint8_t *)recovered_plaintext;
    for (uint32_t i = 0U; i < mlen; ++i) {
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
