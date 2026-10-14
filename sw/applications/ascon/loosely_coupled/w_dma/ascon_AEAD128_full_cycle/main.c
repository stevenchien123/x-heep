#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "../ascon_accelerator_dma.h"

#ifndef AD_LENGTH
#define AD_LENGTH 0U
#endif
#ifndef MESSAGE_LENGTH
#define MESSAGE_LENGTH 1536U
#endif

#define WORDS_FOR_BYTES(n) (((n) + 3U) / 4U)
#define STORAGE_WORDS(n) ((WORDS_FOR_BYTES(n) != 0U) ? WORDS_FOR_BYTES(n) : 1U)
#define AD_WORDS WORDS_FOR_BYTES(AD_LENGTH)
#define TEXT_WORDS WORDS_FOR_BYTES(MESSAGE_LENGTH)
#define TAG_WORDS 4U
#define ENC_INPUT_WORDS (8U + AD_WORDS + TEXT_WORDS)
#define DEC_INPUT_WORDS (8U + AD_WORDS + TEXT_WORDS + TAG_WORDS)
#define ENC_OUTPUT_WORDS (TEXT_WORDS + TAG_WORDS)

static uint32_t enc_input[ENC_INPUT_WORDS];
static uint32_t dec_input[DEC_INPUT_WORDS];
static uint32_t enc_output[ENC_OUTPUT_WORDS];
static uint32_t dec_output[STORAGE_WORDS(MESSAGE_LENGTH)];
static ascon_dma_job_t input_job;
static ascon_dma_job_t output_job;

static const uint32_t key_and_nonce[8] = {
    UINT32_C(0x03020100), UINT32_C(0x07060504),
    UINT32_C(0x0b0a0908), UINT32_C(0x0f0e0d0c),
    UINT32_C(0x03020100), UINT32_C(0x07060504),
    UINT32_C(0x0b0a0908), UINT32_C(0x0f0e0d0c),
};

static int dma_error(dma_config_flags_t result, const char *operation)
{
    if (result == DMA_CONFIG_OK) return 0;
    printf("DMA %s failed: 0x%04x\n", operation, (unsigned int)result);
    return 1;
}

static int prepare_and_launch(const uint32_t *input, uint32_t input_words,
                              uint32_t *output, uint32_t output_words)
{
    dma_config_flags_t result;

    result = ascon_dma_prepare_input(&input_job, input, input_words);
    if (dma_error(result, "input setup")) return 1;
    result = ascon_dma_prepare_output(
        &output_job, output, output_words, DMA_TRANS_END_POLLING);
    if (dma_error(result, "output setup")) return 1;

    /* Launch while accelerator triggers are low. Both channels wait until
       CONTROL.START makes the corresponding stream phase active. */
    result = ascon_dma_launch(&output_job);
    if (dma_error(result, "output launch")) return 1;
    result = ascon_dma_launch(&input_job);
    return dma_error(result, "input launch");
}

int main(void)
{
    const uint32_t adlen = AD_LENGTH;
    const uint32_t mlen = MESSAGE_LENGTH;
    const ascon_accel_t accelerator =
        ascon_accel_init(ASCON_ACCELERATOR_START_ADDRESS);
    uint8_t *const ad = (uint8_t *)&enc_input[8];
    uint8_t *const plaintext = (uint8_t *)&enc_input[8U + AD_WORDS];
    uint32_t enc_setup_cycles;
    uint32_t enc_total_cycles;
    uint32_t dec_setup_cycles;
    uint32_t dec_total_cycles;

    for (uint32_t i = 0U; i < 8U; ++i) enc_input[i] = key_and_nonce[i];
    for (uint32_t i = 0U; i < adlen; ++i) ad[i] = (uint8_t)i;
    for (uint32_t i = 0U; i < mlen; ++i) plaintext[i] = (uint8_t)i;

    dma_init(NULL);
    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));
    ascon_accel_configure(&accelerator, ASCON_ACCEL_AEAD128, false, 0U,
                          adlen, mlen, 0U);
    if (prepare_and_launch(enc_input, ENC_INPUT_WORDS, enc_output,
                           ENC_OUTPUT_WORDS))
        return 1;

    CSR_READ(CSR_REG_MCYCLE, &enc_setup_cycles);
    ascon_accel_start(&accelerator);
    const uint32_t enc_status = ascon_accel_wait_done(&accelerator);
    ascon_dma_wait(&input_job);
    ascon_dma_wait(&output_job);
    CSR_READ(CSR_REG_MCYCLE, &enc_total_cycles);

    const uint32_t enc_hw_cycles = ascon_accel_read(
        &accelerator, ASCON_ACCEL_CYCLE_COUNT_OFFSET);
    const uint32_t enc_input_wait = ascon_accel_read(
        &accelerator, ASCON_ACCEL_INPUT_WAIT_OFFSET);
    const uint32_t enc_output_wait = ascon_accel_read(
        &accelerator, ASCON_ACCEL_OUTPUT_WAIT_OFFSET);

    for (uint32_t i = 0U; i < 8U; ++i) dec_input[i] = key_and_nonce[i];
    for (uint32_t i = 0U; i < AD_WORDS; ++i)
        dec_input[8U + i] = enc_input[8U + i];
    for (uint32_t i = 0U; i < ENC_OUTPUT_WORDS; ++i)
        dec_input[8U + AD_WORDS + i] = enc_output[i];

    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));
    ascon_accel_configure(&accelerator, ASCON_ACCEL_AEAD128, true, 0U,
                          adlen, mlen, 0U);
    if (prepare_and_launch(dec_input, DEC_INPUT_WORDS, dec_output, TEXT_WORDS))
        return 1;

    CSR_READ(CSR_REG_MCYCLE, &dec_setup_cycles);
    ascon_accel_start(&accelerator);
    const uint32_t dec_status = ascon_accel_wait_done(&accelerator);
    ascon_dma_wait(&input_job);
    ascon_dma_wait(&output_job);
    CSR_READ(CSR_REG_MCYCLE, &dec_total_cycles);

    const uint32_t dec_hw_cycles = ascon_accel_read(
        &accelerator, ASCON_ACCEL_CYCLE_COUNT_OFFSET);
    const uint32_t dec_input_wait = ascon_accel_read(
        &accelerator, ASCON_ACCEL_INPUT_WAIT_OFFSET);
    const uint32_t dec_output_wait = ascon_accel_read(
        &accelerator, ASCON_ACCEL_OUTPUT_WAIT_OFFSET);

    int passed = ((enc_status | dec_status) & ASCON_ACCEL_STATUS_ERROR) == 0U;
    uint32_t output_xor = 0U;
    for (uint32_t i = 0U; i < ENC_OUTPUT_WORDS; ++i)
        output_xor ^= enc_output[i];
    const uint8_t *const recovered = (const uint8_t *)dec_output;
    for (uint32_t i = 0U; i < mlen; ++i) {
        if (recovered[i] != plaintext[i]) {
            printf("Mismatch byte %u: expected %02x, got %02x\n",
                   (unsigned int)i, (unsigned int)plaintext[i],
                   (unsigned int)recovered[i]);
            passed = 0;
            break;
        }
    }

    printf("Ascon-AEAD128 DMA no-FIFO ENC (AD=%u, PT=%u): "
           "cpu_total=%u cpu_exec=%u hw=%u input_wait=%u "
           "output_wait=%u xor=0x%08x\n",
           (unsigned int)adlen, (unsigned int)mlen,
           (unsigned int)enc_total_cycles,
           (unsigned int)(enc_total_cycles - enc_setup_cycles),
           (unsigned int)enc_hw_cycles,
           (unsigned int)enc_input_wait, (unsigned int)enc_output_wait,
           (unsigned int)output_xor);
    printf("Ascon-AEAD128 DMA no-FIFO DEC (AD=%u, CT=%u): "
           "cpu_total=%u cpu_exec=%u hw=%u input_wait=%u output_wait=%u\n",
           (unsigned int)adlen, (unsigned int)mlen,
           (unsigned int)dec_total_cycles,
           (unsigned int)(dec_total_cycles - dec_setup_cycles),
           (unsigned int)dec_hw_cycles,
           (unsigned int)dec_input_wait, (unsigned int)dec_output_wait);
    printf(passed ? "DMA encryption/decryption test passed!\n"
                  : "DMA encryption/decryption test failed.\n");
    return passed ? 0 : 1;
}
