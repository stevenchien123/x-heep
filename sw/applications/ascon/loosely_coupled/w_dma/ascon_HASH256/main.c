#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "../ascon_accelerator_dma.h"

#ifndef MESSAGE_LENGTH
#define MESSAGE_LENGTH 1536U
#endif

#define HASH_BYTES 32U
#define WORDS_FOR_BYTES(n) (((n) + 3U) / 4U)
#define STORAGE_WORDS(n) ((WORDS_FOR_BYTES(n) != 0U) ? WORDS_FOR_BYTES(n) : 1U)

static uint32_t message[STORAGE_WORDS(MESSAGE_LENGTH)];
static uint32_t output[HASH_BYTES / 4U];
static ascon_dma_job_t input_job;
static ascon_dma_job_t output_job;

int main(void)
{
    const ascon_accel_t accelerator =
        ascon_accel_init(ASCON_ACCELERATOR_START_ADDRESS);
    uint8_t *const message_bytes = (uint8_t *)message;
    const uint32_t input_words = WORDS_FOR_BYTES(MESSAGE_LENGTH);
    uint32_t dma_cold_init_cycles;
    uint32_t setup_cycles;
    uint32_t total_cycles;

    for (uint32_t i = 0U; i < MESSAGE_LENGTH; ++i)
        message_bytes[i] = (uint8_t)i;

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));
    dma_init(NULL);
    dma_config_flags_t result = ascon_dma_prepare_input(
        &input_job, message, input_words);
    result |= ascon_dma_prepare_output(&output_job, output, HASH_BYTES / 4U);
    CSR_READ(CSR_REG_MCYCLE, &dma_cold_init_cycles);
    if (result != DMA_CONFIG_OK) {
        printf("DMA channel init failed: 0x%04x\n", (unsigned int)result);
        return 1;
    }

    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));
    ascon_accel_configure(&accelerator, ASCON_ACCEL_HASH256, false,
                          HASH_BYTES, 0U, MESSAGE_LENGTH, 0U);
    result = ascon_dma_rearm_and_launch(
        &input_job, message, input_words, &output_job, output,
        HASH_BYTES / 4U);
    if (result != DMA_CONFIG_OK) {
        printf("DMA setup failed: 0x%04x\n", (unsigned int)result);
        return 1;
    }

    CSR_READ(CSR_REG_MCYCLE, &setup_cycles);
    ascon_accel_start(&accelerator);
    const uint32_t status = ascon_dma_wait_operation(
        &accelerator, &input_job, &output_job);
    CSR_READ(CSR_REG_MCYCLE, &total_cycles);

    uint32_t output_xor = 0U;
    for (uint32_t i = 0U; i < HASH_BYTES / 4U; ++i) output_xor ^= output[i];

    printf("Ascon DMA reusable channel cold init: %u cycles\n",
           (unsigned int)dma_cold_init_cycles);
    printf("Ascon-Hash256 DMA no-FIFO fast (message=%u): "
           "cpu_total=%u cpu_exec=%u hw=%u input_wait=%u "
           "output_wait=%u xor=0x%08x\n",
           (unsigned int)MESSAGE_LENGTH, (unsigned int)total_cycles,
           (unsigned int)(total_cycles - setup_cycles),
           (unsigned int)ascon_accel_read(&accelerator,
                                           ASCON_ACCEL_CYCLE_COUNT_OFFSET),
           (unsigned int)ascon_accel_read(&accelerator,
                                           ASCON_ACCEL_INPUT_WAIT_OFFSET),
           (unsigned int)ascon_accel_read(&accelerator,
                                           ASCON_ACCEL_OUTPUT_WAIT_OFFSET),
           (unsigned int)output_xor);
    return (status & ASCON_ACCEL_STATUS_ERROR) != 0U;
}
