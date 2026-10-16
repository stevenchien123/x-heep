#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "../ascon_accelerator_dma.h"

#ifndef MESSAGE_LENGTH
#define MESSAGE_LENGTH 16384U
#endif
#ifndef OUTPUT_LENGTH
#define OUTPUT_LENGTH 16384U
#endif

#define WORDS_FOR_BYTES(n) (((n) + 3U) / 4U)
#define STORAGE_WORDS(n) ((WORDS_FOR_BYTES(n) != 0U) ? WORDS_FOR_BYTES(n) : 1U)

static uint32_t message[STORAGE_WORDS(MESSAGE_LENGTH)];
static uint32_t output[STORAGE_WORDS(OUTPUT_LENGTH)];
static ascon_dma_job_t input_job;
static ascon_dma_job_t output_job;

/* Poll without DMA interrupts so mcycle measures full elapsed operation time. */
static uint32_t busy_wait_operation(const ascon_accel_t *accelerator)
{
    ascon_dma_wait(&output_job);
    ascon_dma_wait(&input_job);
    return ascon_accel_wait_done(accelerator);
}

int main(void)
{
    const ascon_accel_t accelerator =
        ascon_accel_init(ASCON_ACCELERATOR_START_ADDRESS);
    uint8_t *const message_bytes = (uint8_t *)message;
    uint32_t dma_cold_init_cycles;
    uint32_t cycles;

    for (uint32_t i = 0U; i < MESSAGE_LENGTH; ++i)
        message_bytes[i] = (uint8_t)i;

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));
    dma_init(NULL);
    dma_config_flags_t result = ascon_dma_prepare_input(
        &input_job, message, WORDS_FOR_BYTES(MESSAGE_LENGTH));
    result |= ascon_dma_prepare_output(
        &output_job, output, WORDS_FOR_BYTES(OUTPUT_LENGTH),
        DMA_TRANS_END_POLLING);
    CSR_READ(CSR_REG_MCYCLE, &dma_cold_init_cycles);
    if (result != DMA_CONFIG_OK) {
        printf("DMA channel init failed: 0x%04x\n", (unsigned int)result);
        return 1;
    }

    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));
    ascon_accel_configure(&accelerator, ASCON_ACCEL_XOF128, false,
                          OUTPUT_LENGTH, 0U, MESSAGE_LENGTH, 0U);
    result = ascon_dma_rearm_and_launch(
        &input_job, message, WORDS_FOR_BYTES(MESSAGE_LENGTH), &output_job,
        output, WORDS_FOR_BYTES(OUTPUT_LENGTH));
    if (result != DMA_CONFIG_OK) {
        printf("DMA setup failed: 0x%04x\n", (unsigned int)result);
        return 1;
    }

    ascon_accel_start(&accelerator);
    const uint32_t status = busy_wait_operation(&accelerator);
    CSR_READ(CSR_REG_MCYCLE, &cycles);

    const uint32_t hw_cycles = ascon_accel_read(
        &accelerator, ASCON_ACCEL_CYCLE_COUNT_OFFSET);
    const uint32_t input_wait = ascon_accel_read(
        &accelerator, ASCON_ACCEL_INPUT_WAIT_OFFSET);
    const uint32_t output_wait = ascon_accel_read(
        &accelerator, ASCON_ACCEL_OUTPUT_WAIT_OFFSET);

    uint32_t output_xor = 0U;
    for (uint32_t i = 0U; i < WORDS_FOR_BYTES(OUTPUT_LENGTH); ++i)
        output_xor ^= output[i];

    printf("Ascon DMA reusable channel cold init cycles: %u\n",
           (unsigned int)dma_cold_init_cycles);
    printf("Ascon XOF128 DMA warm cycles (message=%u, output=%u): %u\n",
           (unsigned int)MESSAGE_LENGTH, (unsigned int)OUTPUT_LENGTH,
           (unsigned int)cycles);
    printf("  hardware=%u input_wait=%u output_wait=%u xor=0x%08x\n",
           (unsigned int)hw_cycles, (unsigned int)input_wait,
           (unsigned int)output_wait, (unsigned int)output_xor);
    return (status & ASCON_ACCEL_STATUS_ERROR) != 0U;
}
