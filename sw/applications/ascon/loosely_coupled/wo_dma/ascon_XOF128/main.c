#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "../ascon_accelerator.h"

/* Change these two values to benchmark different input/output lengths. */
#ifndef MESSAGE_LENGTH
#define MESSAGE_LENGTH 1536U
#endif
#ifndef OUTPUT_LENGTH
#define OUTPUT_LENGTH 1536U
#endif

#define WORDS_FOR_BYTES(n) (((n) + 3U) / 4U)
#define STORAGE_WORDS(n) \
    ((WORDS_FOR_BYTES(n) > 0U) ? WORDS_FOR_BYTES(n) : 1U)

static uint32_t message[STORAGE_WORDS(MESSAGE_LENGTH)];
static uint32_t xof_output[STORAGE_WORDS(OUTPUT_LENGTH)];

int main(void)
{
    const uint32_t mlen = MESSAGE_LENGTH;
    const uint32_t output_len = OUTPUT_LENGTH;
    uint8_t *const message_bytes = (uint8_t *)message;
    const ascon_accel_t accelerator =
        ascon_accel_init(ASCON_ACCELERATOR_START_ADDRESS);
    uint32_t cycles;

    for (uint32_t i = 0U; i < mlen; ++i) {
        message_bytes[i] = (uint8_t)i;
    }

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    ascon_accel_start(&accelerator, ASCON_ACCEL_XOF128, false, output_len,
                      UINT32_C(0), mlen, UINT32_C(0));
    ascon_accel_push_words(&accelerator, message, mlen);
    ascon_accel_pop_words(&accelerator, xof_output, output_len);

    (void)ascon_accel_wait_done(&accelerator);
    CSR_READ(CSR_REG_MCYCLE, &cycles);

    uint32_t output_xor = 0U;
    const uint32_t output_words = WORDS_FOR_BYTES(OUTPUT_LENGTH);
    for (uint32_t i = 0U; i < output_words; ++i) {
        output_xor ^= xof_output[i];
    }

    printf("Ascon-XOF128 accelerator cycles (message=%u, output=%u): %u\n",
           (unsigned int)mlen, (unsigned int)output_len,
           (unsigned int)cycles);
    printf("benchmark finished (output xor = 0x%08x)\n",
           (unsigned int)output_xor);
    return 0;
}
