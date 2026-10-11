#include <stdint.h>
#include <stdio.h>

#include "csr.h"
#include "../ascon_accelerator.h"

/* Change this value to benchmark a different message length. */
#ifndef MESSAGE_LENGTH
#define MESSAGE_LENGTH 1536U
#endif

#define ASCON_HASH256_SIZE 32U
#define HASH_OUTPUT_WORDS  (ASCON_HASH256_SIZE / 4U)
#define WORDS_FOR_BYTES(n) (((n) + 3U) / 4U)
#define STORAGE_WORDS(n) \
    ((WORDS_FOR_BYTES(n) > 0U) ? WORDS_FOR_BYTES(n) : 1U)

static uint32_t message[STORAGE_WORDS(MESSAGE_LENGTH)];
static uint32_t hash_output[HASH_OUTPUT_WORDS];

int main(void)
{
    const uint32_t mlen = MESSAGE_LENGTH;
    uint8_t *const message_bytes = (uint8_t *)message;
    const ascon_accel_t accelerator =
        ascon_accel_init(ASCON_ACCELERATOR_START_ADDRESS);
    uint32_t cycles;

    for (uint32_t i = 0U; i < mlen; ++i) {
        message_bytes[i] = (uint8_t)i;
    }

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    ascon_accel_start(&accelerator, ASCON_ACCEL_HASH256, false,
                      ASCON_HASH256_SIZE, UINT32_C(0), mlen, UINT32_C(0));
    ascon_accel_push_words(&accelerator, message, mlen);
    ascon_accel_pop_words(&accelerator, hash_output, ASCON_HASH256_SIZE);

    (void)ascon_accel_wait_done(&accelerator);
    CSR_READ(CSR_REG_MCYCLE, &cycles);

    uint32_t output_xor = 0U;
    for (uint32_t i = 0U; i < HASH_OUTPUT_WORDS; ++i) {
        output_xor ^= hash_output[i];
    }

    printf("Ascon-Hash256 accelerator cycles (message=%u): %u\n",
           (unsigned int)mlen, (unsigned int)cycles);
    printf("benchmark finished (output xor = 0x%08x)\n",
           (unsigned int)output_xor);
    return 0;
}
