#include <inttypes.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "ascon_aead128.h"
#include "csr.h"

#define ASSOCIATED_DATA_LENGTH 16U
#define MESSAGE_LENGTH 0U

/*
 * Keep the large test buffers in .bss.  The default X-HEEP heap and stack are
 * only 2 KiB each, so these buffers must not be allocated with malloc() or as
 * non-static local arrays.
 */
static unsigned char msg[MESSAGE_LENGTH];
static unsigned char msg2[MESSAGE_LENGTH];
static unsigned char ct[MESSAGE_LENGTH + ASCON_AEAD128_TAG_SIZE];
static unsigned char ad[(ASSOCIATED_DATA_LENGTH > 0U) ?
                        ASSOCIATED_DATA_LENGTH : 1U];

void init_buffer(unsigned char* buffer, unsigned long long numbytes);

void init_buffer(unsigned char* buffer, unsigned long long numbytes) {
  unsigned long long i;
  for (i = 0; i < numbytes; i++) buffer[i] = (unsigned char)i;
}


int main(void)
{
    const unsigned long long mlen = MESSAGE_LENGTH;
    const unsigned long long adlen = ASSOCIATED_DATA_LENGTH;
    unsigned long long clen, mlen2;

    unsigned char key[ASCON_AEAD128_KEY_SIZE];
    unsigned char nonce[ASCON_AEAD128_NONCE_SIZE];

    unsigned int cycles, cycles2;


    init_buffer(key, sizeof(key));
    init_buffer(nonce, sizeof(nonce));

    init_buffer(msg, mlen);
    init_buffer(ad, adlen);

    printf("Test started!\n");

    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));
    ascon_aead128_encrypt(ct, &clen, msg, mlen, ad, adlen, nonce, key);
    CSR_READ(CSR_REG_MCYCLE, &cycles);
    printf("Number of clock cycles for encryption: %d\n", cycles);

    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));
    ascon_aead128_decrypt(msg2, &mlen2, ct, clen, ad, adlen, nonce, key);
    CSR_READ(CSR_REG_MCYCLE, &cycles2);
    printf("Number of clock cycles for decryption: %d\n", cycles2);

    if (mlen != mlen2) {
        printf("ascon_aead128_decrypt returned bad 'mlen': Got <%" PRIu32">, expected <%" PRIu32 ">\n", (uint32_t)mlen2, (uint32_t)mlen);
    }

    if (memcmp(msg, msg2, mlen)) {
        printf("ascon_aead128_decrypt did not recover the plaintext\n");
    }
    else{
        printf("ascon_aead128_decrypt recover the plaintext\n");
    }

    printf("Test: terminated\n");
    return 0;
}
