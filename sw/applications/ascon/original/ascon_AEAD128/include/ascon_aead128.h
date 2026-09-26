#ifndef ASCON_AEAD128_H_
#define ASCON_AEAD128_H_

#include <stdint.h>

#define ASCON_AEAD128_KEY_SIZE 16U
#define ASCON_AEAD128_NONCE_SIZE 16U
#define ASCON_AEAD128_TAG_SIZE 16U

int ascon_aead128_encrypt(unsigned char *ciphertext, unsigned long long *ciphertext_len,
                          const unsigned char *plaintext, unsigned long long plaintext_len,
                          const unsigned char *associated_data, unsigned long long associated_data_len,
                          const unsigned char *nonce, const unsigned char *key);

int ascon_aead128_decrypt(unsigned char *plaintext, unsigned long long *plaintext_len,
                          const unsigned char *ciphertext, unsigned long long ciphertext_len,
                          const unsigned char *associated_data, unsigned long long associated_data_len,
                          const unsigned char *nonce, const unsigned char *key);

#endif  // ASCON_AEAD128_H_
