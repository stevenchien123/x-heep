#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "csr.h"
#include "ascon_coproc.h"

#define SIZE 5

/*
 * Testcase from NIST KAT AEAD128 No.579
 *   Key: 0x03020100_07060504_0b0a0908_0f0e0d0c
 *   Nonce: 0x03020100_07060504_0b0a0908_0f0e0d0c
 *   Associated Data: 0x03020100_07060504_0b0a0908_0f0e0d0c_10
 *   Plaintext: 0x03020100_07060504_0b0a0908_0f0e0d0c_10
 *   Ciphertext: 0x01b71398_86db8930_4c2a743a_8e40f113_97
 *   Tag: 0x8669d481_3e3bc0cb_8155336a_54a99deb
 */

int main(){
    // Init
    static const uint32_t golden[] = {
      // Plaintext
      UINT32_C(0x03020100),
      UINT32_C(0x07060504),
      UINT32_C(0x0b0a0908),
      UINT32_C(0x0f0e0d0c),
      UINT32_C(0x00000010)
    };

    static uint32_t Ascon_output[SIZE] = {0};

    unsigned int cycles;
    unsigned int error_flag;
    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    // Clear Ascon state
    ascon_coproc_clear();

    // Config and Start Ascon coprocessor
    ascon_coproc_config(ASCON_AEAD128, DEC, 0x00000000);

    // Send Key, Nonce, Associated Data
    // Key
    ascon_coproc_push(0x03020100, 0x07060504, 0xf, 0xf, false, false);
    ascon_coproc_push(0x0b0a0908, 0x0f0e0d0c, 0xf, 0xf, false, true);
    // Nonce
    ascon_coproc_push(0x03020100, 0x07060504, 0xf, 0xf, false, false);
    ascon_coproc_push(0x0b0a0908, 0x0f0e0d0c, 0xf, 0xf, false, true);
    // Associated Data
    ascon_coproc_push(0x03020100, 0x07060504, 0xf, 0xf, false, false);
    ascon_coproc_push(0x0b0a0908, 0x0f0e0d0c, 0xf, 0xf, false, false);
    ascon_coproc_push(0x00000010, 0x00000000, 0x1, 0x0, true, false);


    // Send Ciphertext and Receive Plaintext
    // 1st block of ciphertext
    ascon_coproc_push(0x01b71398, 0x86db8930, 0xf, 0xf, false, false);
    ascon_coproc_push(0x4c2a743a, 0x8e40f113, 0xf, 0xf, false, false);
    Ascon_output[0] = ascon_coproc_pop();
    Ascon_output[1] = ascon_coproc_pop();
    Ascon_output[2] = ascon_coproc_pop();
    Ascon_output[3] = ascon_coproc_pop();

    // 2nd block of ciphertext
    ascon_coproc_push(0x00000097, 0x00000000, 0x1, 0x0, true, false);
    Ascon_output[4] = ascon_coproc_pop();

    // Send Tag
    ascon_coproc_push(0x8669d481, 0x3e3bc0cb, 0xf, 0xf, false, false);
    ascon_coproc_push(0x8155336a, 0x54a99deb, 0xf, 0xf, false, true);

    // Check if Tag is valid (error flag)
    error_flag = ascon_coproc_status();

    CSR_READ(CSR_REG_MCYCLE, &cycles);
    printf("Ascon AEAD128 decryption cycles: %d\n", cycles);

    // Check if Ascon output matches golden output
    int test_passed = 1;
    for(int i=0; i<SIZE; i++){
        if(Ascon_output[i] != golden[i]){
            printf("Test failed at index %d: expected 0x%08x, got 0x%08x\n", i, golden[i], Ascon_output[i]);
            test_passed = 0;
        }
    }

    if(!error_flag && test_passed){
        printf("Tag verification passed.\n");
        printf("test passed!\n");
    } else {
        if(error_flag){
            printf("Tag verification failed.\n");
        } else {
            printf("Ascon output does not match golden output.\n");
        }
        printf("test failed.\n");
    }


    return 0;
}