#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "csr.h"
#include "ascon_coproc.h"

#define SIZE 8

/*
 * Testcase from NIST KAT HASH256 No.10
 *   Msg: 0x03020100_07060504_08
 *   Hashed message: 0x309c2694_1e6e29e0_045566c8_3e824118_f52719fa_c858fd20_19e6bce9_a6c17878
 */

int main(){
    // Init
    static const uint32_t golden[] = {
      // Hashed message
      UINT32_C(0x309c2694),
      UINT32_C(0x1e6e29e0),
      UINT32_C(0x045566c8),
      UINT32_C(0x3e824118),
      UINT32_C(0xf52719fa),
      UINT32_C(0xc858fd20),
      UINT32_C(0x19e6bce9),
      UINT32_C(0xa6c17878)
    };

    static uint32_t Ascon_output[SIZE] = {0};

    unsigned int cycles;
    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    // Clear Ascon state
    ascon_coproc_clear();

    // Config and Start Ascon coprocessor (hash_len = 256-bit)
    ascon_coproc_config(ASCON_HASH256, 0, 0x00000020);

    // Absorbing Phase
    ascon_coproc_push(0x03020100, 0x07060504, 0xf, 0xf, false, false);
    ascon_coproc_push(0x00000008, 0x00000000, 0x1, 0x0, true, false);

    // Squeezing Phase (output 256-bit hashed message)
    Ascon_output[0] = ascon_coproc_pop();
    Ascon_output[1] = ascon_coproc_pop();
    Ascon_output[2] = ascon_coproc_pop();
    Ascon_output[3] = ascon_coproc_pop();
    Ascon_output[4] = ascon_coproc_pop();
    Ascon_output[5] = ascon_coproc_pop();
    Ascon_output[6] = ascon_coproc_pop();
    Ascon_output[7] = ascon_coproc_pop();

    CSR_READ(CSR_REG_MCYCLE, &cycles);
    printf("Ascon Hash256 cycles: %d\n", cycles);

    // Check if Ascon output matches golden output
    int test_passed = 1;
    for(int i=0; i<SIZE; i++){
        if(Ascon_output[i] != golden[i]){
            printf("Test failed at index %d: expected 0x%08x, got 0x%08x\n", i, golden[i], Ascon_output[i]);
            test_passed = 0;
        }
    }

    if(test_passed){
        printf("test passed!\n");
    } else {
        printf("test failed.\n");
    }

    return 0;
}