#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "csr.h"
#include "ascon_coproc.h"

#define SIZE 8

/*
 * Testcase from NIST KAT CXOF128 No.307 (L=256)
 *   Msg: 0x03020100_07060504_08
 *   Z: 0x00000048_00000000_03020100_07060504_08
 *   Hashed message: 0xa2014813_f9facf17_993e0c92_5c221e93_4ef26bda_c9a974c8_b0cd1c49_e379db3b
 */

int main(){
    // Init
    static const uint32_t golden[] = {
      // Hashed message
      UINT32_C(0xa2014813),
      UINT32_C(0xf9facf17),
      UINT32_C(0x993e0c92),
      UINT32_C(0x5c221e93),
      UINT32_C(0x4ef26bda),
      UINT32_C(0xc9a974c8),
      UINT32_C(0xb0cd1c49),
      UINT32_C(0xe379db3b)
    };

    static uint32_t Ascon_output[SIZE] = {0};

    unsigned int cycles;
    CSR_CLEAR_BITS(CSR_REG_MCOUNTINHIBIT, UINT32_C(1));
    CSR_WRITE(CSR_REG_MCYCLE, UINT32_C(0));

    // Clear Ascon state
    ascon_coproc_clear();

    // Config and Start Ascon coprocessor (hash_len L=256)
    ascon_coproc_config(ASCON_CXOF128, 0, 0x00000020);

    // Customization Phase
    ascon_coproc_push(0x00000048, 0x00000000, 0xf, 0xf, false, false);
    ascon_coproc_push(0x03020100, 0x07060504, 0xf, 0xf, false, false);
    ascon_coproc_push(0x00000008, 0x00000000, 0x1, 0x0, true, false);

    // Absorbing Phase
    ascon_coproc_push(0x03020100, 0x07060504, 0xf, 0xf, false, false);
    ascon_coproc_push(0x00000008, 0x00000000, 0x1, 0x0, true, false);

    // Squeezing Phase (output L-bit hashed message)
    Ascon_output[0] = ascon_coproc_pop();
    Ascon_output[1] = ascon_coproc_pop();
    Ascon_output[2] = ascon_coproc_pop();
    Ascon_output[3] = ascon_coproc_pop();
    Ascon_output[4] = ascon_coproc_pop();
    Ascon_output[5] = ascon_coproc_pop();
    Ascon_output[6] = ascon_coproc_pop();
    Ascon_output[7] = ascon_coproc_pop();

    CSR_READ(CSR_REG_MCYCLE, &cycles);
    printf("Ascon CXOF128 cycles: %d\n", cycles);

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