#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// ,insn r operand order: opcode, funct3, funct7, rd, rs1, rs2
static inline void coproc_store(uint32_t value)
{
    asm volatile(
        ".insn r 0x0b, 0, 0, x0, %0, x0"
        :
        : "r"(value)
        : "memory");
}

static inline uint32_t coproc_load(void)
{
    uint32_t value;

    asm volatile(
        ".insn r 0x0b, 0, 1, %0, x0, x0"
        : "=r"(value)
        :
        : "memory");

    return value;
}

static int check_value(const char *name, uint32_t expected, uint32_t actual)
{
    printf("%s: expected=0x%08x actual=0x%08x\n", name,
           (unsigned int)expected, (unsigned int)actual);
    return actual == expected;
}

int main(void)
{
    static const uint32_t test_values[] = {
        UINT32_C(0x12345678),
        UINT32_C(0xA5A55A5A),
        UINT32_C(0xFFFFFFFF),
        UINT32_C(0x00000000),
    };
    int passed = 1;

    /* Verify the coprocessor register reset value before the first CSTORE. */
    passed &= check_value("reset", UINT32_C(0), coproc_load());

    for (size_t i = 0; i < sizeof(test_values) / sizeof(test_values[0]); ++i) {
        coproc_store(test_values[i]);
        passed &= check_value("CSTORE/CLOAD", test_values[i], coproc_load());
    }

    if (passed) {
        printf("PASS\n");
        return EXIT_SUCCESS;
    }

    printf("FAIL\n");
    return EXIT_FAILURE;
}
