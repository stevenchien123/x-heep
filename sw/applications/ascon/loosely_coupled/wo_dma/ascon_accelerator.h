#ifndef ASCON_ACCELERATOR_H_
#define ASCON_ACCELERATOR_H_

#include <stdbool.h>
#include <stdint.h>

#include "core_v_mini_mcu.h"
#include "mmio.h"

/*
 * The accelerator is intended to replace the example simple accelerator in
 * external-peripheral slot 3.  The address can be overridden at compile time
 * when a different testharness slot is selected.
 */
#ifndef ASCON_ACCELERATOR_START_ADDRESS
#define ASCON_ACCELERATOR_START_ADDRESS \
    (EXT_PERIPHERAL_START_ADDRESS + UINT32_C(0x3000))
#endif

enum {
    ASCON_ACCEL_MODE_OFFSET        = 0x00,
    ASCON_ACCEL_ED_OFFSET          = 0x04,
    ASCON_ACCEL_HASH_LEN_OFFSET    = 0x08,
    ASCON_ACCEL_AD_LEN_OFFSET      = 0x0c,
    ASCON_ACCEL_DATA_LEN_OFFSET    = 0x10,
    ASCON_ACCEL_CUSTOM_LEN_OFFSET  = 0x14,
    ASCON_ACCEL_CONTROL_OFFSET     = 0x18,
    ASCON_ACCEL_INPUT_DATA_OFFSET  = 0x1c,
    ASCON_ACCEL_OUTPUT_DATA_OFFSET = 0x20,
    ASCON_ACCEL_STATUS_OFFSET      = 0x24,
};

enum {
    ASCON_ACCEL_CONTROL_START        = UINT32_C(1) << 0,
    ASCON_ACCEL_CONTROL_CLEAR_STATUS = UINT32_C(1) << 1,
};

enum {
    ASCON_ACCEL_STATUS_DONE         = UINT32_C(1) << 0,
    ASCON_ACCEL_STATUS_ERROR        = UINT32_C(1) << 1,
    ASCON_ACCEL_STATUS_BUSY         = UINT32_C(1) << 2,
    ASCON_ACCEL_STATUS_INPUT_READY  = UINT32_C(1) << 3,
    ASCON_ACCEL_STATUS_OUTPUT_VALID = UINT32_C(1) << 4,
};

typedef enum ascon_accel_mode {
    ASCON_ACCEL_AEAD128 = 0,
    ASCON_ACCEL_HASH256 = 1,
    ASCON_ACCEL_XOF128  = 2,
    ASCON_ACCEL_CXOF128 = 3,
} ascon_accel_mode_t;

typedef struct ascon_accel {
    mmio_region_t base;
} ascon_accel_t;

static inline ascon_accel_t ascon_accel_init(uintptr_t address)
{
    ascon_accel_t accelerator = {
        .base = mmio_region_from_addr(address),
    };
    return accelerator;
}

static inline uint32_t ascon_accel_words_for_bytes(uint32_t byte_length)
{
    return (byte_length >> 2) + ((byte_length & UINT32_C(3)) != 0U);
}

/*
 * Configure and start one operation.  custom_len is the complete byte count
 * presented to the CXOF custom phase, including its 8-byte bit-length prefix.
 */
static inline void ascon_accel_start(const ascon_accel_t *accelerator,
                                     ascon_accel_mode_t mode,
                                     bool decrypt,
                                     uint32_t hash_len,
                                     uint32_t ad_len,
                                     uint32_t data_len,
                                     uint32_t custom_len)
{
    mmio_region_write32(accelerator->base, ASCON_ACCEL_CONTROL_OFFSET,
                        ASCON_ACCEL_CONTROL_CLEAR_STATUS);
    mmio_region_write32(accelerator->base, ASCON_ACCEL_MODE_OFFSET,
                        (uint32_t)mode);
    mmio_region_write32(accelerator->base, ASCON_ACCEL_ED_OFFSET,
                        decrypt ? UINT32_C(1) : UINT32_C(0));
    mmio_region_write32(accelerator->base, ASCON_ACCEL_HASH_LEN_OFFSET,
                        hash_len);
    mmio_region_write32(accelerator->base, ASCON_ACCEL_AD_LEN_OFFSET, ad_len);
    mmio_region_write32(accelerator->base, ASCON_ACCEL_DATA_LEN_OFFSET,
                        data_len);
    mmio_region_write32(accelerator->base, ASCON_ACCEL_CUSTOM_LEN_OFFSET,
                        custom_len);
    mmio_region_write32(accelerator->base, ASCON_ACCEL_CONTROL_OFFSET,
                        ASCON_ACCEL_CONTROL_START);
}

/* Blocking MMIO write: returns only after the core accepts this input word. */
static inline void ascon_accel_push(const ascon_accel_t *accelerator,
                                    uint32_t data)
{
    mmio_region_write32(accelerator->base, ASCON_ACCEL_INPUT_DATA_OFFSET,
                        data);
}

/* Blocking MMIO read: returns only when one output word is available. */
static inline uint32_t ascon_accel_pop(const ascon_accel_t *accelerator)
{
    return mmio_region_read32(accelerator->base,
                              ASCON_ACCEL_OUTPUT_DATA_OFFSET);
}

static inline uint32_t ascon_accel_status(const ascon_accel_t *accelerator)
{
    return mmio_region_read32(accelerator->base, ASCON_ACCEL_STATUS_OFFSET);
}

static inline uint32_t ascon_accel_wait_done(
    const ascon_accel_t *accelerator)
{
    uint32_t status;
    do {
        status = ascon_accel_status(accelerator);
    } while ((status & ASCON_ACCEL_STATUS_DONE) == 0U);
    return status;
}

/*
 * The source must contain ceil(byte_length / 4) readable words.  The final
 * word's unused high byte lanes may be zero; the wrapper generates keep/last.
 * A zero byte length performs no write because the wrapper injects the empty
 * terminator itself when required by the active phase.
 */
static inline void ascon_accel_push_words(
    const ascon_accel_t *accelerator,
    const uint32_t *data,
    uint32_t byte_length)
{
    const uint32_t word_count = ascon_accel_words_for_bytes(byte_length);
    for (uint32_t word = 0U; word < word_count; ++word) {
        ascon_accel_push(accelerator, data[word]);
    }
}

static inline void ascon_accel_pop_words(const ascon_accel_t *accelerator,
                                         uint32_t *data,
                                         uint32_t byte_length)
{
    const uint32_t word_count = ascon_accel_words_for_bytes(byte_length);
    for (uint32_t word = 0U; word < word_count; ++word) {
        data[word] = ascon_accel_pop(accelerator);
    }
}

#endif  // ASCON_ACCELERATOR_H_
