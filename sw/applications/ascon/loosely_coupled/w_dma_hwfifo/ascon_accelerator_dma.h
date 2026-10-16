#ifndef ASCON_ACCELERATOR_DMA_H_
#define ASCON_ACCELERATOR_DMA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core_v_mini_mcu.h"
#include "dma.h"
#include "mmio.h"

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
    ASCON_ACCEL_CYCLE_COUNT_OFFSET = 0x28,
    ASCON_ACCEL_INPUT_WAIT_OFFSET  = 0x2c,
    ASCON_ACCEL_OUTPUT_WAIT_OFFSET = 0x30,
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

/* testharness.sv.tpl connects Ascon's HW-FIFO port to DMA channel 2. */
enum { ASCON_ACCEL_DMA_CHANNEL = 2 };

_Static_assert(DMA_CH_NUM > ASCON_ACCEL_DMA_CHANNEL,
               "Ascon HW-FIFO mode requires DMA channel 2");

#if !defined(DMA_HW_FIFO_MODE) || (DMA_HW_FIFO_MODE == 0)
#error "The selected X-HEEP configuration does not enable DMA HW-FIFO mode"
#endif

typedef enum ascon_accel_mode {
    ASCON_ACCEL_AEAD128 = 0,
    ASCON_ACCEL_HASH256 = 1,
    ASCON_ACCEL_XOF128  = 2,
    ASCON_ACCEL_CXOF128 = 3,
} ascon_accel_mode_t;

typedef struct ascon_accel {
    mmio_region_t base;
} ascon_accel_t;

/*
 * In X-HEEP HW-FIFO mode one DMA channel owns both sides of the stream:
 *
 *   source SRAM -> DMA read unit -> Ascon -> DMA write unit -> destination SRAM
 *
 * Consequently there is one descriptor and one common transfer size. Ascon
 * can consume and produce different numbers of words, so transaction_words is
 * max(input_words, output_words). If output_words is larger, source must point
 * to an allocation containing transaction_words words; the unused tail is
 * padding that protects against DMA read-ahead and is not sent to the core.
 */
typedef struct ascon_dma_job {
    dma_target_t source;
    dma_target_t destination;
    dma_trans_t transaction;
    uint32_t input_words;
    uint32_t output_words;
    bool active;
} ascon_dma_job_t;

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

static inline uint32_t ascon_dma_max_words(uint32_t input_words,
                                           uint32_t output_words)
{
    return input_words > output_words ? input_words : output_words;
}

static inline void ascon_accel_configure(const ascon_accel_t *accelerator,
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
}

static inline void ascon_accel_start(const ascon_accel_t *accelerator)
{
    mmio_region_write32(accelerator->base, ASCON_ACCEL_CONTROL_OFFSET,
                        ASCON_ACCEL_CONTROL_START);
}

static inline uint32_t ascon_accel_read(const ascon_accel_t *accelerator,
                                        ptrdiff_t offset)
{
    return mmio_region_read32(accelerator->base, offset);
}

static inline uint32_t ascon_accel_wait_done(
    const ascon_accel_t *accelerator)
{
    uint32_t status;
    do {
        status = ascon_accel_read(accelerator, ASCON_ACCEL_STATUS_OFFSET);
    } while ((status & ASCON_ACCEL_STATUS_DONE) == 0U);
    return status;
}

static inline dma_config_flags_t ascon_dma_prepare(
    ascon_dma_job_t *job, const uint32_t *source, uint32_t input_words,
    uint32_t *destination, uint32_t output_words)
{
    const uint32_t transaction_words =
        ascon_dma_max_words(input_words, output_words);

    *job = (ascon_dma_job_t){0};
    if (transaction_words == 0U) return DMA_CONFIG_OK;

    job->active = true;
    job->input_words = input_words;
    job->output_words = output_words;
    job->source = (dma_target_t){
        .ptr = (uint8_t *)(uintptr_t)source,
        .inc_d1_du = 1,
        .type = DMA_DATA_TYPE_WORD,
        .trig = DMA_TRIG_MEMORY,
    };
    job->destination = (dma_target_t){
        .ptr = (uint8_t *)(uintptr_t)destination,
        .inc_d1_du = 1,
        .type = DMA_DATA_TYPE_WORD,
        .trig = DMA_TRIG_MEMORY,
    };
    job->transaction = (dma_trans_t){
        .src = &job->source,
        .dst = &job->destination,
        .size_d1_du = transaction_words,
        .dim = DMA_DIM_CONF_1D,
        .hw_fifo_en = 1,
        .src_type = DMA_DATA_TYPE_WORD,
        .dst_type = DMA_DATA_TYPE_WORD,
        .mode = DMA_TRANS_MODE_SINGLE,
        .end = DMA_TRANS_END_POLLING,
        .channel = ASCON_ACCEL_DMA_CHANNEL,
    };

    /* The benchmark owns aligned static buffers, so sanity checks are enough
       and avoid including full region validation in the cold-start cost. */
    dma_config_flags_t result = dma_validate_transaction(
        &job->transaction, DMA_DO_NOT_ENABLE_REALIGN,
        DMA_PERFORM_CHECKS_ONLY_SANITY);
    if ((result & DMA_CONFIG_CRITICAL_ERROR) != 0U) return result;
    return result | dma_load_transaction(&job->transaction);
}

/*
 * Fast warm re-arm path. ascon_dma_prepare() installs all invariant channel
 * settings once. Writing SIZE_D1 last launches the transaction. The Ascon
 * accelerator must be started afterwards; until then its HW-FIFO full signal
 * keeps the DMA read side blocked.
 */
static inline dma_config_flags_t ascon_dma_rearm_and_launch(
    ascon_dma_job_t *job, const uint32_t *source, uint32_t input_words,
    uint32_t *destination, uint32_t output_words)
{
    const uint32_t transaction_words =
        ascon_dma_max_words(input_words, output_words);

    if (transaction_words == 0U) {
        job->active = false;
        return DMA_CONFIG_OK;
    }
    if (!job->active ||
        job->transaction.channel != ASCON_ACCEL_DMA_CHANNEL) {
        return DMA_CONFIG_CRITICAL_ERROR;
    }
    if (!dma_is_ready(ASCON_ACCEL_DMA_CHANNEL)) {
        return DMA_CONFIG_TRANS_OVERRIDE;
    }

    job->source.ptr = (uint8_t *)(uintptr_t)source;
    job->destination.ptr = (uint8_t *)(uintptr_t)destination;
    job->input_words = input_words;
    job->output_words = output_words;
    job->transaction.size_d1_du = transaction_words;

    volatile dma *const channel = dma_peri(ASCON_ACCEL_DMA_CHANNEL);
    channel->SRC_PTR = (uint32_t)(uintptr_t)source;
    channel->DST_PTR = (uint32_t)(uintptr_t)destination;
    channel->WINDOW_SIZE = transaction_words;
    /* SIZE_D1 is the DMA start command and therefore must be written last. */
    channel->SIZE_D1 = transaction_words;
    return DMA_CONFIG_OK;
}

static inline void ascon_dma_wait(const ascon_dma_job_t *job)
{
    if (job->active) {
        while (!dma_is_ready(job->transaction.channel)) {
        }
    }
}

static inline uint32_t ascon_dma_wait_operation(
    const ascon_accel_t *accelerator, const ascon_dma_job_t *job)
{
    ascon_dma_wait(job);
    return ascon_accel_wait_done(accelerator);
}

#endif  // ASCON_ACCELERATOR_DMA_H_
