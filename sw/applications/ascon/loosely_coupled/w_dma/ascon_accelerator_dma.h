#ifndef ASCON_ACCELERATOR_DMA_H_
#define ASCON_ACCELERATOR_DMA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core_v_mini_mcu.h"
#include "csr.h"
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

enum {
    ASCON_ACCEL_INPUT_DMA_CHANNEL  = 0,
    /* Channels 0/1 share DMA master port 0 and channels 2/3 share port 1 in
       the current {2,2} X-HEEP mapping. Keep input and output on separate
       master ports so they do not arbitrate inside the DMA subsystem. */
    ASCON_ACCEL_OUTPUT_DMA_CHANNEL = 2,
};

_Static_assert(DMA_CH_NUM > ASCON_ACCEL_OUTPUT_DMA_CHANNEL,
               "Ascon DMA fast path requires at least three DMA channels");

typedef enum ascon_accel_mode {
    ASCON_ACCEL_AEAD128 = 0,
    ASCON_ACCEL_HASH256 = 1,
    ASCON_ACCEL_XOF128  = 2,
    ASCON_ACCEL_CXOF128 = 3,
} ascon_accel_mode_t;

typedef struct ascon_accel {
    mmio_region_t base;
} ascon_accel_t;

typedef struct ascon_dma_job {
    dma_target_t source;
    dma_target_t destination;
    dma_trans_t transaction;
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

static inline dma_config_flags_t ascon_dma_prepare_input(
    ascon_dma_job_t *job, const uint32_t *source, uint32_t word_count)
{
    *job = (ascon_dma_job_t){0};
    if (word_count == 0U) return DMA_CONFIG_OK;

    job->active = true;
    job->source = (dma_target_t){
        .ptr = (uint8_t *)(uintptr_t)source,
        .inc_d1_du = 1,
        .type = DMA_DATA_TYPE_WORD,
        .trig = DMA_TRIG_MEMORY,
    };
    job->destination = (dma_target_t){
        .ptr = (uint8_t *)(uintptr_t)(ASCON_ACCELERATOR_START_ADDRESS +
                                     ASCON_ACCEL_INPUT_DATA_OFFSET),
        .inc_d1_du = 0,
        .type = DMA_DATA_TYPE_WORD,
        .trig = DMA_TRIG_SLOT_EXT_TX,
    };
    job->transaction = (dma_trans_t){
        .src = &job->source,
        .dst = &job->destination,
        .size_d1_du = word_count,
        .dim = DMA_DIM_CONF_1D,
        .src_type = DMA_DATA_TYPE_WORD,
        .dst_type = DMA_DATA_TYPE_WORD,
        .mode = DMA_TRANS_MODE_SINGLE,
        .end = DMA_TRANS_END_POLLING,
        .channel = ASCON_ACCEL_INPUT_DMA_CHANNEL,
    };

    /* This descriptor is fixed, word-aligned and built by this driver. Full
       runtime integrity/realignment checks only add cold-start overhead. */
    dma_config_flags_t result = dma_validate_transaction(
        &job->transaction, DMA_DO_NOT_ENABLE_REALIGN,
        DMA_PERFORM_CHECKS_ONLY_SANITY);
    if ((result & DMA_CONFIG_CRITICAL_ERROR) != 0U) return result;
    return result | dma_load_transaction(&job->transaction);
}

static inline dma_config_flags_t ascon_dma_prepare_output(
    ascon_dma_job_t *job, uint32_t *destination, uint32_t word_count)
{
    *job = (ascon_dma_job_t){0};
    if (word_count == 0U) return DMA_CONFIG_OK;

    job->active = true;
    job->source = (dma_target_t){
        .ptr = (uint8_t *)(uintptr_t)(ASCON_ACCELERATOR_START_ADDRESS +
                                     ASCON_ACCEL_OUTPUT_DATA_OFFSET),
        .inc_d1_du = 0,
        .type = DMA_DATA_TYPE_WORD,
        .trig = DMA_TRIG_SLOT_EXT_RX,
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
        .size_d1_du = word_count,
        .dim = DMA_DIM_CONF_1D,
        .src_type = DMA_DATA_TYPE_WORD,
        .dst_type = DMA_DATA_TYPE_WORD,
        .mode = DMA_TRANS_MODE_SINGLE,
        /* The output transaction is the completion event for one complete
           Ascon stream. It wakes the CPU without STATUS-register polling. */
        .end = DMA_TRANS_END_INTR,
        .channel = ASCON_ACCEL_OUTPUT_DMA_CHANNEL,
    };

    dma_config_flags_t result = dma_validate_transaction(
        &job->transaction, DMA_DO_NOT_ENABLE_REALIGN,
        DMA_PERFORM_CHECKS_ONLY_SANITY);
    if ((result & DMA_CONFIG_CRITICAL_ERROR) != 0U) return result;
    return result | dma_load_transaction(&job->transaction);
}

static inline dma_config_flags_t ascon_dma_launch(ascon_dma_job_t *job)
{
    return job->active ? dma_launch(&job->transaction) : DMA_CONFIG_OK;
}

/*
 * Fast warm re-arm path.
 *
 * ascon_dma_prepare_input/output() must have been called once after dma_init().
 * Those calls install all invariant channel settings (word type, increments,
 * trigger slots, mode and interrupt policy). A subsequent Ascon operation only
 * changes the SRAM-side pointer and transfer length. Writing SIZE_D1 last arms
 * and starts the DMA channel; the external trigger keeps it blocked until the
 * accelerator requests/produces a word.
 */
static inline dma_config_flags_t ascon_dma_rearm_output(
    ascon_dma_job_t *job, uint32_t *destination, uint32_t word_count)
{
    if (word_count == 0U) {
        job->active = false;
        return DMA_CONFIG_OK;
    }
    if (!job->active ||
        job->transaction.channel != ASCON_ACCEL_OUTPUT_DMA_CHANNEL) {
        return DMA_CONFIG_CRITICAL_ERROR;
    }
    if (!dma_is_ready(ASCON_ACCEL_OUTPUT_DMA_CHANNEL)) {
        return DMA_CONFIG_TRANS_OVERRIDE;
    }

    job->destination.ptr = (uint8_t *)(uintptr_t)destination;
    job->transaction.size_d1_du = word_count;

    volatile dma *const channel =
        dma_peri(ASCON_ACCEL_OUTPUT_DMA_CHANNEL);
    /* Reading the IFR clears a stale completion before the next launch. */
    (void)channel->TRANSACTION_IFR;
    channel->DST_PTR = (uint32_t)(uintptr_t)destination;
    channel->WINDOW_SIZE = word_count;
    channel->SIZE_D1 = word_count;
    return DMA_CONFIG_OK;
}

static inline dma_config_flags_t ascon_dma_rearm_input(
    ascon_dma_job_t *job, const uint32_t *source, uint32_t word_count)
{
    if (word_count == 0U) {
        job->active = false;
        return DMA_CONFIG_OK;
    }
    if (!job->active ||
        job->transaction.channel != ASCON_ACCEL_INPUT_DMA_CHANNEL) {
        return DMA_CONFIG_CRITICAL_ERROR;
    }
    if (!dma_is_ready(ASCON_ACCEL_INPUT_DMA_CHANNEL)) {
        return DMA_CONFIG_TRANS_OVERRIDE;
    }

    job->source.ptr = (uint8_t *)(uintptr_t)source;
    job->transaction.size_d1_du = word_count;

    volatile dma *const channel = dma_peri(ASCON_ACCEL_INPUT_DMA_CHANNEL);
    channel->SRC_PTR = (uint32_t)(uintptr_t)source;
    channel->WINDOW_SIZE = word_count;
    channel->SIZE_D1 = word_count;
    return DMA_CONFIG_OK;
}

static inline dma_config_flags_t ascon_dma_rearm_and_launch(
    ascon_dma_job_t *input_job, const uint32_t *input,
    uint32_t input_words, ascon_dma_job_t *output_job, uint32_t *output,
    uint32_t output_words)
{
    /* Arm output first so no produced word can be missed. Both channels wait
       on low external triggers until CONTROL.START is written. */
    dma_config_flags_t result = ascon_dma_rearm_output(
        output_job, output, output_words);
    if (result != DMA_CONFIG_OK) return result;
    return ascon_dma_rearm_input(input_job, input, input_words);
}

static inline void ascon_dma_wait(const ascon_dma_job_t *job)
{
    if (job->active) {
        while (!dma_is_ready(job->transaction.channel)) {
        }
    }
}

/* Wait on the output-DMA completion interrupt instead of repeatedly reading
   the accelerator STATUS register while DMA owns its streaming registers.
   The double ready check follows the X-HEEP DMA examples and closes the race
   between checking READY and entering WFI. */
static inline void ascon_dma_wait_output_interrupt(
    const ascon_dma_job_t *output_job)
{
    if (!output_job->active) return;

    const uint8_t channel = output_job->transaction.channel;
    while (!dma_is_ready(channel)) {
        CSR_CLEAR_BITS(CSR_REG_MSTATUS, UINT32_C(0x8));
        if (!dma_is_ready(channel)) {
            wait_for_interrupt();
        }
        CSR_SET_BITS(CSR_REG_MSTATUS, UINT32_C(0x8));
    }
}

static inline uint32_t ascon_dma_wait_operation(
    const ascon_accel_t *accelerator, const ascon_dma_job_t *input_job,
    const ascon_dma_job_t *output_job)
{
    ascon_dma_wait_output_interrupt(output_job);
    ascon_dma_wait(input_job);

    /* Once the final output word has been drained, Ascon normally asserts
       DONE immediately or within a few clocks. STATUS polling is deliberately
       deferred until now, so it cannot contend with stream DMA traffic. */
    return ascon_accel_wait_done(accelerator);
}

#endif  // ASCON_ACCELERATOR_DMA_H_
