/*
 * Ascon loosely-coupled accelerator wrapper (DMA-fed, 4-word stream FIFOs)
 *
 * The CPU configures the operation and programs two X-HEEP DMA channels.
 * The input channel repeatedly writes INPUT_DATA and the output channel
 * repeatedly reads OUTPUT_DATA. Both peripheral addresses remain fixed while
 * the SRAM address advances. INPUT_DATA writes enqueue a four-word input FIFO
 * and OUTPUT_DATA reads dequeue a four-word output FIFO. A register-bus
 * transaction blocks only while its corresponding FIFO cannot make progress.
 *
 * The wrapper derives data_keep/data_last from the configured byte lengths.
 * When a phase requires an empty terminator, the wrapper injects
 * {data=0, keep=0, last=1} internally; software must not write that word.
 * dma_input_ready_o and dma_output_valid_o drive the DMA external TX/RX
 * trigger slots. The accelerator has no OBI master ports.
 *
 * Register map (byte offsets):
 *   0x00 MODE         RW [1:0]
 *   0x04 ED           RW [0]       0: encrypt, 1: decrypt
 *   0x08 HASH_LEN     RW [31:0]    XOF/CXOF output bytes
 *   0x0c AD_LEN       RW [31:0]    AEAD associated-data bytes
 *   0x10 DATA_LEN     RW [31:0]    PT/CT/message bytes
 *   0x14 CUSTOM_LEN   RW [31:0]    CXOF customization bytes
 *   0x18 CONTROL      W  [0] START, [1] CLEAR_STATUS
 *   0x1c INPUT_DATA   W  [31:0]    input-FIFO push
 *   0x20 OUTPUT_DATA  R  [31:0]    output-FIFO pop
 *   0x24 STATUS       R             see status layout below
 *   0x28 CYCLE_COUNT  R  [31:0]    active accelerator cycles
 *   0x2c INPUT_WAIT   R  [31:0]    cycles stalled by an empty input FIFO
 *   0x30 OUTPUT_WAIT  R  [31:0]    cycles stalled by a full output FIFO
 *
 * STATUS layout:
 *   [0] DONE (sticky until START or CLEAR_STATUS)
 *   [1] ERROR (sticky until START or CLEAR_STATUS)
 *   [2] BUSY
 *   [3] input FIFO can accept a DMA word for the current phase
 *   [4] output FIFO is not empty
 *   [7:5] current input phase
 *   [8] Ascon reset synchronization complete
 *
 * Software must use full-word stores for INPUT_DATA. For a partial final
 * word, valid bytes occupy the least-significant byte lanes; the wrapper
 * generates the corresponding keep mask from the configured length.
 */

module ascon_wrapper_wdma #(
    parameter type reg_req_t = logic,
    parameter type reg_rsp_t = logic
) (
    input logic clk_i,
    input logic rst_ni,

    input  reg_req_t reg_req_i,
    output reg_rsp_t reg_rsp_o,

    output logic dma_input_ready_o,
    output logic dma_output_valid_o
);

  // -------------------------------------------------------------------------
  // Register map and local types
  // -------------------------------------------------------------------------

  localparam logic [7:0] MODE_OFFSET = 8'h00;
  localparam logic [7:0] ED_OFFSET = 8'h04;
  localparam logic [7:0] HASH_LEN_OFFSET = 8'h08;
  localparam logic [7:0] AD_LEN_OFFSET = 8'h0c;
  localparam logic [7:0] DATA_LEN_OFFSET = 8'h10;
  localparam logic [7:0] CUSTOM_LEN_OFFSET = 8'h14;
  localparam logic [7:0] CONTROL_OFFSET = 8'h18;
  localparam logic [7:0] INPUT_DATA_OFFSET = 8'h1c;
  localparam logic [7:0] OUTPUT_DATA_OFFSET = 8'h20;
  localparam logic [7:0] STATUS_OFFSET = 8'h24;
  localparam logic [7:0] CYCLE_COUNT_OFFSET = 8'h28;
  localparam logic [7:0] INPUT_WAIT_OFFSET = 8'h2c;
  localparam logic [7:0] OUTPUT_WAIT_OFFSET = 8'h30;

  localparam logic [1:0] MODE_AEAD128 = 2'b00;
  localparam logic [1:0] MODE_HASH256 = 2'b01;
  localparam logic [1:0] MODE_XOF128 = 2'b10;
  localparam logic [1:0] MODE_CXOF128 = 2'b11;

  localparam int unsigned INPUT_FIFO_DEPTH = 4;
  localparam int unsigned INPUT_FIFO_PTR_WIDTH = $clog2(INPUT_FIFO_DEPTH);
  localparam int unsigned INPUT_FIFO_COUNT_WIDTH = $clog2(INPUT_FIFO_DEPTH + 1);
  localparam int unsigned OUTPUT_FIFO_DEPTH = 4;
  localparam int unsigned OUTPUT_FIFO_PTR_WIDTH = $clog2(OUTPUT_FIFO_DEPTH);
  localparam int unsigned OUTPUT_FIFO_COUNT_WIDTH = $clog2(OUTPUT_FIFO_DEPTH + 1);

  typedef enum logic [2:0] {
    PHASE_IDLE,
    PHASE_KEY,
    PHASE_NONCE,
    PHASE_AD,
    PHASE_TEXT,
    PHASE_CUSTOM,
    PHASE_TAG,
    PHASE_WAIT
  } phase_t;

  typedef enum logic [1:0] {
    OP_IDLE,
    OP_START,
    OP_RUN
  } operation_state_t;

  function automatic logic [31:0] apply_wstrb(
      input logic [31:0] old_value, input logic [31:0] new_value, input logic [3:0] write_strobe);
    logic [31:0] merged_value;
    merged_value = old_value;
    for (int unsigned byte_idx = 0; byte_idx < 4; byte_idx++) begin
      if (write_strobe[byte_idx]) merged_value[byte_idx*8+:8] = new_value[byte_idx*8+:8];
    end
    return merged_value;
  endfunction

  function automatic logic [3:0] keep_from_remaining(input logic [31:0] remaining_bytes);
    if (remaining_bytes >= 32'd4) return 4'b1111;
    case (remaining_bytes[2:0])
      3'd1:    return 4'b0001;
      3'd2:    return 4'b0011;
      3'd3:    return 4'b0111;
      default: return 4'b0000;
    endcase
  endfunction

  // -------------------------------------------------------------------------
  // Configuration and operation state
  // -------------------------------------------------------------------------

  logic             [                        1:0] cfg_mode_q;
  logic                                           cfg_ed_q;
  logic             [                       31:0] cfg_hash_len_q;
  logic             [                       31:0] cfg_ad_len_q;
  logic             [                       31:0] cfg_data_len_q;
  logic             [                       31:0] cfg_custom_len_q;

  logic             [                        1:0] active_mode_q;
  logic                                           active_ed_q;
  logic             [                       31:0] active_hash_len_q;
  logic             [                       31:0] active_ad_len_q;
  logic             [                       31:0] active_data_len_q;
  logic             [                       31:0] active_custom_len_q;

  operation_state_t                               operation_state_q;
  logic                                           busy_q;
  logic                                           done_q;
  logic                                           error_q;
  logic             [                       31:0] cycle_count_q;
  logic             [                       31:0] input_wait_count_q;
  logic             [                       31:0] output_wait_count_q;

  logic                                           configuration_valid;
  logic                                           start_request;
  logic                                           clear_status_request;
  logic                                           start_accept;
  logic                                           start_reject;

  // Ascon stream interface signals are declared before the phase controller
  // because configuration/start logic also observes reset completion.
  logic                                           ascon_reset_complete;
  logic                                           ascon_start;
  logic                                           ascon_core_done;
  logic                                           ascon_core_error;
  logic                                           ascon_key_en;
  logic                                           ascon_nonce_en;
  logic                                           ascon_assoc_en;
  logic                                           ascon_text_en;
  logic                                           ascon_custom_en;
  logic                                           ascon_input_request;
  logic                                           ascon_input_valid;
  logic             [                       31:0] ascon_data_in;
  logic             [                        3:0] ascon_data_keep;
  logic                                           ascon_data_last;
  logic                                           ascon_output_valid;
  logic                                           ascon_output_ready;
  logic             [                       31:0] ascon_data_out;
  logic             [                        3:0] ascon_output_keep;
  logic                                           ascon_output_last;
  logic                                           core_advance;
  logic                                           input_fire;
  logic                                           output_fire;

  logic             [                       31:0] input_fifo_data_q       [ INPUT_FIFO_DEPTH];
  logic             [                        3:0] input_fifo_keep_q       [ INPUT_FIFO_DEPTH];
  logic                                           input_fifo_last_q       [ INPUT_FIFO_DEPTH];
  logic             [   INPUT_FIFO_PTR_WIDTH-1:0] input_fifo_read_ptr_q;
  logic             [   INPUT_FIFO_PTR_WIDTH-1:0] input_fifo_write_ptr_q;
  logic             [ INPUT_FIFO_COUNT_WIDTH-1:0] input_fifo_count_q;
  logic                                           input_fifo_empty;
  logic                                           input_fifo_full;
  logic                                           input_fifo_can_push;
  logic                                           input_fifo_push;
  logic                                           input_fifo_pop;
  logic             [                       31:0] input_fifo_data_head;
  logic             [                        3:0] input_fifo_keep_head;
  logic                                           input_fifo_last_head;

  logic             [                       31:0] output_fifo_data_q      [OUTPUT_FIFO_DEPTH];
  logic             [  OUTPUT_FIFO_PTR_WIDTH-1:0] output_fifo_read_ptr_q;
  logic             [  OUTPUT_FIFO_PTR_WIDTH-1:0] output_fifo_write_ptr_q;
  logic             [OUTPUT_FIFO_COUNT_WIDTH-1:0] output_fifo_count_q;
  logic                                           output_fifo_empty;
  logic                                           output_fifo_full;
  logic                                           output_fifo_can_push;
  logic                                           output_fifo_push;
  logic                                           output_fifo_pop;
  logic             [                       31:0] output_fifo_data_head;
  logic                                           stream_output_access;

  assign configuration_valid =
      ((cfg_mode_q == MODE_AEAD128) ||
       (cfg_mode_q == MODE_HASH256) ||
       ((cfg_mode_q == MODE_XOF128) && (cfg_hash_len_q != 0)) ||
       ((cfg_mode_q == MODE_CXOF128) && (cfg_hash_len_q != 0) &&
        (cfg_custom_len_q <= 32'd264)));

  assign start_request = reg_req_i.valid && reg_req_i.write &&
                         (reg_req_i.addr[7:0] == CONTROL_OFFSET) &&
                         reg_req_i.wstrb[0] && reg_req_i.wdata[0];
  assign clear_status_request = reg_req_i.valid && reg_req_i.write &&
                                (reg_req_i.addr[7:0] == CONTROL_OFFSET) &&
                                reg_req_i.wstrb[0] && reg_req_i.wdata[1];
  // Do not allow a new operation to discard output that its DMA channel has
  // not drained yet.
  assign start_accept = start_request && !busy_q && output_fifo_empty &&
                        ascon_reset_complete && configuration_valid;
  assign start_reject = start_request && !start_accept;

  // -------------------------------------------------------------------------
  // Input phase controller
  // -------------------------------------------------------------------------

  phase_t        phase_q;
  phase_t        phase_load_value;
  logic          phase_load;
  logic          phase_complete;
  logic   [31:0] phase_byte_length;
  logic          phase_needs_empty_terminator;
  logic   [31:0] input_bytes_remaining_q;
  logic          empty_terminator_pending_q;

  logic          input_phase_request;
  logic          stream_input_access;
  logic          stream_input_access_legal;
  logic          input_word_ready;
  logic          inject_empty_terminator;

  always_comb begin : phase_next_value
    phase_load = 1'b0;
    phase_load_value = phase_q;

    if (operation_state_q == OP_START) begin
      phase_load = 1'b1;
      case (active_mode_q)
        MODE_AEAD128: phase_load_value = PHASE_KEY;
        MODE_CXOF128: phase_load_value = PHASE_CUSTOM;
        default:      phase_load_value = PHASE_TEXT;
      endcase
    end else if (phase_complete) begin
      phase_load = 1'b1;
      case (phase_q)
        PHASE_KEY: phase_load_value = PHASE_NONCE;
        PHASE_NONCE: phase_load_value = PHASE_AD;
        PHASE_AD: phase_load_value = PHASE_TEXT;
        PHASE_CUSTOM: phase_load_value = PHASE_TEXT;
        PHASE_TEXT:
        phase_load_value = ((active_mode_q == MODE_AEAD128) && active_ed_q) ?
                           PHASE_TAG : PHASE_WAIT;
        PHASE_TAG: phase_load_value = PHASE_WAIT;
        default: phase_load_value = PHASE_WAIT;
      endcase
    end
  end

  always_comb begin : phase_configuration
    phase_byte_length = 32'd0;
    phase_needs_empty_terminator = 1'b0;

    case (phase_load_value)
      PHASE_KEY:   phase_byte_length = 32'd16;
      PHASE_NONCE: phase_byte_length = 32'd16;

      PHASE_AD: begin
        phase_byte_length = active_ad_len_q;
        phase_needs_empty_terminator = (active_ad_len_q[3:0] == 4'd0);
      end

      PHASE_TEXT: begin
        phase_byte_length = active_data_len_q;
        if (active_mode_q == MODE_AEAD128)
          phase_needs_empty_terminator = (active_data_len_q == 32'd0);
        else phase_needs_empty_terminator = (active_data_len_q[2:0] == 3'd0);
      end

      PHASE_CUSTOM: begin
        phase_byte_length = active_custom_len_q;
        phase_needs_empty_terminator = (active_custom_len_q[2:0] == 3'd0);
      end

      PHASE_TAG: phase_byte_length = 32'd16;
      default:   ;
    endcase
  end

  always_comb begin : phase_input_request_select
    input_phase_request = 1'b0;
    case (phase_q)
      PHASE_KEY:    input_phase_request = ascon_key_en;
      PHASE_NONCE:  input_phase_request = ascon_nonce_en;
      PHASE_AD:     input_phase_request = ascon_assoc_en;
      PHASE_TEXT:   input_phase_request = ascon_text_en;
      PHASE_CUSTOM: input_phase_request = ascon_custom_en;
      PHASE_TAG:    input_phase_request = ascon_text_en;
      default:      input_phase_request = 1'b0;
    endcase
  end

  // -------------------------------------------------------------------------
  // Ascon stream interface
  // -------------------------------------------------------------------------

  assign ascon_start = (operation_state_q == OP_START);
  assign ascon_input_request = ascon_key_en | ascon_nonce_en |
                               ascon_assoc_en | ascon_text_en |
                               ascon_custom_en;

  assign inject_empty_terminator = busy_q && input_fifo_empty &&
                                   empty_terminator_pending_q &&
                                   (input_bytes_remaining_q == 0) &&
                                   input_phase_request;

  assign stream_input_access = reg_req_i.valid && reg_req_i.write &&
                               (reg_req_i.addr[7:0] == INPUT_DATA_OFFSET);
  assign stream_input_access_legal = stream_input_access &&
                                     (reg_req_i.wstrb == 4'b1111) &&
                                     busy_q && (phase_q != PHASE_WAIT);

  // The DMA may fill the FIFO while the core is permuting and has temporarily
  // deasserted its input request. input_bytes_remaining_q counts bytes that
  // have not yet been enqueued, rather than bytes not yet consumed by Ascon.
  assign input_word_ready = busy_q && (phase_q != PHASE_IDLE) &&
                            (phase_q != PHASE_WAIT) &&
                            (input_bytes_remaining_q != 0) &&
                            input_fifo_can_push;
  assign input_fifo_push = stream_input_access_legal && input_word_ready;

  assign ascon_input_valid = inject_empty_terminator || (!input_fifo_empty && input_phase_request);
  assign ascon_data_in = inject_empty_terminator ? 32'd0 : input_fifo_data_head;
  assign ascon_data_keep = inject_empty_terminator ? 4'b0000 : input_fifo_keep_head;
  assign ascon_data_last = inject_empty_terminator ? 1'b1 : input_fifo_last_head;

  assign stream_output_access = reg_req_i.valid && !reg_req_i.write &&
                                (reg_req_i.addr[7:0] == OUTPUT_DATA_OFFSET);
  assign output_fifo_pop = stream_output_access && !output_fifo_empty;
  assign output_fifo_can_push = !output_fifo_full || output_fifo_pop;
  assign ascon_output_ready = output_fifo_can_push;

  assign core_advance = (~ascon_input_request | ascon_input_valid) &&
                        (~ascon_output_valid | ascon_output_ready);
  assign input_fire = core_advance && ascon_input_request && ascon_input_valid;
  assign output_fire = core_advance && ascon_output_valid && ascon_output_ready;
  assign input_fifo_pop = input_fire && !inject_empty_terminator;
  assign output_fifo_push = output_fire;
  assign phase_complete = input_fire && ascon_data_last;

  // A simultaneous FIFO pop may free a full slot in the same cycle.
  assign input_fifo_empty = (input_fifo_count_q == 0);
  assign input_fifo_full = (input_fifo_count_q == INPUT_FIFO_COUNT_WIDTH'(INPUT_FIFO_DEPTH));
  assign input_fifo_can_push = !input_fifo_full || input_fifo_pop;
  assign input_fifo_data_head = input_fifo_data_q[input_fifo_read_ptr_q];
  assign input_fifo_keep_head = input_fifo_keep_q[input_fifo_read_ptr_q];
  assign input_fifo_last_head = input_fifo_last_q[input_fifo_read_ptr_q];

  assign output_fifo_empty = (output_fifo_count_q == 0);
  assign output_fifo_full = (output_fifo_count_q == OUTPUT_FIFO_COUNT_WIDTH'(OUTPUT_FIFO_DEPTH));
  assign output_fifo_data_head = output_fifo_data_q[output_fifo_read_ptr_q];

  // The trigger levels advertise that the corresponding fixed-address DMA
  // access can enqueue/dequeue a FIFO word.
  assign dma_input_ready_o = input_word_ready;
  assign dma_output_valid_o = !output_fifo_empty;

  // -------------------------------------------------------------------------
  // Register slave
  // -------------------------------------------------------------------------

  logic configuration_register_write;

  always_comb begin : register_response
    reg_rsp_o = '0;
    reg_rsp_o.ready = 1'b1;

    if (reg_req_i.valid) begin
      case (reg_req_i.addr[7:0])
        MODE_OFFSET: begin
          reg_rsp_o.rdata = {30'd0, cfg_mode_q};
          if (reg_req_i.write && busy_q) reg_rsp_o.error = 1'b1;
        end

        ED_OFFSET: begin
          reg_rsp_o.rdata = {31'd0, cfg_ed_q};
          if (reg_req_i.write && busy_q) reg_rsp_o.error = 1'b1;
        end

        HASH_LEN_OFFSET: begin
          reg_rsp_o.rdata = cfg_hash_len_q;
          if (reg_req_i.write && busy_q) reg_rsp_o.error = 1'b1;
        end

        AD_LEN_OFFSET: begin
          reg_rsp_o.rdata = cfg_ad_len_q;
          if (reg_req_i.write && busy_q) reg_rsp_o.error = 1'b1;
        end

        DATA_LEN_OFFSET: begin
          reg_rsp_o.rdata = cfg_data_len_q;
          if (reg_req_i.write && busy_q) reg_rsp_o.error = 1'b1;
        end

        CUSTOM_LEN_OFFSET: begin
          reg_rsp_o.rdata = cfg_custom_len_q;
          if (reg_req_i.write && busy_q) reg_rsp_o.error = 1'b1;
        end

        CONTROL_OFFSET: begin
          if (!reg_req_i.write) begin
            reg_rsp_o.error = 1'b1;
          end else if (reg_req_i.wstrb[0] && reg_req_i.wdata[0] && !start_accept) begin
            reg_rsp_o.error = 1'b1;
          end
        end

        INPUT_DATA_OFFSET: begin
          if (!reg_req_i.write || (reg_req_i.wstrb != 4'b1111) || !busy_q ||
              (phase_q == PHASE_WAIT)) begin
            reg_rsp_o.error = 1'b1;
          end else begin
            reg_rsp_o.ready = input_fifo_push;
          end
        end

        OUTPUT_DATA_OFFSET: begin
          if (reg_req_i.write) begin
            reg_rsp_o.error = 1'b1;
          end else if (!output_fifo_empty) begin
            reg_rsp_o.rdata = output_fifo_data_head;
          end else if (busy_q) begin
            reg_rsp_o.ready = 1'b0;
          end else begin
            reg_rsp_o.error = 1'b1;
          end
        end

        STATUS_OFFSET: begin
          if (reg_req_i.write) begin
            reg_rsp_o.error = 1'b1;
          end else begin
            reg_rsp_o.rdata = {
              23'd0,
              ascon_reset_complete,
              phase_q,
              !output_fifo_empty,
              input_word_ready,
              busy_q,
              error_q,
              done_q
            };
          end
        end

        CYCLE_COUNT_OFFSET: begin
          if (reg_req_i.write) reg_rsp_o.error = 1'b1;
          else reg_rsp_o.rdata = cycle_count_q;
        end

        INPUT_WAIT_OFFSET: begin
          if (reg_req_i.write) reg_rsp_o.error = 1'b1;
          else reg_rsp_o.rdata = input_wait_count_q;
        end

        OUTPUT_WAIT_OFFSET: begin
          if (reg_req_i.write) reg_rsp_o.error = 1'b1;
          else reg_rsp_o.rdata = output_wait_count_q;
        end

        default: reg_rsp_o.error = 1'b1;
      endcase
    end
  end

  assign configuration_register_write = reg_req_i.valid && reg_req_i.write &&
                                        reg_rsp_o.ready && !reg_rsp_o.error && !busy_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin : configuration_registers
    if (!rst_ni) begin
      cfg_mode_q       <= MODE_AEAD128;
      cfg_ed_q         <= 1'b0;
      cfg_hash_len_q   <= 32'd0;
      cfg_ad_len_q     <= 32'd0;
      cfg_data_len_q   <= 32'd0;
      cfg_custom_len_q <= 32'd0;
    end else if (configuration_register_write) begin
      case (reg_req_i.addr[7:0])
        MODE_OFFSET: if (reg_req_i.wstrb[0]) cfg_mode_q <= reg_req_i.wdata[1:0];
        ED_OFFSET: if (reg_req_i.wstrb[0]) cfg_ed_q <= reg_req_i.wdata[0];
        HASH_LEN_OFFSET:
        cfg_hash_len_q <= apply_wstrb(cfg_hash_len_q, reg_req_i.wdata, reg_req_i.wstrb);
        AD_LEN_OFFSET: cfg_ad_len_q <= apply_wstrb(cfg_ad_len_q, reg_req_i.wdata, reg_req_i.wstrb);
        DATA_LEN_OFFSET:
        cfg_data_len_q <= apply_wstrb(cfg_data_len_q, reg_req_i.wdata, reg_req_i.wstrb);
        CUSTOM_LEN_OFFSET:
        cfg_custom_len_q <= apply_wstrb(cfg_custom_len_q, reg_req_i.wdata, reg_req_i.wstrb);
        default: ;
      endcase
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : active_configuration_registers
    if (!rst_ni) begin
      active_mode_q       <= MODE_AEAD128;
      active_ed_q         <= 1'b0;
      active_hash_len_q   <= 32'd0;
      active_ad_len_q     <= 32'd0;
      active_data_len_q   <= 32'd0;
      active_custom_len_q <= 32'd0;
    end else if (start_accept) begin
      active_mode_q       <= cfg_mode_q;
      active_ed_q         <= cfg_ed_q;
      active_hash_len_q   <= cfg_hash_len_q;
      active_ad_len_q     <= cfg_ad_len_q;
      active_data_len_q   <= cfg_data_len_q;
      active_custom_len_q <= cfg_custom_len_q;
    end
  end

  // -------------------------------------------------------------------------
  // Operation and phase state registers
  // -------------------------------------------------------------------------

  always_ff @(posedge clk_i or negedge rst_ni) begin : operation_controller
    if (!rst_ni) begin
      operation_state_q <= OP_IDLE;
      busy_q            <= 1'b0;
      done_q            <= 1'b0;
      error_q           <= 1'b0;
    end else begin
      if (clear_status_request) begin
        done_q  <= 1'b0;
        error_q <= 1'b0;
      end

      case (operation_state_q)
        OP_IDLE: begin
          busy_q <= 1'b0;
          if (start_accept) begin
            operation_state_q <= OP_START;
            busy_q            <= 1'b1;
            done_q            <= 1'b0;
            error_q           <= 1'b0;
          end else if (start_reject) begin
            done_q  <= 1'b1;
            error_q <= 1'b1;
          end
        end

        OP_START: operation_state_q <= OP_RUN;

        OP_RUN: begin
          if (ascon_core_done) begin
            operation_state_q <= OP_IDLE;
            busy_q            <= 1'b0;
            done_q            <= 1'b1;
            error_q           <= ascon_core_error;
          end
        end

        default: begin
          operation_state_q <= OP_IDLE;
          busy_q            <= 1'b0;
          done_q            <= 1'b1;
          error_q           <= 1'b1;
        end
      endcase
    end
  end

  // Hardware-side measurements exclude software setup and polling overhead.
  // Saturation prevents a pathological stalled transaction from wrapping.
  always_ff @(posedge clk_i or negedge rst_ni) begin : performance_counters
    if (!rst_ni) begin
      cycle_count_q       <= 32'd0;
      input_wait_count_q  <= 32'd0;
      output_wait_count_q <= 32'd0;
    end else if (start_accept) begin
      cycle_count_q       <= 32'd0;
      input_wait_count_q  <= 32'd0;
      output_wait_count_q <= 32'd0;
    end else if (busy_q) begin
      if ((&cycle_count_q) == 1'b0) cycle_count_q <= cycle_count_q + 32'd1;
      if (ascon_input_request && !ascon_input_valid && ((&input_wait_count_q) == 1'b0))
        input_wait_count_q <= input_wait_count_q + 32'd1;
      if (ascon_output_valid && !ascon_output_ready && ((&output_wait_count_q) == 1'b0))
        output_wait_count_q <= output_wait_count_q + 32'd1;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : phase_registers
    if (!rst_ni) begin
      phase_q                    <= PHASE_IDLE;
      input_bytes_remaining_q    <= 32'd0;
      empty_terminator_pending_q <= 1'b0;
    end else if (start_accept) begin
      phase_q                    <= PHASE_IDLE;
      input_bytes_remaining_q    <= 32'd0;
      empty_terminator_pending_q <= 1'b0;
    end else if (phase_load) begin
      phase_q                    <= phase_load_value;
      input_bytes_remaining_q    <= phase_byte_length;
      empty_terminator_pending_q <= phase_needs_empty_terminator;
    end else begin
      if (input_fifo_push) begin
        if (input_bytes_remaining_q > 32'd4) begin
          input_bytes_remaining_q <= input_bytes_remaining_q - 32'd4;
        end else begin
          input_bytes_remaining_q <= 32'd0;
        end
      end

      if (input_fire && inject_empty_terminator) empty_terminator_pending_q <= 1'b0;

      if (operation_state_q == OP_IDLE) begin
        phase_q                    <= PHASE_IDLE;
        input_bytes_remaining_q    <= 32'd0;
        empty_terminator_pending_q <= 1'b0;
      end
    end
  end

  // -------------------------------------------------------------------------
  // Four-word input/output FIFOs
  // -------------------------------------------------------------------------

  always_ff @(posedge clk_i or negedge rst_ni) begin : input_fifo_registers
    if (!rst_ni) begin
      input_fifo_read_ptr_q  <= '0;
      input_fifo_write_ptr_q <= '0;
      input_fifo_count_q     <= '0;
    end else if (start_accept) begin
      input_fifo_read_ptr_q  <= '0;
      input_fifo_write_ptr_q <= '0;
      input_fifo_count_q     <= '0;
    end else begin
      if (input_fifo_push) begin
        input_fifo_data_q[input_fifo_write_ptr_q] <= reg_req_i.wdata;
        input_fifo_keep_q[input_fifo_write_ptr_q] <= keep_from_remaining(input_bytes_remaining_q);
        input_fifo_last_q[input_fifo_write_ptr_q] <=
            (input_bytes_remaining_q <= 32'd4) && !empty_terminator_pending_q;
        input_fifo_write_ptr_q <= input_fifo_write_ptr_q + 1'b1;
      end

      if (input_fifo_pop) input_fifo_read_ptr_q <= input_fifo_read_ptr_q + 1'b1;

      case ({
        input_fifo_push, input_fifo_pop
      })
        2'b10:   input_fifo_count_q <= input_fifo_count_q + 1'b1;
        2'b01:   input_fifo_count_q <= input_fifo_count_q - 1'b1;
        default: ;
      endcase
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : output_fifo_registers
    if (!rst_ni) begin
      output_fifo_read_ptr_q  <= '0;
      output_fifo_write_ptr_q <= '0;
      output_fifo_count_q     <= '0;
    end else if (start_accept) begin
      output_fifo_read_ptr_q  <= '0;
      output_fifo_write_ptr_q <= '0;
      output_fifo_count_q     <= '0;
    end else begin
      if (output_fifo_push) begin
        output_fifo_data_q[output_fifo_write_ptr_q] <= ascon_data_out;
        output_fifo_write_ptr_q <= output_fifo_write_ptr_q + 1'b1;
      end

      if (output_fifo_pop) output_fifo_read_ptr_q <= output_fifo_read_ptr_q + 1'b1;

      case ({
        output_fifo_push, output_fifo_pop
      })
        2'b10:   output_fifo_count_q <= output_fifo_count_q + 1'b1;
        2'b01:   output_fifo_count_q <= output_fifo_count_q - 1'b1;
        default: ;
      endcase
    end
  end

  // -------------------------------------------------------------------------
  // Ascon core
  // -------------------------------------------------------------------------

  Ascon ascon_i (
      .clk(clk_i),
      .rst(~rst_ni),
      .rst_complete_o(ascon_reset_complete),
      .start(ascon_start),
      .input_valid(ascon_input_valid),
      .output_ready(ascon_output_ready),
      .mode(active_mode_q),
      .ED(active_ed_q),
      .key_en(ascon_key_en),
      .nonce_en(ascon_nonce_en),
      .assoc_en(ascon_assoc_en),
      .text_en(ascon_text_en),
      .custom_en(ascon_custom_en),
      .Data_in(ascon_data_in),
      .data_last(ascon_data_last),
      .data_keep(ascon_data_keep),
      .hash_len(active_hash_len_q),
      .Data_out(ascon_data_out),
      .output_valid(ascon_output_valid),
      .output_last(ascon_output_last),
      .output_keep(ascon_output_keep),
      .done(ascon_core_done),
      .error(ascon_core_error)
  );

  // The CPU already knows the requested output length. These sidebands do not
  // need storage in the data-only output FIFO or software-visible registers.
  logic unused_stream_sidebands;
  assign unused_stream_sidebands = ^{ascon_output_keep, ascon_output_last};

endmodule
