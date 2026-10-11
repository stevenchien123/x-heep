module ascon_stream_adapter (
    input logic clk_i,
    input logic rst_ni,

    //
    input logic [4:0] command_type,
    input logic       command_valid,

    // Coproc -> Adapter: CONFIG
    input logic [ 1:0] cfg_mode,
    input logic        cfg_ed,
    input logic [31:0] cfg_hash_len,

    // Coproc -> Adapter: PUSH
    input logic [31:0] push_data0,
    input logic [31:0] push_data1,
    input logic [ 3:0] push_keep0,
    input logic [ 3:0] push_keep1,
    input logic        push_last0,
    input logic        push_last1,

    // Adapter -> Coproc: POP
    output logic [31:0] pop_data,

    // Adapter -> Coproc: busy signal
    output logic busy_o,

    // Pulses when the current command completes.  This lets the outer CV-X-IF
    // controller enter RESULT without waiting an extra cycle for busy_o to fall.
    output logic command_done_o
);
  typedef enum logic [4:0] {
    CMD_CONFIG = 5'b00001,
    CMD_PUSH   = 5'b00010,
    CMD_POP    = 5'b00100,
    CMD_CLEAR  = 5'b01000,
    CMD_STATUS = 5'b10000
  } command_type_t;

  typedef enum logic [2:0] {
    IDLE,
    WAIT_PUSH,
    WAIT_POP,
    ASSERT_CLEAR,
    WAIT_CLEAR,
    WAIT_STATUS
  } state_t;
  state_t cur_state, nxt_state;

  logic [ 1:0] cfg_mode_reg;
  logic        cfg_ed_reg;
  logic [31:0] cfg_hash_len_reg;
  logic [31:0] push_data0_reg;
  logic [31:0] push_data1_reg;
  logic [ 3:0] push_keep0_reg;
  logic [ 3:0] push_keep1_reg;
  logic        push_last0_reg;
  logic        push_last1_reg;

  logic        start;
  logic key_en, nonce_en, assoc_en, text_en, custom_en;
  logic input_valid, input_ready, data_in_last;
  logic [31:0] data_in;
  logic [ 3:0] data_in_keep;
  logic output_valid, output_ready;
  logic [31:0] data_out;
  logic done, error;
  logic done_reg, error_reg;
  logic input_accept, output_accept;
  logic [1:0] core_mode;
  logic core_ed;
  logic [31:0] core_hash_len;

  // CONFIG is consumed directly in the issue cycle.  The direct muxes are
  // required because cfg_*_reg is updated at the same clock edge at which the
  // Ascon core samples start and its configuration inputs.
  assign start = (cur_state == IDLE) && command_valid && (command_type == CMD_CONFIG);
  assign core_mode = start ? cfg_mode : cfg_mode_reg;
  assign core_ed = start ? cfg_ed : cfg_ed_reg;
  assign core_hash_len = start ? cfg_hash_len : cfg_hash_len_reg;

  assign input_ready = (key_en || nonce_en || assoc_en || text_en || custom_en);

  // An input/output word is accepted only when the Ascon core can advance as a
  // whole.  In particular, a blocked output must not make the adapter consume
  // an input word that the core has not actually sampled.
  assign input_accept = input_valid && input_ready && (!output_valid || output_ready);
  assign output_accept = output_valid && output_ready && (!input_ready || input_valid);

  logic rst_complete_o, rst_clear_n, rst_ascon_n;
  // A pulse reset signal
  assign rst_clear_n = !(cur_state == ASSERT_CLEAR);
  assign rst_ascon_n = rst_ni && rst_clear_n;

  logic counter;  // For PUSH command
  always_ff @(posedge clk_i or negedge rst_ni) begin : counter_logic
    if (!rst_ni) begin
      counter <= '0;
    end else begin
      if (cur_state == IDLE && command_valid && (command_type == CMD_PUSH)) begin
        // The first word is offered directly in the issue cycle.  If it is
        // accepted and a second word exists, WAIT_PUSH starts from word 1.
        counter <= (input_accept && !push_last0) ? 1'b1 : 1'b0;
      end else if (cur_state == WAIT_PUSH && input_accept) begin
        counter <= counter + 1'b1;
      end else if (cur_state != WAIT_PUSH) begin
        counter <= '0;
      end
    end
  end

  always_comb begin : data_in_logic
    data_in = '0;
    data_in_keep = '0;
    data_in_last = 1'b0;
    input_valid = 1'b0;

    if (cur_state == IDLE && command_valid && (command_type == CMD_PUSH)) begin
      // Fast path: do not spend a cycle merely copying the first PUSH word into
      // the adapter registers.
      input_valid = 1'b1;
      data_in = push_data0;
      data_in_keep = push_keep0;
      data_in_last = push_last0;
    end else if (cur_state == WAIT_PUSH) begin
      input_valid = 1'b1;
      if (counter == 0) begin
        data_in = push_data0_reg;
        data_in_keep = push_keep0_reg;
        data_in_last = push_last0_reg;
      end else if (counter == 1) begin
        data_in = push_data1_reg;
        data_in_keep = push_keep1_reg;
        data_in_last = push_last1_reg;
      end
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : data_out_logic
    if (!rst_ni) begin
      pop_data <= '0;
    end else begin
      if (output_accept) begin
        pop_data <= data_out;
      end else if (((cur_state == IDLE && command_valid && (command_type == CMD_STATUS)) ||
                    cur_state == WAIT_STATUS) && (done || done_reg)) begin
        pop_data <= {31'b0, error || error_reg};
      end
    end
  end
  // POP also has a direct path when the core is already presenting output.
  assign output_ready = (cur_state == WAIT_POP) ||
                        (cur_state == IDLE && command_valid && (command_type == CMD_POP));

  // STATUS may execute after done signal is asserted, so we need to latch the done/error signals to ensure they are available for STATUS command.
  always_ff @(posedge clk_i or negedge rst_ni) begin : done_error_reg_logic
    if (!rst_ni) begin
      done_reg  <= 1'b0;
      error_reg <= 1'b0;
    end else if (command_valid && (command_type == CMD_CLEAR || command_type == CMD_CONFIG)) begin
      done_reg  <= 1'b0;
      error_reg <= 1'b0;
    end else if (done) begin
      done_reg  <= 1'b1;
      error_reg <= error;
    end
  end


  always_ff @(posedge clk_i or negedge rst_ni) begin : state_register
    if (!rst_ni) begin
      cur_state <= IDLE;
    end else begin
      cur_state <= nxt_state;
    end
  end

  always_comb begin : nxt_state_logic
    nxt_state = cur_state;

    unique case (cur_state)
      IDLE: begin
        if (command_valid) begin
          unique case (command_type)
            CMD_CONFIG: nxt_state = IDLE;
            CMD_PUSH: begin
              if (input_accept && push_last0) nxt_state = IDLE;
              else nxt_state = WAIT_PUSH;
            end
            CMD_POP: begin
              if (output_accept) nxt_state = IDLE;
              else nxt_state = WAIT_POP;
            end
            CMD_CLEAR:  nxt_state = ASSERT_CLEAR;
            CMD_STATUS: begin
              if (done || done_reg) nxt_state = IDLE;
              else nxt_state = WAIT_STATUS;
            end
            default:    nxt_state = IDLE;
          endcase
        end
      end

      WAIT_PUSH: begin
        // the value of nxt_state is depends on push_last0/1,
        // if push_last0 is set, only send 1 32-bit data into Ascon, nxt_state is IDLE,
        // otherwise, send 2 32-bit data into Ascon, stay in WAIT_PUSH until the second data was sent.
        if (input_accept && (push_last0_reg || counter == 1)) begin
          nxt_state = IDLE;
        end
      end

      WAIT_POP: begin
        if (output_accept) begin
          nxt_state = IDLE;
        end
      end

      ASSERT_CLEAR: begin
        nxt_state = WAIT_CLEAR;
      end

      WAIT_CLEAR: begin
        if (rst_complete_o) begin
          nxt_state = IDLE;
        end
      end

      WAIT_STATUS: begin
        if (done || done_reg) begin
          nxt_state = IDLE;
        end
      end
    endcase
  end

  // Report completion in the actual handshake cycle rather than one cycle
  // later after cur_state has returned to IDLE.
  always_comb begin : command_done_logic
    command_done_o = 1'b0;

    unique case (cur_state)
      IDLE: begin
        if (command_valid) begin
          unique case (command_type)
            CMD_CONFIG: command_done_o = 1'b1;
            CMD_PUSH:   command_done_o = input_accept && push_last0;
            CMD_POP:    command_done_o = output_accept;
            CMD_STATUS: command_done_o = done || done_reg;
            default:    command_done_o = 1'b0;
          endcase
        end
      end

      WAIT_PUSH:   command_done_o = input_accept && (push_last0_reg || counter == 1);
      WAIT_POP:    command_done_o = output_accept;
      WAIT_CLEAR:  command_done_o = rst_complete_o;
      WAIT_STATUS: command_done_o = done || done_reg;
      default:     command_done_o = 1'b0;
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cfg_mode_reg     <= '0;
      cfg_ed_reg       <= '0;
      cfg_hash_len_reg <= '0;
      push_data0_reg   <= '0;
      push_data1_reg   <= '0;
      push_keep0_reg   <= '0;
      push_keep1_reg   <= '0;
      push_last0_reg   <= '0;
      push_last1_reg   <= '0;
    end else begin
      if (command_valid) begin
        if (command_type == CMD_CONFIG) begin
          cfg_mode_reg     <= cfg_mode;
          cfg_ed_reg       <= cfg_ed;
          cfg_hash_len_reg <= cfg_hash_len;
        end else if (command_type == CMD_PUSH) begin
          push_data0_reg <= push_data0;
          push_data1_reg <= push_data1;
          push_keep0_reg <= push_keep0;
          push_keep1_reg <= push_keep1;
          push_last0_reg <= push_last0;
          push_last1_reg <= push_last1;
        end
      end
    end
  end

  assign busy_o = (cur_state != IDLE);

  Ascon ascon_i (
      .clk(clk_i),
      .rst(~rst_ascon_n),
      .rst_complete_o(rst_complete_o),
      .start(start),
      .mode(core_mode),
      .ED(core_ed),
      .key_en(key_en),
      .nonce_en(nonce_en),
      .assoc_en(assoc_en),
      .text_en(text_en),
      .custom_en(custom_en),
      .input_valid(input_valid),
      .Data_in(data_in),
      .data_last(data_in_last),
      .data_keep(data_in_keep),
      .hash_len(core_hash_len),
      .Data_out(data_out),
      .output_valid(output_valid),
      .output_ready(output_ready),
      .output_last(),
      .output_keep(),
      .done(done),
      .error(error)
  );

endmodule
