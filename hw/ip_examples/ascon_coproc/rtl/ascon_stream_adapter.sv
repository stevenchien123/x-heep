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
    output logic busy_o
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
    WAIT_CONFIG,
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
  assign start = (cur_state == WAIT_CONFIG);
  assign input_ready = (key_en || nonce_en || assoc_en || text_en || custom_en);

  logic rst_complete_o, rst_clear_n, rst_ascon_n;
  // A pulse reset signal
  assign rst_clear_n = !(cur_state == ASSERT_CLEAR);
  assign rst_ascon_n = rst_ni && rst_clear_n;

  logic counter;  // For PUSH command
  always_ff @(posedge clk_i or negedge rst_ni) begin : counter_logic
    if (!rst_ni) begin
      counter <= '0;
    end else begin
      if (cur_state == WAIT_PUSH && input_valid && input_ready) begin
        counter <= counter + 1;
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

    if (cur_state == WAIT_PUSH) begin
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
      if (cur_state == WAIT_POP && output_valid && output_ready) begin
        pop_data <= data_out;
      end else if (cur_state == WAIT_STATUS && (done || done_reg)) begin
        pop_data <= {31'b0, error || error_reg};
      end
    end
  end
  assign output_ready = (cur_state == WAIT_POP);

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
            CMD_CONFIG: nxt_state = WAIT_CONFIG;
            CMD_PUSH:   nxt_state = WAIT_PUSH;
            CMD_POP:    nxt_state = WAIT_POP;
            CMD_CLEAR:  nxt_state = ASSERT_CLEAR;
            CMD_STATUS: nxt_state = WAIT_STATUS;
            default:    nxt_state = IDLE;
          endcase
        end
      end

      WAIT_CONFIG: begin
        nxt_state = IDLE;
      end

      WAIT_PUSH: begin
        // the value of nxt_state is depends on push_last0/1,
        // if push_last0 is set, only send 1 32-bit data into Ascon, nxt_state is IDLE,
        // otherwise, send 2 32-bit data into Ascon, stay in WAIT_PUSH until the second data was sent.
        if (input_valid && input_ready && (push_last0_reg || counter == 1)) begin
          nxt_state = IDLE;
        end
      end

      WAIT_POP: begin
        if (output_valid && output_ready) begin
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
      .mode(cfg_mode_reg),
      .ED(cfg_ed_reg),
      .key_en(key_en),
      .nonce_en(nonce_en),
      .assoc_en(assoc_en),
      .text_en(text_en),
      .custom_en(custom_en),
      .input_valid(input_valid),
      .Data_in(data_in),
      .data_last(data_in_last),
      .data_keep(data_in_keep),
      .hash_len(cfg_hash_len_reg),
      .Data_out(data_out),
      .output_valid(output_valid),
      .output_ready(output_ready),
      .output_last(),
      .output_keep(),
      .done(done),
      .error(error)
  );

endmodule
