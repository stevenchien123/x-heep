/*
 *  Ascon Coprocessor
 *
 *  Custom instructions:
 *    Machine code: (OPCODE = 0x0B = 7'b0001011)
 *    R4-type:
 *    31       27 26 25 24       20 19        15  14    12 11      7 6       0
 *    +-----------+-----+-----------+-----------+--------+----------+---------+
 *    |    rs3    | 00  |    rs2    |    rs1    | funct3 |    rd    | 0001011 |
 *    +-----------+-----+-----------+-----------+--------+----------+---------+
 *
 *    R-type:
 *    31       25 24       20 19       15 14    12 11         7 6       0
 *    +-----------+-----------+-----------+--------+-----------+---------+
 *    |   func7   |    rs2    |    rs1    | func3  |    rd     | 0001011 |
 *    +-----------+-----------+-----------+--------+-----------+---------+
 *
 *    1. CONFIG:
 *      * R-type, send metadata to coproc (mode, ED, hash_len)
 *      * func3=3'b000, func7=7'b0000001
 *      * rs1[1:0] = mode, rs1[2] = ED, rs2[31:0] = hash_len
 *    2. PUSH  :
 *      * R4-type, send data into coproc (Key, Nonce, AD, PT/CT, message), rs1 and rs2 send data, rs3 send metadata (data_keep, data_last)
 *      * func3=3'b001
 *      * rs1[31:0] & rs2[31:0] = data, rs3[7:0] = data_keep, rs3[8:9] = data_last
 *    3. POP   :
 *      * R-type,  receive coproc output (CT/PT, tag, hash message), read 32-bit output
 *      * func3=3'b010, func7=7'b0000001
 *      * rd[31:0] = data
 *    4. CLEAR :
 *      * R-type,  clear Ascon state
 *      * func3=3'b011, func7=7'b0000001
 *      * nothing to send or receive
 *    5. STATUS:
 *      * R-type,  read Ascon error output
 *      * func3=3'b100, func7=7'b0000001
 *
 *
 */

module ascon_coproc #(
    parameter int unsigned X_ID_WIDTH = 4
) (
    input logic clk_i,
    input logic rst_ni,

    if_xif.coproc_compressed xif_compressed_if,
    if_xif.coproc_issue      xif_issue_if,
    if_xif.coproc_commit     xif_commit_if,
    if_xif.coproc_mem        xif_mem_if,
    if_xif.coproc_mem_result xif_mem_result_if,
    if_xif.coproc_result     xif_result_if
);

  // Compressed & Memory interfaces are unused, assign to 0.
  assign xif_compressed_if.compressed_ready = 1'b1;
  assign xif_compressed_if.compressed_resp = '0;
  assign xif_mem_if.mem_valid = 1'b0;
  assign xif_mem_if.mem_req = '0;

  typedef enum logic [1:0] {
    IDLE,
    WAIT_ASCON,
    RESULT
  } state_t;
  state_t cur_state, nxt_state;

  logic instruction_supported;
  logic is_config, is_push, is_pop, is_clear, is_status;
  assign is_config = (xif_issue_if.issue_req.instr[6:0] == 7'h0B && xif_issue_if.issue_req.instr[14:12] == 3'b000 && xif_issue_if.issue_req.instr[31:25] == 7'b0000001);
  assign is_push   = (xif_issue_if.issue_req.instr[6:0] == 7'h0B && xif_issue_if.issue_req.instr[14:12] == 3'b001 && xif_issue_if.issue_req.instr[26:25] == 2'b00);
  assign is_pop    = (xif_issue_if.issue_req.instr[6:0] == 7'h0B && xif_issue_if.issue_req.instr[14:12] == 3'b010 && xif_issue_if.issue_req.instr[31:25] == 7'b0000001);
  assign is_clear  = (xif_issue_if.issue_req.instr[6:0] == 7'h0B && xif_issue_if.issue_req.instr[14:12] == 3'b011 && xif_issue_if.issue_req.instr[31:25] == 7'b0000001);
  assign is_status = (xif_issue_if.issue_req.instr[6:0] == 7'h0B && xif_issue_if.issue_req.instr[14:12] == 3'b100 && xif_issue_if.issue_req.instr[31:25] == 7'b0000001);
  assign instruction_supported = is_config || is_push || is_pop || is_clear || is_status;

  logic [ 4:0] command_type;
  logic        command_valid;
  logic [ 1:0] cfg_mode;
  logic        cfg_ed;
  logic [31:0] cfg_hash_len;
  logic [31:0] push_data0;
  logic [31:0] push_data1;
  logic [ 3:0] push_keep0;
  logic [ 3:0] push_keep1;
  logic        push_last0;
  logic        push_last1;
  logic [31:0] pop_data;
  logic        ascon_busy;
  assign command_type = {is_status, is_clear, is_pop, is_push, is_config};
  assign command_valid = xif_issue_if.issue_valid && xif_issue_if.issue_ready && instruction_supported;
  assign cfg_mode = xif_issue_if.issue_req.rs[0][1:0];
  assign cfg_ed = xif_issue_if.issue_req.rs[0][2];
  assign cfg_hash_len = xif_issue_if.issue_req.rs[1];
  assign push_data0 = xif_issue_if.issue_req.rs[0];
  assign push_data1 = xif_issue_if.issue_req.rs[1];
  assign push_keep0 = xif_issue_if.issue_req.rs[2][3:0];
  assign push_keep1 = xif_issue_if.issue_req.rs[2][7:4];
  assign push_last0 = xif_issue_if.issue_req.rs[2][8];
  assign push_last1 = xif_issue_if.issue_req.rs[2][9];



  always_ff @(posedge clk_i or negedge rst_ni) begin
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
        if (xif_issue_if.issue_valid && xif_issue_if.issue_ready) begin
          if (instruction_supported) nxt_state = WAIT_ASCON;
          else nxt_state = IDLE;
        end
      end

      WAIT_ASCON: begin
        if (!ascon_busy) begin
          nxt_state = RESULT;
        end
      end

      RESULT: begin
        if (xif_result_if.result_valid && xif_result_if.result_ready) begin
          nxt_state = IDLE;
        end
      end
    endcase
  end

  logic operands_valid;
  always_comb begin : operands_valid_logic
    operands_valid = 1'b1;

    if (is_config) begin
      // CONFIG is R-type: rs1=control, rs2=hash_len
      operands_valid = &xif_issue_if.issue_req.rs_valid[1:0];
    end else if (is_push) begin
      // PUSH is R4-type: rs1=data0, rs2=data1, rs3=metadata
      operands_valid = &xif_issue_if.issue_req.rs_valid[2:0];
    end else begin
      // POP, CLEAR and unsupported instructions need no operand
      operands_valid = 1'b1;
    end
  end

  logic [X_ID_WIDTH-1:0] id_reg;
  logic [           4:0] rd_reg;
  logic                  is_pop_reg;
  logic                  is_status_reg;
  // logic [31:0]           pop_data_reg;

  always_comb begin : interface_signals
    xif_issue_if.issue_ready   = 1'b0;
    xif_issue_if.issue_resp    = '0;
    xif_result_if.result_valid = 1'b0;
    xif_result_if.result       = '0;

    unique case (cur_state)
      IDLE: begin
        xif_issue_if.issue_ready          = operands_valid;
        xif_issue_if.issue_resp.accept    = instruction_supported;
        xif_issue_if.issue_resp.writeback = is_pop || is_status;
      end

      RESULT: begin
        xif_result_if.result_valid = 1'b1;
        xif_result_if.result.id    = id_reg;
        xif_result_if.result.data  = (is_pop_reg || is_status_reg) ? pop_data : '0;
        xif_result_if.result.rd    = (is_pop_reg || is_status_reg) ? rd_reg : '0;
        xif_result_if.result.we    = (is_pop_reg || is_status_reg) ? 1'b1 : 1'b0;
      end

      default: begin

      end
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      id_reg <= '0;
      rd_reg <= '0;
      is_pop_reg <= 1'b0;
      is_status_reg <= 1'b0;
    end else begin
      if (xif_issue_if.issue_valid && xif_issue_if.issue_ready && instruction_supported) begin
        id_reg <= xif_issue_if.issue_req.id;
        rd_reg <= xif_issue_if.issue_req.instr[11:7];
        is_pop_reg <= is_pop;
        is_status_reg <= is_status;
      end
    end
  end

  // always_ff @( posedge clk_i or negedge rst_ni ) begin
  //     if(!rst_ni) begin
  //         pop_data_reg <= '0;
  //     end else begin
  //         if(cur_state == WAIT_ASCON && !ascon_busy && is_pop) begin
  //             pop_data_reg <= pop_data;
  //         end
  //     end
  // end

  ascon_stream_adapter ascon_stream_adapter_i (
      .clk_i(clk_i),
      .rst_ni(rst_ni),
      .command_type(command_type),
      .command_valid(command_valid),
      .cfg_mode(cfg_mode),
      .cfg_ed(cfg_ed),
      .cfg_hash_len(cfg_hash_len),
      .push_data0(push_data0),
      .push_data1(push_data1),
      .push_keep0(push_keep0),
      .push_keep1(push_keep1),
      .push_last0(push_last0),
      .push_last1(push_last1),
      .pop_data(pop_data),
      .busy_o(ascon_busy)
  );


endmodule
