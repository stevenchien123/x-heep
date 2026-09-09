module simple_xif_coproc #(
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

  typedef enum logic [1:0] {
    IDLE,
    WAIT_COMMIT,
    WAIT_RESULT
  } state_t;

  state_t cur_state, nxt_state;

  logic [          31:0] coproc_reg_q;
  logic [X_ID_WIDTH-1:0] pending_id_q;
  logic [           4:0] pending_rd_q;
  logic [          31:0] pending_rs1_q;
  logic                  pending_is_cload_q;

  logic                  is_cstore;
  logic                  is_cload;
  logic                  instruction_accepted;
  logic                  issue_fire;
  logic                  issue_commit;
  logic                  pending_commit;

  assign is_cstore =
      xif_issue_if.issue_req.instr[6:0]   == 7'h0B &&
      xif_issue_if.issue_req.instr[14:12] == 3'b000 &&
      xif_issue_if.issue_req.instr[31:25] == 7'd0;

  assign is_cload =
      xif_issue_if.issue_req.instr[6:0]   == 7'h0B &&
      xif_issue_if.issue_req.instr[14:12] == 3'b000 &&
      xif_issue_if.issue_req.instr[31:25] == 7'd1;

  assign instruction_accepted = is_cstore || is_cload;
  assign issue_fire = xif_issue_if.issue_valid && xif_issue_if.issue_ready && instruction_accepted;

  // CV32E40PX may assert commit in the same cycle as the issue handshake.
  assign issue_commit = xif_commit_if.commit_valid &&
                        (xif_commit_if.commit.id == xif_issue_if.issue_req.id);
  assign pending_commit = xif_commit_if.commit_valid && (xif_commit_if.commit.id == pending_id_q);

  // Compressed instructions and coprocessor memory accesses are unsupported.
  // Keep the compressed channel ready so an unsupported compressed instruction
  // is rejected rather than stalling the core indefinitely.
  assign xif_compressed_if.compressed_ready = 1'b1;
  assign xif_compressed_if.compressed_resp = '0;
  assign xif_mem_if.mem_valid = 1'b0;
  assign xif_mem_if.mem_req = '0;

  always_comb begin : interface_signals
    xif_issue_if.issue_ready   = 1'b0;
    xif_issue_if.issue_resp    = '0;
    xif_result_if.result_valid = 1'b0;
    xif_result_if.result       = '0;

    unique case (cur_state)
      IDLE: begin
        // CSTORE needs rs1; CLOAD has no source operand.
        xif_issue_if.issue_ready = !is_cstore || xif_issue_if.issue_req.rs_valid[0];
        xif_issue_if.issue_resp.accept    = instruction_accepted;
        xif_issue_if.issue_resp.writeback = is_cload;
      end

      WAIT_RESULT: begin
        xif_result_if.result_valid = 1'b1;
        xif_result_if.result.id    = pending_id_q;
        xif_result_if.result.data  = pending_is_cload_q ? coproc_reg_q : '0;
        xif_result_if.result.rd    = pending_is_cload_q ? pending_rd_q : '0;
        xif_result_if.result.we    = pending_is_cload_q;
      end

      default: begin
        // WAIT_COMMIT accepts neither a new issue nor produces a result.
      end
    endcase
  end

  always_comb begin : next_state_logic
    nxt_state = cur_state;

    unique case (cur_state)
      IDLE: begin
        if (issue_fire) begin
          if (issue_commit) begin
            if (xif_commit_if.commit.commit_kill) begin
              nxt_state = IDLE;
            end else begin
              // Every accepted, non-killed instruction requires one result
              // transaction, including CSTORE with result.we == 0.
              nxt_state = WAIT_RESULT;
            end
          end else begin
            nxt_state = WAIT_COMMIT;
          end
        end
      end

      WAIT_COMMIT: begin
        if (pending_commit) begin
          if (xif_commit_if.commit.commit_kill) begin
            nxt_state = IDLE;
          end else begin
            // CSTORE and CLOAD both complete through the result interface.
            nxt_state = WAIT_RESULT;
          end
        end
      end

      WAIT_RESULT: begin
        if (xif_result_if.result_valid && xif_result_if.result_ready) begin
          nxt_state = IDLE;
        end
      end

      default: nxt_state = IDLE;
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : state_register
    if (!rst_ni) begin
      cur_state <= IDLE;
    end else begin
      cur_state <= nxt_state;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : coprocessor_register
    if (!rst_ni) begin
      coproc_reg_q <= '0;
    end else begin
      // coproc_reg_q is architectural state, changes only after a non-killed commit.

      // Same-cycle issue/commit path: CV32E40PX can assert commit_valid in the
      // cycle in which the issue handshake occurs. In this case, rs1 is still
      // available directly on the issue interface.
      if (issue_fire && is_cstore && issue_commit && !xif_commit_if.commit.commit_kill) begin
        coproc_reg_q <= xif_issue_if.issue_req.rs[0];
      end else if ((cur_state == WAIT_COMMIT) && pending_commit &&
                   !xif_commit_if.commit.commit_kill &&
                   !pending_is_cload_q) begin
        // Delayed-commit path: when commit arrives later, the FSM is in
        // WAIT_COMMIT and rs1 must come from the saved pending transaction.
        // pending_commit verifies the commit ID; pending_is_cload_q == 0
        // identifies the pending instruction as CSTORE.
        coproc_reg_q <= pending_rs1_q;
      end
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : pending_registers
    if (!rst_ni) begin
      pending_id_q       <= '0;
      pending_rd_q       <= '0;
      pending_rs1_q      <= '0;
      pending_is_cload_q <= 1'b0;
    end else if (issue_fire) begin
      pending_id_q       <= xif_issue_if.issue_req.id;
      pending_rd_q       <= xif_issue_if.issue_req.instr[11:7];
      pending_rs1_q      <= xif_issue_if.issue_req.rs[0];
      pending_is_cload_q <= is_cload;
    end
  end

endmodule : simple_xif_coproc
