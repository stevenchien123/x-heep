// =============================================================================
//  Author:         SHAN-CHI, YU (Toby)
//  Filename:       Ascon.sv
//  Module:         Ascon (Unified Hardware Architecture)
//  Date:           2026/05/25
//  Version:        v5.4 (Block-Serial AEAD Text Flow)
//  Target:         Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128, and Ascon-CXOF128
//
//  Main functional updates since v2.0:
//    - v2.0
//       - Fixed Little-Endian correctness for Data_in and Data_out, resolving
//         additional logic overhead present in prior versions.
//       - Integrated a reset synchronization bridge to ensure robust reset behavior.
//    - v2.1
//       - Added support for Ascon-Hash256.
//       - Minimized redundant internal logics.
//    - v2.2
//       - Added support for Ascon-XOF128.
//    - v2.3
//       - Added support for Ascon-CXOF128.
//
//  Main functional updates since v3.0:
//    - v3.0
//       - Redeclared input ports to fully accommodate the new AXI4-Stream based testbench.
//       - Streamlined data_len and block boundary detection mechanisms, resulting in a cleaner and more efficient design.
//    - v3.1
//       - Eliminated the dedicated tag register (reusing the general_reg instead).
//       - Removed redundant logic for handling empty ciphertext decryption scenarios.
//    - v3.2
//       - Enhanced error detection logic during decryption to strictly capture transient authentication failures.
//    - v3.3
//       - Initiated architectural optimization targeting area reduction (TSMC 40nm).
//
//  Main functional updates since v4.0:
//    - v4.0
//       - Synthesized at 400 MHz, TSMC 40nm, achieving 8368.919699 µm^2.
//       - Refactored code structure and comments for advanced maintainability.
//       - Formal Verification (Superlint):
//           - Eliminated unreachable branches and cases.
//           - Refined NONCE state register logic.
//           - Introduced internal signals for assoc_en, text_en, custom_en, and error to prevent glitches on output ports.
//       - Gate-Level Simulation (GLS) fully verified.
//    - v4.1
//       - Synthesized at 400 MHz, TSMC 40nm, achieving 8371.414501 µm^2.
//       - Introduced dynamic 'start'/'done' handshake protocol, enabling seamless task re-triggering without requiring global hardware reset.
//       - Added internal logic signal for the 'done' status.
//    - v4.2
//       - Synthesized at 400 MHz, TSMC 40nm, achieved area optimization: 8342.384096 µm^2 (12.26 kGE).
//       - Achieved Verification Code Coverage (SCORE: 90.71, LINE: 100.00%, COND: 97.67%, TOGGLE: 97.03%, BRANCH: 100.00%).
//           - Note on FSM Coverage: The 58.82% metric represents the theoretically reachable state space.
//             Unexercised state transitions are physically unreachable arcs, strictly enforced by the unidirectional cryptographic sequencing and phase-locking mechanisms
//             (e.g., ensuring state transitions only return to IDLE post-DONE).
//       - Performed extreme datapath & control-path area optimization through strategic logic factoring and DC synthesis directives.
//       - Gate-Level Simulation (GLS) passed.
//    - v4.3
//       - Architectural Refinement: Eliminated 'assoc_last' and 'custom_last' boundary tracking registers.
//           - Consolidated protocol decoding by uniquely leveraging the 'inter_final' phase state to govern AD/Custom-to-Text phase transitions.
//             This aggressive state minimization further compressed the datapath control logic and minimized routing congestion.
//       - Synthesized at 400 MHz, TSMC 40nm, pushing the Pareto frontier of area optimization: 8336.033713 µm^2 (12.25 kGE).
//       - Retained exceptional Verification Code Coverage (SCORE: 90.78, LINE: 100.00%, COND: 98.07%, TOGGLE: 97.02%, FSM: 58.82%, BRANCH: 100.00%).
//       - Gate-Level Simulation (GLS) passed.
//  Main functional updates since v5.0:
//    - v5.0
//       - Achieved robust AXI4-Stream protocol compliance (TVALID, TREADY, TLAST, TKEEP alignment).
//       - Resolved asynchronous TLAST handshaking vulnerabilities by capturing `data_last` synchronously with internal request (`_int`) signals.
//       - Streamlined Output Qualification Logic (`out_val_ad_fin` & `dec_out_last`) to accurately drive TVALID/TLAST based on byte boundaries without inflating critical path delays.
//       - Synthesized at 400 MHz, TSMC 40nm, achieving 8336.714099 µm^2 (12.25 kGE).
//       - Exceptional Verification Code Coverage (SCORE: 91.18, LINE: 100.00%, COND: 100.00%, TOGGLE: 97.05%, FSM: 58.82%, BRANCH: 100.00%).
//       - Gate-Level Simulation (GLS) passed.
//    - v5.1
//       - Modify unique if (rst_sync) to if (rst_sync).
//    - v5.2:
//       - Migrated from 400 MHz to 500 MHz target frequency on TSMC 40nm RVT.
//       - Synthesis result: 8800.066507 µm² (12.93 kGE), all four modes GLS verified.
//       - Conclusion: This represents the architectural floor for unified
//         AEAD + Hash + XOF + CXOF support at 500 MHz on TSMC 40nm RVT.
//    - v5.3:
//       - Potential Bug Fix: S0-S4 initialization in IDLE state, ADD condition to handle undefined mode signals.
//       - Synthesis result: 8913.693316 µm² (13.10 kGE), all four modes GLS verified.
//    - v5.4:
//       - Serialized AEAD PT/CT input and output at 128-bit block boundaries.
//       - Added a separate decryption-tag input phase after final plaintext output.
//       - Hash, XOF, and CXOF control flows remain unchanged.
//  =============================================================================
//  Description:
//    A highly optimized, standard-compliant (NIST SP 800-232) unified hardware
//    architecture for ASCON cryptography.
//    - The module interfaces with an AXI4-Stream compatible testbench that provides
//      configuration, data inputs, and receives standard-compliant outputs.
//  =============================================================================
//  Note on Ascon-CXOF128:
//  The maximum length of the customization string is 2048 bits (excluding the
//  length encoding itself). The effective maximum length of Z = 2048 + 64 bits = 2112 bits (264 bytes).

`include "def.svh"
`include "rst_sync_bridge.sv"
`include "permutation.sv"

module Ascon (
    input logic clk,
    input logic rst,  // System active high asynchronous reset
    output logic              rst_complete_o, // Asserted high when the reset synchronization bridge has completed its operation
    input logic start,  // Active high pulse to initiate a new cryptographic operation
    input logic input_valid,  // Qualifies Data_in/data_last/data_keep
    input logic output_ready,  // Allows the producer to apply backpressure

    // ------------------------------------------------------------
    // 1. Configuration Interface
    // ------------------------------------------------------------
    input logic [`Mode] mode,  // Operation Mode selection:
                               // 00: Ascon-AEAD128
                               // 01: Ascon-Hash256
                               // 10: Ascon-XOF128
                               // 11: Ascon-CXOF128
    input logic         ED,    // Encryption/Decryption flag (Valid only in AEAD mode):
                               // 0: Encryption
                               // 1: Decryption

    // ------------------------------------------------------------
    // 2. Data Request Flags (Hardware -> TB) (S_AXIS_TREADY equivalents)
    // ------------------------------------------------------------
    output logic key_en,    // Request Key payload
    output logic nonce_en,  // Request Nonce payload
    output logic assoc_en,  // Request Associated Data (AD) payload
    output logic text_en,   // Request Plaintext / Ciphertext / Message payload
    output logic custom_en, // Request Customization String (CXOF specific)

    // ------------------------------------------------------------
    // 3. Data Input Interface (TB -> Hardware)
    // ------------------------------------------------------------
    input logic [`DataBus] Data_in,  // 32-bit Data Input (Little Endian format) (S_AXIS_TDATA)
    input  logic              data_last,    // Asserts high when the current word is the final chunk of the phase (S_AXIS_TLAST)
    input logic [`KeepWidth] data_keep,  // Byte valid indicator for Data_in (S_AXIS_TKEEP)

    // ------------------------------------------------------------
    // 4. Static Configuration Parameters
    // ------------------------------------------------------------
    input logic [`DataBus] hash_len,  // Expected Hash/XOF output length in Bytes.
                                      // Hash256 ignores this (fixed 32B), XOF/CXOF processes dynamically.

    // ------------------------------------------------------------
    // 5. Data Output Interface
    // ------------------------------------------------------------
    output logic [`DataBus] Data_out,  // 32-bit Cryptographic Data Output (M_AXIS_TDATA)
    output logic              output_valid, // Asserts high when Data_out holds valid calculated results (M_AXIS_TVALID)
    output logic              output_last,  // Asserts high on the final output word (Crucial for Hash/XOF) (M_AXIS_TLAST)
    output logic [`KeepWidth] output_keep,  // Byte valid indicator for Data_out (M_AXIS_TKEEP)

    // ------------------------------------------------------------
    // 6. Status & Error Flags
    // ------------------------------------------------------------
    output logic done,  // Asserted high to indicate cryptographic operation completion

    output logic error  // Tag Verification Error Flag (Applicable in Decryption mode)
                        // 0: Authentication passed successfully
                        // 1: Authentication failed (Tag mismatch)
);

  // Synchronized reset signal for internal logic stability
  /* verilator lint_off SYNCASYNCNET */
  logic rst_sync;
  /* verilator lint_on SYNCASYNCNET */

  // -----------------------------------------------------------------------------
  // Reset Synchronization Bridge
  // Ensures reliable initialization. By synchronizing the asynchronous
  // external `rst` to the `clk` domain, we prevent metastability within the FSM
  // and datapath registers if the reset asserts/deasserts near the clock edge.
  // -----------------------------------------------------------------------------
  rst_sync_bridge u_rst_sync_bridge (
      .clk(clk),
      .rst_in(rst),
      .rst_out(rst_sync)
  );

  assign rst_complete_o = ~rst_sync;

  // -----------------------------------------------------------------------------
  // Internal Signals Mapping (Glitch prevention on Output Ports)
  // Decouples internal logic from top-level routing to prevent combinational glitches.
  // -----------------------------------------------------------------------------
  logic assoc_int;
  assign assoc_en = assoc_int;

  logic text_int;
  assign text_en = text_int;

  logic custom_int;
  assign custom_en = custom_int;

  logic done_int;
  assign done = done_int;

  logic error_int;
  assign error = error_int;

  // Freeze every state-holding element when an input word is missing or an
  // output word has not been accepted. This turns the original request-only
  // stream into a lossless ready/valid interface without gating the clock.
  logic input_request;
  logic input_fire;
  logic advance;
  assign input_request = key_en | nonce_en | assoc_en | text_en | custom_en;
  assign input_fire = input_request & input_valid;
  assign advance = (~input_request | input_valid) & (~output_valid | output_ready);
  // -----------------------------------------------------------------------------

  // FSM: State Definitions
  typedef enum logic [4:0] {
    IDLE,

    // Authenticated Encryption Scheme: Ascon-AEAD128
    KEY,
    NONCE,
    INITIALIZATION,
    INITIALXOR,
    AD_TEXT_INIT,
    AD_TEXT,
    TEXT_LOAD,
    FINALIZATION,
    TAG,
    TAG_INPUT,

    // Hash and eXtendable-Output Functions (XOFs)
    HASHINIT,
    ABSORB_INIT,
    ABSORB,
    FIRSTSQUEEZE,
    SQUEEZE,
    FINALSQUEEZE,

    DONE
  } ascon_state_e;

  ascon_state_e cur_state, nxt_state;

  // ASCON Internal 320-bit State Lanes
  logic [`StateWidth] S0, S1, S2, S3, S4;
  logic [`StateWidth]
      S0_post, S1_post, S2_post, S3_post, S4_post;  // Combinational permutation output

  logic [`KeyWidth] key;  // 128-bit storage for secret key
  logic [`RegWidth] general_reg;  // 128-bit multi-purpose shift register (Conveyor Belt)

  // Global Operation Counters
  logic [      3:0] counter;  // Round counter (0 to 11) for ASCON permutations
  logic [      4:0] text_counter;  // Byte-level accumulator for input data alignment tracking

  // -----------------------------------------------------------------------------
  // Round Constant Generation (Subtractor Elimination)
  // Ascon permutation uses a round constant: ( (15 - round) << 4 ) | round.
  // By leveraging 4-bit unsigned binary mathematical equivalence (15 - X == ~X),
  // we eliminate the arithmetic subtractor entirely, yielding a pure combinational
  // routing logic that saves significant gate area.
  // -----------------------------------------------------------------------------
  logic             target_round;  // 1 for 8 rounds (AD_TEXT), 0 for 12 rounds
  assign target_round = (cur_state == AD_TEXT);
  logic [3:0] base_c;
  assign base_c = target_round ? (counter + 4'd4) : counter;
  logic [`ConstantWidth] round_constant;
  assign round_constant = {~base_c, base_c};

  // Operational Flags
  logic assoc_empty;  // Asserts high if Associated Data phase is skipped
  logic inter_final;     // Indicates transition boundary between Phase 1 (AD/Custom) and Phase 2 (Text/Message)
  logic text_final;  // Indicates the final block of the message payload has been processed

  // Payload Boundary Tracking Registers (Synchronized S_AXIS_TLAST Handshaking)
  logic assoc_last;
  logic text_last;
  logic custom_last;
  logic hash_last;

  // XOF Output Length Tracker
  logic [`DataBus] hash_len_reg;  // Remaining output bytes to be squeezed

  // Cryptographic Domain Separation Flag
  logic domain_sep_flag;  // Strictly asserts once to flip S4[63] between AD and TEXT phases

  // Accumulates valid bytes from AXI-Stream TKEEP dynamically
  logic [2:0] din_valid_cnt;
  assign din_valid_cnt = {2'b00, data_keep[0]} + {2'b00, data_keep[1]} + {2'b00, data_keep[2]} + {2'b00, data_keep[3]};

  // AEAD text is loaded one complete 128-bit rate block at a time.  Keeping
  // the load phase separate from AD_TEXT/FINALIZATION guarantees that the
  // core never requests a PUSH while a PT/CT word is waiting for a POP.
  logic       text_load_fire;
  logic [4:0] text_load_count_next;
  logic       text_load_last_next;
  logic       text_pad_pending;
  assign text_load_fire = (cur_state == TEXT_LOAD) && text_int && input_valid;
  assign text_load_count_next = ((counter == 4'd0) ? 5'd0 : text_counter) +
                                  (text_load_fire ? {2'd0, din_valid_cnt} : 5'd0);
  assign text_load_last_next = text_last || (text_load_fire && data_last);

  //---------------------------------- MASKS ----------------------------------\\

    // -----------------------------------------------------------------------------
    // Little-Endian Masking Engine (Padding Mask)
    // Decodes AXI-Stream TKEEP into a 4-bit mask indicating the exact byte position
    // for the obligatory 0x01 padding insertion.
    // -----------------------------------------------------------------------------
    logic [3:0] pad_mask;
  always_comb begin
    unique case (data_keep)
      4'b0000: pad_mask = 4'b0001;
      4'b0001: pad_mask = 4'b0010;
      4'b0011: pad_mask = 4'b0100;
      4'b0111: pad_mask = 4'b1000;
      4'b1111: pad_mask = 4'b0000;
      default: pad_mask = 4'b0000;
    endcase
  end

  // -----------------------------------------------------------------------------
  // Global Result Mask (128-bit)
  // Dynamically filters valid byte lanes during partial block XORs. This prevents
  // out-of-bounds padded data from corrupting the internal state during decryption.
  // -----------------------------------------------------------------------------
  logic [127:0] result_mask;
  always_comb begin
    unique case (text_counter)
      5'd0:    result_mask = 128'h0000_0000_0000_0000_0000_0000_0000_0000;
      5'd1:    result_mask = 128'h0000_0000_0000_0000_0000_0000_0000_00FF;
      5'd2:    result_mask = 128'h0000_0000_0000_0000_0000_0000_0000_FFFF;
      5'd3:    result_mask = 128'h0000_0000_0000_0000_0000_0000_00FF_FFFF;
      5'd4:    result_mask = 128'h0000_0000_0000_0000_0000_0000_FFFF_FFFF;
      5'd5:    result_mask = 128'h0000_0000_0000_0000_0000_00FF_FFFF_FFFF;
      5'd6:    result_mask = 128'h0000_0000_0000_0000_0000_FFFF_FFFF_FFFF;
      5'd7:    result_mask = 128'h0000_0000_0000_0000_00FF_FFFF_FFFF_FFFF;
      5'd8:    result_mask = 128'h0000_0000_0000_0000_FFFF_FFFF_FFFF_FFFF;
      5'd9:    result_mask = 128'h0000_0000_0000_00FF_FFFF_FFFF_FFFF_FFFF;
      5'd10:   result_mask = 128'h0000_0000_0000_FFFF_FFFF_FFFF_FFFF_FFFF;
      5'd11:   result_mask = 128'h0000_0000_00FF_FFFF_FFFF_FFFF_FFFF_FFFF;
      5'd12:   result_mask = 128'h0000_0000_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;
      5'd13:   result_mask = 128'h0000_00FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;
      5'd14:   result_mask = 128'h0000_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;
      5'd15:   result_mask = 128'h00FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;
      5'd16:   result_mask = 128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;
      default: result_mask = 128'h0000_0000_0000_0000_0000_0000_0000_0000;
    endcase
  end

  // Extracts M_AXIS_TKEEP valid bits continuously from the pre-computed result_mask
  logic [3:0] ED_keep;
  always_comb begin
    case (counter[1:0])  // don't use unique case here, would have warning when system initializes.
      2'd0: ED_keep = {result_mask[24], result_mask[16], result_mask[8], result_mask[0]};
      2'd1: ED_keep = {result_mask[56], result_mask[48], result_mask[40], result_mask[32]};
      2'd2: ED_keep = {result_mask[88], result_mask[80], result_mask[72], result_mask[64]};
      2'd3: ED_keep = {result_mask[120], result_mask[112], result_mask[104], result_mask[96]};
    endcase
  end

  // logic [15:0] byte_mask;  // 1 bit per byte instead of 128 bits
  // always_comb begin
  //     unique case (text_counter)
  //         5'd0:    byte_mask = 16'b0000_0000_0000_0000;
  //         5'd1:    byte_mask = 16'b0000_0000_0000_0001;
  //         5'd2:    byte_mask = 16'b0000_0000_0000_0011;
  //         5'd3:    byte_mask = 16'b0000_0000_0000_0111;
  //         5'd4:    byte_mask = 16'b0000_0000_0000_1111;
  //         5'd5:    byte_mask = 16'b0000_0000_0001_1111;
  //         5'd6:    byte_mask = 16'b0000_0000_0011_1111;
  //         5'd7:    byte_mask = 16'b0000_0000_0111_1111;
  //         5'd8:    byte_mask = 16'b0000_0000_1111_1111;
  //         5'd9:    byte_mask = 16'b0000_0001_1111_1111;
  //         5'd10:   byte_mask = 16'b0000_0011_1111_1111;
  //         5'd11:   byte_mask = 16'b0000_0111_1111_1111;
  //         5'd12:   byte_mask = 16'b0000_1111_1111_1111;
  //         5'd13:   byte_mask = 16'b0001_1111_1111_1111;
  //         5'd14:   byte_mask = 16'b0011_1111_1111_1111;
  //         5'd15:   byte_mask = 16'b0111_1111_1111_1111;
  //         5'd16:   byte_mask = 16'b1111_1111_1111_1111;
  //         default: byte_mask = 16'b0000_0000_0000_0000;
  //     endcase
  // end

  // // Expand only where needed
  // logic [127:0] result_mask;
  // genvar i;
  // generate
  //     for (i = 0; i < 16; i++)
  //     begin : g_expand
  //         assign result_mask[i*8 +: 8] = {8{byte_mask[i]}};
  //     end
  // endgenerate

  // logic [3:0] ED_keep;
  // // ED_keep simplifies dramatically
  // assign ED_keep = byte_mask[counter[1:0]*4 +: 4];

  // -----------------------------------------------------------------------------
  // Hash Mask (64-bit)
  // Truncates the squeezed data output boundaries dynamically based on the
  // remaining requested hash length.
  // -----------------------------------------------------------------------------
  logic [63:0] hash_mask;
  always_comb begin
    unique if (|hash_len_reg[31:3]) begin
      hash_mask = 64'hFFFF_FFFF_FFFF_FFFF;
    end else begin
      case (hash_len_reg[2:0]) // look only at the last 3 bits  // don't use unique case here, would have warning when system initializes.
        3'd0: hash_mask = 64'h0000_0000_0000_0000;
        3'd1: hash_mask = 64'h0000_0000_0000_00FF;
        3'd2: hash_mask = 64'h0000_0000_0000_FFFF;
        3'd3: hash_mask = 64'h0000_0000_00FF_FFFF;
        3'd4: hash_mask = 64'h0000_0000_FFFF_FFFF;
        3'd5: hash_mask = 64'h0000_00FF_FFFF_FFFF;
        3'd6: hash_mask = 64'h0000_FFFF_FFFF_FFFF;
        3'd7: hash_mask = 64'h00FF_FFFF_FFFF_FFFF;
      endcase
    end
  end

  // Extracts M_AXIS_TKEEP valid bits specifically for Hash/XOF squeeze operations
  logic [3:0] hash_keep;
  always_comb begin
    case (counter[0])  // don't use unique case here, would have warning when system initializes.
      1'b0: hash_keep = {hash_mask[24], hash_mask[16], hash_mask[8], hash_mask[0]};
      1'b1: hash_keep = {hash_mask[56], hash_mask[48], hash_mask[40], hash_mask[32]};
    endcase
  end

  // -----------------------------------------------------------------------------
  // Architecture Insight: Decryption Masking & Little-Endian Padding Preservation
  // According to the NIST SP 800-232 standard for Ascon (Little-Endian), the
  // padding scheme appends a single 0x01 byte immediately following the valid
  // message bytes, followed by 0x00 bytes up to the block boundary.
  //
  // During the decryption of the final partial block, the internal state contains
  // this 0x01 padding. When extracting the plaintext and updating the state with
  // the ciphertext, we MUST NOT overwrite or corrupt this padding inside the state.
  //
  // `dec_mask` solves this by applying `~result_mask`. It zeros out the valid
  // ciphertext bit-lanes in the state (allowing `0 ^ Ciphertext = Ciphertext`),
  // while keeping the padded bit-lanes transparent (`State_pad ^ 0 = State_pad`).
  // For non-final or encryption operations, the mask defaults to all 1s.
  // -----------------------------------------------------------------------------
  logic [127:0] dec_mask;
  assign dec_mask = (ED && inter_final) ? ~result_mask : 128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;

  //---------------------------------- PAD DATA ----------------------------------\\

    // -----------------------------------------------------------------------------
    // Dynamic Padding Injector
    // Appends the mandatory 0x01 byte marker synchronously aligned with AXI TKEEP.
    // Engineered via bitwise OR to circumvent extensive combinational multiplexing.
    // -----------------------------------------------------------------------------
    logic [31:0] pad_data;
  assign pad_data = (data_keep[0]) ?
                (Data_in | {{7{1'b0}}, pad_mask[3],
                            {7{1'b0}}, pad_mask[2],
                            {7{1'b0}}, pad_mask[1],
                            {7{1'b0}}, pad_mask[0]}) : 32'h0000_0001;

  //---------------------------------- MAIN PROCESSING STARTS ----------------------------------\\

    // FSM State Transition
    always_ff @ (posedge clk or posedge rst_sync)
    begin
    if (rst_sync) cur_state <= IDLE;
    else if (advance) cur_state <= nxt_state;
  end

  // FSM Next State Logic (Strict unrolling for definitive path synthesis)
  always_comb begin
    nxt_state = IDLE;  // Default safe state

    case (cur_state)  // don't use unique case here, would have warning when system initializes.
      IDLE: nxt_state = (start) ? ((~|mode) ? KEY : HASHINIT) : IDLE;

      // Authenticated Encryption Scheme: Ascon-AEAD128
      KEY: nxt_state = (counter == 4'd3) ? NONCE : KEY;
      NONCE: nxt_state = (counter == 4'd3) ? INITIALIZATION : NONCE;
      INITIALIZATION: nxt_state = (counter == 4'd11) ? INITIALXOR : INITIALIZATION;
      INITIALXOR: nxt_state = (assoc_empty) ? TEXT_LOAD : AD_TEXT_INIT;
      AD_TEXT_INIT: nxt_state = (text_final) ? FINALIZATION : AD_TEXT;
      AD_TEXT: nxt_state = (counter == 4'd7) ? ((inter_final) ? TEXT_LOAD : AD_TEXT_INIT) : AD_TEXT;
      TEXT_LOAD: nxt_state = (counter == 4'd3) ? AD_TEXT_INIT : TEXT_LOAD;
      FINALIZATION: nxt_state = (counter == 4'd11) ? TAG : FINALIZATION;
      TAG: nxt_state = (ED) ? TAG_INPUT : DONE;
      TAG_INPUT: nxt_state = (counter == 4'd3) ? DONE : TAG_INPUT;

      // Hash and eXtendable-Output Functions (XOFs)
      HASHINIT: nxt_state = (counter[0]) ? ABSORB_INIT : HASHINIT;
      ABSORB_INIT: nxt_state = (text_final) ? FIRSTSQUEEZE : ABSORB;
      ABSORB: nxt_state = (counter == 4'd11) ? ABSORB_INIT : ABSORB;
      FIRSTSQUEEZE:
      nxt_state = (counter == 4'd11) ? ((hash_last) ? FINALSQUEEZE : SQUEEZE) : FIRSTSQUEEZE;
      SQUEEZE: nxt_state = (hash_last) ? FINALSQUEEZE : SQUEEZE;
      FINALSQUEEZE: nxt_state = (counter[0]) ? DONE : FINALSQUEEZE;

      // Enables dynamic software polling/re-triggering without hardware reset.
      DONE: nxt_state = (done_int) ? IDLE : DONE;
      default: nxt_state = IDLE;  // Default safe state
    endcase
  end

  // -----------------------------------------------------------------------------
  // Request Enables (AXI S_AXIS_TREADY generation) & Done Signal Decoding
  // -----------------------------------------------------------------------------
  always_comb begin
    key_en     = 1'b0;
    nonce_en   = 1'b0;
    assoc_int  = 1'b0;
    text_int   = 1'b0;
    custom_int = 1'b0;
    done_int   = 1'b0;

    unique case (cur_state)

      // Authenticated Encryption Scheme: Ascon-AEAD128
      KEY: key_en = 1'b1;

      NONCE: begin
        key_en   = 1'b0;
        nonce_en = 1'b1;
      end

      INITIALIZATION: begin
        nonce_en = 1'b0;
        assoc_int = (counter == 4'd0) | ( (~assoc_last) & (counter > 4'd3) & (counter < 4'd7) ); // & (~assoc_last) to ensure no unintentional enable.
      end

      AD_TEXT: begin
        assoc_int =               (~assoc_last) & (counter > 4'd2) & (counter < 4'd7); // (~assoc_last) to ensure no unintentional enable.
      end

      // Load one complete PT/CT block before starting its state update.
      // Once TLAST has been observed, the remaining slots are filled
      // internally with padding instead of requesting more input.
      TEXT_LOAD: text_int = ~text_last;

      // A decryption tag is accepted only after the final plaintext has
      // been drained and the final p12 permutation/key XOR has completed.
      TAG_INPUT: text_int = ED;


      // Hash and eXtendable-Output Functions (XOFs)
      HASHINIT: begin
        custom_int = (&mode);
        text_int   = (~&mode) & (~text_last);
      end

      ABSORB: begin
        custom_int = (~inter_final) & (~custom_last) & (counter < 4'd2); // ~inter_final & (~custom_last) to ensure no unintentional enable. // I don't really think (~inter_final) is necessary here...
        text_int   =   inter_final  & (~text_last)   & (counter < 4'd2); // inter_final & (~text_last) to ensure no unintentional enable.
      end

      DONE:
      // Hash/XOF/CXOF keep their original one-cycle completion
      // behavior.  AEAD encryption must not report completion while
      // the final tag word is still held under output backpressure.
      done_int = (|mode) | (counter[2] & ((~output_valid) | output_ready));

      default: begin
        key_en     = 1'b0;
        nonce_en   = 1'b0;
        assoc_int  = 1'b0;
        text_int   = 1'b0;
        custom_int = 1'b0;
        done_int   = 1'b0;
      end
    endcase
  end

  // Internal State Registers (S0-S4) Management
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) begin
      S0 <= 64'd0;
      S1 <= 64'd0;
      S2 <= 64'd0;
      S3 <= 64'd0;
      S4 <= 64'd0;
    end else if (advance) begin
      if (cur_state == IDLE && !start) begin
        S0 <= 64'd0;
        S1 <= 64'd0;
        S2 <= 64'd0;
        S3 <= 64'd0;
        S4 <= 64'd0;
      end else begin
        unique case (cur_state)
          IDLE: begin
            case (mode)  // don't use unique case here, would have warning when system initializes.
              `Ascon_AEAD128: begin
                S0 <= 64'h0000_1000_808c_0001;
                S1 <= 64'd0;
                S2 <= 64'd0;
                S3 <= 64'd0;
                S4 <= 64'd0;
              end

              `Ascon_Hash256: // (Precomputed initialization phase IVs)
                        begin
                S0 <= 64'h9b1e_5494_e934_d681;
                S1 <= 64'h4bc3_a01e_3337_51d2;
                S2 <= 64'hae65_396c_6b34_b81a;
                S3 <= 64'h3c7f_d4a4_d56a_4db3;
                S4 <= 64'h1a5c_4649_06c5_976d;
              end

              `Ascon_XOF128: // (Precomputed initialization phase IVs)
                        begin
                S0 <= 64'hda82_ce76_8d94_47eb;
                S1 <= 64'hcc7c_e6c7_5f1e_f969;
                S2 <= 64'he750_8fd7_8008_5631;
                S3 <= 64'h0ee0_ea53_416b_58cc;
                S4 <= 64'he054_7524_db6f_0bde;
              end

              `Ascon_CXOF128: // (Precomputed initialization phase IVs)
                        begin
                S0 <= 64'h6755_27c2_a0e8_de03;
                S1 <= 64'h43d1_2d7d_c037_7bbc;
                S2 <= 64'he990_1dec_426e_81b5;
                S3 <= 64'h2ab1_4907_7207_80b6;
                S4 <= 64'h8f3f_1d02_d432_bc46;
              end

              default: begin
                S0 <= 64'd0;
                S1 <= 64'd0;
                S2 <= 64'd0;
                S3 <= 64'd0;
                S4 <= 64'd0;
              end
            endcase
          end

          // Shift-in architecture eliminates explicit byte-lane multiplexers
          KEY: begin
            unique if (counter == 4'd0 || counter == 4'd1)
              S1 <= {Data_in, S1[63:32]};  // High MSB injection, cascade to LSB
            else S2 <= {Data_in, S2[63:32]};
          end

          // Shift-in architecture eliminates explicit byte-lane multiplexers
          NONCE: begin
            unique if (counter == 4'd0 || counter == 4'd1)
              S3 <= {Data_in, S3[63:32]};  // High MSB injection, cascade to LSB
            else S4 <= {Data_in, S4[63:32]};
          end

          INITIALIZATION, AD_TEXT, FINALIZATION, ABSORB, FIRSTSQUEEZE, SQUEEZE: begin
            S0 <= S0_post;
            S1 <= S1_post;
            S2 <= S2_post;
            S3 <= S3_post;
            S4 <= S4_post;
          end

          INITIALXOR, TAG: begin
            S3 <= S3 ^ key[63:0];
            S4 <= S4 ^ key[127:64];
          end

          AD_TEXT_INIT: begin
            // Execute Partial Block masking (dec_mask) seamlessly
            S0     <= (S0 & dec_mask[63:0]) ^ general_reg[63:0];
            S1     <= (S1 & dec_mask[127:64]) ^ general_reg[127:64];
            S2     <= (text_final) ? S2 ^ key[63:0] : S2;  //??
            S3     <= (text_final) ? S3 ^ key[127:64] : S3;  //??
            S4[63] <= (inter_final && (~domain_sep_flag)) ? (S4[63] ^ 1'b1) : S4[63];
          end

          TEXT_LOAD: begin
            // For non-empty AD this executes after the last AD p8;
            // for empty AD it executes immediately after INITIALXOR.
            // In either case domain separation precedes text absorption.
            S4[63] <= (inter_final && (~domain_sep_flag)) ? (S4[63] ^ 1'b1) : S4[63];
          end

          DONE: begin
            // Stream out the calculated tag 32-bits per cycle
            S3       <= {S4[31:0], S3[63:32]};
            S4[31:0] <= S4[63:32];
          end

          // Hash and eXtendable-Output Functions (XOFs)
          ABSORB_INIT: S0 <= S0 ^ general_reg[63:0];

          default: begin
            S0 <= S0;
            S1 <= S1;
            S2 <= S2;
            S3 <= S3;
            S4 <= S4;
          end
        endcase
      end
    end
  end

  // -----------------------------------------------------------------------------
  // Data Conditioning & Zero-Padding Selector
  // This combinational block determines whether the shift register should ingest
  // the actual `pad_data` or a forced `32'd0` based on the byte boundary (`text_counter`).
  // -----------------------------------------------------------------------------
  logic [31:0] shift_in_data;
  always_comb begin
    shift_in_data = pad_data;  // Pre-configured data vector

    unique if (cur_state == TEXT_LOAD) begin
      // A partial last word already contains its 0x01 marker via
      // pad_data.  If the message length is an exact multiple of the
      // rate, synthesize the required empty padding block locally.
      if (text_load_fire) shift_in_data = pad_data;
      else if (text_pad_pending) shift_in_data = 32'h0000_0001;
      else shift_in_data = 32'd0;
    end else if (cur_state == INITIALIZATION || cur_state == AD_TEXT) begin
      unique if (counter == 4'd4 && (~text_counter[2])) shift_in_data = 32'd0;
      else if (counter == 4'd5 && (~text_counter[3])) shift_in_data = 32'd0;
      else if (counter == 4'd6 && (~&text_counter[3:2])) shift_in_data = 32'd0;
      else shift_in_data = pad_data;
    end else if (cur_state == HASHINIT || cur_state == ABSORB) begin
      unique if (counter == 4'd1 && (~text_counter[2])) shift_in_data = 32'd0;
      else shift_in_data = pad_data;
    end else shift_in_data = pad_data;
  end

  // Secret Key Buffer
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) key <= 128'd0;
    else if (advance) begin
      unique if (cur_state == KEY) key <= {shift_in_data, key[127:32]};
      else key <= key;
    end
  end

  // -----------------------------------------------------------------
  // Architecture Insight: Conveyor Belt Shift Register (MUX Elimination)
  // To drastically reduce the area footprint, `general_reg` functions
  // as a continuous right-shifting FIFO rather than a static register
  // with a massive 128-to-32 output multiplexer tree.
  // -----------------------------------------------------------------
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) general_reg <= 128'd0;
    else if (advance) begin
      unique case (cur_state)

        // Authenticated Encryption Scheme: Ascon-AEAD128
        INITIALIZATION: begin
          unique if ( counter == 4'd0 || (counter == 4'd3 && assoc_empty) || (counter >= 4'd4 && counter <= 4'd6) )
            general_reg <= {shift_in_data, general_reg[127:32]};
          else general_reg <= general_reg;
        end

        AD_TEXT_INIT: general_reg <= ({S1, S0} ^ general_reg) & result_mask;

        AD_TEXT: begin
          // AD keeps the original input-only preload pipeline.  In
          // the text phase, the register is used only as the output
          // conveyor; the next block is loaded later in TEXT_LOAD.
          unique if (!inter_final && (counter <= 4'd6))
            general_reg <= {shift_in_data, general_reg[127:32]};
          else if (inter_final && (counter <= 4'd3)) general_reg <= {32'd0, general_reg[127:32]};
          else general_reg <= general_reg;
        end

        TEXT_LOAD: general_reg <= {shift_in_data, general_reg[127:32]};

        FINALIZATION: begin
          // Drain only the final PT/CT result.  The decryption tag
          // is loaded later so input and output requests cannot
          // overlap.
          if (counter <= 4'd3) general_reg <= {32'd0, general_reg[127:32]};
          else general_reg <= general_reg;
        end

        TAG_INPUT: general_reg <= {Data_in, general_reg[127:32]};

        DONE: general_reg <= {32'd0, general_reg[127:32]};

        // Hash and eXtendable-Output Functions (XOFs)
        HASHINIT, ABSORB: begin
          // Reutilize the shift-register pipeline to systematically ingest padding data.
          unique if (counter == 4'd0 || counter == 4'd1)
            general_reg[63:0] <= {shift_in_data, general_reg[63:32]};
          else general_reg <= general_reg;
        end

        FIRSTSQUEEZE, SQUEEZE: begin
          unique if (counter == 4'd0) general_reg[63:0] <= {32'd0, general_reg[63:32]};
          else if (counter == 4'd11) general_reg[63:0] <= S0_post & hash_mask;
          else general_reg <= general_reg;
        end

        FINALSQUEEZE: general_reg[63:0] <= {32'd0, general_reg[63:32]};

        default: general_reg <= general_reg;
      endcase
    end
  end

  // Global FSM Cycle Counter
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) counter <= 4'd0;
    else if (advance) begin
      if ( (cur_state == KEY       && counter == 4'd3) ||
                 (cur_state == NONCE     && counter == 4'd3) ||
                 (cur_state == AD_TEXT   && counter == 4'd7) ||
                 (cur_state == TEXT_LOAD && counter == 4'd3) ||
                 (cur_state == TAG_INPUT && counter == 4'd3) ||
                 counter == 4'd11)
        counter <= 4'd0;
      else if (cur_state == KEY     || cur_state == NONCE  || cur_state == INITIALIZATION || cur_state == AD_TEXT || cur_state == FINALIZATION ||
                    cur_state == TEXT_LOAD || cur_state == TAG_INPUT ||
                    cur_state == HASHINIT || cur_state == ABSORB || cur_state == FIRSTSQUEEZE   || cur_state == SQUEEZE || cur_state == FINALSQUEEZE ||
                    cur_state == DONE)
        counter <= counter + 4'd1;
      else counter <= 4'd0;
    end
  end

  // Input Valid Byte Accumulator (text_counter)
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) text_counter <= 5'd0;
    else if (advance) begin
      unique case (cur_state)
        IDLE: text_counter <= 5'd0;
        INITIALIZATION, HASHINIT: begin
          if (input_fire) text_counter <= text_counter + {2'd0, din_valid_cnt};
        end
        AD_TEXT: begin
          if (!inter_final && input_fire)
            text_counter <= (counter == 4'd3) ?
                            {2'd0, din_valid_cnt} :
                            text_counter + {2'd0, din_valid_cnt};
        end
        TEXT_LOAD: text_counter <= text_load_count_next;
        ABSORB: begin
          if (input_fire)
            text_counter <= (counter == 4'd0) ?
                            {2'd0, din_valid_cnt} :
                            text_counter + {2'd0, din_valid_cnt};
        end
        default: text_counter <= text_counter;
      endcase
    end
  end

  // Associated Data Emptiness Flag
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) assoc_empty <= 1'b0;
    else if (advance && start) assoc_empty <= 1'b0;
    else if (advance)
      assoc_empty <= assoc_empty | (cur_state == INITIALIZATION && (counter == 4'd0) && (~data_keep[0]));
  end

  // Intermediate Phase Boundary Flag
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) inter_final <= 1'b0;
    else if (advance && start) inter_final <= 1'b0;
    else if (advance)
      inter_final <= inter_final | (mode[0] ^ mode[1]) | assoc_empty | (cur_state == AD_TEXT_INIT && (~text_counter[4])) | (cur_state == ABSORB_INIT && (~text_counter[3]));
  end

  // Text Finalization Processing Flag
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) text_final <= 1'b0;
    else if (advance) begin
      unique case (cur_state)
        IDLE: text_final <= 1'b0;
        TEXT_LOAD:
        text_final <= (counter == 4'd3) ?
                                                (text_load_last_next && (text_load_count_next < 5'd16)) :
                                                text_final;
        HASHINIT: text_final <= (counter[0]) & (~data_keep[3]);
        ABSORB:
        text_final <= inter_final  & (counter == 4'd11) & (~text_counter[3]); // counter == 4'd11 to ensure clean text_final signal.
        default: text_final <= text_final;
      endcase
    end
  end

  // -----------------------------------------------------------------------------
  // Payload Boundary (LAST) Evaluators
  // Implements strict AXI-Stream synchronicity: TLAST is only asserted and latched
  // when both TVALID (from TB) and TREADY (internal _int flags) are high concurrently.
  // -----------------------------------------------------------------------------
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) assoc_last <= 1'b0;
    else if (advance && start) assoc_last <= 1'b0;
    else if (advance) assoc_last <= assoc_last | (assoc_int && data_last);
  end

  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) text_last <= 1'b0;
    else if (advance && start) text_last <= 1'b0;
    else if (advance) text_last <= text_last | (text_int && data_last);
  end

  // A full final 32-bit word has no room for the 0x01 padding byte.  Remember
  // that condition until the next internally generated word (or block) can
  // consume the marker.  Partial and empty final words already carry their
  // marker through pad_data.
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) text_pad_pending <= 1'b0;
    else if (advance && start) text_pad_pending <= 1'b0;
    else if (advance) begin
      if (text_load_fire && data_last) text_pad_pending <= &data_keep;
      else if ((cur_state == TEXT_LOAD) && !text_load_fire && text_pad_pending)
        text_pad_pending <= 1'b0;
    end
  end

  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) custom_last <= 1'b0;
    else if (advance && start) custom_last <= 1'b0;
    else if (advance) custom_last <= custom_last | (custom_int && data_last);
  end

  //------------------- HASH/XOF LENGTH SUBTRACTOR -------------------\\
    always_ff @ (posedge clk or posedge rst_sync)
    begin
    if (rst_sync) hash_len_reg <= 32'd0;
    else if (advance && start) hash_len_reg <= hash_len;
    else if (advance)
      hash_len_reg <= {
        (hash_len_reg[31:3] - {28'd0, (cur_state == SQUEEZE && counter == 4'd9)}), hash_len_reg[2:0]
      };
  end

  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) hash_last <= 1'b0;
    else if (advance) hash_last <= (hash_len_reg <= 32'd8);
  end

  // -----------------------------------------------------------------------------
  // Domain Separation Execution (Flipping S4[63])
  // -----------------------------------------------------------------------------
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) domain_sep_flag <= 1'b0;
    else if (advance && start) domain_sep_flag <= 1'b0;
    else if (advance)
      domain_sep_flag <= domain_sep_flag |
                               (cur_state == AD_TEXT_INIT && inter_final) |
                               (cur_state == TEXT_LOAD && inter_final);
  end

  // -----------------------------------------------------------------------------
  // Output Qualification Logic (M_AXIS_TVALID Generation)
  // Synchronizes the M_AXIS_TVALID assertion with valid internal 32-bit datapath chunks
  // ensuring glitch-free alignment with the testbench.
  // -----------------------------------------------------------------------------
  logic out_val_ad_fin;
  always_comb begin
    out_val_ad_fin = 1'b0;

    unique if (cur_state == AD_TEXT || cur_state == FINALIZATION) begin
      unique if (counter == 4'd0) out_val_ad_fin = (|text_counter) & domain_sep_flag;
      else if (counter == 4'd1) out_val_ad_fin = (text_counter > 5'd4) & domain_sep_flag;
      else if (counter == 4'd2) out_val_ad_fin = (text_counter > 5'd8) & domain_sep_flag;
      else if (counter == 4'd3) out_val_ad_fin = (text_counter > 5'd12) & domain_sep_flag;
      else out_val_ad_fin = 1'b0;
    end else out_val_ad_fin = 1'b0;
  end

  // -----------------------------------------------------------------------------
  // Output Boundary Evaluator (M_AXIS_TLAST Generation)
  // Pinpoints the precise clock cycle of the final 32-bit chunk output during
  // AEAD operations to drive M_AXIS_TLAST synchronously.
  // -----------------------------------------------------------------------------
  logic dec_out_last;
  always_comb begin
    dec_out_last = 1'b0;

    unique if (ED && text_last && (cur_state == AD_TEXT || cur_state == FINALIZATION)) begin
      unique if (counter == 4'd0) dec_out_last = (text_counter <= 5'd4);
      else if (counter == 4'd1) dec_out_last = (text_counter > 5'd4) & (text_counter <= 5'd8);
      else if (counter == 4'd2) dec_out_last = (text_counter > 5'd8) & (text_counter <= 5'd12);
      else if (counter == 4'd3) dec_out_last = (text_counter > 5'd12);
      else dec_out_last = 1'b0;
    end else dec_out_last = 1'b0;
  end

  // -----------------------------------------------------------------------------
  // AXI4-Stream Output Registers
  // -----------------------------------------------------------------------------
  always_ff @(posedge clk or posedge rst_sync) begin
    if (rst_sync) begin
      Data_out     <= 32'd0;
      output_valid <= 1'b0;
      output_last  <= 1'b0;
      output_keep  <= 4'b0000;
      error_int    <= 1'b0;
    end else if (advance) begin
      unique case (cur_state)
        AD_TEXT, FINALIZATION: begin
          Data_out     <= general_reg[31:0];
          output_valid <= out_val_ad_fin;
          output_last  <= dec_out_last;
          output_keep  <= ED_keep;
        end

        SQUEEZE, FINALSQUEEZE: begin
          Data_out <= general_reg[31:0];

          unique if (counter == 4'd0) begin
            output_valid <= 1'b1;
            output_last  <= (hash_len_reg <= 32'd4);
            output_keep  <= hash_keep;
          end else if (counter == 4'd1) begin
            output_valid <= (hash_len_reg > 32'd4);
            output_last  <= (cur_state == FINALSQUEEZE && hash_len_reg > 32'd4);
            output_keep  <= hash_keep;
          end else begin
            output_valid <= 1'b0;
            output_last  <= 1'b0;
            output_keep  <= 4'b0000;
          end
        end

        // Security Feature: Sticky Error Flag
        // In AEAD, any tag verification discrepancy completely invalidates the payload.
        // The error bit acts as a latch ensuring transient mismatches are securely caught.
        DONE: begin
          Data_out     <= S3[31:0];
          output_valid <= (~|mode) & (~ED) & (counter < 4'd4);
          output_last  <= (~ED) & (counter == 4'd3);
          output_keep  <= 4'b1111;  // Tag is always 16 bytes, so all lanes are valid during output.
          unique if (counter < 4'd4)
            error_int <= error_int | (ED && (S3[31:0] != general_reg[31:0]));
          else error_int <= error_int;
        end

        default: begin
          Data_out     <= 32'd0;
          output_valid <= 1'b0;
          output_last  <= 1'b0;
          output_keep  <= 4'b0000;
          error_int    <= 1'b0;
        end
      endcase
    end
  end

  // Hardware instantiation of the core ASCON permutation element
  permutation u_permutation (
      .round_constant(round_constant),

      .S0_in(S0),
      .S1_in(S1),
      .S2_in(S2),
      .S3_in(S3),
      .S4_in(S4),

      .S0_out(S0_post),
      .S1_out(S1_post),
      .S2_out(S2_post),
      .S3_out(S3_post),
      .S4_out(S4_post)
  );

endmodule
