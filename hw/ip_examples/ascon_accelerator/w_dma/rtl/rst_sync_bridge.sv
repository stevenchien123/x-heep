// =============================================================================
//  Author:         SHAN-CHI, YU (Toby)
//  Filename:       rst_sync_bridge.sv
//  Module:         rst_sync_bridge
//  Version:        v1.0 (Initial Release)
//
//  Description:
//    Industry-standard Asynchronous Reset Synchronizer (Reset Synchronizer Bridge).
//    Safely transitions an asynchronous active-high reset across clock domains.
//    - Asynchronous Assertion: Instantly triggers the destination reset to
//      guarantee immediate hardware initialization.
//    - Synchronous De-assertion (Removal): Flushes the reset signal synchronously
//      to the destination clock edge, strictly preventing reset recovery/removal
//      timing violations and subsequent metastability.
// =============================================================================
module rst_sync_bridge #(
    parameter int SYNC_STAGES = 2  // Number of synchronization stages (Minimum 2 to guarantee MTBF)
) (
    input logic clk,  // Destination Clock Domain
    input logic rst_in,  // Asynchronous Reset Input (Active High, from external TB/System)
    output logic rst_out  // Synchronized Reset Output (Active High, safe for internal FSM/Datapath)
);

  // Multi-stage synchronizer chain to maximize Mean Time Between Failures (MTBF).
  // Note: Default initialization to '1' ensures safe power-on-reset behavior
  // for SRAM-based FPGAs or specific ASIC flip-flop initializations.
  logic [SYNC_STAGES-1:0] sync_regs;

  always_ff @(posedge clk or posedge rst_in) begin
    if (rst_in) begin
      // Phase 1: Asynchronous Assertion
      // External reset directly drives the asynchronous preset/clear of the flip-flops,
      // immediately forcing the synchronization chain high regardless of the clock.
      sync_regs <= '1;
    end else begin
      // Phase 2: Synchronous De-assertion (Removal)
      // 0-padding shifts through the pipeline on each clock edge. The MSB safely
      // de-asserts only after the pulse has fully propagated, ensuring timing closure.
      sync_regs <= {sync_regs[SYNC_STAGES-2:0], 1'b0};
    end
  end

  // The output is driven by the MSB of the shift register chain, ensuring complete synchronization.
  assign rst_out = sync_regs[SYNC_STAGES-1];

endmodule
