`include "def.svh"

// =============================================================================
//  Author:         SHAN-CHI, YU (Toby)
//  Filename:       permutation.sv
//  Module:         permutation
//  Version:        v2.0 (Selected Production Version)
//
//  Architecture Evolution:
//    - v1.1
//       - Evaluated associative transformations in the Linear Diffusion Layer
//         (e.g., A ^ (B ^ C) -> A ^ B ^ C) for potential PPA improvements.
//         Retained original structure post-verification for optimal mapping.
//    - v2.0
//       - Transitioned to an explicit Directed Acyclic Graph (DAG) based
//         implementation. This significantly enhances RTL readability and
//         forces the synthesis technology mapper to reuse common Boolean sub-expressions.
//
//  Description:
//    Executes the core 320-bit ASCON permutation function.
//    - Input: 5-lane internal state registers (S0-S4) and the current round constant.
//    - Output: Permuted 5-lane internal state (S0-S4).
// =============================================================================
module permutation (
    input logic [`ConstantWidth] round_constant,

    input  logic [`StateWidth] S0_in,
    S1_in,
    S2_in,
    S3_in,
    S4_in,
    output logic [`StateWidth] S0_out,
    S1_out,
    S2_out,
    S3_out,
    S4_out
);

  // Explicit intermediate nodes for deterministic hardware mapping and optimal resource sharing
  logic [`StateWidth] T0, T1, T2, T3, T4;  // Phase 2.1: Initial XOR Transformation
  logic [`StateWidth] N0, N1, N2, N3, N4;  // Phase 2.2: Non-linear Substitution (Chi)
  logic [`StateWidth] F0, F1, F2, F3, F4;  // Phase 2.3: Final XOR and Inversion

  // Pure Combinational logic
  always_comb begin
    // === Phase 1 & Phase 2.1: Constant-Addition & Initial XOR ===
    // The round constant addition is architecturally folded into the initial XOR
    // stage to compress the logic depth and minimize routing overhead.
    T0 = S0_in ^ S4_in;
    T1 = S1_in;
    T2 = S2_in ^ {56'd0, round_constant} ^ S1_in; // Phase 1 merged seamlessly here
    T3 = S3_in;
    T4 = S4_in ^ S3_in;

    // === Phase 2.2: Non-linear transformation (Chi) ===
    // DAG structuring eliminates redundant Boolean sub-expressions (e.g., bypassing
    // the re-computation of S0_in ^ S4_in), inherently guiding the EDA tool's optimization.
    N0 = T0 ^ (~T1 & T2);
    N1 = T1 ^ (~T2 & T3);
    N2 = T2 ^ (~T3 & T4);
    N3 = T3 ^ (~T4 & T0);
    N4 = T4 ^ (~T0 & T1);

    // === Phase 2.3: Final XOR and Inversion ===
    F0 = N0 ^ N4;
    F1 = N1 ^ N0;
    F2 = ~N2;
    F3 = N3 ^ N2;
    F4 = N4;

    // === Phase 3: Linear Diffusion Layer ===
    // Implements the specified bitwise rotations and XORs.
    S0_out = F0 ^ {F0[18:0], F0[63:19]} ^ {F0[27:0], F0[63:28]};
    S1_out = F1 ^ {F1[60:0], F1[63:61]} ^ {F1[38:0], F1[63:39]};
    S2_out = F2 ^ {F2[   0], F2[63: 1]} ^ {F2[ 5:0], F2[63: 6]};
    S3_out = F3 ^ {F3[ 9:0], F3[63:10]} ^ {F3[16:0], F3[63:17]};
    S4_out = F4 ^ {F4[ 6:0], F4[63: 7]} ^ {F4[40:0], F4[63:41]};
  end

endmodule
