// -----------------------------------------------------------------------------
// def.svh
//   version v1.0 (stable version)
// Description:
//   This file contains global parameter definitions for the Ascon hardware design.
// -----------------------------------------------------------------------------

`ifndef _PARAMETER_SETTING_
`define _PARAMETER_SETTING_

    `define Mode            1:0

    `define DataBus        31:0

    `define KeyWidth      127:0
    `define ConstantWidth   7:0
    `define StateWidth     63:0

    `define KeepWidth       3:0
    `define RegWidth      127:0

    `define Ascon_AEAD128 2'b00
    `define Ascon_Hash256 2'b01
    `define Ascon_XOF128  2'b10
    `define Ascon_CXOF128 2'b11

`endif
