pragma circom 2.1.9;

include "Straight.circom";

// Wrapper entrypoint for compiling Straight as a standalone circuit.
// Keep this file separate so `Straight.circom` can still be safely included by other circuits.
component main = Straight(4);


