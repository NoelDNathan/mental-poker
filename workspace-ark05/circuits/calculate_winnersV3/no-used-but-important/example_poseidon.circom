pragma circom 2.1.6;

include "circomlib/poseidon.circom";
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

// include "circomlib/mimcsponge.circom";

template Example() {
    signal input a[31];

    signal output h;

    // Absorber los primeros 16
    component p1 = Poseidon(16);
    for (var i = 0; i < 16; i++) {
        p1.inputs[i] <== a[i];
    }

    // Absorber los siguientes 16 usando el output anterior como input adicional
    component p2 = Poseidon(16);
    for (var i = 0; i < 15; i++) {
        p2.inputs[i] <== a[i+16];
    }
    p2.inputs[15] <== p1.out;

    h <== p2.out;
}

component main { public [ a ] } = Example();

/* INPUT = {
    "a": ["8", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5", "5"]
} */
