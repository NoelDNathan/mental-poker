pragma circom 2.1.9;

// A minimal selector (mux) without enforcing that `condition` is boolean.
// Use only when `condition` is already constrained to be 0/1 elsewhere.
template SelectorUnchecked() {
    signal input condition;
    signal input true;
    signal input false;
    signal output out;

    // Quadratic form (single multiplication): out = false + condition * (true - false)
    out <== false + condition * (true - false);
}


