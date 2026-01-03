pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";

// Asserts that `in` is sorted in non-increasing (descending) order:
// in[0] >= in[1] >= ... >= in[n-1].
template AssertSorted(n, maxNumBits) {
  signal input in[n];

  component geq[n - 1];
  signal accumulator[n];
  accumulator[0] <== 0;

  for (var i = 1; i < n; i++) {
    var idx = i - 1;
    geq[idx] = GreaterEqThan(maxNumBits);
    geq[idx].in[0] <== in[i - 1];
    geq[idx].in[1] <== in[i];
    accumulator[i] <== accumulator[i - 1] + geq[idx].out;
  }

  accumulator[n - 1] === n - 1;
}


