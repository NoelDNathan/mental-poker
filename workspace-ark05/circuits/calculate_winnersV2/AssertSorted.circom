pragma circom 2.2.0;

include "circomlib/circuits/comparators.circom";

template AssertSorted(n, b) {
  signal input in[n];

  // accumulator for in[i-1] >= in[i] checks (to verify descending order)
  component isGreaterThan[n-1];
  signal accumulator[n];
  accumulator[0] <== 0;
  
  for (var i = 1; i < n; i++) {
    var index = i - 1;
    isGreaterThan[index] = GreaterEqThan(b);
    isGreaterThan[index].in[0] <== in[i-1];
    isGreaterThan[index].in[1] <== in[i];
    accumulator[i] <== accumulator[i-1] + isGreaterThan[index].out;
  }

  accumulator[n-1] === n - 1;
}