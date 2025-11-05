pragma circom 2.2.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

template IsInRange(maxNumBits) {
  signal input MIN;
  signal input num;
  signal input MAX;
  signal output out;

  component isLessThan = LessEqThan(maxNumBits);
  isLessThan.in <== [num, MAX];
  component isGreaterThan = GreaterThan(maxNumBits);
  isGreaterThan.in <== [num, MIN];

  component isInRange = AND();
  isInRange.a <== isLessThan.out;
  isInRange.b <== isGreaterThan.out;
  
  out <== isInRange.out;

}
