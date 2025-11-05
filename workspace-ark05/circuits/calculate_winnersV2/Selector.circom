pragma circom 2.2.0;

template Selector() {
  signal input condition;
  signal input true;
  signal input false;
  signal output out;

  // Ensure condition is binary (0 or 1)
  condition * (1 - condition) === 0;

  signal notCondition;
  notCondition <== 1 - condition;

  signal temp1;
  signal temp2;

  temp1 <== condition * true;
  temp2 <== notCondition * false;

  out <== temp1 + temp2;
}