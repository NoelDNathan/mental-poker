pragma circom 2.2.0;
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "Selector.circom";


template Straight(maxNumBits) {
    signal input cards[7];
    signal output scoreOut;

    component hasAs = IsEqual();

    hasAs.in <== [cards[0], 14];

    signal cardplus[6];
    component isNextNumber[6];
    component isTwo[6];
    component isGreaterThanThree[6];
    component isTwoAndHasAs[6];


    signal straightScore[7];
    straightScore[0] <== 0;
    signal straightCountPlus[6];
    signal straightCountInternal[6];
    signal straightCount[7];
    straightCount[0] <== 0;

    component selectCard[6];
    component selectScore[6];

    for (var i = 1; i < 7; i++) {
      var index = i - 1;
      isNextNumber[index] = IsEqual();
      isTwo[index] = IsEqual();
      isTwoAndHasAs[index] = AND();
      isGreaterThanThree[index] = GreaterThan(maxNumBits);

      cardplus[index] <== cards[i] + 1;
      isNextNumber[index].in <== [cards[i-1], cardplus[index]];

    
      //if card[i-1] == card + 1 then straightCount += 1
      straightCountPlus[index] <== (straightCount[i - 1] + 1) * isNextNumber[index].out;

      isTwo[index].in <== [cards[i], 2];

      // if card[i] == 2 and card[0] == 14 then straightCount += 1
      isTwoAndHasAs[index].a <== isTwo[index].out;
      isTwoAndHasAs[index].b <== hasAs.out;

      // if isTwoAndHasAs: straightCount += 1
      straightCountInternal[index] <== straightCountPlus[index] + isTwoAndHasAs[index].out;

      // straightCount > 3 || isTwoAndHasAs
      // true || true => cards[i - 3]
      // true || false => cards[i - 4]
      // false || true => straightScore[i-1]
      // false || false => straightScore[i-1]

      isGreaterThanThree[index].in <== [straightCountInternal[index], 3];

      var j = i > 3 ? i - 4 : i;
      selectCard[index] = Selector();
      selectCard[index].condition <== isTwoAndHasAs[index].out;
      selectCard[index].true <== cards[j + 1];
      selectCard[index].false <== cards[j];

      
      selectScore[index] = Selector();
      selectScore[index].condition <== isGreaterThanThree[index].out;
      selectScore[index].true <== selectCard[index].out;
      selectScore[index].false <== straightScore[i-1];
      straightScore[i] <== selectScore[index].out;


      // Reset straightCount to 0 if straightCount > 3
      straightCount[i] <== (1 - isGreaterThanThree[index].out) * straightCountInternal[index];
    }
    scoreOut <== straightScore[6];

}
