pragma circom 2.2.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "Selector.circom";
include "IsInRange.circom";


template CurrentColor(maxNumBits){
    signal input card;
    signal output colorOut;

    component isClubs;
    component isDiamonds; 
    component isSpades; 
    component isHearts; 

    isClubs = IsInRange(maxNumBits);
    isClubs.MIN <== 0;
    isClubs.MAX <== 12;
    isClubs.num <== card;

    isDiamonds = IsInRange(maxNumBits);
    isDiamonds.MIN <== 13;
    isDiamonds.MAX <== 25;
    isDiamonds.num <== card;

    isSpades = IsInRange(maxNumBits);
    isSpades.MIN <== 26;
    isSpades.MAX <== 38;
    isSpades.num <== card;

    isHearts = IsInRange(maxNumBits);
    isHearts.MIN <== 39;
    isHearts.MAX <== 51;
    isHearts.num <== card;

    // 1 => clubs, 2 => diamonds, 3 => spades, 4 => hearts
    colorOut <== isClubs.out + isDiamonds.out * 2 + isSpades.out * 3 + isHearts.out * 4;
}

template IsAs(maxNumBits){
    signal input card;
    signal output colorOut;

    component isAs = IsEqual();
    isAs.in <== [card, 14];

    component currentColor = CurrentColor(maxNumBits);
    currentColor.card <== card;

    colorOut <== isAs.out * currentColor.colorOut;

    // 0 => no as, 1 => clubs, 2 => diamonds, 3 => spades, 4 => hearts
}


template StraightFlush(maxNumBits){
    signal input cards[7];
    signal output scoreOut;

    component hasSameColor[6];
    

    // Pueden haber varios ases
    component isAs0 = IsAs(maxNumBits);
    isAs0.card <== cards[0];

    component isAs1 = IsAs(maxNumBits);
    isAs1.card <== cards[1];

    component isAs2 = IsAs(maxNumBits);
    isAs2.card <== cards[2];

    component isAs3 = IsAs(maxNumBits);
    isAs3.card <== cards[3];


    signal AnyIsAs[6];

    signal cardplus[6];
    component isNextNumber[6];
    component isTwo[6];
    component isGreaterThanThree[6];
    component hasEqualColor0[6];
    component hasEqualColor1[6];
    component hasEqualColor2[6];
    component hasEqualColor3[6];
    component isTwoAndHasAs[6];
    component currentColor[7];
    currentColor[0] = CurrentColor(maxNumBits);
    currentColor[0].card <== cards[0];
    component isNextNumberAndSameColor[6];

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

      currentColor[i] = CurrentColor(maxNumBits);
      currentColor[i].card <== cards[i];
    
      hasSameColor[index] = IsEqual();
      hasSameColor[index].in <== [currentColor[i].colorOut, currentColor[i-1].colorOut];

      cardplus[index] <== cards[i] + 1;

      isNextNumber[index] = IsEqual();
      isNextNumber[index].in <== [cards[i-1], cardplus[index]];

      isNextNumberAndSameColor[index] = AND();
      isNextNumberAndSameColor[index].a <== isNextNumber[index].out;
      isNextNumberAndSameColor[index].b <== hasSameColor[index].out;
    
      //if card[i-1] == card + 1 then straightCount += 1
      // Si la carta anterior es la carta actual + 1 y tiene el mismo color, 
      //entonces el contador de escalera se incrementa en 1
      straightCountPlus[index] <== (straightCount[i - 1] + 1) * isNextNumberAndSameColor[index].out;    
      
      // Miramos si en caso de que haya un as, si es del mismo color que  la carta actual
      
      hasEqualColor0[index] = IsEqual();
      hasEqualColor0[index].in <== [currentColor[i].colorOut, isAs0.colorOut];

      hasEqualColor1[index] = IsEqual();
      hasEqualColor1[index].in <== [currentColor[i].colorOut, isAs1.colorOut];

      hasEqualColor2[index] = IsEqual();
      hasEqualColor2[index].in <== [currentColor[i].colorOut, isAs2.colorOut];   

      hasEqualColor3[index] = IsEqual();
      hasEqualColor3[index].in <== [currentColor[i].colorOut, isAs3.colorOut];
      
      AnyIsAs[index] <== hasEqualColor0[index].out + hasEqualColor1[index].out + hasEqualColor2[index].out + hasEqualColor3[index].out;
      
      // if card[i] == 2 : nos aseguramos de que la carta actual sea un 2
      isTwo[index] = IsEqual();
      isTwo[index].in <== [cards[i], 2];


      isTwoAndHasAs[index] = AND();
      isTwoAndHasAs[index].a <== isTwo[index].out;
      isTwoAndHasAs[index].b <== AnyIsAs[index];
      

      // if isTwoAndHasAs: straightCount += 1
      straightCountInternal[index] <== straightCountPlus[index] + isTwoAndHasAs[index].out;

      // straightCount > 3 || isTwoAndHasAs
      // true || true => cards[i - 3]
      // true || false => cards[i - 4]
      // false || true => straightScore[i-1]
      // false || false => straightScore[i-1]

      isGreaterThanThree[index] = GreaterThan(maxNumBits);
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