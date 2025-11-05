pragma circom 2.2.0;
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "Selector.circom";
include "AssertSorted.circom";
include "StraightFlush.circom";
include "Color.circom";
include "Straight.circom";
include "EvaluateCard.circom";
include "HighScoreCard.circom";


template CalculateScore(maxNumBits) {
    signal input cards[7];

    component sortedCheck = AssertSorted(7, maxNumBits);
    sortedCheck.in <== cards;

    signal output scoreOut;
    
    // constants
    var ace = 14;
    var king = 13;
    var queen = 12;
    var jack = 11;
    var ten = 10;
    var nine = 9;
    var eight = 8;
    var seven = 7;
    var six = 6;
    var five = 5;
    var four = 4;
    var three = 3;
    var two = 2;

    var m13 = 13;
    var m169 = 169;
    var m2197 = 2197;
    var m28561 = 28561;


  component straightFlush = StraightFlush(maxNumBits);
  straightFlush.cards <== cards;

  // repeated cards

  component isEqualAce[7];
  component isEqualKing[7];
  component isEqualQueen[7];
  component isEqualJack[7];
  component isEqualTen[7];
  component isEqualNine[7];
  component isEqualEight[7];
  component isEqualSeven[7];
  component isEqualSix[7];
  component isEqualFive[7];
  component isEqualFour[7];
  component isEqualThree[7];
  component isEqualTwo[7];  

  // Accumulators as signals (size 8: initial 0 + 7 iterations)
  signal countAce[8];
  signal countKing[8];
  signal countQueen[8];
  signal countJack[8];
  signal countTen[8];
  signal countNine[8];
  signal countEight[8];
  signal countSeven[8];
  signal countSix[8];
  signal countFive[8];
  signal countFour[8];
  signal countThree[8];
  signal countTwo[8];

  // Initialize accumulators to 0
  countAce[0] <== 0;
  countKing[0] <== 0;
  countQueen[0] <== 0;
  countJack[0] <== 0;
  countTen[0] <== 0;
  countNine[0] <== 0;
  countEight[0] <== 0;
  countSeven[0] <== 0;
  countSix[0] <== 0;
  countFive[0] <== 0;
  countFour[0] <== 0;
  countThree[0] <== 0;
  countTwo[0] <== 0;

  for(var i = 0; i < 7; i++){
    var card = cards[i];
    isEqualAce[i] = IsEqual();
    isEqualKing[i] = IsEqual();
    isEqualQueen[i] = IsEqual();
    isEqualJack[i] = IsEqual();
    isEqualTen[i] = IsEqual();
    isEqualNine[i] = IsEqual();
    isEqualEight[i] = IsEqual();
    isEqualSeven[i] = IsEqual();
    isEqualSix[i] = IsEqual();
    isEqualFive[i] = IsEqual();
    isEqualFour[i] = IsEqual();
    isEqualThree[i] = IsEqual();
    isEqualTwo[i] = IsEqual();
 
    isEqualAce[i].in <== [card, ace];
    isEqualKing[i].in <== [card, king];
    isEqualQueen[i].in <== [card, queen];
    isEqualJack[i].in <== [card, jack];
    isEqualTen[i].in <== [card, ten];
    isEqualNine[i].in <== [card, nine];
    isEqualEight[i].in <== [card, eight];
    isEqualSeven[i].in <== [card, seven];
    isEqualSix[i].in <== [card, six];
    isEqualFive[i].in <== [card, five];
    isEqualFour[i].in <== [card, four];
    isEqualThree[i].in <== [card, three];
    isEqualTwo[i].in <== [card, two];

    // Accumulate using signals (each iteration adds to previous)
    countAce[i+1] <== countAce[i] + isEqualAce[i].out;
    countKing[i+1] <== countKing[i] + isEqualKing[i].out;
    countQueen[i+1] <== countQueen[i] + isEqualQueen[i].out;
    countJack[i+1] <== countJack[i] + isEqualJack[i].out;
    countTen[i+1] <== countTen[i] + isEqualTen[i].out;
    countNine[i+1] <== countNine[i] + isEqualNine[i].out;
    countEight[i+1] <== countEight[i] + isEqualEight[i].out;
    countSeven[i+1] <== countSeven[i] + isEqualSeven[i].out;
    countSix[i+1] <== countSix[i] + isEqualSix[i].out;
    countFive[i+1] <== countFive[i] + isEqualFive[i].out;
    countFour[i+1] <== countFour[i] + isEqualFour[i].out;
    countThree[i+1] <== countThree[i] + isEqualThree[i].out;
    countTwo[i+1] <== countTwo[i] + isEqualTwo[i].out;
  }


  var cardsList[13] = [two, three, four, five, six, seven, eight, nine, ten, jack, queen, king, ace];
  // Array of final count signals (index 7 after 7 iterations)
  signal countSignals[13];
  countSignals[0] <== countTwo[7];
  countSignals[1] <== countThree[7];
  countSignals[2] <== countFour[7];
  countSignals[3] <== countFive[7];
  countSignals[4] <== countSix[7];
  countSignals[5] <== countSeven[7];
  countSignals[6] <== countEight[7];
  countSignals[7] <== countNine[7];
  countSignals[8] <== countTen[7];
  countSignals[9] <== countJack[7];
  countSignals[10] <== countQueen[7];
  countSignals[11] <== countKing[7];
  countSignals[12] <== countAce[7];
  
  component evaluateCards[13];

  // Two
  evaluateCards[0] = EvaluateCard(two, maxNumBits, m13, m169, m2197, m28561);
  evaluateCards[0].cards <== cards;
  evaluateCards[0].cardCount <== countSignals[0];
  evaluateCards[0].hasPokerIn <== 0;
  evaluateCards[0].hasFullHouseIn <== 0;
  evaluateCards[0].hasTrioIn <== 0;
  evaluateCards[0].hasDoublePairsIn <== 0;
  evaluateCards[0].hasPairsIn <== 0;
  evaluateCards[0].pokerScoreIn <== 0;
  evaluateCards[0].fullHouseScoreIn <== 0;
  evaluateCards[0].trioScoreIn <== 0;
  evaluateCards[0].doublePairsScoreIn <== 0;
  evaluateCards[0].pairsScoreIn <== 0;

  evaluateCards[0].trioCardIn <== 0;
  evaluateCards[0].pairsCardIn <== 0;

  for(var i = 1; i < 13; i++){
    var card = cardsList[i];

    evaluateCards[i] = EvaluateCard(card, maxNumBits, m13, m169, m2197, m28561);
    evaluateCards[i].cards <== cards;
    evaluateCards[i].cardCount <== countSignals[i];
    evaluateCards[i].hasPokerIn <== evaluateCards[i-1].hasPokerOut;
    evaluateCards[i].hasFullHouseIn <== evaluateCards[i-1].hasFullHouseOut;
    evaluateCards[i].hasTrioIn <== evaluateCards[i-1].hasTrioOut;
    evaluateCards[i].hasDoublePairsIn <== evaluateCards[i-1].hasDoublePairsOut;
    evaluateCards[i].hasPairsIn <== evaluateCards[i-1].hasPairsOut;
    
    evaluateCards[i].pokerScoreIn <== evaluateCards[i-1].pokerScoreOut;
    evaluateCards[i].fullHouseScoreIn <== evaluateCards[i-1].fullHouseScoreOut;
    evaluateCards[i].trioScoreIn <== evaluateCards[i-1].trioScoreOut;
    evaluateCards[i].doublePairsScoreIn <== evaluateCards[i-1].doublePairsScoreOut;
    evaluateCards[i].pairsScoreIn <== evaluateCards[i-1].pairsScoreOut;
    
    evaluateCards[i].trioCardIn <== evaluateCards[i-1].trioCardOut;
    evaluateCards[i].pairsCardIn <== evaluateCards[i-1].pairsCardOut;
  }

  component color = Color(maxNumBits);
  color.cards <== cards;

  component straight = Straight(maxNumBits);
  straight.cards <== cards;

  component highScoreCard = HighScoreCard(maxNumBits, m13, m169, m2197, m28561);
  highScoreCard.cards <== cards;

 component notHasStraightFlush = IsEqual();
 notHasStraightFlush.in <== [0, straightFlush.scoreOut];

 signal notHasPoker <== 1 - evaluateCards[12].hasPokerOut;
 signal notHasFullHouse <== 1 - evaluateCards[12].hasFullHouseOut;
 
 component notHasColor = IsEqual();
 notHasColor.in <== [0, color.scoreOut];

 component notHasStraight = IsEqual();
 notHasStraight.in <== [0, straight.scoreOut];

 signal notHasTrio <== 1 - evaluateCards[12].hasTrioOut;
 signal notHasDoublePairs <== 1 - evaluateCards[12].hasDoublePairsOut;
 signal notHasPairs <== 1 - evaluateCards[12].hasPairsOut;

  // multiplicadores
  // Añadimos estos valores para diferenciar las scores de los diferentes rangos
  signal m1 <== 1000000000000 * evaluateCards[12].hasPairsOut;
  signal m2 <== 2000000000000 * evaluateCards[12].hasDoublePairsOut;
  signal m3 <== 3000000000000 * evaluateCards[12].hasTrioOut;
  signal m4 <== 4000000000000 * (1 - notHasStraight.out) ;
  signal m5 <== 5000000000000 * (1 - notHasColor.out);
  signal m6 <== 6000000000000 * evaluateCards[12].hasFullHouseOut;
  signal m7 <== 7000000000000 * evaluateCards[12].hasPokerOut;
  signal m8 <== 8000000000000 * (1 - notHasStraightFlush.out);

  signal s1 <== notHasPairs * highScoreCard.scoreOut;
  signal s2 <== notHasDoublePairs * (evaluateCards[12].pairsScoreOut + s1 + m1);
  signal s3 <== notHasTrio * (evaluateCards[12].doublePairsScoreOut + s2 + m2);
  signal s4 <== notHasStraight.out * (evaluateCards[12].trioScoreOut + s3 + m3);
  signal s5 <== notHasColor.out * (straight.scoreOut + s4 + m4);
  signal s6 <== notHasFullHouse * (color.scoreOut + s5 + m5);
  signal s7 <== notHasPoker * (evaluateCards[12].fullHouseScoreOut + s6 + m6);
  signal s8 <== notHasStraightFlush.out * (evaluateCards[12].pokerScoreOut + s7 + m7);
  scoreOut <== straightFlush.scoreOut + s8 + m8;

}