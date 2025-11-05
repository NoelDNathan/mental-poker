pragma circom 2.2.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "Selector.circom";

template EvaluateCard(card, maxNumBits, m13, m169, m2197, m28561) {
  signal input cards[7];
  signal input cardCount;
  signal input hasPokerIn;
  signal input hasFullHouseIn;
  signal input hasTrioIn;
  signal input hasDoublePairsIn;
  signal input hasPairsIn;

  signal input pokerScoreIn;
  signal input fullHouseScoreIn;
  signal input trioScoreIn;
  signal input doublePairsScoreIn;
  signal input pairsScoreIn;

  signal input trioCardIn;
  signal input pairsCardIn;

  signal output hasPokerOut;
  signal output hasFullHouseOut;
  signal output hasTrioOut;
  signal output hasDoublePairsOut;
  signal output hasPairsOut;

  signal output pokerScoreOut;
  signal output fullHouseScoreOut;
  signal output trioScoreOut;
  signal output doublePairsScoreOut;
  signal output pairsScoreOut;

  signal output trioCardOut;
  signal output pairsCardOut;

  signal card0 <== cards[0];
  signal card1 <== cards[1];
  signal card2 <== cards[2];
  signal card3 <== cards[3];
  signal card4 <== cards[4];
  signal card5 <== cards[5];
  signal card6 <== cards[6];

  component isFirstBigger = GreaterThan(maxNumBits);
  component isSecondBigger = GreaterThan(maxNumBits);
  component isThirdBigger = GreaterThan(maxNumBits);
  
  component cardCountIsEqual4 = IsEqual();
  component cardCountIsEqual3 = IsEqual();
  component cardCountIsEqual2 = IsEqual();

  isFirstBigger.in <== [card0, card];
  isSecondBigger.in <== [card1, card];
  isThirdBigger.in <== [card2, card];

  cardCountIsEqual4.in <== [cardCount, 4];
  cardCountIsEqual3.in <== [cardCount, 3];
  cardCountIsEqual2.in <== [cardCount, 2];

  signal hasPokerCurrent <== cardCountIsEqual4.out;
  signal hasTrioCurrent <== cardCountIsEqual3.out;
  signal hasPairsCurrent <== cardCountIsEqual2.out;

  //.......................................................


  // if countCard == 4

  // poker score
  // if card0 > card
  // true -> card0
  // false -> card4

  component selectorPoker = Selector();
  selectorPoker.condition <== isFirstBigger.out;
  selectorPoker.true <== card0;
  selectorPoker.false <== card4;

  signal pokerScore <== card * m13 + selectorPoker.out;
  

  component OrHasPoker = OR();
  OrHasPoker.a <== hasPokerCurrent;
  OrHasPoker.b <== hasPokerIn;
  hasPokerOut <== OrHasPoker.out;


  component selectorBestPoker = Selector();
  selectorBestPoker.condition <== hasPokerCurrent;
  selectorBestPoker.true <== pokerScore;
  selectorBestPoker.false <== pokerScoreIn;

  pokerScoreOut <== selectorBestPoker.out;

 
  //..............................  ......................

  
  // if countCard == 3

      // full house score
      component isFullHouseTrio = AND();
      isFullHouseTrio.a <== hasPairsIn;
      isFullHouseTrio.b <== hasTrioCurrent;      
      signal fullhouseScoreTrio <== isFullHouseTrio.out * (pairsCardIn + card * m13);


      // (1) card1 > card  || (2) card2 > card
      // true  || true  -> [card0, card1]
      // true  || false -> [card0, card4] // card0 trio trio trio card4
      // false || true  ->  impossible card1 > card2
      // false || false -> [card3, card4] // trio trio trio card3 card4

      component selectorTrio2 = Selector();
      selectorTrio2.condition <== isSecondBigger.out;
      selectorTrio2.true <== card1;
      selectorTrio2.false <== card4;

      component selectorTrio1 = Selector();
      selectorTrio1.condition <== isFirstBigger.out;
      selectorTrio1.true <== card0;
      selectorTrio1.false <== card3;

      signal trioScore <== card * m169 + selectorTrio1.out * m13 + selectorTrio2.out; 
      

      component OrHasTrio = OR();
      OrHasTrio.a <== hasTrioCurrent;
      OrHasTrio.b <== hasTrioIn;
      hasTrioOut <== OrHasTrio.out;

      component selectorBestTrio = Selector();
      selectorBestTrio.condition <== hasTrioCurrent;
      selectorBestTrio.true <== trioScore;
      selectorBestTrio.false <== trioScoreIn;
      trioScoreOut <== selectorBestTrio.out; 

      component selectorBestTrioCard = Selector();
      selectorBestTrioCard.condition <== hasTrioCurrent;
      selectorBestTrioCard.true <== card;
      selectorBestTrioCard.false <== trioCardIn;
      trioCardOut <== selectorBestTrioCard.out;

  
  //....................................................

  // if countCard == 2

    // fullhouse
    component isFullHousePair = AND();
    isFullHousePair.a <== hasTrioIn;
    isFullHousePair.b <== hasPairsCurrent;
    signal fullhouseScorePair <== isFullHousePair.out * (trioCardIn * m13 + card);


    // double pairs
    // Asumimos que pairsCardIn > card
    // if: (1) card0 > card | (2) pairsCardIn > card
    // true  || true/false  -> [card0]
    // false || true -> [card4]
    // false || false -> [card2]
    
    component isPairsBigger = GreaterThan(maxNumBits);
    isPairsBigger.in <== [pairsCardIn, card2];
    
    component selectorDPs2 = Selector();
    selectorDPs2.condition <== isPairsBigger.out;
    selectorDPs2.true <== card4;
    selectorDPs2.false <== card2;

    component selectorDPs1 = Selector();
    selectorDPs1.condition <== isFirstBigger.out;
    selectorDPs1.true <== card0;
    selectorDPs1.false <== selectorDPs2.out;

    component isDoublePairs = AND();
    isDoublePairs.a <== hasPairsIn;
    isDoublePairs.b <== hasPairsCurrent;
    signal doublePairsScore <== isDoublePairs.out * (pairsCardIn * m13 + card * m169 + selectorDPs1.out);

    component OrHasDoublePairs = OR();
    OrHasDoublePairs.a <== isDoublePairs.out;
    OrHasDoublePairs.b <== hasDoublePairsIn;
    hasDoublePairsOut <== OrHasDoublePairs.out;

    component selectorBestDPs = Selector();
    selectorBestDPs.condition <== isDoublePairs.out;
    selectorBestDPs.true <== doublePairsScore;
    selectorBestDPs.false <== doublePairsScoreIn;

    doublePairsScoreOut <== selectorBestDPs.out;
    
    // pairs score
    // asumimos que card0 > card1 > card2
    // if: (1) card0 > card | (2) card1 > card | (3) card2 > card
    // true  || true  || true  -> [card0, card1, card2]
    // true  || true  || false  -> [card0, card1, card4]
    // true  || false  || false  -> [card0, card3, card4]
    // false || false || false  -> [card2, card3, card4]

    component selector3 = Selector();
    selector3.condition <== isThirdBigger.out;
    selector3.true <== card2;
    selector3.false <== card4;

    component selector2 = Selector();
    selector2.condition <== isSecondBigger.out;
    selector2.true <== card1;
    selector2.false <== card3;

    component selector1 = Selector();
    selector1.condition <== isFirstBigger.out;
    selector1.true <== card0;
    selector1.false <== card2;

    signal pairsScore <== card * m2197 + selector1.out * m169 + selector2.out * m13 + selector3.out;

    component OrHasPairs = OR();
    OrHasPairs.a <== hasPairsCurrent;
    OrHasPairs.b <== hasPairsIn;
    hasPairsOut <== OrHasPairs.out;


    component selectorBestPairs = Selector();
    selectorBestPairs.condition <== hasPairsCurrent;
    selectorBestPairs.true <== pairsScore;
    selectorBestPairs.false <== pairsScoreIn;

    pairsScoreOut <== selectorBestPairs.out;

    component selectorBestPairsCard = Selector();
    selectorBestPairsCard.condition <== hasPairsCurrent;
    selectorBestPairsCard.true <== card;
    selectorBestPairsCard.false <== pairsCardIn;
    pairsCardOut <== selectorBestPairsCard.out;

  // ........................................................
  // fullhouse out
  component OrHasFullHouseInternal = OR();
  OrHasFullHouseInternal.a <== isFullHousePair.out;
  OrHasFullHouseInternal.b <== isFullHouseTrio.out;

  component OrHasFullHouse = OR();
  OrHasFullHouse.a <== OrHasFullHouseInternal.out;
  OrHasFullHouse.b <== hasFullHouseIn;
  hasFullHouseOut <== OrHasFullHouse.out;
 
  component selectorBestInternalFH = Selector();
  selectorBestInternalFH.condition <== isFullHouseTrio.out;
  selectorBestInternalFH.true <== fullhouseScorePair;
  selectorBestInternalFH.false <== fullhouseScoreTrio;

  component selectorBestFullHouse = Selector();
  selectorBestFullHouse.condition <== OrHasFullHouseInternal.out;
  selectorBestFullHouse.true <== selectorBestInternalFH.out;
  selectorBestFullHouse.false <== fullHouseScoreIn;

  fullHouseScoreOut <== selectorBestFullHouse.out;
}
