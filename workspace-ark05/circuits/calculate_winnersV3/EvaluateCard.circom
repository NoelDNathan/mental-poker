pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "SelectorUnchecked.circom";
include "Constants.circom";

// Evaluates all repeated-rank hands for a specific rank `card`.
//
// Preconditions:
// - `cards` are ranks sorted in non-increasing order (ace-high first).
//
// Encoding notes:
// - Scores are base-13 encoded using `rankBase*()` from `Constants.circom`.
// - Category offsets are applied in `CalculateScore.circom` (not here).
template EvaluateCard(card, maxNumBits) {
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
  // cards[5] and cards[6] are not used in this evaluator.

  // Local compile-time constants for readability.
  var B1 = rankBase1();
  var B2 = rankBase2();
  var B3 = rankBase3();
  var B4 = rankBase4();
  var B5 = rankBase5();

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

  // --------------------------------------------------------------------------
  // Quads (four of a kind)
  // --------------------------------------------------------------------------


  // if countCard == 4

  // poker score
  // if card0 > card
  // true -> card0
  // false -> card4

  component selectorPoker = SelectorUnchecked();
  selectorPoker.condition <== isFirstBigger.out;
  selectorPoker.true <== card0;
  selectorPoker.false <== card4;

  signal pokerScore <== card * B2 + selectorPoker.out * B1;
  

  component orHasPoker = OR();
  orHasPoker.a <== hasPokerCurrent;
  orHasPoker.b <== hasPokerIn;
  hasPokerOut <== orHasPoker.out;


  component selectBestPoker = SelectorUnchecked();
  selectBestPoker.condition <== hasPokerCurrent;
  selectBestPoker.true <== pokerScore;
  selectBestPoker.false <== pokerScoreIn;
  pokerScoreOut <== selectBestPoker.out;

 
  // --------------------------------------------------------------------------
  // Trips (three of a kind) + full house (when a pair already exists)
  // --------------------------------------------------------------------------

      // Full house formed by (current trips) + (best available "pair rank" from previous pairs OR previous trips).
      //
      // Important edge-case:
      // - With 7 cards, a full house can be formed by two trips (e.g. AAA + KKK + X).
      //   Legacy logic that only considers "previous pairs" would miss this, so we also allow "previous trips"
      //   to serve as the pair rank.
      component hasPairOrPrevTrips = OR();
      hasPairOrPrevTrips.a <== hasPairsIn;
      hasPairOrPrevTrips.b <== hasTrioIn;

      component prevTripsBetterThanPrevPair = GreaterThan(maxNumBits);
      prevTripsBetterThanPrevPair.in <== [trioCardIn, pairsCardIn];

      // Only pick the previous trips rank as the pair rank if a previous trips actually exists.
      // `hasTrioIn` and comparator outputs are already constrained to be 0/1.
      signal usePrevTripsAsPair <== hasTrioIn * prevTripsBetterThanPrevPair.out;

      component selectPairRankForTrips = SelectorUnchecked();
      selectPairRankForTrips.condition <== usePrevTripsAsPair;
      selectPairRankForTrips.true <== trioCardIn;
      selectPairRankForTrips.false <== pairsCardIn;

      component isFullHouseFromTrips = AND();
      isFullHouseFromTrips.a <== hasPairOrPrevTrips.out;
      isFullHouseFromTrips.b <== hasTrioCurrent;

      // Encode as (tripsRank * 13 + pairRank).
      signal fullHouseScoreFromTrips <== isFullHouseFromTrips.out * (card * B2 + selectPairRankForTrips.out * B1);


      // (1) card1 > card  || (2) card2 > card
      // true  || true  -> [card0, card1]
      // true  || false -> [card0, card4] // card0 trio trio trio card4
      // false || true  ->  impossible card1 > card2
      // false || false -> [card3, card4] // trio trio trio card3 card4

      component selectorTrio2 = SelectorUnchecked();
      selectorTrio2.condition <== isSecondBigger.out;
      selectorTrio2.true <== card1;
      selectorTrio2.false <== card4;

      component selectorTrio1 = SelectorUnchecked();
      selectorTrio1.condition <== isFirstBigger.out;
      selectorTrio1.true <== card0;
      selectorTrio1.false <== card3;

      signal trioScore <== card * B3 + selectorTrio1.out * B2 + selectorTrio2.out * B1; 
      

      component orHasTrio = OR();
      orHasTrio.a <== hasTrioCurrent;
      orHasTrio.b <== hasTrioIn;
      hasTrioOut <== orHasTrio.out;

      component selectBestTrips = SelectorUnchecked();
      selectBestTrips.condition <== hasTrioCurrent;
      selectBestTrips.true <== trioScore;
      selectBestTrips.false <== trioScoreIn;
      trioScoreOut <== selectBestTrips.out; 

      component selectBestTripsRank = SelectorUnchecked();
      selectBestTripsRank.condition <== hasTrioCurrent;
      selectBestTripsRank.true <== card;
      selectBestTripsRank.false <== trioCardIn;
      trioCardOut <== selectBestTripsRank.out;

  
  // --------------------------------------------------------------------------
  // Pair + two pair + full house (when trips already exists)
  // --------------------------------------------------------------------------

    // Full house formed by (previous trips) + (current pair).
    component isFullHouseFromPair = AND();
    isFullHouseFromPair.a <== hasTrioIn;
    isFullHouseFromPair.b <== hasPairsCurrent;
    signal fullHouseScoreFromPair <== isFullHouseFromPair.out * (trioCardIn * B2 + card * B1);


    // Double pair kicker selection: find highest card not in either pair
    // card0, card2, card4 are potential kickers since cards are sorted.
    component isCard0Pair = IsEqual();
    isCard0Pair.in <== [card0, card];

    component isCard0Pair2 = IsEqual();
    isCard0Pair2.in <== [card0, pairsCardIn];

    component isCard0Reserved = OR();
    isCard0Reserved.a <== isCard0Pair.out;
    isCard0Reserved.b <== isCard0Pair2.out;

    component isCard2Pair = IsEqual();
    isCard2Pair.in <== [card2, pairsCardIn];

    component kickerSel2 = SelectorUnchecked();
    kickerSel2.condition <== isCard2Pair.out;
    kickerSel2.true <== card4;
    kickerSel2.false <== card2;

    component kickerSel1 = SelectorUnchecked();
    kickerSel1.condition <== isCard0Reserved.out;
    kickerSel1.true <== kickerSel2.out;
    kickerSel1.false <== card0;

    component isDoublePairs = AND();
    isDoublePairs.a <== hasPairsIn;
    isDoublePairs.b <== hasPairsCurrent;
    signal doublePairsScore <== isDoublePairs.out * (card * B3 + pairsCardIn * B2 + kickerSel1.out * B1);

    component orHasTwoPair = OR();
    orHasTwoPair.a <== isDoublePairs.out;
    orHasTwoPair.b <== hasDoublePairsIn;
    hasDoublePairsOut <== orHasTwoPair.out;

    component selectBestTwoPair = SelectorUnchecked();
    selectBestTwoPair.condition <== isDoublePairs.out;
    selectBestTwoPair.true <== doublePairsScore;
    selectBestTwoPair.false <== doublePairsScoreIn;
    doublePairsScoreOut <== selectBestTwoPair.out;
    
    // Pair score (legacy V2 logic):
    // assumes cards are sorted non-increasingly.
    // if: (1) card0 > card | (2) card1 > card | (3) card2 > card
    // true  || true  || true  -> [card0, card1, card2]
    // true  || true  || false  -> [card0, card1, card4]
    // true  || false  || false  -> [card0, card3, card4]
    // false || false || false  -> [card2, card3, card4]

    component selector3 = SelectorUnchecked();
    selector3.condition <== isThirdBigger.out;
    selector3.true <== card2;
    selector3.false <== card4;

    component selector2 = SelectorUnchecked();
    selector2.condition <== isSecondBigger.out;
    selector2.true <== card1;
    selector2.false <== card3;

    component selector1 = SelectorUnchecked();
    selector1.condition <== isFirstBigger.out;
    selector1.true <== card0;
    selector1.false <== card2;

    signal pairsScore <== card * B4 + selector1.out * B3 + selector2.out * B2 + selector3.out * B1;

    component orHasPair = OR();
    orHasPair.a <== hasPairsCurrent;
    orHasPair.b <== hasPairsIn;
    hasPairsOut <== orHasPair.out;


    component selectBestPair = SelectorUnchecked();
    selectBestPair.condition <== hasPairsCurrent;
    selectBestPair.true <== pairsScore;
    selectBestPair.false <== pairsScoreIn;
    pairsScoreOut <== selectBestPair.out;

    component selectBestPairRank = SelectorUnchecked();
    selectBestPairRank.condition <== hasPairsCurrent;
    selectBestPairRank.true <== card;
    selectBestPairRank.false <== pairsCardIn;
    pairsCardOut <== selectBestPairRank.out;

  // --------------------------------------------------------------------------
  // Full house aggregation (either created by trips or by a pair).
  // --------------------------------------------------------------------------
  component orHasFullHouseInternal = OR();
  orHasFullHouseInternal.a <== isFullHouseFromPair.out;
  orHasFullHouseInternal.b <== isFullHouseFromTrips.out;

  component orHasFullHouse = OR();
  orHasFullHouse.a <== orHasFullHouseInternal.out;
  orHasFullHouse.b <== hasFullHouseIn;
  hasFullHouseOut <== orHasFullHouse.out;
 
  component selectBestInternalFullHouse = SelectorUnchecked();
  selectBestInternalFullHouse.condition <== isFullHouseFromTrips.out;
  selectBestInternalFullHouse.true <== fullHouseScoreFromTrips;
  selectBestInternalFullHouse.false <== fullHouseScoreFromPair;

  component selectBestFullHouse = SelectorUnchecked();
  selectBestFullHouse.condition <== orHasFullHouseInternal.out;
  selectBestFullHouse.true <== selectBestInternalFullHouse.out;
  selectBestFullHouse.false <== fullHouseScoreIn;
  fullHouseScoreOut <== selectBestFullHouse.out;
}
