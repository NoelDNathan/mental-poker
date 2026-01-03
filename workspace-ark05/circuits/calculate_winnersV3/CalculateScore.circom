pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "SelectorUnchecked.circom";

include "Constants.circom";
include "AssertSorted.circom";
include "FlushAndStraightLogic.circom";
include "EvaluateCard.circom";
include "HighScoreCard.circom";

// Calculates a single 7-card poker score.
//
// Inputs:
// - `cardsRank[7]`: ranks sorted in non-increasing order (two=0 .. ace=12).
// - `cardsSuit[7]`: matching suits for each card (0..3).
//
// Output:
// - `scoreOut`: a single integer where higher means a stronger hand.
template CalculateScore(maxNumBits) {
  signal input cardsRank[7];
  signal input cardsSuit[7];
  signal output scoreOut;
    

  // --------------------------------------------------------------------------
  // Basic input sanity: ranks are sorted (Straight/Flush logic expects this).
  // --------------------------------------------------------------------------
  component sortedCheck = AssertSorted(7, maxNumBits);
  sortedCheck.in <== cardsRank;

  // --------------------------------------------------------------------------
  // Rank counts (how many occurrences of each rank in the 7 cards).
  // --------------------------------------------------------------------------
  component isRank[13][7];
  signal rankAccum[13][8];
  signal rankCount[13];

  for (var r = 0; r < 13; r++) {
    rankAccum[r][0] <== 0;
  }

  for (var i = 0; i < 7; i++) {
    for (var r = 0; r < 13; r++) {
      isRank[r][i] = IsEqual();
      isRank[r][i].in <== [cardsRank[i], r];
      rankAccum[r][i + 1] <== rankAccum[r][i] + isRank[r][i].out;
    }
  }

  for (var r = 0; r < 13; r++) {
    rankCount[r] <== rankAccum[r][7];
  }

  // --------------------------------------------------------------------------
  // Repeated-rank hands (pair / two-pair / trips / full-house / quads).
  // The evaluation is done from low to high ranks to keep the best (highest)
  // rank combination when multiple candidates exist.
  // --------------------------------------------------------------------------
  component eval[13];

  eval[0] = EvaluateCard(0, maxNumBits);
  eval[0].cards <== cardsRank;
  eval[0].cardCount <== rankCount[0];
  eval[0].hasPokerIn <== 0;
  eval[0].hasFullHouseIn <== 0;
  eval[0].hasTrioIn <== 0;
  eval[0].hasDoublePairsIn <== 0;
  eval[0].hasPairsIn <== 0;
  eval[0].pokerScoreIn <== 0;
  eval[0].fullHouseScoreIn <== 0;
  eval[0].trioScoreIn <== 0;
  eval[0].doublePairsScoreIn <== 0;
  eval[0].pairsScoreIn <== 0;
  eval[0].trioCardIn <== 0;
  eval[0].pairsCardIn <== 0;

  for (var r = 1; r < 13; r++) {
    eval[r] = EvaluateCard(r, maxNumBits);
    eval[r].cards <== cardsRank;
    eval[r].cardCount <== rankCount[r];

    eval[r].hasPokerIn <== eval[r - 1].hasPokerOut;
    eval[r].hasFullHouseIn <== eval[r - 1].hasFullHouseOut;
    eval[r].hasTrioIn <== eval[r - 1].hasTrioOut;
    eval[r].hasDoublePairsIn <== eval[r - 1].hasDoublePairsOut;
    eval[r].hasPairsIn <== eval[r - 1].hasPairsOut;

    eval[r].pokerScoreIn <== eval[r - 1].pokerScoreOut;
    eval[r].fullHouseScoreIn <== eval[r - 1].fullHouseScoreOut;
    eval[r].trioScoreIn <== eval[r - 1].trioScoreOut;
    eval[r].doublePairsScoreIn <== eval[r - 1].doublePairsScoreOut;
    eval[r].pairsScoreIn <== eval[r - 1].pairsScoreOut;

    eval[r].trioCardIn <== eval[r - 1].trioCardOut;
    eval[r].pairsCardIn <== eval[r - 1].pairsCardOut;
  }

  // --------------------------------------------------------------------------
  // Straight / flush / straight-flush (computed together by `FlushAndStraightLogic`).
  // --------------------------------------------------------------------------
  component flushAndStraight = FlushAndStraightLogic(maxNumBits);
  flushAndStraight.cardsRank <== cardsRank;
  flushAndStraight.cardsSuit <== cardsSuit;


  // --------------------------------------------------------------------------
  // High cards (only used when no higher category applies).
  // --------------------------------------------------------------------------
  component highCards = HighScoreCard(maxNumBits);
  highCards.cardsRank <== cardsRank;

  // --------------------------------------------------------------------------
  // Build category scores using the shared offsets from `Constants.circom`.
  // --------------------------------------------------------------------------
  signal scoreHigh <== highCardsOffset() + highCards.scoreOut;
  signal scorePairs <== pairsOffset() + eval[12].pairsScoreOut;
  signal scoreTwoPairs <== doublePairsOffset() + eval[12].doublePairsScoreOut;
  signal scoreTrips <== trioOffset() + eval[12].trioScoreOut;
  signal scoreStraight <== straightOffset() + flushAndStraight.straightScoreOut;
  signal scoreFlush <== flushOffset() + flushAndStraight.flushScoreOut;
  signal scoreFullHouse <== fullHouseOffset() + eval[12].fullHouseScoreOut;
  signal scoreQuads <== pokerOffset() + eval[12].pokerScoreOut;
  signal scoreStraightFlush <== straightFlushOffset() + flushAndStraight.straightFlushScoreOut;

  // --------------------------------------------------------------------------
  // Priority selection (highest category wins).
  // --------------------------------------------------------------------------
  signal best0 <== scoreHigh;

  component selPairs = SelectorUnchecked();
  selPairs.condition <== eval[12].hasPairsOut;
  selPairs.true <== scorePairs;
  selPairs.false <== best0;
  signal best1 <== selPairs.out;

  component selTwoPairs = SelectorUnchecked();
  selTwoPairs.condition <== eval[12].hasDoublePairsOut;
  selTwoPairs.true <== scoreTwoPairs;
  selTwoPairs.false <== best1;
  signal best2 <== selTwoPairs.out;

  component selTrips = SelectorUnchecked();
  selTrips.condition <== eval[12].hasTrioOut;
  selTrips.true <== scoreTrips;
  selTrips.false <== best2;
  signal best3 <== selTrips.out;

  component selStraight = SelectorUnchecked();
  selStraight.condition <== flushAndStraight.hasStraight;
  selStraight.true <== scoreStraight;
  selStraight.false <== best3;
  signal best4 <== selStraight.out;

  component selFlush = SelectorUnchecked();
  selFlush.condition <== flushAndStraight.hasFlush;
  selFlush.true <== scoreFlush;
  selFlush.false <== best4;
  signal best5 <== selFlush.out;

  component selFullHouse = SelectorUnchecked();
  selFullHouse.condition <== eval[12].hasFullHouseOut;
  selFullHouse.true <== scoreFullHouse;
  selFullHouse.false <== best5;
  signal best6 <== selFullHouse.out;

  component selQuads = SelectorUnchecked();
  selQuads.condition <== eval[12].hasPokerOut;
  selQuads.true <== scoreQuads;
  selQuads.false <== best6;
  signal best7 <== selQuads.out;

  component selStraightFlush = SelectorUnchecked();
  selStraightFlush.condition <== flushAndStraight.hasStraightFlush;
  selStraightFlush.true <== scoreStraightFlush;
  selStraightFlush.false <== best7;

  scoreOut <== selStraightFlush.out;
}


