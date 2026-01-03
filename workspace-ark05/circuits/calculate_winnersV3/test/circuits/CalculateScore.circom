pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "SelectorUnchecked.circom";

include "Constants.circom";
include "AssertSorted.circom";
include "FlushAndStraightLogic.circom";
include "EvaluateCard.circom";
include "HighScoreCard.circom";

include "../../CalculateScore.circom";
component main {public [cardsRank, cardsSuit]} = CalculateScores();


