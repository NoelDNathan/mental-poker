pragma circom 2.1.9;
include "CalculateScore.circom";

template CalculateScores() {
  var numPlayers = 4;
  var maxNumBits = 4;
  
  signal input cardsRank[numPlayers][7];
  signal input cardsSuit[numPlayers][7];

  
  signal output scores[numPlayers];
  component calculateScore[numPlayers];
  for (var i = 0; i < numPlayers; i++) {
    calculateScore[i] = CalculateScore(maxNumBits);
    
    for (var j = 0; j < 7; j++) {
      calculateScore[i].cardsRank[j] <== cardsRank[i][j];
      calculateScore[i].cardsSuit[j] <== cardsSuit[i][j];
    }
    
    scores[i] <== calculateScore[i].scoreOut;
  }
}

// Main component: the full 7-card hands are public (end of game).
component main {public [cardsRank, cardsSuit]} = CalculateScores();

