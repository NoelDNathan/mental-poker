pragma circom 2.2.0;
include "CalculateScore.circom";

template CalculateScores() {
  var numPlayers = 5;
  var maxNumBits = 8;
  
  // Public input: community cards (5 cards shared by all players)
  signal input communityCards[5];
  
  // Private input: 2 cards per player
  signal input privateCards[numPlayers][2];
  
  signal output scores[numPlayers];
  
  component calculateScore[numPlayers];
  for (var i = 0; i < numPlayers; i++) {
    calculateScore[i] = CalculateScore(maxNumBits);
    
    // Combine private cards (2) with community cards (5) to form 7 cards total
    for (var j = 0; j < 2; j++) {
      calculateScore[i].cards[j] <== privateCards[i][j];
    }
    for (var j = 0; j < 5; j++) {
      calculateScore[i].cards[j + 2] <== communityCards[j];
    }
    
    scores[i] <== calculateScore[i].scoreOut;
  }
}

// Main component: both communityCards and privateCards are public (end of game)
component main {public [communityCards, privateCards]} = CalculateScores();

