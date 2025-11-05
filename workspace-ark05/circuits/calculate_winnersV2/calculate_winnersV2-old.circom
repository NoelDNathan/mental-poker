pragma circom 2.2.0;
include "CalculateScore.circom";
include "circomlib/circuits/comparators.circom";

template CalculateWinners() {
  var numPlayers = 4;
  var maxNumBits = 8;
  signal input cards[numPlayers][7];
  signal output score[numPlayers];
  component calculateWinners[numPlayers];
  for (var i = 0; i < numPlayers; i++) {
    calculateWinners[i] = CalculateScore(maxNumBits);
    calculateWinners[i].cards <== cards[i];
    score[i] <== calculateWinners[i].scoreOut;
  }
  var acc = 0;
  for (var i = 1; i < numPlayers; i++) {
    var isGreaterThan = GreaterEqThan(maxNumBits)([score[i-1],
     score[i]]);
    acc += isGreaterThan;
  }

  acc === numPlayers - 1;

}

// Componente principal con las cartas como entrada pública
component main {public [cards]} = CalculateWinners(); 