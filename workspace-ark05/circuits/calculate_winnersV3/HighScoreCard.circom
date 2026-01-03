pragma circom 2.1.9;
include "Constants.circom";

template HighScoreCard(maxNumBits){
    signal input cardsRank[7];
    signal output scoreOut;
   
   scoreOut <== cardsRank[0] * rankBase5() +
                cardsRank[1] * rankBase4() +
                cardsRank[2] * rankBase3() +
                cardsRank[3] * rankBase2() +
                cardsRank[4] * rankBase1();
}
