pragma circom 2.2.0;

template HighScoreCard(maxNumBits, m13, m169, m2197, m28561){
    signal input cards[7];
    signal output scoreOut;
   
   scoreOut <== cards[0] * m28561 +
                cards[1] * m2197 +
                cards[2] * m169 +
                cards[3] * m13 +
                cards[4];
}
