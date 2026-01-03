pragma circom 2.1.9;
include "../../Flush.circom";
component main {public [cardsRank, cardsSuit]} = Flush(4);
