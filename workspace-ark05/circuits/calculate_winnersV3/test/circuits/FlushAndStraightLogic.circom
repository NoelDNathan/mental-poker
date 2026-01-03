pragma circom 2.1.9;

include "../../FlushAndStraightLogic.circom";

 component main {public [cardsRank, cardsSuit]} = FlushAndStraightLogic(4);
