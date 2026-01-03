pragma circom 2.1.9;

include "../../EvaluateCard.circom";
var card = 12
component main {public [cardsRank, cardsSuit]} = EvaluateCard(card, 4);
