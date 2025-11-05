pragma circom 2.2.0;
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "IsInRange.circom";


template Color(maxNumBits) {
    signal input cards[7];
    signal output scoreOut;


    var ColorMultplier = 5000000;
                    //13**6, 13**5 13**4, 13**3, 13**2, 13**1, 13**0
    
    var colorScorePowers[7] = [4826809, 371293, 28561, 2197, 169, 13, 1];

    var clubCount = 0;
    var clubAccum = 0;
    var diamondCount = 0;
    var heartCount = 0;
    var spadeCount = 0;

    var colorScores[4] = [0,0,0,0];

    // Contar cartas de cada palo
    component isClubs[7];
    component isDiamonds[7]; 
    component isSpades[7]; 
    component isHearts[7]; 

    component Clubs_lessThan5[7];
    component Diamonds_lessThan5[7];
    component Spades_lessThan5[7];
    component Hearts_lessThan5[7];

    signal Clubs_isSelected[7];
    signal Diamonds_isSelected[7];
    signal Spades_isSelected[7];
    signal Hearts_isSelected[7];

    signal Clubs_card[7];
    signal Diamonds_card[7];
    signal Hearts_card[7];
    signal Spades_card[7];


    // Hay rangos de valores para cada color
    // Clubs: 0-12 (MAX=13, exclusivo superior)
    // Diamonds: 13-25 (MAX=26, exclusivo superior)
    // Hearts: 26-38 (MAX=39, exclusivo superior)
    // Spades: 39-51 (MIN=39, MAX=52, exclusivo superior en MAX)
    // Nota: IsInRange usa LessEqThan que incluye MAX, pero GreaterThan excluye MIN
    // Entonces:
    // Detecta el rango de cada carta
    // Solo tiene en cuenta las primeras 5 cartas de cada rango ya que son las más grandes
    // es decir, solo tiene en cuenta el color más grande
    // Para darle más peso a los colores más grandes, se multiplica por 13^(7-i)
    // Hay un accumulador que va contando cuantas cartas de cada color hay


    for (var i = 0; i < 7; i++) {
        
        // Color
        var card = cards[i];

        // Clubs: [0-13)
        isClubs[i] = IsInRange(maxNumBits);
        isClubs[i].MIN <== 0;
        isClubs[i].num <== card;
        isClubs[i].MAX <== 13;

        // Solo tiene en cuenta las primeras 5 cartas en ser clubs (ya que son las más grandes)
        Clubs_lessThan5[i] = LessThan(maxNumBits);
        Clubs_lessThan5[i].in <== [clubCount, 5];
        
        // Clubs_lessThan5 and isClubs
        Clubs_isSelected[i] <== Clubs_lessThan5[i].out * isClubs[i].out;
        Clubs_card[i] <== card * Clubs_isSelected[i];
        colorScores[0] += Clubs_card[i] * colorScorePowers[i];
        clubCount += isClubs[i].out;

        // Diamonds: 13-25
        isDiamonds[i] = IsInRange(maxNumBits);
        isDiamonds[i].MIN <== 13;
        isDiamonds[i].num <== card;
        isDiamonds[i].MAX <== 26;

        Diamonds_lessThan5[i] = LessThan(maxNumBits);
        Diamonds_lessThan5[i].in <== [diamondCount, 5];
        Diamonds_isSelected[i] <== Diamonds_lessThan5[i].out * isDiamonds[i].out;
        
        Diamonds_card[i] <== card * Diamonds_isSelected[i];
        colorScores[1] += Diamonds_card[i] * colorScorePowers[i];
        diamondCount += isDiamonds[i].out;


        // Hearts: 26-38
        isHearts[i] = IsInRange(maxNumBits);
        isHearts[i].MIN <== 26;
        isHearts[i].num <== card;
        isHearts[i].MAX <== 39;

        Hearts_lessThan5[i] = LessThan(maxNumBits);
        Hearts_lessThan5[i].in <== [heartCount, 5];
        Hearts_isSelected[i] <== Hearts_lessThan5[i].out * isHearts[i].out;

        Hearts_card[i] <== card * Hearts_isSelected[i];
        colorScores[2] += Hearts_card[i] * colorScorePowers[i];
        heartCount += isHearts[i].out;

        // Spades: 39-51 (MIN > 38, MAX <= 52, but LessEqThan includes 52)
        // Actual range is num > 38 and num <= 52, which gives 39-52
        // However, valid card range is 0-51, so effective range is 39-51
        isSpades[i] = IsInRange(maxNumBits);
        isSpades[i].MIN <== 39;
        isSpades[i].num <== card;
        isSpades[i].MAX <== 52;

        Spades_lessThan5[i] = LessThan(maxNumBits);
        Spades_lessThan5[i].in <== [spadeCount, 5];
        Spades_isSelected[i] <== Spades_lessThan5[i].out * isSpades[i].out;
        
        Spades_card[i] <== card * Spades_isSelected[i];
        colorScores[3] += Spades_card[i] * colorScorePowers[i];
        spadeCount += isSpades[i].out;

    }
    
    component hasClubs = GreaterThan(maxNumBits);
    component hasDiamonds = GreaterThan(maxNumBits);
    component hasHearts = GreaterThan(maxNumBits);
    component hasSpades = GreaterThan(maxNumBits);
    
    // Si hay 4 cartas de un color, entonces es un color
    
    hasClubs.in <== [clubCount, 4];
    hasDiamonds.in <== [diamondCount, 4];
    hasHearts.in <== [heartCount, 4];
    hasSpades.in <== [spadeCount, 4];

    signal colorScoreClubs <== colorScores[0];
    signal colorScoreDiamonds <== colorScores[1];
    signal colorScoreHearts <== colorScores[2];
    signal colorScoreSpades <== colorScores[3];

   signal isClubsScore <== colorScoreClubs * hasClubs.out;
   signal isDiamondsScore <== colorScoreDiamonds * hasDiamonds.out;
   signal isHeartsScore <== colorScoreHearts * hasHearts.out;
   signal isSpadesScore <== colorScoreSpades * hasSpades.out;


    signal colorScore;
    colorScore <== isClubsScore +
                  isDiamondsScore +
                  isHeartsScore +
                  isSpadesScore;
    scoreOut <== colorScore;

}

