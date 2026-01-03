pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "SelectorUnchecked.circom";
include "Flush.circom";
include "constants.circom";


template FlushAndStraightLogic(maxNumBits) {
    signal input cardsRank[7];
    signal input cardsSuit[7];
    signal output straightScoreOut;
    signal output straightFlushScoreOut;
    signal output flushScoreOut;

    signal output hasStraight;
    signal output hasStraightFlush;
    signal output hasFlush;
    
    //___________________________________________________________________________________________________________
    //___________________________________________________________________________________________________________
    // BOTH components and signals
    //___________________________________________________________________________________________________________
    //___________________________________________________________________________________________________________    
    signal cardplus[6];

    component isNextRank[6];
    component isSameRank[6];
    component isTwo[4];
    component isTwoAndHasAce[4];
    component isGreaterThanThree[4];

    component NextOrSameRank[6];
    component selectScoreStraight[4];
    component selectScoreStraightFlush[4][6];
    component isPrevStraightScoreZero[3];
    signal updateStraightScoreCond[3];

    component hasAce1;
    component hasAce2;
    component hasAce3;
    component hasAce4;

    //___________________________________________________________________________________________________________
    //___________________________________________________________________________________________________________
    // Straight components and signals
    //___________________________________________________________________________________________________________
    //___________________________________________________________________________________________________________
    
    signal straightCountInternal[4];

    signal straightScore[5]; 
    signal straightCount[7];
    signal straightNextPart[6];
    signal straightSamePart[6];


    //___________________________________________________________________________________________________________
    //___________________________________________________________________________________________________________
    // Straight Flush components and signals
    //___________________________________________________________________________________________________________
    //___________________________________________________________________________________________________________


    //___________________________________________________________________________________________________________
    //___________________________________________________________________________________________________________
    // Straight Flush components and signals
    //___________________________________________________________________________________________________________
    //___________________________________________________________________________________________________________

    signal prevRankPerSuit[4][7];
    signal prevCountPerSuit[4][7];
    component isSamePrev[4][6];
    component isNextPrev[4][6];
    signal newCountSF[4][6];
    signal sfNextPart[4][6];
    signal sfSamePart[4][6];
    signal sfPropagatePart1[4][6];
    signal sfPropagatePart2[4][6];
    signal rankUpdatePart1[4][6];
    signal rankUpdatePart2[4][6];
    signal straightFlushCounterInternal2[4][6];
    component isPrevSFScoreZero[4][6];
    signal updateSFScoreCond[4][6];

    component isTwoAndHasAceSameSuit[4][6];
    component isStraightFlush[4][6];
    signal straightFlushScore[4][6];

    signal hasClubAce;
    signal hasDiamondAce;
    signal hasHeartAce;
    signal hasSpadeAce;

    component flush = Flush(maxNumBits);
    flush.cardsRank <== cardsRank;
    flush.cardsSuit <== cardsSuit;

    // Local compile-time constants (rank mapping: two=0 .. ace=12)
    var RANK_TWO = 0;
    var RANK_ACE = 12;

    // Straight flush values
    hasAce1 = IsEqual();
    hasAce2 = IsEqual();  
    hasAce3 = IsEqual();
    hasAce4 = IsEqual();

    hasAce1.in <== [cardsRank[0], RANK_ACE];
    hasAce2.in <== [cardsRank[1], RANK_ACE];
    hasAce3.in <== [cardsRank[2], RANK_ACE];
    hasAce4.in <== [cardsRank[3], RANK_ACE];

    // Avoid non-quadratic constraints by splitting each multiplication into its own constraint.
    signal clubAceTerm[4];
    clubAceTerm[0] <== hasAce1.out * flush.isSuit[0][0];
    clubAceTerm[1] <== hasAce2.out * flush.isSuit[0][1];
    clubAceTerm[2] <== hasAce3.out * flush.isSuit[0][2];
    clubAceTerm[3] <== hasAce4.out * flush.isSuit[0][3];
    hasClubAce <== clubAceTerm[0] + clubAceTerm[1] + clubAceTerm[2] + clubAceTerm[3];

    signal diamondAceTerm[4];
    diamondAceTerm[0] <== hasAce1.out * flush.isSuit[1][0];
    diamondAceTerm[1] <== hasAce2.out * flush.isSuit[1][1];
    diamondAceTerm[2] <== hasAce3.out * flush.isSuit[1][2];
    diamondAceTerm[3] <== hasAce4.out * flush.isSuit[1][3];
    hasDiamondAce <== diamondAceTerm[0] + diamondAceTerm[1] + diamondAceTerm[2] + diamondAceTerm[3];

    signal heartAceTerm[4];
    heartAceTerm[0] <== hasAce1.out * flush.isSuit[2][0];
    heartAceTerm[1] <== hasAce2.out * flush.isSuit[2][1];
    heartAceTerm[2] <== hasAce3.out * flush.isSuit[2][2];
    heartAceTerm[3] <== hasAce4.out * flush.isSuit[2][3];
    hasHeartAce <== heartAceTerm[0] + heartAceTerm[1] + heartAceTerm[2] + heartAceTerm[3];

    signal spadeAceTerm[4];
    spadeAceTerm[0] <== hasAce1.out * flush.isSuit[3][0];
    spadeAceTerm[1] <== hasAce2.out * flush.isSuit[3][1];
    spadeAceTerm[2] <== hasAce3.out * flush.isSuit[3][2];
    spadeAceTerm[3] <== hasAce4.out * flush.isSuit[3][3];
    hasSpadeAce <== spadeAceTerm[0] + spadeAceTerm[1] + spadeAceTerm[2] + spadeAceTerm[3];
    
    signal hasAce[4];
    hasAce[0] <== hasClubAce;
    hasAce[1] <== hasDiamondAce;
    hasAce[2] <== hasHeartAce;
    hasAce[3] <== hasSpadeAce;

    // Check if there's any ace (for straight detection)
    signal hasAnyAce;
    component hasAnyAceGT = GreaterThan(maxNumBits);
    hasAnyAce <== hasAce[0] + hasAce[1] + hasAce[2] + hasAce[3];
    hasAnyAceGT.in <== [hasAnyAce, 0];

    // Initial values for loop

    straightScore[0] <== 0;
    straightCount[0] <== 0;

    // initial straight flush values for loop


    // We compute the straight flush from the last card to the first
    // We compute the straight flush by tracking the last rank seen for each suit.
    for (var suitInit = 0; suitInit < 4; suitInit++) {
        prevRankPerSuit[suitInit][0] <== flush.isSuit[suitInit][0] * cardsRank[0];
        prevCountPerSuit[suitInit][0] <== 0;
        
        straightFlushScore[suitInit][0] <== 0;
        straightFlushScore[suitInit][1] <== 0;
    }


    // dos problemas, como se que el suit de antes era correcto
    // como se que el rank anterior es correcto

    for (var i = 1; i < 7; i++) {
      var index = i - 1;
      isNextRank[index] = IsEqual();
      isSameRank[index] = IsEqual();
      NextOrSameRank[index] = OR();
     
      
      //___________________________________________________________________________________________________________
      //___________________________________________________________________________________________________________
      // BOTH LOGIC
      //___________________________________________________________________________________________________________
      //___________________________________________________________________________________________________________
      cardplus[index] <== cardsRank[i-1] - 1;

      isNextRank[index].in <== [cardsRank[i], cardplus[index]];
      isSameRank[index].in <== [cardsRank[i-1], cardsRank[i]];
      NextOrSameRank[index].a <== isNextRank[index].out;
      NextOrSameRank[index].b <== isSameRank[index].out;


      //___________________________________________________________________________________________________________
      //___________________________________________________________________________________________________________
      // STRAIGHT LOGIC
      //___________________________________________________________________________________________________________
      //___________________________________________________________________________________________________________
      
      // If nextRank => straightCount += 1, if sameRank => keep straightCount, else 0.
      // Split into quadratic constraints (one multiplication per assignment).
      straightNextPart[index] <== (straightCount[i - 1] + 1) * isNextRank[index].out;
      straightSamePart[index] <== straightCount[i - 1] * isSameRank[index].out;
      straightCount[i] <== straightNextPart[index] + straightSamePart[index];

      if(i >= 3){
        var index2 = i - 3;
        // i - 3
        //0, 1, 2, || 3, 4, 5, 6 está bien?

        isTwo[index2] = IsEqual();
        isTwoAndHasAce[index2] = AND();
        isGreaterThanThree[index2] = GreaterThan(maxNumBits);

        isTwo[index2].in <== [cardsRank[i], rankTwo()];

        // if card[i] == 2 and has any ace then straightCount += 1
        isTwoAndHasAce[index2].a <== isTwo[index2].out;
        isTwoAndHasAce[index2].b <== hasAnyAceGT.out;
        // if isTwoAndHasAce: straightCount += 1
        straightCountInternal[index2] <== straightCount[i] + isTwoAndHasAce[index2].out;

        isGreaterThanThree[index2].in  <== [straightCountInternal[index2], 3];
        

        selectScoreStraight[index2] = SelectorUnchecked();

        if(i >= 4){
          var index3 = i - 4;
          // Only set the straight score once (keep the first non-zero score).
          // This avoids overwriting a previously found straight with a later one.
          isPrevStraightScoreZero[index3] = IsZero();
          isPrevStraightScoreZero[index3].in <== straightScore[index2];
          updateStraightScoreCond[index3] <== isGreaterThanThree[index2].out * isPrevStraightScoreZero[index3].out;
          
          selectScoreStraight[index2].condition <== updateStraightScoreCond[index3];
          selectScoreStraight[index2].true <== (2 + cardsRank[i] - isTwoAndHasAce[index2].out);
          selectScoreStraight[index2].false <== straightScore[index2];
          straightScore[index2 + 1] <== selectScoreStraight[index2].out;

        } else{
          selectScoreStraight[index2].condition <== isGreaterThanThree[index2].out;
          selectScoreStraight[index2].true <== (2 + cardsRank[i] - isTwoAndHasAce[index2].out);
          selectScoreStraight[index2].false <== straightScore[index2];
          straightScore[index2 + 1] <== selectScoreStraight[index2].out;
        }
      }


     
      //___________________________________________________________________________________________________________
      //___________________________________________________________________________________________________________
      // STRAIGHT FLUSH LOGIC
      //___________________________________________________________________________________________________________
      //___________________________________________________________________________________________________________     

      for (var suit = 0; suit < 4; suit++) {
        isSamePrev[suit][index] = IsEqual();
        isNextPrev[suit][index] = IsEqual();

        isSamePrev[suit][index].in <== [cardsRank[i], prevRankPerSuit[suit][index]];
        isNextPrev[suit][index].in <== [cardsRank[i], prevRankPerSuit[suit][index] - 1];

        // Split newCountSF calculation into quadratic parts
        sfNextPart[suit][index] <== isNextPrev[suit][index].out * (prevCountPerSuit[suit][index] + 1);
        sfSamePart[suit][index] <== isSamePrev[suit][index].out * prevCountPerSuit[suit][index];
        newCountSF[suit][index] <== sfNextPart[suit][index] + sfSamePart[suit][index];

        // Split state propagation into quadratic parts
        sfPropagatePart1[suit][index] <== flush.isSuit[suit][i] * newCountSF[suit][index];
        sfPropagatePart2[suit][index] <== (1 - flush.isSuit[suit][i]) * prevCountPerSuit[suit][index];
        prevCountPerSuit[suit][i] <== sfPropagatePart1[suit][index] + sfPropagatePart2[suit][index];

        rankUpdatePart1[suit][index] <== flush.isSuit[suit][i] * cardsRank[i];
        rankUpdatePart2[suit][index] <== (1 - flush.isSuit[suit][i]) * prevRankPerSuit[suit][index];
        prevRankPerSuit[suit][i] <== rankUpdatePart1[suit][index] + rankUpdatePart2[suit][index];
        
        if (i >= 3) {
          var wheelIdx = i - 3;
          isTwoAndHasAceSameSuit[suit][index] = AND();
          isTwoAndHasAceSameSuit[suit][index].a <== isTwo[wheelIdx].out;
          isTwoAndHasAceSameSuit[suit][index].b <== hasAce[suit];
          
          straightFlushCounterInternal2[suit][index] <== prevCountPerSuit[suit][i] + isTwoAndHasAceSameSuit[suit][index].out;

          isStraightFlush[suit][index] = GreaterThan(maxNumBits);
          isStraightFlush[suit][index].in <== [straightFlushCounterInternal2[suit][index], 3];

          // Priority logic: once a straight flush is found, keep it (it will be the highest rank due to sorting).
          isPrevSFScoreZero[suit][index] = IsZero();
          isPrevSFScoreZero[suit][index].in <== straightFlushScore[suit][index-1];
          updateSFScoreCond[suit][index] <== isStraightFlush[suit][index].out * isPrevSFScoreZero[suit][index].out;

          selectScoreStraightFlush[suit][index] = SelectorUnchecked();
          selectScoreStraightFlush[suit][index].condition <== updateSFScoreCond[suit][index];
          selectScoreStraightFlush[suit][index].true <== (2 + cardsRank[i] - isTwoAndHasAceSameSuit[suit][index].out);
          selectScoreStraightFlush[suit][index].false <== straightFlushScore[suit][index-1];
          straightFlushScore[suit][index] <== selectScoreStraightFlush[suit][index].out;
        }
      }

    }

    signal straightFlushScoreSum;
    straightFlushScoreSum <== straightFlushScore[0][5] + 
                      straightFlushScore[1][5] + 
                      straightFlushScore[2][5] + 
                      straightFlushScore[3][5]; 

    component straightIsZero = IsZero();
    straightIsZero.in <== straightScore[4];
    hasStraight <== 1 - straightIsZero.out;

    component straightFlushIsZero = IsZero();
    straightFlushIsZero.in <== straightFlushScoreSum;
    hasStraightFlush <== 1 - straightFlushIsZero.out;

    component flushIsZero = IsZero();
    flushIsZero.in <== flush.scoreOut;
    hasFlush <== 1 - flushIsZero.out;

    straightFlushScoreOut <== straightFlushScoreSum;
    flushScoreOut <== flush.scoreOut;
    straightScoreOut <== straightScore[4];

}
