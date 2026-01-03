const chai = require("chai");
const wasm_tester = require("circom_tester").wasm;  // Versión WASM
const path = require("path");
const assert = chai.assert;
const { printSignals } = require("./helper/printSignals");

const { RANKS, SUITS, BASES, allspades, allhearts, alldiamonds, allclubs, allstraighs } = require("./helper/constant");

describe("Circom Straight, Flush and Straight Flush ", function () {
  this.timeout(100000);

  let circuit;

  before(async function () {
      const circuitDir = path.join(__dirname, "./circuits/");
      process.chdir(circuitDir);
      circuit = await wasm_tester("FlushAndStraightLogic.circom");
      await circuit.loadSymbols();

      console.log("Circuit keys:", Object.keys(circuit));
  });


  async function expectStraightFlushScore(cardsRank, cardsSuit, expectedScore, message = "") {
    const input = {
      cardsRank,
      cardsSuit
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);
    
    const output = w[2];
    
    if (output.toString() !== expectedScore.toString()) {
        // printSignals(circuit, w);
    }
    
    assert.equal(output.toString(), expectedScore.toString(), message);
  }

  async function expectStraightScore(cardsRank, cardsSuit, expectedScore, message = "") {
    const input = {
      cardsRank,
      cardsSuit
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);
    
    const output = w[1];
    
    if (output.toString() !== expectedScore.toString()) {
        // printSignals(circuit, w);
    }
    
    assert.equal(output.toString(), expectedScore.toString(), message);
  }

   it("is straight or straight flush", async () => {
    const twoAdditionalCards = [RANKS.two, RANKS.two];
    const offset = 10; 
    for (let i = 0; i < allstraighs.length; i++) {
        const straight = [...allstraighs[i], ...twoAdditionalCards];    
        await expectStraightFlushScore(straight, allspades, offset - i);
        await expectStraightFlushScore(straight, allhearts, offset - i);
        await expectStraightFlushScore(straight, alldiamonds, offset - i);
        await expectStraightFlushScore(straight, allclubs, offset - i);
        
        // await expectStraightScore(straight, allspades, offset - i);
    }

  });


  it("is straight", async () => {
    let cardsRank = [RANKS.ace,    RANKS.king,   RANKS.queen,   RANKS.jack,  RANKS.ten,   RANKS.nine,    RANKS.eight]
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.diamonds, SUITS.clubs]
    await expectStraightScore(cardsRank, cardsSuit, RANKS.ten + 2, "Straight flush 0");
    
    cardsRank = [RANKS.ace,    RANKS.king,   RANKS.king,   RANKS.queen,  RANKS.jack,   RANKS.ten,    RANKS.seven]
    cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.diamonds, SUITS.clubs]
    await expectStraightScore(cardsRank, cardsSuit, RANKS.ten + 2, "Straight flush 1");

    cardsRank = [RANKS.queen,   RANKS.jack,  RANKS.jack,   RANKS.ten,      RANKS.ten,   RANKS.nine,    RANKS.eight]
    await expectStraightScore(cardsRank, cardsSuit, RANKS.eight + 2, "Straight flush 2");

    cardsRank = [RANKS.ace,   RANKS.king,  RANKS.queen,   RANKS.jack, RANKS.four,   RANKS.four,    RANKS.two]
    await expectStraightScore(cardsRank, cardsSuit, 0, " no Straight flush 1");

  });

  it("straight - duplicate high card", async () => {
    // A K K Q J 10 7  -> straight K..10 (ten-high)
    let cardsRank = [RANKS.ace, RANKS.king, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.seven];
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.diamonds, SUITS.clubs];
    await expectStraightScore(cardsRank, cardsSuit, RANKS.ten + 2, "Straight with duplicate high");
  });

  it("straight - duplicates in the middle", async () => {
    // Q J J 10 10 9 8 -> straight 10..8 (eight-high)
    let cardsRank = [RANKS.queen, RANKS.jack, RANKS.jack, RANKS.ten, RANKS.ten, RANKS.nine, RANKS.eight];
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.diamonds, SUITS.clubs];
    await expectStraightScore(cardsRank, cardsSuit, RANKS.eight + 2, "Straight with middle duplicates");
  });

  it("no straight - gap present", async () => {
    // A K Q J 4 4 2 -> no straight
    let cardsRank = [RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.four, RANKS.four, RANKS.two];
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.diamonds, SUITS.clubs];
    await expectStraightScore(cardsRank, cardsSuit, 0, "No straight because of gap");
  });

  it("straight flush - five consecutive same suit", async () => {
    // K Q J 10 9 are all spades -> King-high straight flush
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.four, RANKS.three];
    let cardsSuit = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.hearts, SUITS.diamonds];
    // esperamos detectar straight (y además straight flush). El expected que usas suele ser la puntuacion straight (rank + 2)
    await expectStraightScore(cardsRank, cardsSuit, RANKS.nine + 2, "Straight flush king-high");
  });

  it("flush only (no straight)", async () => {
    // A K J 9 7 of hearts -> flush pero no consecutivos -> no straight
    let cardsRank = [RANKS.ace, RANKS.king, RANKS.jack, RANKS.nine, RANKS.seven, RANKS.four, RANKS.three];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.diamonds];
    await expectStraightScore(cardsRank, cardsSuit, 0, "Flush only, not straight");
  });

  it("multiple possible straights - pick highest", async () => {
    // K Q J 10 9 8 7 -> hay más de una secuencia, la más alta es K..10
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven];
    let cardsSuit = [SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts];
    await expectStraightScore(cardsRank, cardsSuit, RANKS.nine + 2, "Choose highest straight when many possible");
  });


  it("is straight flush", async () => {
    
    let cardsRank = [RANKS.ace,    RANKS.king,   RANKS.king,   RANKS.queen,  RANKS.jack,   RANKS.ten,    RANKS.seven]
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.clubs]
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.ten + 2, "Straight flush 1");

    cardsRank = [RANKS.queen,   RANKS.jack,  RANKS.jack,   RANKS.ten,      RANKS.ten,   RANKS.nine,    RANKS.eight]
    cardsSuit = [SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.diamonds, SUITS.clubs, SUITS.clubs, SUITS.clubs]
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.eight + 2, "Straight flush 2");


    cardsRank = [RANKS.nine,   RANKS.nine,  RANKS.nine,  RANKS.eight, RANKS.seven, RANKS.six, RANKS.five]
    cardsSuit = [SUITS.clubs, SUITS.diamonds, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades]
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.five + 2, "Straight flush 3");


    cardsRank = [RANKS.eight,   RANKS.eight,  RANKS.eight,    RANKS.seven,   RANKS.six,   RANKS.five, RANKS.four]
    cardsSuit = [SUITS.clubs, SUITS.diamonds, SUITS.spades, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs]
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.four + 2, "Straight flush 4");
    
    cardsRank = [RANKS.seven,   RANKS.seven,  RANKS.seven,  RANKS.six, RANKS.five, RANKS.four, RANKS.three]
    cardsSuit = [SUITS.clubs, SUITS.diamonds, SUITS.spades, SUITS.diamonds, SUITS.diamonds, SUITS.diamonds, SUITS.diamonds]
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.three + 2  , "Straight flush 5");
    

    cardsRank = [RANKS.six,    RANKS.five,     RANKS.five,   RANKS.five, RANKS.four, RANKS.three, RANKS.two]
    cardsSuit = [SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts, SUITS.hearts]
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.two + 2, "Straight flush 6");
    
    
    cardsRank = [RANKS.six,    RANKS.five,   RANKS.four,  RANKS.four,  RANKS.three,  RANKS.three, RANKS.two]
    cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts]
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.two + 2, "Straight flush 7");


    cardsRank = [RANKS.ace,    RANKS.five,   RANKS.four,  RANKS.four,  RANKS.three,  RANKS.three, RANKS.two]
    cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts]
    await expectStraightFlushScore(cardsRank, cardsSuit, 1, "Straight flush 8");


  
    
  });


  it("SF-1: mixed duplicates but spade straight flush A..10", async () => {
    let cardsRank = [RANKS.ace, RANKS.king, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.seven];
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.ten + 2, "SF-1");
  });

  it("SF-2: king-high hearts straight flush (K Q J T 9 hearts)", async () => {
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.four, RANKS.three];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.diamonds];
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.nine + 2, "SF-2");
  });

  it("SF-3: nine..five spade straight flush (9 8 7 6 5)", async () => {
    let cardsRank = [RANKS.nine, RANKS.nine, RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five];
    let cardsSuit = [SUITS.spades, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades];
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.five + 2, "SF-3");
  });

  it("SF-4: eight..four club straight flush (8 7 6 5 4)", async () => {
    let cardsRank = [RANKS.eight, RANKS.eight, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.four];
    let cardsSuit = [SUITS.clubs, SUITS.diamonds, SUITS.spades, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.four + 2, "SF-4");
  });

  it("SF-5: seven..three diamond straight flush (7 6 5 4 3)", async () => {
    let cardsRank = [RANKS.seven, RANKS.seven, RANKS.seven, RANKS.six, RANKS.five, RANKS.four, RANKS.three];
    let cardsSuit = [SUITS.clubs, SUITS.diamonds, SUITS.spades, SUITS.diamonds, SUITS.diamonds, SUITS.diamonds, SUITS.diamonds];
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.three + 2, "SF-5");
  });

  it("SF-6: six..two heart straight flush (6 5 4 3 2) with duplicates", async () => {
    let cardsRank = [RANKS.six, RANKS.five, RANKS.five, RANKS.five, RANKS.four, RANKS.three, RANKS.two];
    let cardsSuit = [SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.two + 2, "SF-6");
  });

  it("SF-7: six..two heart straight flush (6 5 4 3 2) alternate duplicate layout", async () => {
    let cardsRank = [RANKS.six, RANKS.five, RANKS.four, RANKS.four, RANKS.three, RANKS.three, RANKS.two];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.two + 2, "SF-7");
  });

  it("SF-8: wheel straight flush (A 5 4 3 2) - ace low special case", async () => {
    let cardsRank = [RANKS.ace, RANKS.five, RANKS.four, RANKS.four, RANKS.three, RANKS.three, RANKS.two];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts];
    // según tus tests anteriores, la rueda la validas con expectativa 1
    await expectStraightFlushScore(cardsRank, cardsSuit, 1, "SF-8 wheel");
  });

  it("SF-9: non-adjacent but same-suit chain (K Q Q J T 9 8) forms K..9 spade SF", async () => {
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight];
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.nine + 2, "SF-9");
  });

  it("SF-10: contiguous five spades (K Q J T 9) at head", async () => {
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven];
    let cardsSuit = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades];
    await expectStraightFlushScore(cardsRank, cardsSuit, RANKS.nine + 2, "SF-10");
  });

  it("is not straight flush", async () => {
    
    cardsRank = [RANKS.six,    RANKS.five,   RANKS.four,  RANKS.four,  RANKS.three,  RANKS.three, RANKS.two]
    cardsSuit = [SUITS.hearts, SUITS.clubs, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts]
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "Not straight flush 1");
    

    cardsRank = [RANKS.ace,    RANKS.king,   RANKS.four,  RANKS.four,  RANKS.three,  RANKS.three, RANKS.two]
    cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts]
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "Not Straight flush 2");
    
    
  });

    it("NotSF-1: flush only (not consecutive)", async () => {
    let cardsRank = [RANKS.ace, RANKS.king, RANKS.jack, RANKS.nine, RANKS.seven, RANKS.four, RANKS.three];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.diamonds];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-1 flush only");
  });

  it("NotSF-2: straight only (mixed suits)", async () => {
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.four, RANKS.two];
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.diamonds];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-2 straight only");
  });

  it("NotSF-3: four-in-a-row same suit but missing one card", async () => {
    let cardsRank = [RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven, RANKS.five, RANKS.four, RANKS.two];
    let cardsSuit = [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-3 four-in-row only");
  });

  it("NotSF-4: duplicates break suit sequence", async () => {
    let cardsRank = [RANKS.queen, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven];
    let cardsSuit = [SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-4 duplicates break seq");
  });

  it("NotSF-5: five consecutive ranks but suits alternate - no SF", async () => {
    let cardsRank = [RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.three, RANKS.two];
    let cardsSuit = [SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-5 alt suits");
  });

  it("NotSF-6: wheel present but suits not same", async () => {
    let cardsRank = [RANKS.ace, RANKS.five, RANKS.four, RANKS.three, RANKS.two, RANKS.king, RANKS.jack];
    let cardsSuit = [SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.diamonds, SUITS.spades, SUITS.hearts, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-6 wheel mixed suits");
  });

  it("NotSF-7: gap in middle prevents SF", async () => {
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.jack, RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six];
    let cardsSuit = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.diamonds, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-7 gap at T");
  });

  it("NotSF-8: only three same-suit consecutive", async () => {
    let cardsRank = [RANKS.ten, RANKS.nine, RANKS.eight, RANKS.six, RANKS.four, RANKS.three, RANKS.two];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-8 only three in suit");
  });

  it("NotSF-9: non-descending would be invalid - but keep descending and mixed suits", async () => {
    let cardsRank = [RANKS.jack, RANKS.ten, RANKS.ten, RANKS.nine, RANKS.seven, RANKS.five, RANKS.two];
    let cardsSuit = [SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.hearts, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-9 duplicates and mixed suits");
  });

  it("NotSF-10: five same suit but not consecutive (A K Q J 9 hearts)", async () => {
    let cardsRank = [RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.nine, RANKS.three, RANKS.two];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.diamonds];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-10 flush but not straight");
  });

  it("NotSF-11: single long run but different suit for one middle card", async () => {
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven];
    let cardsSuit = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.diamonds, SUITS.spades, SUITS.spades, SUITS.spades];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-11 one middle off-suit");
  });

  it("NotSF-12: many duplicates, no 5-in-suit consecutive", async () => {
    let cardsRank = [RANKS.queen, RANKS.queen, RANKS.ten, RANKS.ten, RANKS.nine, RANKS.nine, RANKS.eight];
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-12 many duplicates");
  });

  it("NotSF-13: alternating suits prevent SF", async () => {
    let cardsRank = [RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.four, RANKS.three];
    let cardsSuit = [SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-13 alternating suits");
  });

  it("NotSF-14: four-of-a-kind plus two suited cards not forming SF", async () => {
    let cardsRank = [RANKS.jack, RANKS.jack, RANKS.jack, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight];
    let cardsSuit = [SUITS.spades, SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.spades, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-14 quads present");
  });

  it("NotSF-15: three pairs and two singles - no SF", async () => {
    let cardsRank = [RANKS.ten, RANKS.ten, RANKS.nine, RANKS.nine, RANKS.eight, RANKS.eight, RANKS.seven];
    let cardsSuit = [SUITS.clubs, SUITS.diamonds, SUITS.clubs, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-15 multiple pairs");
  });

  it("NotSF-16: close but only 4 consecutive of same suit (Q J T 9 hearts)", async () => {
    let cardsRank = [RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.seven, RANKS.five, RANKS.three];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.diamonds, SUITS.spades];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-16 only four consec");
  });

  it("NotSF-17: single straight but suits all different", async () => {
    let cardsRank = [RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.four, RANKS.two, RANKS.two];
    let cardsSuit = [SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.diamonds];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-17 straight mixed suits");
  });

  it("NotSF-18: five same suit but ranks not consecutive because of duplicate breaking", async () => {
    let cardsRank = [RANKS.ten, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five];
    let cardsSuit = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.clubs, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-18 duplicate breaks consecutiveness");
  });

  it("NotSF-19: two disjoint small runs of same suit but none of length 5", async () => {
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.ten, RANKS.nine, RANKS.four, RANKS.three, RANKS.two];
    let cardsSuit = [SUITS.diamonds, SUITS.diamonds, SUITS.diamonds, SUITS.clubs, SUITS.diamonds, SUITS.diamonds, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-19 disjoint runs");
  });

  it("NotSF-20: mostly same suit but gap >1 between ranks", async () => {
    let cardsRank = [RANKS.ace, RANKS.king, RANKS.jack, RANKS.ten, RANKS.eight, RANKS.seven, RANKS.six];
    let cardsSuit = [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-20 gap between K and J");
  });

  it("NotSF-21: only hearts but ranks  A Q J 9 7 - not consec", async () => {
    let cardsRank = [RANKS.ace, RANKS.queen, RANKS.jack, RANKS.nine, RANKS.seven, RANKS.five, RANKS.three];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.diamonds, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-21 hearts but not straight");
  });

  it("NotSF-22: consecutive ranks but first card of run is off-suit so no SF", async () => {
    let cardsRank = [RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.six, RANKS.four];
    let cardsSuit = [SUITS.clubs, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.clubs, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-22 first of run off-suit");
  });

  it("NotSF-23: five cards of same suit but ranks out of order if considered descending constraint", async () => {
    let cardsRank = [RANKS.ten, RANKS.nine, RANKS.seven, RANKS.six, RANKS.four, RANKS.three, RANKS.two];
    let cardsSuit = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.clubs, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-23 missing one rank for consecutiveness");
  });

  it("NotSF-24: one-off suit breaks a potential SF (middle card off-suit)", async () => {
    let cardsRank = [RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.four, RANKS.three];
    let cardsSuit = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.diamonds];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-24 middle off-suit breaks SF");
  });

  it("NotSF-25: short sequences across suits - no SF", async () => {
    let cardsRank = [RANKS.seven, RANKS.six, RANKS.five, RANKS.four, RANKS.three, RANKS.two, RANKS.two];
    let cardsSuit = [SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-25 short runs across suits");
  });

  it("NotSF-26: four-of-a-suit not enough (need 5 consec)", async () => {
    let cardsRank = [RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.three, RANKS.two, RANKS.two];
    let cardsSuit = [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.hearts, SUITS.spades, SUITS.diamonds];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-26 four-in-suit only");
  });

  it("NotSF-27: random hand - no SF", async () => {
    let cardsRank = [RANKS.ace, RANKS.jack, RANKS.ten, RANKS.ten, RANKS.seven, RANKS.five, RANKS.three];
    let cardsSuit = [SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.clubs, SUITS.diamonds, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-27 random hand");
  });

  it("NotSF-28: near-wheel but missing 2 so no SF", async () => {
    let cardsRank = [RANKS.ace, RANKS.five, RANKS.four, RANKS.three, RANKS.six, RANKS.king, RANKS.queen];
    let cardsSuit = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.spades];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-28 near wheel missing 2");
  });

  it("NotSF-29: lower end mixed suits and duplicates", async () => {
    let cardsRank = [RANKS.five, RANKS.five, RANKS.four, RANKS.three, RANKS.two, RANKS.two, RANKS.two];
    let cardsSuit = [SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.diamonds, SUITS.spades, SUITS.clubs, SUITS.hearts];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-29 duplicates and mixed suits");
  });

  it("NotSF-30: five consecutive ranks but suits insufficient (only 3 same suit)", async () => {
    let cardsRank = [RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.four, RANKS.three];
    let cardsSuit = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.hearts, SUITS.clubs, SUITS.diamonds, SUITS.clubs];
    await expectStraightFlushScore(cardsRank, cardsSuit, 0, "NotSF-30 only 3 same-suit consec");
  });
  

});
