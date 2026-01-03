const chai = require("chai");
const wasm_tester = require("circom_tester").wasm;  // Versión WASM
const path = require("path");
const assert = chai.assert;
const { printSignals } = require("./helper/printSignals");

const { RANKS, SUITS, BASES, allspades, allhearts, alldiamonds, allclubs } = require("./helper/constant");

describe("Circom flush", function () {
  this.timeout(100000);

  let circuit;

  before(async function () {
      const circuitDir = path.join(__dirname, "./circuits/");
      process.chdir(circuitDir);
      circuit = await wasm_tester("Flush.circom");
      await circuit.loadSymbols();
      console.log("Circuit keys:", Object.keys(circuit));
  });

  async function expectFlushScore(cardsRank, cardsSuit, suit, expectedScore=null) {
    const input = {
      cardsRank,
      cardsSuit
    };

    // Filtrar cartas que coinciden con el suit
    const matchingRanks = [];
    for (let i = 0; i < cardsRank.length; i++) {
      if (cardsSuit[i] === suit) {
        matchingRanks.push(cardsRank[i]);
      }
      if (matchingRanks.length === 5) break;
    }

    if (expectedScore === null) {
      expectedScore = 0n;
      if (matchingRanks.length >= 5) {
        expectedScore =
        BigInt(matchingRanks[0] + 1) * BigInt(BASES[5]) +
        BigInt(matchingRanks[1] + 1) * BigInt(BASES[4]) +
        BigInt(matchingRanks[2] + 1) * BigInt(BASES[3]) +
        BigInt(matchingRanks[3] + 1) * BigInt(BASES[2]) +
        BigInt(matchingRanks[4] + 1) * BigInt(BASES[1]);
      }
    }
    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);
    const output = w[1];
    assert.equal(output.toString(), expectedScore.toString());
  }

  
  it("is flush", async () => {
    await expectFlushScore([
      RANKS.two, RANKS.two, RANKS.two, RANKS.two, RANKS.two, RANKS.two, RANKS.two
    ], allspades, SUITS.spades);
    
    let expectedScore =   28561 + 2197 + 169 + 13 + 1;
    await expectFlushScore([
      RANKS.two, RANKS.two, RANKS.two, RANKS.two, RANKS.two, RANKS.two, RANKS.two
    ], allspades, SUITS.spades, expectedScore);
    
    expectedScore =   (RANKS.ace + 1) * 28561 + 2197 + 169 + 13 + 1;
    
    await expectFlushScore([
      RANKS.ace, RANKS.two, RANKS.two, RANKS.two, RANKS.two, RANKS.two, RANKS.two
    ], allspades, SUITS.spades, expectedScore);

    expectedScore =   (RANKS.ace + 1) * 28561 + (RANKS.king + 1) * 2197 +  (RANKS.three + 1) * 169 + 13 + 1;
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.three, RANKS.two, RANKS.two, RANKS.two, RANKS.two
    ], allspades, SUITS.spades, expectedScore);
    

    expectedScore =   (RANKS.king + 1) * 28561 + (RANKS.seven + 1) * 2197 +  (RANKS.six + 1) * 169 + (RANKS.six + 1) * 13 + 1 * (RANKS.four + 1);
    await expectFlushScore([
      RANKS.king, RANKS.seven, RANKS.six, RANKS.six, RANKS.four, RANKS.two, RANKS.two
    ], allspades, SUITS.spades, expectedScore);
    

    
  });

  it("no flush should return 0", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, 
      RANKS.ten, RANKS.nine, RANKS.eight
    ], [
      SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, 
      SUITS.hearts, SUITS.hearts, SUITS.hearts
    ], SUITS.spades, 0n);
  });

  it("flush in hearts", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.two, RANKS.three
    ], allhearts, SUITS.hearts);
  });

  it("flush in diamonds", async () => {
    await expectFlushScore([
      RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.two, RANKS.three
    ], alldiamonds, SUITS.diamonds);
  });

  it("flush in clubs", async () => {
    await expectFlushScore([
      RANKS.four, RANKS.three, RANKS.two, RANKS.ace, RANKS.king, RANKS.two, RANKS.three
    ], allclubs, SUITS.clubs);
  });


  it("exactly 5 cards of a suit", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.two, RANKS.three
    ], [
      SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.hearts, SUITS.hearts
    ], SUITS.spades);
  });

  it("flush with 6 cards of the same suit (should take first 5)", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.two
    ], [
      SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.hearts
    ], SUITS.spades);
  });

  it("flush with 7 cards of the same suit (should take first 5)", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight
    ], [
      SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades
    ], SUITS.spades);
  });

  it("flush at the end (first 2 cards diff suit)", async () => {
    const cardsRank = [
      RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight
    ];
    const cardsSuit = [
      SUITS.hearts, SUITS.hearts, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades
    ];


    // falla porque el contador va mal, temina una antes, less than 4 ==> si multiplas el resultado por 13 y le sumas 7 da igual

    await expectFlushScore(cardsRank, cardsSuit, SUITS.spades);
  });

  it("flush in the middle (1 diff, 5 same, 1 diff)", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight
    ], [
      SUITS.hearts, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.clubs
    ], SUITS.spades);
  });

  it("flush with highest ranks (Royal Flush)", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.two, RANKS.three
    ], allspades, SUITS.spades);
  });

  it("flush with lowest ranks (6-high)", async () => {
    await expectFlushScore([
      RANKS.six, RANKS.five, RANKS.four, RANKS.three, RANKS.two, RANKS.ace, RANKS.king
    ], [
      SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.hearts, SUITS.hearts
    ], SUITS.spades);
  });

  it("flush 1", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.ten, RANKS.nine, RANKS.nine, RANKS.five, RANKS.three, RANKS.two
    ], [
      SUITS.spades, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.hearts
    ], SUITS.spades);
  });

  it("flush 2", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.ten, RANKS.nine, RANKS.nine, RANKS.five, RANKS.three, RANKS.two
    ], [
      SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.spades, SUITS.clubs, SUITS.clubs
    ], SUITS.clubs);
  });

  it("flush 3", async () => {
    await expectFlushScore([
      RANKS.king, RANKS.jack, RANKS.jack, RANKS.ten, RANKS.eight, RANKS.five, RANKS.three
    ], [
      SUITS.clubs, SUITS.clubs, SUITS.hearts, SUITS.clubs, SUITS.spades, SUITS.clubs, SUITS.clubs
    ], SUITS.clubs);
  });

  it("flush 4", async () => {
    await expectFlushScore([
      RANKS.king, RANKS.king, RANKS.king, RANKS.nine, RANKS.five, RANKS.three, RANKS.two
    ], [
      SUITS.clubs, SUITS.hearts, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades
    ], SUITS.spades);
  });

  it("flush 5", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.two, RANKS.two, RANKS.two
    ], [
      SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.hearts
    ], SUITS.hearts);
  });

   it("flush 6", async () => {
    await expectFlushScore([
      RANKS.queen, RANKS.jack, RANKS.seven, RANKS.three, RANKS.three, RANKS.three, RANKS.two
    ], [
      SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.spades, SUITS.hearts, SUITS.clubs, SUITS.hearts
    ], SUITS.hearts);
  });

  it("flush 7", async () => {
    await expectFlushScore([
      RANKS.queen, RANKS.jack, RANKS.seven, RANKS.three, RANKS.three, RANKS.three, RANKS.two
    ], [
      SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.spades, SUITS.hearts, SUITS.clubs, SUITS.hearts
    ], SUITS.hearts);
  });

  it("flush 7.1", async () => {
    await expectFlushScore([
      RANKS.queen, RANKS.queen, RANKS.seven, RANKS.seven, RANKS.four, RANKS.three, RANKS.two
    ], [
      SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.hearts, SUITS.hearts, SUITS.hearts
    ], SUITS.hearts);
  });

  it("flush 7.5", async () => {
    await expectFlushScore([
      RANKS.queen, RANKS.jack, RANKS.seven, RANKS.five, RANKS.four, RANKS.three, RANKS.two
    ], [
      SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts
    ], SUITS.hearts);
  });

  it("flush 8", async () => {
    await expectFlushScore([
      RANKS.queen, RANKS.jack, RANKS.seven, RANKS.five, RANKS.four, RANKS.three, RANKS.two
    ], [
      SUITS.spades, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts
    ], SUITS.hearts);
  });

  it("flush 9", async () => {
    await expectFlushScore([
      RANKS.queen, RANKS.jack, RANKS.seven, RANKS.five, RANKS.four, RANKS.three, RANKS.two
    ], [
      SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.spades
    ], SUITS.hearts);
  });

  it("flush 10", async () => {
    await expectFlushScore([
      RANKS.queen, RANKS.jack, RANKS.seven, RANKS.five, RANKS.four, RANKS.three, RANKS.two
    ], [
      SUITS.hearts, SUITS.hearts, SUITS.spades, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts
    ], SUITS.hearts);
  });

  it("flush 11", async () => {
    await expectFlushScore([
      RANKS.queen, RANKS.jack, RANKS.seven, RANKS.five, RANKS.four, RANKS.three, RANKS.two
    ], [
      SUITS.hearts, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.hearts, SUITS.hearts, SUITS.hearts
    ], SUITS.hearts);
  });



  it("no flush 1", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ten, RANKS.nine, RANKS.nine
    ], [
      SUITS.clubs, SUITS.hearts, SUITS.diamonds, SUITS.spades, SUITS.spades, SUITS.clubs, SUITS.clubs
    ], SUITS.clubs, 0n);
  });


   it("no flush 2", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.king, RANKS.king, RANKS.ten, RANKS.nine, RANKS.nine
    ], [
      SUITS.clubs, SUITS.clubs, SUITS.diamonds, SUITS.spades, SUITS.spades, SUITS.clubs, SUITS.clubs
    ], SUITS.clubs, 0n);
  });

  it("no flush 3", async () => {
    await expectFlushScore([
      RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight
    ], [
      SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.hearts
    ], SUITS.clubs, 0n);
  });

  it("no flush 4", async () => {
    await expectFlushScore([
      RANKS.nine, RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.four
    ], [
      SUITS.hearts, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.hearts, SUITS.hearts
    ], SUITS.clubs, 0n);
  });

  it("no flush 5", async () => {
    await expectFlushScore([
      RANKS.queen, RANKS.seven, RANKS.four, RANKS.three, RANKS.three, RANKS.two, RANKS.two
    ], [
      SUITS.hearts, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.hearts, SUITS.hearts
    ], SUITS.clubs, 0n);
  });

});
