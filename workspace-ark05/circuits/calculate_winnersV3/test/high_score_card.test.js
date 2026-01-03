const chai = require("chai");
const wasm_tester = require("circom_tester").wasm;
const path = require("path");
const assert = chai.assert;

const { RANKS, BASES } = require("./helper/constant");

describe("HighScoreCard", function () {
    this.timeout(100000);

    let circuit;

    before(async function () {
        const circuitDir = path.join(__dirname, "./circuits/");
        process.chdir(circuitDir);
        circuit = await wasm_tester("HighScoreCard.circom");
    });

    async function expectHighScoreCard(cardsRank) {
        const input = {
            "cardsRank": cardsRank
        };
        
        // Expected score calculation:
        // out = cardsRank[0] * rankBase5 + cardsRank[1] * rankBase4 + ... + cardsRank[4] * rankBase1
        const expectedScore = 
            BigInt(cardsRank[0]) * BigInt(BASES[5]) +
            BigInt(cardsRank[1]) * BigInt(BASES[4]) +
            BigInt(cardsRank[2]) * BigInt(BASES[3]) +
            BigInt(cardsRank[3]) * BigInt(BASES[2]) +
            BigInt(cardsRank[4]) * BigInt(BASES[1]);

        const w = await circuit.calculateWitness(input, true);
        await circuit.checkConstraints(w);
        await circuit.assertOut(w, { scoreOut: expectedScore });
    }

    it("should calculate high score correctly for a standard set of cards", async () => {
        await expectHighScoreCard([
            RANKS.ace,
            RANKS.king,
            RANKS.queen,
            RANKS.jack,
            RANKS.ten,
            RANKS.nine,
            RANKS.eight
        ]);
    });

    it("should calculate high score for another set of cards", async () => {
        await expectHighScoreCard([
            RANKS.ten,
            RANKS.nine,
            RANKS.eight,
            RANKS.seven,
            RANKS.six,
            RANKS.five,
            RANKS.four
        ]);
    });

    it("should calculate high score when cards are at minimum rank", async () => {
        await expectHighScoreCard([
            RANKS.two,
            RANKS.two,
            RANKS.two,
            RANKS.two,
            RANKS.two,
            RANKS.two,
            RANKS.two
        ]);
    });

    it("should calculate high score when all cards are Aces (maximum possible score)", async () => {
        await expectHighScoreCard([
            RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ace
        ]);
    });

    it("should only use the first 5 cards for score calculation (6th and 7th are ignored)", async () => {
        // Same score expected for both because top 5 are identical
        await expectHighScoreCard([
            RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, 
            RANKS.two, RANKS.two
        ]);
        
        await expectHighScoreCard([
            RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, 
            RANKS.nine, RANKS.eight
        ]);
    });

    it("should calculate score correctly when only the 5th card has value", async () => {
        await expectHighScoreCard([
            RANKS.two, RANKS.two, RANKS.two, RANKS.two, RANKS.ace, 
            RANKS.two, RANKS.two
        ]);
    });

    it("should calculate score correctly when only the 1st card has value", async () => {
        await expectHighScoreCard([
            RANKS.ace, RANKS.two, RANKS.two, RANKS.two, RANKS.two, 
            RANKS.two, RANKS.two
        ]);
    });

    it("should handle mixed medium ranks", async () => {
        await expectHighScoreCard([
            RANKS.nine, RANKS.seven, RANKS.five, RANKS.four, RANKS.three, 
            RANKS.two, RANKS.two
        ]);
    });
});

