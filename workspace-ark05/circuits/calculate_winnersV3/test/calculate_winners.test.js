const chai = require("chai");
const wasm_tester = require("circom_tester").wasm;  // Versión WASM
const path = require("path");
const assert = chai.assert;
const { printSignals } = require("./helper/printSignals");



const { RANKS, 
        SUITS, 
        BASES, 
        allspades, 
        allhearts, 
        alldiamonds,
        allclubs,
        STRAIGHT_FLUSH_OFFSET,
        FOUR_OF_A_KIND_OFFSET,
        FULL_HOUSE_OFFSET,
        FLUSH_OFFSET,
        STRAIGHT_OFFSET,
        THREE_OF_A_KIND_OFFSET,
        TWO_PAIR_OFFSET,
        ONE_PAIR_OFFSET,
        HIGH_CARD_OFFSET,
    } = require("./helper/constant");

describe("Circom calculate winners", function () {
  this.timeout(100000);

  let circuit;

  before(async function () {
      const circuitDir = path.join(__dirname, "../");
      process.chdir(circuitDir);
      circuit = await wasm_tester("calculate_winners.circom");
      await circuit.loadSymbols();
      console.log("Circuit keys:", Object.keys(circuit));
  });

  const rankToScore = {
    'straight_flush': STRAIGHT_FLUSH_OFFSET,
    'straight flush': STRAIGHT_FLUSH_OFFSET,
    'poker': FOUR_OF_A_KIND_OFFSET,
    'four of a kind': FOUR_OF_A_KIND_OFFSET,
    'full_house': FULL_HOUSE_OFFSET,
    'full house': FULL_HOUSE_OFFSET,
    'flush': FLUSH_OFFSET,
    'straight': STRAIGHT_OFFSET,
    'trips': THREE_OF_A_KIND_OFFSET,
    'three of a kind': THREE_OF_A_KIND_OFFSET,
    'double_pair': TWO_PAIR_OFFSET,
    'double pair': TWO_PAIR_OFFSET,
    'two pair': TWO_PAIR_OFFSET,
    'pair': ONE_PAIR_OFFSET,
    'one pair': ONE_PAIR_OFFSET,
    'high_card': HIGH_CARD_OFFSET,
    'high card': HIGH_CARD_OFFSET
  };



  async function expectedWinnersScore(players, winner_orders_idx) {
    let cardsRank = [];
    let cardsSuit = [];
    let expectedOffsets = [];

    players.forEach(player => {
        cardsRank.push(player.cardsRank);
        cardsSuit.push(player.cardsSuit);
        expectedOffsets.push(rankToScore[player.name]);
    });

    const input = {
      cardsRank,
      cardsSuit
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    // Get outputs safely using symbols
    const scoresOut = [];
    for (let i = 0; i < players.length; i++) {
        const signalName = `main.scores[${i}]`;
        const varIdx = circuit.symbols[signalName].varIdx;
        scoresOut.push(w[varIdx]);
    }
    console.log(scoresOut)
    
    // Check that each player's score is within the correct range for their hand type
    // The ranges are spaced by 10,000,000 (e.g., Flush=50M, Full House=60M)
    players.forEach((player, i) => {
        const score = scoresOut[i];
        const offset = rankToScore[player.name];
        
        if (offset === undefined) {
            throw new Error(`Unknown hand name: "${player.name}". Check rankToScore mapping.`);
        }
        
        // Assert score is >= offset
        assert.isTrue(
            score >= BigInt(offset), 
            `Player ${i} (${player.name}) score ${score} should be >= offset ${offset}`
        );
        
        // Assert score < offset + 10,000,000 (next tier)
        assert.isTrue(
            score < BigInt(offset + 10000000), 
            `Player ${i} (${player.name}) score ${score} should be < next tier ${offset + 10000000}`
        );
    });

    // If winner order is provided, verify sorting
    if (winner_orders_idx) {
        // Collect scores with original index
        let playerScores = players.map((_, i) => ({
            index: i,
            score: scoresOut[i]
        }));
        
        // Sort descending by score
        playerScores.sort((a, b) => {
            if (a.score > b.score) return -1;
            if (a.score < b.score) return 1;
            return 0;
        });

        // Check against expected order
        // winner_orders_idx is expected to be an array of indices [winner, 2nd, 3rd, last]
        winner_orders_idx.forEach((expectedIndex, rank) => {
            assert.equal(
                playerScores[rank].index, 
                expectedIndex, 
                `Rank ${rank + 1} should be player ${expectedIndex} but was ${playerScores[rank].index}`
            );
        });
    }
  }

  describe("straight flush", () => {
    it("straight flush vs straight flush", async () => {
        await expectedWinnersScore([
            {
                name: "straight flush",
                cardsRank: [
                    RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight
                ],
                cardsSuit: allspades
            },
            {
                name: "straight flush",
                cardsRank: [
                    RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven
                ],
                cardsSuit: allspades
            },
            {
                name: "straight flush",
                cardsRank: [
                    RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.four, RANKS.three, RANKS.two
                ],
                cardsSuit: allspades
            },
            {
                name: "straight flush",
                cardsRank: [
                    RANKS.ace, RANKS.five, RANKS.four, RANKS.three, RANKS.two, RANKS.two, RANKS.two
                ],
                cardsSuit: allspades
            },
        ], [0, 1, 2, 3]);
    });
  });
  
    describe("poker", () => {
        it("poker vs poker", async () => {
            await expectedWinnersScore([
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ace, RANKS.two, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.king, RANKS.king, RANKS.king, RANKS.queen, RANKS.queen
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.king, RANKS.king, RANKS.king, RANKS.king, RANKS.queen
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.ace, RANKS.king, RANKS.king, RANKS.king, RANKS.king 
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [0, 1, 2, 3]);
        })
        it("poker vs poker 2", async () => {
            await expectedWinnersScore([
                 {
                    name: "poker",
                    cardsRank: [
                      RANKS.king, RANKS.king, RANKS.king, RANKS.king, RANKS.ten, RANKS.eight, RANKS.seven
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.king, RANKS.king, RANKS.queen, RANKS.queen, RANKS.jack
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.king, RANKS.king, RANKS.ten, RANKS.nine, RANKS.eight
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                       RANKS.king, RANKS.king, RANKS.king, RANKS.king, RANKS.jack, RANKS.ten, RANKS.nine
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [1, 3, 0, 2]);
        })
        it("poker vs poker 3", async () => {
            await expectedWinnersScore([
                 {
                    name: "poker",
                    cardsRank: [
                      RANKS.seven, RANKS.seven, RANKS.seven, RANKS.seven, RANKS.five, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.king, RANKS.king, RANKS.queen, RANKS.queen, RANKS.jack
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.ten, RANKS.ten, RANKS.ten, RANKS.ten, RANKS.eight
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                       RANKS.queen, RANKS.nine, RANKS.nine, RANKS.nine, RANKS.nine, RANKS.seven, RANKS.seven
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [1, 2, 3, 0]);
        })
    })

    describe("full house", () => {
        
        it("trio fullhouse vs pair fullhouse", async () => {
            await expectedWinnersScore([
                {
                    name: "full_house",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.six, RANKS.four, RANKS.two, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "full_house",
                    cardsRank: [
                        RANKS.six, RANKS.four, RANKS.three, RANKS.three, RANKS.three, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "full_house",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.six, RANKS.four, RANKS.two, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "full_house",
                    cardsRank: [
                        RANKS.queen, RANKS.queen,RANKS.six, RANKS.four, RANKS.two, RANKS.two, RANKS.two 
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [1, 0, 2, 3]);
        })
        it("trio fullhouse vs pair fullhouse 2", async () => {
            await expectedWinnersScore([
                {
                    name: "full_house",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.six, RANKS.five, RANKS.five, RANKS.five, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "full_house",
                    cardsRank: [
                        RANKS.six, RANKS.four, RANKS.four, RANKS.four, RANKS.two, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "full_house",
                    cardsRank: [
                        RANKS.jack, RANKS.jack, RANKS.jack, RANKS.four, RANKS.two, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "full_house",
                    cardsRank: [
                        RANKS.king, RANKS.king,RANKS.king, RANKS.four, RANKS.three, RANKS.two, RANKS.two 
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [3, 2, 0, 1]);
        })
    })

    describe("flush", () => {
        it("flush vs flush", async () => {
            await expectedWinnersScore([
                {
                name: "flush",
                cardsRank: [
                RANKS.nine, RANKS.seven, RANKS.six, RANKS.six, RANKS.three, RANKS.three, RANKS.two
                ],
                cardsSuit: [
                    SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.clubs]
            },
            {
                name: "flush",
                cardsRank: [
                RANKS.king, RANKS.seven, RANKS.six, RANKS.six, RANKS.three, RANKS.three, RANKS.two
                ],
                cardsSuit: [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.clubs]
            },
            {
                name: "flush",
                cardsRank: [
                RANKS.ace, RANKS.seven, RANKS.six, RANKS.six, RANKS.three, RANKS.three, RANKS.two
                ],
                cardsSuit: [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.clubs]
            },
            {
                name: "flush",
                cardsRank: [
                    RANKS.king, RANKS.eight, RANKS.six, RANKS.six, RANKS.three, RANKS.three, RANKS.two
                ],
                cardsSuit:  [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.clubs]
            },
            ], [2, 3, 1, 0]);
        })

        it("flush vs flush 2", async () => {
            await expectedWinnersScore([
                {
                name: "flush",
                cardsRank: [
                    RANKS.king, RANKS.seven, RANKS.five, RANKS.three, RANKS.three, RANKS.three, RANKS.two
                ],
                cardsSuit: [
                    SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.clubs]
            },
            {
                name: "flush",
                cardsRank: [
                        RANKS.king, RANKS.seven, RANKS.five, RANKS.four, RANKS.three, RANKS.three, RANKS.two
                ],
                cardsSuit: [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.diamonds, SUITS.clubs]
            },
            {
                name: "flush",
                cardsRank: [
                            RANKS.king, RANKS.seven, RANKS.six, RANKS.five, RANKS.three, RANKS.three, RANKS.two
                ],
                cardsSuit: [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.clubs]
            },
            {
                name: "flush",
                cardsRank: [
                            RANKS.king, RANKS.eight, RANKS.seven, RANKS.six, RANKS.three, RANKS.three, RANKS.two
                ],
                cardsSuit:  [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.clubs]
            },
            ], [3, 2, 1, 0]);
        })



        it("flush vs flush 3", async () => {
            await expectedWinnersScore([
                {
                    name: "flush",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.queen, RANKS.ten, RANKS.seven, RANKS.six, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts
                    ]
                },
                {
                    name: "flush",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.queen, RANKS.jack, RANKS.seven, RANKS.six, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts
                    ]
                },
                {
                    name: "flush",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.queen, RANKS.ten, RANKS.seven, RANKS.six, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts
                    ]
                },
                {
                    name: "flush",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.queen, RANKS.ten, RANKS.seven, RANKS.seven, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.hearts
                    ]
                },
            
            ], [1, 3, 2, 0]);
        })

        it("flush vs flush 4", async () => {
            await expectedWinnersScore([
                {
                    name: "flush",
                    cardsRank: [
                        RANKS.king, RANKS.queen, RANKS.queen, RANKS.ten, RANKS.eight, RANKS.six, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs
                    ]
                },
                {
                    name: "flush",
                    cardsRank: [
                        RANKS.king, RANKS.queen, RANKS.queen, RANKS.jack, RANKS.nine, RANKS.six, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs
                    ]
                },
                {
                    name: "flush",
                    cardsRank: [
                        RANKS.king, RANKS.queen, RANKS.queen, RANKS.ten, RANKS.nine, RANKS.six, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs
                    ]
                },
                {
                    name: "flush",
                    cardsRank: [
                        RANKS.king, RANKS.queen, RANKS.queen, RANKS.ten, RANKS.nine, RANKS.six, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs
                    ]
                },
            
            ], [1, 2, 3, 0]);
        })

    })

    describe("straigh", () => {
        
        it("straight vs straight", async () => {
            await expectedWinnersScore([
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.six, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.four, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [0, 1, 2, 3]);
        })


        it("straight vs straight 2 (all same straight)", async () => {
            await expectedWinnersScore([
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.eight
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [0, 1, 2, 3]);
        })

        it("Straight vs straight (with trips", async () => {
            it("trips vs trips", async () => {
            await expectedWinnersScore([
                 {
                    name: "straight",
                    cardsRank: [
                      RANKS.seven, RANKS.seven, RANKS.seven, RANKS.six, RANKS.five, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.eight, RANKS.eight, RANKS.eight, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.ten, RANKS.nine, RANKS.nine, RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.ace, RANKS.five, RANKS.four, RANKS.three, RANKS.three, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [2, 1, 0, 3]);
        })
        })

    })    

    describe("trips", () => { 
        it("trips vs trips", async () => {
            await expectedWinnersScore([
                 {
                    name: "trips",
                    cardsRank: [
                      RANKS.ace, RANKS.seven, RANKS.seven, RANKS.seven, RANKS.six,  RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "trips",
                    cardsRank: [
                        RANKS.king, RANKS.queen, RANKS.eight, RANKS.eight, RANKS.eight, RANKS.seven, RANKS.five
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "trips",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.four, RANKS.four, RANKS.four, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "trips",
                    cardsRank: [
                       RANKS.ace, RANKS.queen, RANKS.jack, RANKS.jack, RANKS.jack, RANKS.seven, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [3, 1, 0, 2]);
        })

        it("same trip, diffent values", async () => {
            await expectedWinnersScore([
                 {
                    name: "trips",
                    cardsRank: [
                      RANKS.ace, RANKS.seven, RANKS.seven, RANKS.seven, RANKS.six,  RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "trips",
                    cardsRank: [
                      RANKS.ace, RANKS.seven, RANKS.seven, RANKS.seven, RANKS.five,  RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "trips",
                    cardsRank: [
                      RANKS.ace, RANKS.seven, RANKS.seven, RANKS.seven, RANKS.six,  RANKS.four, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "trips",
                    cardsRank: [
                      RANKS.king,  RANKS.queen,  RANKS.seven, RANKS.seven, RANKS.seven, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                
            
            ], [0, 2, 1, 3]);
        })
    })

    describe("double pair", () => {
        it("double pair vs double pair", async () => {
            await expectedWinnersScore([
                 {
                    name: "double pair",
                    cardsRank: [
                      RANKS.ace, RANKS.ace, RANKS.seven, RANKS.seven, RANKS.six,  RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double pair",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.eight, RANKS.eight, RANKS.six, RANKS.six, RANKS.five
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double pair",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.eight, RANKS.eight, RANKS.seven, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double pair",
                    cardsRank: [
                       RANKS.ace, RANKS.ace, RANKS.seven, RANKS.seven, RANKS.five, RANKS.four, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [0, 3, 2, 1]);
        })
        it("double pair vs double pair 2", async () => {
            await expectedWinnersScore([
                 {
                    name: "double pair",
                    cardsRank: [
                      RANKS.ace, RANKS.king, RANKS.king, RANKS.queen, RANKS.queen,  RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double pair",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.king, RANKS.queen, RANKS.queen,  RANKS.jack, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double pair",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.jack, RANKS.jack, RANKS.ten, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double pair",
                    cardsRank: [
                       RANKS.king, RANKS.king, RANKS.queen, RANKS.queen, RANKS.five, RANKS.four, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [0, 1, 3, 2]);
        })
    it("double pair vs double pair 3", async () => {
        await expectedWinnersScore([
                 {
                    name: "double pair",
                    cardsRank: [
                      RANKS.ace, RANKS.king, RANKS.five, RANKS.five, RANKS.four,  RANKS.four, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double pair",
                    cardsRank: [
                        RANKS.seven, RANKS.five, RANKS.five, RANKS.three, RANKS.three,  RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double pair",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.jack, RANKS.jack, RANKS.three, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double pair",
                    cardsRank: [
                       RANKS.queen, RANKS.jack, RANKS.ten, RANKS.ten, RANKS.nine, RANKS.nine, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [2, 3, 0, 1]);
        })

    })

    describe("pair", () => {
        it("pair", async () => {
            await expectedWinnersScore([
                 {
                    name: "pair",
                    cardsRank: [
                      RANKS.ace, RANKS.ace, RANKS.king, RANKS.seven, RANKS.six,  RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.king, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.jack, RANKS.eight, RANKS.seven, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.jack, RANKS.nine, RANKS.seven, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [0, 1, 3, 2]);
        })
        it("pair", async () => {
            await expectedWinnersScore([
                 {
                    name: "pair",
                    cardsRank: [
                      RANKS.ace, RANKS.ace, RANKS.king, RANKS.seven, RANKS.six,  RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.king, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.jack, RANKS.eight, RANKS.seven, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.jack, RANKS.nine, RANKS.seven, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [0, 1, 3, 2]);
        })

        it("pair 3", async () => {
            await expectedWinnersScore([
                 {
                    name: "pair",
                    cardsRank: [
                      RANKS.king, RANKS.jack, RANKS.seven, RANKS.seven, RANKS.six,  RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.king, RANKS.jack, RANKS.seven, RANKS.seven, RANKS.five, RANKS.four, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.king, RANKS.queen, RANKS.seven, RANKS.seven, RANKS.five, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.ace, RANKS.seven, RANKS.seven, RANKS.six, RANKS.five, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [3, 2, 0, 1]);
        })

    })
    describe("high card", () => {
        it("high card vs high card", async () => {
            await expectedWinnersScore([
                {
                    name: "high_card",
                    cardsRank: [
                    RANKS.ace, RANKS.ten, RANKS.eight, RANKS.seven, RANKS.five, RANKS.four, RANKS.three
                ],
                cardsSuit: [
                    SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                ]
            },
            {
                name: "high_card",
                cardsRank: [
                    RANKS.king, RANKS.queen, RANKS.ten, RANKS.seven, RANKS.four, RANKS.three, RANKS.two
                ],
                cardsSuit: [
                    SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                ]
            },
            {
                name: "high_card",
                cardsRank: [
                    RANKS.jack, RANKS.nine, RANKS.seven, RANKS.five, RANKS.four, RANKS.three, RANKS.two
                ],
                cardsSuit: [
                    SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                ]
            },
             {
                name: "high_card",
                cardsRank: [
                    RANKS.king, RANKS.nine, RANKS.eight, RANKS.seven, RANKS.four, RANKS.three, RANKS.two 
                ],
                cardsSuit: [
                    SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                ]
            },
        
            ], [0, 1, 3, 2]);
        })

        it("high card vs high card 2", async () => {
            await expectedWinnersScore([
                {
                    name: "high_card",
                    cardsRank: [
                        RANKS.ace, RANKS.ten, RANKS.eight, RANKS.six, RANKS.five, RANKS.four, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "high_card",
                    cardsRank: [
                        RANKS.ace, RANKS.ten, RANKS.eight, RANKS.seven, RANKS.six, RANKS.four, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "high_card",
                    cardsRank: [
                        RANKS.ace, RANKS.ten, RANKS.eight, RANKS.seven, RANKS.five, RANKS.four, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "high_card",
                    cardsRank: [
                        RANKS.ace, RANKS.ten, RANKS.eight, RANKS.seven, RANKS.five, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [1, 2, 3, 0]);
        })
        it("high card vs high card 3", async () => {
            await expectedWinnersScore([
                {
                    name: "high_card",
                    cardsRank: [
                        RANKS.king, RANKS.ten, RANKS.eight, RANKS.six, RANKS.five, RANKS.four, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "high_card",
                    cardsRank: [
                        RANKS.king, RANKS.ten, RANKS.seven, RANKS.six, RANKS.four, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "high_card",
                    cardsRank: [
                        RANKS.ace, RANKS.ten, RANKS.eight, RANKS.seven, RANKS.five, RANKS.four, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "high_card",
                    cardsRank: [
                        RANKS.king, RANKS.jack, RANKS.eight, RANKS.seven, RANKS.five, RANKS.three, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [2, 3, 0, 1]);
        })
    });


    describe("multiples rank", () => {
        it("straight flush vs poker", async () => {
            await expectedWinnersScore([
                {
                name: "poker",
                cardsRank: [
                RANKS.queen, RANKS.queen, RANKS.queen, RANKS.queen, RANKS.four, RANKS.three, RANKS.two
                ],
                cardsSuit: [SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts]
            },
            {
                name: "straight flush",
                cardsRank: [
                RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven
                ],
                cardsSuit: allspades
            },
            {
                name: "straight flush",
                cardsRank: [
                RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight
                ],
                cardsSuit: allspades
            },
            {
                name: "poker",
                cardsRank: [
                RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ace, RANKS.two, RANKS.two, RANKS.two
                ],
                cardsSuit: [SUITS.clubs, SUITS.diamonds, SUITS.hearts, SUITS.spades, SUITS.clubs, SUITS.diamonds, SUITS.hearts]
            },
            ], [2, 1, 3, 0]);

        
        
        });
        it("fullhouse vs straight vs straight flush vs poker", async () => {
            await expectedWinnersScore([
                {
                    name: "full_house",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ten, RANKS.ten, RANKS.six, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.five, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight_flush",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.jack, RANKS.ten, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.clubs, SUITS.hearts, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.king, RANKS.queen, RANKS.queen, RANKS.two, RANKS.two, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.diamonds, SUITS.clubs
                    ]
                },
            
            ], [2, 3, 0, 1]);
        })

        
        it("pair vs straight vs trips vs two pairs", async () => {
            await expectedWinnersScore([
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.six, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "straight",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "trips",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.ace, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "double_pair",
                    cardsRank: [
                        RANKS.ace, RANKS.ace, RANKS.king, RANKS.king, RANKS.seven, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [1, 2, 3, 0]);
        })

        it("pair vs highcard vs flush vs poker", async () => {
            await expectedWinnersScore([
                {
                    name: "pair",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.six, RANKS.four
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "high_card",
                    cardsRank: [
                        RANKS.ace, RANKS.queen, RANKS.jack, RANKS.nine, RANKS.seven, RANKS.five, RANKS.three
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "flush",
                    cardsRank: [
                        RANKS.ace, RANKS.king, RANKS.queen, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
                {
                    name: "poker",
                    cardsRank: [
                        RANKS.king, RANKS.king, RANKS.king, RANKS.king, RANKS.seven, RANKS.two, RANKS.two
                    ],
                    cardsSuit: [
                        SUITS.hearts, SUITS.diamonds, SUITS.clubs, SUITS.spades, SUITS.hearts, SUITS.spades, SUITS.clubs
                    ]
                },
            
            ], [3, 2, 0, 1]);
        })
    })

});
