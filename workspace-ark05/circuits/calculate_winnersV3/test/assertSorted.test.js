const chai = require("chai");
const wasm_tester = require("circom_tester").wasm;  // Versión WASM
const path = require("path");
const assert = chai.assert;

const { RANKS, SUITS, BASES } = require("./helper/constant");

describe("Circom assertSorted", function () {
  this.timeout(100000);
  
  let circuit;

  // Compilar el circuito UNA SOLA VEZ antes de todos los tests
  before(async function() {
    const circuitDir = path.join(
      __dirname,
      "./circuits/"
    );

    // Cambiamos el directorio de trabajo
    process.chdir(circuitDir);

    circuit = await wasm_tester("AssertSorted.circom");
  });

  async function expectSorted(cardsRank, must_fail = false) {
    const input = {
        "in": cardsRank
    }
    let failed = false;
    try {
        const w = await circuit.calculateWitness(input, true);
        await circuit.checkConstraints(w); 
    } catch (err) {
        failed = true;
    }
    assert.equal(failed, must_fail);   
  }

  it("is sorted", async () => {
    await expectSorted([
        RANKS.ace, 
        RANKS.king,
        RANKS.queen,
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
        RANKS.eight]
    );
    await expectSorted([
        RANKS.king,
        RANKS.queen,
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
        RANKS.eight,
        RANKS.seven
    ]);

    await expectSorted([
        RANKS.queen,
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
        RANKS.eight,
        RANKS.seven,
        RANKS.six,
    ]);
    await expectSorted([
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
        RANKS.eight,
        RANKS.seven,
        RANKS.six,
        RANKS.five,
    ]);
    await expectSorted([
        RANKS.ten,
        RANKS.nine,
        RANKS.eight,
        RANKS.seven,
        RANKS.six,
        RANKS.five,
        RANKS.four
    ]);
    await expectSorted([
        RANKS.nine,
        RANKS.eight,
        RANKS.seven,
        RANKS.six,
        RANKS.five,
        RANKS.four,
        RANKS.three
    ]);
    await expectSorted([
        RANKS.eight,
        RANKS.seven,
        RANKS.six,
        RANKS.five,
        RANKS.four,
        RANKS.three,
        RANKS.two
    ]);
    await expectSorted([
        RANKS.ace, 
        RANKS.king,
        RANKS.king,
        RANKS.king,
        RANKS.king,
        RANKS.king,
        RANKS.queen,
    ]);

    await expectSorted([
        RANKS.ace, 
        RANKS.king,
        RANKS.king,
        RANKS.king,
        RANKS.queen,
        RANKS.queen,
        RANKS.queen,
    ]);

    // All same values
    await expectSorted([
        RANKS.seven,
        RANKS.seven,
        RANKS.seven,
        RANKS.seven,
        RANKS.seven,
        RANKS.seven,
        RANKS.seven,
    ]);

    // Descending with duplicates at the end
    await expectSorted([
        RANKS.ace,
        RANKS.king,
        RANKS.queen,
        RANKS.jack,
        RANKS.ten,
        RANKS.ten,
        RANKS.ten,
    ]);

    // Descending with duplicates in the middle
    await expectSorted([
        RANKS.ace,
        RANKS.king,
        RANKS.king,
        RANKS.jack,
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
    ]);

    // Minimum values (all twos)
    await expectSorted([
        RANKS.two,
        RANKS.two,
        RANKS.two,
        RANKS.two,
        RANKS.two,
        RANKS.two,
        RANKS.two,
    ]);

    // Descending to minimum
    await expectSorted([
        RANKS.seven,
        RANKS.six,
        RANKS.five,
        RANKS.four,
        RANKS.three,
        RANKS.two,
        RANKS.two,
    ]);

    // Alternating duplicates
    await expectSorted([
        RANKS.ten,
        RANKS.ten,
        RANKS.nine,
        RANKS.nine,
        RANKS.eight,
        RANKS.eight,
        RANKS.seven,
    ]);

    // Maximum values (all aces)
    await expectSorted([
        RANKS.ace,
        RANKS.ace,
        RANKS.ace,
        RANKS.ace,
        RANKS.ace,
        RANKS.ace,
        RANKS.ace,
    ]);
  });

  it("is not sorted", async () => {
    await expectSorted([
        RANKS.king,
        RANKS.ace, 
        RANKS.queen,
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
        RANKS.eight], must_fail = true
    );
    await expectSorted([
        RANKS.king,
        RANKS.queen,
        RANKS.ten,
        RANKS.nine,
        RANKS.jack,
        RANKS.eight,
        RANKS.seven], must_fail = true
    );

    await expectSorted([
        RANKS.jack,
        RANKS.queen,
        RANKS.ten,
        RANKS.nine,
        RANKS.eight,
        RANKS.six,
        RANKS.seven,
    ], must_fail = true);
    await expectSorted([
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
        RANKS.eight,
        RANKS.five,
        RANKS.seven,
        RANKS.six,
    ], must_fail = true);
    await expectSorted([
        RANKS.ten,
        RANKS.nine,
        RANKS.eight,
        RANKS.four,
        RANKS.six,
        RANKS.seven,
        RANKS.five,
    ], must_fail = true);
    await expectSorted([
        RANKS.eight,
        RANKS.nine,
        RANKS.six,
        RANKS.five,
        RANKS.seven,
        RANKS.four,
        RANKS.three
    ], must_fail = true);
    await expectSorted([
        RANKS.eight,
        RANKS.seven,
        RANKS.six,
        RANKS.four,
        RANKS.five,
        RANKS.two,
        RANKS.three,
    ], must_fail = true);
    await expectSorted([
        RANKS.ace, 
        RANKS.king,
        RANKS.king,
        RANKS.king,
        RANKS.queen,
        RANKS.king,
        RANKS.king,
    ], must_fail = true);

    await expectSorted([
        RANKS.ace, 
        RANKS.king,
        RANKS.queen,
        RANKS.king,
        RANKS.king,
        RANKS.queen,
        RANKS.queen,
    ], must_fail = true);

    // Single element out of place at the beginning
    await expectSorted([
        RANKS.king,
        RANKS.ace,
        RANKS.king,
        RANKS.queen,
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
    ], must_fail = true);

    // Single element out of place at the end
    await expectSorted([
        RANKS.ace,
        RANKS.king,
        RANKS.queen,
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
        RANKS.queen,
    ], must_fail = true);

    // Ascending order (opposite of what's expected)
    await expectSorted([
        RANKS.two,
        RANKS.three,
        RANKS.four,
        RANKS.five,
        RANKS.six,
        RANKS.seven,
        RANKS.eight,
    ], must_fail = true);

    // Partially ascending
    await expectSorted([
        RANKS.ace,
        RANKS.king,
        RANKS.queen,
        RANKS.jack,
        RANKS.queen,
        RANKS.king,
        RANKS.ace,
    ], must_fail = true);

    // Duplicates breaking sort order
    await expectSorted([
        RANKS.ten,
        RANKS.nine,
        RANKS.nine,
        RANKS.ten,
        RANKS.eight,
        RANKS.seven,
        RANKS.six,
    ], must_fail = true);

    // Random order
    await expectSorted([
        RANKS.five,
        RANKS.ace,
        RANKS.three,
        RANKS.king,
        RANKS.seven,
        RANKS.two,
        RANKS.nine,
    ], must_fail = true);

    // Almost sorted with one swap
    await expectSorted([
        RANKS.ace,
        RANKS.king,
        RANKS.queen,
        RANKS.ten,
        RANKS.jack,
        RANKS.nine,
        RANKS.eight,
    ], must_fail = true);

    // Minimum value out of place
    await expectSorted([
        RANKS.ace,
        RANKS.two,
        RANKS.king,
        RANKS.queen,
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
    ], must_fail = true);

    // Maximum value at the end
    await expectSorted([
        RANKS.king,
        RANKS.queen,
        RANKS.jack,
        RANKS.ten,
        RANKS.nine,
        RANKS.eight,
        RANKS.ace,
    ], must_fail = true);

    // Duplicates with ascending pattern
    await expectSorted([
        RANKS.seven,
        RANKS.seven,
        RANKS.eight,
        RANKS.eight,
        RANKS.nine,
        RANKS.nine,
        RANKS.ten,
    ], must_fail = true);

  });
});
