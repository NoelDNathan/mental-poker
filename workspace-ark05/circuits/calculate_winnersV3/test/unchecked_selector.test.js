const chai = require("chai");
const wasm_tester = require("circom_tester").wasm;
const path = require("path");
const assert = chai.assert;

describe("unchecked_selector", function () {
    this.timeout(100000);

    let circuit;

    before(async function () {
        const circuitDir = path.join(__dirname, "./circuits/");
        process.chdir(circuitDir);
        circuit = await wasm_tester("SelectorUnchecked.circom");
    });

    async function expectSelector(condition, trueVal, falseVal, expectedOut) {
        const input = {
            condition: condition,
            true: trueVal,
            false: falseVal
        };
        const w = await circuit.calculateWitness(input, true);
        await circuit.checkConstraints(w);
        await circuit.assertOut(w, {out: expectedOut});
    }

    it("should select the true value when condition is 1", async () => {
        await expectSelector(1, 100, 50, 100);
        await expectSelector(1, 0, 1, 0);
        await expectSelector(1, 4294967295, 0, 4294967295);
    });

    it("should select the false value when condition is 0", async () => {
        await expectSelector(0, 100, 50, 50);
        await expectSelector(0, 0, 1, 1);
        await expectSelector(0, 4294967295, 12345, 12345);
    });

    it("should work with large values for true and false", async () => {
        const largeTrue = "123456789012345678901234567890";
        const largeFalse = "987654321098765432109876543210";
        await expectSelector(1, largeTrue, largeFalse, largeTrue);
        await expectSelector(0, largeTrue, largeFalse, largeFalse);
    });

    it("should behave predictably when condition is not 0 or 1 (unchecked)", async () => {
        // out = false + condition * (true - false)
        // If condition = 2, true = 10, false = 5:
        // out = 5 + 2 * (10 - 5) = 5 + 2 * 5 = 15
        await expectSelector(2, 10, 5, 15);
        
        // If condition = 5, true = 10, false = 10 (same values):
        // out = 10 + 5 * (10 - 10) = 10 + 0 = 10
        await expectSelector(5, 10, 10, 10);

        // If condition is a larger value
        await expectSelector(10, 20, 10, 110); // 10 + 10 * (20 - 10) = 110
    });
});
