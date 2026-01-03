/* eslint-disable no-console */
const { existsSync } = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

function requireFileExists(filePath, hint) {
  if (!existsSync(filePath)) {
    const msg = hint ? `Missing ${filePath}. ${hint}` : `Missing ${filePath}.`;
    throw new Error(msg);
  }
}

function main() {
  const projectDir = __dirname; // .../calculate_winnersV3/scripts
  const circuitDir = path.resolve(projectDir, ".."); // .../calculate_winnersV3

  const symPath = path.join(circuitDir, "calculate_winner.sym");
  const wasmPath = path.join(circuitDir, "calculate_winner_js", "calculate_winner.wasm");
  const witnessCalcPath = path.join(circuitDir, "calculate_winner_js", "witness_calculator.js");

  const hasArtifacts = existsSync(symPath) && existsSync(wasmPath) && existsSync(witnessCalcPath);
  if (hasArtifacts) return;

  console.log("[ensure_artifacts] Compiling calculate_winner.circom -> wasm/sym ...");

  try {
    execFileSync("circom", ["--O2", "calculate_winner.circom", "--r1cs", "--wasm", "--sym"], {
      cwd: circuitDir,
      stdio: "inherit",
    });
  } catch (e) {
    throw new Error(
      [
        "Failed to compile circuit with `circom`.",
        "Make sure circom is installed and available on PATH.",
        "Command: circom --O2 calculate_winner.circom --r1cs --wasm --sym",
        `cwd: ${circuitDir}`,
        String(e?.message || e),
      ].join("\n")
    );
  }

  requireFileExists(symPath, "Compilation did not produce the .sym file.");
  requireFileExists(wasmPath, "Compilation did not produce the .wasm file.");
  requireFileExists(witnessCalcPath, "Compilation did not produce witness_calculator.js.");
}

main();
