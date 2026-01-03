/* eslint-disable no-console */
const path = require("node:path");
const { execFileSync } = require("node:child_process");

function main() {
  const cases = process.env.TEST_CASES || "5000";
  const seed = process.env.TEST_SEED || "1";

  const projectDir = path.resolve(__dirname, "..");

  const env = {
    ...process.env,
    RUN_FUZZ: "1",
    TEST_CASES: String(cases),
    TEST_SEED: String(seed),
  };

  console.log(`[fuzz] RUN_FUZZ=1 TEST_CASES=${env.TEST_CASES} TEST_SEED=${env.TEST_SEED}`);

  execFileSync(
    process.platform === "win32" ? "npx.cmd" : "npx",
    ["jest", "--runInBand", "-t", "fuzz:"],
    { cwd: projectDir, stdio: "inherit", env }
  );
}

main();


