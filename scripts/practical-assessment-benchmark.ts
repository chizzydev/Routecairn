import { readFileSync, writeFileSync, lstatSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import {
  importPracticalBenchmark,
  commitPracticalRun,
  scorePracticalRun,
  summarizePracticalRuns
} from "../src/benchmark/PracticalAssessmentBenchmark.js";
const [mode, manifestPath, expectedHash, ...args] = process.argv.slice(2);
function read(path: string) {
  const s = lstatSync(path);
  if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.size > 1048576)
    throw Error("BENCHMARK_ORDINARY_BOUNDED_INPUT_REQUIRED");
  const b = readFileSync(path);
  if (b.length > 1048576) throw Error("BENCHMARK_INPUT_BOUND");
  return b;
}
if (!mode || !manifestPath || !expectedHash)
  throw Error(
    "USAGE: commit manifest expectedHash runId measurements output | score manifest expectedHash receipt privateOracle output | summarize manifest expectedHash receipts privateOracle output"
  );
const imported = importPracticalBenchmark(read(resolve(manifestPath)), expectedHash),
  m = imported.manifest;
let result: unknown, output: string;
if (mode === "commit" && args.length === 3) {
  const [runId, measurements, out] = args;
  result = commitPracticalRun(m, runId!, JSON.parse(read(resolve(measurements!)).toString()));
  output = out!;
} else if ((mode === "score" || mode === "summarize") && args.length === 3) {
  const [receipts, oracle, out] = args;
  const r = JSON.parse(read(resolve(receipts!)).toString()),
    key = read(resolve(oracle!));
  result = mode === "score" ? scorePracticalRun(m, r, key) : summarizePracticalRuns(m, r, key);
  output = out!;
} else throw Error("BENCHMARK_EXACT_ARGUMENTS");
// Exclusive output: never overwrite prior predictions, oracle evidence or retained failures.
const bytes = Buffer.from(JSON.stringify(result, null, 2) + "\n");
writeFileSync(resolve(output), bytes, { flag: "wx" });
console.log(
  JSON.stringify({
    outputSha256: createHash("sha256").update(bytes).digest("hex"),
    mode,
    executionAuthority: "NONE",
    independentAcceptance: false
  })
);
