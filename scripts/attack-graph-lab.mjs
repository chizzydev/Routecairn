import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
if (process.argv.length !== 4 || process.argv[2] !== "--output") throw new Error("Use --output FRESH_DIRECTORY.");
const output = resolve(process.argv[3]);
await mkdir(dirname(output), { recursive: true }); await mkdir(output);
const testFiles = ["tests/unit/graphql-document-safety.test.ts", "tests/dashboard/adaptive-attack-state-graph.test.ts", "tests/dashboard/adaptive-graph-safety.test.ts", "tests/dashboard/adaptive-executed-contract-compiler.test.ts", "tests/dashboard/adaptive-read-only-compiler.test.ts", "tests/dashboard/adaptive-security-service.test.ts", "tests/dashboard/adaptive-ng0-characterization.test.ts", "tests/integration/adaptive-attack-graph-runtime.test.ts", "apps/dashboard-ui/src/AttackStateGraphPanel.test.tsx", "apps/dashboard-ui/src/AdaptiveSecurityWorkspace.test.tsx"];
const snapshot = async () => {
  const sources = {};
  const walk = async (folder, prefix) => {
    for (const entry of (await readdir(folder, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isSymbolicLink()) throw new Error("Source snapshots must not contain symbolic links.");
      if (["dist", "node_modules"].includes(entry.name)) continue;
      const name = `${prefix}${entry.name}`;
      if (entry.isDirectory()) await walk(join(folder, entry.name), `${name}/`);
      else sources[name] = sha256(await readFile(join(folder, entry.name)));
    }
  };
  await walk(join(repository, "src"), "src/"); await walk(join(repository, "apps/dashboard-ui/src"), "apps/dashboard-ui/src/");
  for (const file of [...testFiles, "tests/helpers/mutation-isolation.ts", "tests/helpers/assisted-review.ts", "scripts/attack-graph-lab.mjs", "package.json", "package-lock.json", "vitest.config.ts"]) sources[file] = sha256(await readFile(join(repository, file)));
  return sources;
};
const sources = await snapshot();
const transient = join(repository, ".routecairn-attack-graph-lab", `vitest-${randomUUID()}.json`);
await mkdir(dirname(transient), { recursive: true });
const exitCode = await new Promise((done, reject) => {
  const child = spawn(process.execPath, [join(repository, "node_modules/vitest/vitest.mjs"), "run", ...testFiles, "--pool=forks", "--maxWorkers=1", "--reporter=json", `--outputFile=${transient}`], { cwd: repository, windowsHide: true, env: { ...process.env, ROUTECAIRN_ATTACK_GRAPH_LAB_OUTPUT: output }, stdio: "inherit" });
  child.once("error", reject); child.once("exit", (code) => done(code ?? 1));
});
let complete = exitCode === 0; let tests = {}; let runtime = {};
try {
  const result = JSON.parse(await readFile(transient, "utf8"));
  tests = { total: result.numTotalTests, passed: result.numPassedTests, failed: result.numFailedTests, skipped: result.numPendingTests };
  if (!tests.total || tests.total !== tests.passed || tests.failed || tests.skipped) complete = false;
} catch { complete = false; } finally { await rm(transient, { force: true }); }
try {
  const bytes = await readFile(join(output, "runtime-proof.json")); const value = JSON.parse(bytes);
  runtime = { sha256: sha256(bytes), checks: value.checks?.length, cleanup: value.cleanup, executionOutcome: value.executionOutcome };
  if (value.checks?.length !== 12 || value.cleanup !== "CONFIRMED" || value.executionOutcome !== "VERIFIED" || value.externalTargetsTested !== false || value.independentlyOperated !== false) complete = false;
} catch { complete = false; }
const sourcesUnchanged = JSON.stringify(sources) === JSON.stringify(await snapshot()); if (!sourcesUnchanged) complete = false;
const result = { schemaVersion: 1, generatedAt: new Date().toISOString(), status: complete ? "COMPLETED" : "FAILED", nodeVersion: process.version, testExitCode: exitCode, tests, sourcesUnchanged, provenance: "SELF_MAINTAINED_LOOPBACK", externalTargetsTested: false, independentlyOperated: false, runtime, sources, limitations: ["The runtime exercise uses an owned disposable HTTP fixture and local SQLite dashboard.", "No independent operator, external target or public deployment is asserted."] };
const bytes = Buffer.from(`${JSON.stringify(result, null, 2)}\n`);
await writeFile(join(output, "attack-graph-lab-result.json"), bytes, { flag: "wx" });
await writeFile(join(output, "SHA256SUMS"), `${runtime.sha256 ? `${runtime.sha256}  runtime-proof.json\n` : ""}${sha256(bytes)}  attack-graph-lab-result.json\n`, { flag: "wx" });
process.stdout.write(`Attack graph lab: ${result.status}; ${join(output, "attack-graph-lab-result.json")}\n`);
if (!complete) process.exitCode = 1;
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
