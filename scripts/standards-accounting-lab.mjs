import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
if (process.argv.length !== 4 || process.argv[2] !== "--output") throw new Error("Use --output FRESH_DIRECTORY.");
const output = resolve(process.argv[3]); await mkdir(dirname(output), { recursive: true }); await mkdir(output);
const tests = ["tests/unit/standards-coverage.test.ts", "tests/unit/official-standards-catalog.test.ts", "tests/integration/standards-accounting.test.ts", "tests/integration/active-vulnerability-validation.test.ts", "tests/integration/authentication-lifecycle.test.ts", "tests/integration/protocol-security.test.ts", "tests/integration/api-graphql.test.ts", "tests/integration/business-invariant.test.ts", "tests/integration/controlled-race.test.ts", "tests/unit/report-commands.test.ts", "tests/unit/report-diff.test.ts"];
async function snapshot() {
  const files = {};
  async function walk(directory, prefix) { for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) { if (entry.isSymbolicLink()) throw new Error("Source links are not accepted."); if (["dist", "node_modules"].includes(entry.name)) continue; const name = prefix + entry.name; if (entry.isDirectory()) await walk(join(directory, entry.name), name + "/"); else files[name] = sha(await readFile(join(directory, entry.name))); } }
  await walk(join(root, "src"), "src/"); await walk(join(root, "standards"), "standards/");
  for (const file of [...tests, "scripts/standards-accounting-lab.mjs", "scripts/standards-catalog.ts", "scripts/check-standards-mappings.ts", "scripts/copy-runtime-assets.mjs", "scripts/package-smoke.mjs", "scripts/verify-release-inputs.mjs", "package.json", "package-lock.json", "docs/STANDARDS_ACCOUNTING.md", ".gitattributes", ".github/workflows/continuous-assurance.yml", "apps/dashboard-ui/src/main.tsx"]) files[file] = sha(await readFile(join(root, file)));
  return files;
}
const sources = await snapshot();
const results = [];
async function run(label, args, env = {}) {
  const chunks = [];
  const code = await new Promise((done, reject) => { const child = spawn(process.execPath, args, { cwd: root, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } }); for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { chunks.push(chunk); process.stdout.write(chunk); }); child.on("error", reject); child.on("exit", (code) => done(code ?? 1)); });
  const name = `${label}.log`; await writeFile(join(output, name), Buffer.concat(chunks), { flag: "wx" }); results.push({ label, exitCode: code, log: name, sha256: sha(Buffer.concat(chunks)) }); return code;
}
await run("catalog-check", ["--import", "tsx", "scripts/standards-catalog.ts", "--check"]);
await run("mapping-check", ["--import", "tsx", "scripts/check-standards-mappings.ts"]);
await run("tests", ["node_modules/vitest/vitest.mjs", "run", ...tests, "--pool=forks", "--maxWorkers=1", "--reporter=json", `--outputFile=${join(output, "tests.json")}`], { ROUTECAIRN_STANDARDS_PROOF: join(output, "runtime") });
let counts = {}; let runtime = {};
try { const report = JSON.parse(await readFile(join(output, "tests.json"), "utf8")); counts = { total: report.numTotalTests, passed: report.numPassedTests, failed: report.numFailedTests, skipped: report.numPendingTests }; runtime = JSON.parse(await readFile(join(output, "runtime/runtime-proof.json"), "utf8")); } catch { /* Missing artifacts fail the acceptance summary. */ }
const sourcesUnchanged = JSON.stringify(sources) === JSON.stringify(await snapshot());
const complete = results.every((result) => result.exitCode === 0) && counts.total > 0 && counts.passed === counts.total && !counts.failed && !counts.skipped && sourcesUnchanged && runtime.realHttpRequests > 3 && runtime.cliVerify === 0 && runtime.cliValidate === 0 && runtime.cliRejectEdited === 1;
const result = { schemaVersion: 1, status: complete ? "COMPLETED" : "FAILED", generatedAt: new Date().toISOString(), nodeVersion: process.version, platform: process.platform, tests: counts, results, sourcesUnchanged, catalogSha256: runtime.catalogSha256, mappingSha256: runtime.mappingsSha256, provenance: "SELF_MAINTAINED_LOOPBACK_ACCEPTANCE", independentlyReviewed: false, certificationClaimed: false, limitations: ["Mappings are bounded case associations, not complete requirement verification or certification.", "Publisher digests provide integrity and reproducibility, not an independent assessment signature."], sources };
await writeFile(join(output, "standards-accounting-result.json"), `${JSON.stringify(result, null, 2)}\n`, { flag: "wx" });
const sums = [];
async function hashes(directory, prefix = "") { for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) { const path = join(directory, entry.name); if (entry.isDirectory()) await hashes(path, prefix + entry.name + "/"); else sums.push(`${sha(await readFile(path))}  ${prefix}${entry.name}`); } }
await hashes(output); await writeFile(join(output, "SHA256SUMS"), `${sums.join("\n")}\n`, { flag: "wx" });
process.stdout.write(`Standards acceptance: ${result.status}; ${counts.passed ?? 0} passed.\n`); if (!complete) process.exitCode = 1;
function sha(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
