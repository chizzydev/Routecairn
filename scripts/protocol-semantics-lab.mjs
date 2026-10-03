import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
if (process.argv.length !== 4 || process.argv[2] !== "--output") throw new Error("Use --output FRESH_DIRECTORY; supply ROUTECAIRN_CADDY_BINARY and ROUTECAIRN_NGINX_BINARY.");
for (const name of ["ROUTECAIRN_CADDY_BINARY", "ROUTECAIRN_NGINX_BINARY"]) if (!process.env[name] || !(await stat(resolve(process.env[name]))).isFile()) throw new Error(`Required native executable: ${name}.`);
const output = resolve(process.argv[3]); await mkdir(dirname(output), { recursive: true }); await mkdir(output);
const testFiles = ["tests/integration/protocol-semantics-runtime.test.ts", "tests/unit/protocol-semantics-safety.test.ts", "tests/integration/protocol-security.test.ts", "tests/integration/protocol-transports.test.ts", "tests/integration/protocol-acceptance.test.ts", "tests/unit/protocol-security-planner.test.ts", "tests/unit/proxy-chain-proof.test.ts"];
const snapshot = async () => {
  const sources = {};
  const walk = async (folder, prefix) => { for (const entry of (await readdir(folder, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) { if (entry.isSymbolicLink()) throw new Error("Source symlinks are not allowed."); if (entry.isDirectory()) await walk(join(folder, entry.name), `${prefix}${entry.name}/`); else sources[`${prefix}${entry.name}`] = sha256(await readFile(join(folder, entry.name))); } };
  for (const folder of ["src/modules/protocolSecurity", "src/core/http", "src/core/authorization", "src/config", "node_modules/quico", "node_modules/lemon-tls"]) await walk(join(repository, folder), `${folder}/`);
  for (const file of [...testFiles, "tests/helpers/active-proxy-lab.ts", "tests/helpers/protocol-semantics-lab.ts", "tests/helpers/plan.ts", "tests/helpers/mutation-isolation.ts", "src/core/engine/ScanContext.ts", "src/modules/apiGraphql/GraphqlDocumentSafety.ts", "src/validation/ProtocolAcceptance.ts", "src/cli/commands/validateProtocolFixtures.ts", "scripts/protocol-semantics-lab.mjs", "scripts/package-smoke.mjs", "scripts/verify-release-inputs.mjs", "docs/PROTOCOL_SEMANTICS_OPERATIONS.md", ".github/workflows/continuous-assurance.yml", "package.json", "package-lock.json", "vitest.config.ts"]) sources[file] = sha256(await readFile(join(repository, file)));
  return sources;
};
const sources = await snapshot();
const nativeBinaries = Object.fromEntries(await Promise.all(["ROUTECAIRN_CADDY_BINARY", "ROUTECAIRN_NGINX_BINARY"].map(async (name) => [name, sha256(await readFile(resolve(process.env[name])))])));
const transient = join(repository, ".routecairn-protocol-lab", `vitest-${randomUUID()}.json`); await mkdir(dirname(transient), { recursive: true });
const exitCode = await new Promise((done, reject) => { const child = spawn(process.execPath, [join(repository, "node_modules/vitest/vitest.mjs"), "run", ...testFiles, "--pool=forks", "--maxWorkers=1", "--reporter=default", "--reporter=json", `--outputFile.json=${transient}`], { cwd: repository, windowsHide: true, env: { ...process.env, ROUTECAIRN_PROTOCOL_LAB_OUTPUT: output }, stdio: "inherit" }); child.once("error", reject); child.once("exit", (code) => done(code ?? 1)); });
let complete = exitCode === 0; let tests = {};
try { const raw = await readFile(transient, "utf8"); await writeFile(join(output, "test-results.json"), raw, { flag: "wx" }); const value = JSON.parse(raw); tests = { total: value.numTotalTests, passed: value.numPassedTests, failed: value.numFailedTests, skipped: value.numPendingTests }; if (!tests.total || tests.total !== tests.passed || tests.failed || tests.skipped || value.numRuntimeErrorTestSuites || value.unhandledErrors?.length) complete = false; } catch { complete = false; } finally { await rm(transient, { force: true }); }
const artifacts = {};
for (const name of ["module-runtime.json", "proxy-H1-module-runtime.json", "proxy-H2-module-runtime.json"]) {
  try {
    const bytes = await readFile(join(output, name)); const value = JSON.parse(bytes); artifacts[name] = { sha256: sha256(bytes), executedCases: value.report?.executedCases, cleanup: value.cleanup };
    if (value.cleanup !== "CONFIRMED" || value.externalTargetsTested !== false || value.independentlyOperated !== false) complete = false;
    if (name === "module-runtime.json" ? value.report?.executedCases !== 21 || value.checks?.length !== 20 : value.report?.executedCases !== 4 || value.report?.passedCases !== 2 || value.report?.inconclusiveCases !== 2 || value.report?.failedCases || value.report?.blockedCases) complete = false;
  } catch { complete = false; }
}
const sourcesUnchanged = JSON.stringify(sources) === JSON.stringify(await snapshot()); if (!sourcesUnchanged) complete = false;
const binariesUnchanged = (await Promise.all(Object.entries(nativeBinaries).map(async ([name, digest]) => sha256(await readFile(resolve(process.env[name]))) === digest))).every(Boolean); if (!binariesUnchanged) complete = false;
const result = { schemaVersion: 1, generatedAt: new Date().toISOString(), status: complete ? "COMPLETED" : "FAILED", nodeVersion: process.version, platform: process.platform, architecture: process.arch, testExitCode: exitCode, tests, sourcesUnchanged, binariesUnchanged, nativeBinaries, artifacts, sources, provenance: "SELF_MAINTAINED_LOOPBACK_REAL_NATIVE_INTERMEDIARIES", externalTargetsTested: false, independentlyOperated: false, publicDeploymentVerified: false, limitations: ["Native Caddy and nginx execute on loopback; this is real intermediary deployment evidence, not external or independent acceptance.", "H1 CL.TE/TE.CL cells remain inconclusive when no bound backend misrouting is observed; ambiguity is not a finding.", "Matrices cover H1/H2/H3 ingress, Caddy-to-nginx H1 and H2, and nginx-to-application H1. H3 upstream hops are not asserted.", "Subscription reauthorization tests reconnect with old/new credentials; continuous revocation of an existing stream is a separate contract.", "Compression PASS at the expansion limit proves a scanner resource bound, not a target decompression defense.", "Default public QUIC trust requires a verified TLS endpoint on the same pinned TCP port; private QUIC-only services require an explicit CA."] };
const bytes = Buffer.from(`${JSON.stringify(result, null, 2)}\n`); await writeFile(join(output, "protocol-semantics-lab-result.json"), bytes, { flag: "wx" }); await writeFile(join(output, "SHA256SUMS"), `${Object.entries(artifacts).map(([name, value]) => `${value.sha256}  ${name}`).join("\n")}\n${sha256(bytes)}  protocol-semantics-lab-result.json\n`, { flag: "wx" });
process.stdout.write(`Protocol semantics lab: ${result.status}; ${join(output, "protocol-semantics-lab-result.json")}\n`); if (!complete) process.exitCode = 1;
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
