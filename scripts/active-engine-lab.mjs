import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const flags = new Map();
for (let i = 2; i < process.argv.length; i += 2) { const name = process.argv[i], value = process.argv[i + 1]; if (!["--caddy", "--nginx", "--python", "--pypdf-path", "--output"].includes(name) || !value || flags.has(name)) throw new Error("Use --caddy PATH --nginx PATH --pypdf-path PATH [--python PATH] [--output DIRECTORY]."); flags.set(name, value); }
for (const key of ["--caddy", "--nginx", "--pypdf-path"]) if (!flags.has(key)) throw new Error(`Required: ${key}. Supply approved local vendor binaries and pypdf 6.19.0; this command never downloads or installs software.`);
const output = resolve(flags.get("--output") ?? ".routecairn-active-lab/results"); await mkdir(output, { recursive: true });
for (const name of ["oauth-journeys.json", "file-processing.json", "proxy-deployment.json", "active-lab-result.json"]) { try { await readFile(join(output, name)); throw new Error("Output already contains a retained run; use a fresh directory."); } catch (error) { if (error.code !== "ENOENT") throw error; } }
const env = { ...process.env, ROUTECAIRN_CADDY_BINARY: resolve(flags.get("--caddy")), ROUTECAIRN_NGINX_BINARY: resolve(flags.get("--nginx")), ROUTECAIRN_PYPDF_PATH: resolve(flags.get("--pypdf-path")), ROUTECAIRN_PYTHON: flags.get("--python") ?? "python", ROUTECAIRN_ACTIVE_LAB_OUTPUT: output };
const testFiles = ["tests/integration/active-oauth-journey.test.ts", "tests/integration/active-file-processing.test.ts", "tests/integration/active-proxy-deployment.test.ts", "tests/unit/proxy-chain-proof.test.ts", "tests/unit/active-native-contracts.test.ts"];
const snapshot = async () => {
  const sources = {};
  for (const folder of ["src/modules/activeVulnerability", "src/modules/protocolSecurity", "tests/helpers"]) for (const entry of (await readdir(join(repository, folder))).sort()) { if (!/\.(ts|mjs|py)$/.test(entry)) continue; const path = `${folder}/${entry}`; sources[path] = createHash("sha256").update(await readFile(join(repository, path))).digest("hex"); }
  for (const path of [...testFiles, "src/core/http/RequestSafetyBroker.ts", "src/core/http/RawHttp1Transport.ts", "src/core/engine/ScanContext.ts", "package-lock.json", "scripts/active-engine-lab.mjs"]) sources[path] = createHash("sha256").update(await readFile(join(repository, path))).digest("hex");
  return sources;
};
const sources = await snapshot();
const exitCode = await new Promise((done, reject) => { const child = spawn(process.execPath, [join(repository, "node_modules/vitest/vitest.mjs"), "run", ...testFiles, "--pool=forks", "--maxWorkers=1"], { cwd: repository, env, windowsHide: true, stdio: "inherit" }); child.once("error", reject); child.once("exit", (code) => done(code ?? 1)); });
const artifacts = {}; let complete = exitCode === 0; const limitations = ["Application policies and execution are owner-maintained loopback fixtures; this is not independent or external acceptance.", "CSV formula and archive escape policies are simulations; archives are inspected without filesystem extraction.", "A clean proxy trace cannot prove a vulnerability; accepted ambiguity remains inconclusive.", "OAuth HTTP journeys require an approved authenticated authorization-server session; interactive login/consent stays inconclusive."];
for (const [name, count] of [["oauth-journeys.json", 8], ["file-processing.json", 28], ["proxy-deployment.json", 4]]) {
  try { const bytes = await readFile(join(output, name)); const value = JSON.parse(bytes); const rows = value.cases ?? value.cells; if (rows.length !== count || value.cleanup !== "CONFIRMED" || value.externalTargetsTested !== false || value.independentlyOperated !== false) complete = false; artifacts[name] = { sha256: createHash("sha256").update(bytes).digest("hex"), cases: rows.length }; } catch { complete = false; artifacts[name] = { missingOrInvalid: true }; }
}
const sourcesUnchanged = JSON.stringify(sources) === JSON.stringify(await snapshot()); if (!sourcesUnchanged) complete = false;
const report = { schemaVersion: 1, generatedAt: new Date().toISOString(), status: complete ? "COMPLETED" : "FAILED", testExitCode: exitCode, sourcesUnchanged, nodeVersion: process.version, provenance: "SELF_MAINTAINED_LOOPBACK", externalTargetsTested: false, independentlyOperated: false, artifacts, sources, limitations };
const bytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`); await writeFile(join(output, "active-lab-result.json"), bytes); await writeFile(join(output, "SHA256SUMS"), `${Object.entries(artifacts).filter(([, value]) => value.sha256).map(([name, value]) => `${value.sha256}  ${name}`).join("\n")}\n${createHash("sha256").update(bytes).digest("hex")}  active-lab-result.json\n`);
process.stdout.write(`Active engine lab: ${report.status}; ${join(output, "active-lab-result.json")}\n`); if (!complete) process.exitCode = 1;
