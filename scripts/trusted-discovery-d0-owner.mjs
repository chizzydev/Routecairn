import { spawn, execFileSync } from "node:child_process";
import { createWriteStream, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { frozenParent, sha256, machineProof, requireHeadroom, assertTestAccounting, assertBrowserAccounting } from "./trusted-discovery-d0-policy.mjs";

// Owner-only acceptance driver. This file is excluded from the package and is
// never imported by dashboard startup. Review the packet before invoking it.
const args = process.argv.slice(2), options = {};
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--source-review-accepted") { options.reviewed = true; continue; }
  if (!["--repo", "--artifacts", "--platform"].includes(args[i]) || !args[i + 1] || args[i + 1].startsWith("--")) throw Error("D0_OWNER_ARGUMENTS");
  const name = args[i++].slice(2); if (options[name]) throw Error("D0_OWNER_DUPLICATE_ARGUMENT"); options[name] = args[i];
}
const repo = resolve(options.repo || dirname(dirname(fileURLToPath(import.meta.url))));
const artifacts = options.artifacts && resolve(options.artifacts);
let evidence, machine, environment, inputs, inventory;
const commands = {}, gates = [], json = (p) => JSON.parse(readFileSync(p, "utf8"));
const git = (...a) => execFileSync("git", a, { cwd: repo, encoding: "utf8", windowsHide: true }).trim();
const record = (id, status, detail) => { gates.push({ id, status, detail }); };
function safePath(root, name) {
  if (typeof name !== "string" || !name || isAbsolute(name) || name.includes("\\") || name.split("/").some((v) => !v || v === "." || v === "..")) throw Error("D0_MANIFEST_PATH");
  const path = resolve(root, name), rel = relative(realpathSync(root), realpathSync(path));
  if (rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel) || lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()) throw Error("D0_MANIFEST_CANONICAL_PATH");
  return path;
}
function integrity() {
  for (const ref of ["HEAD", "main", "origin/main"]) if (git("rev-parse", ref) !== frozenParent) throw Error("D0_LOCAL_PIN");
  const remote = git("ls-remote", "origin", "refs/heads/main");
  if (remote.split(/\s+/)[0] !== frozenParent || remote.split(/\s+/)[1] !== "refs/heads/main") throw Error("D0_REMOTE_PIN");
  if (git("diff", "--cached", "--name-only")) throw Error("D0_INDEX_NOT_CLEAN");
  const actual = [...git("diff", "--name-only", frozenParent, "--").split("\n"), ...git("ls-files", "--others", "--exclude-standard").split("\n")].filter(Boolean).sort();
  const expected = Object.keys(inputs.changedFiles).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw Error("D0_UNEXPECTED_SOURCE_SCOPE");
  for (const [file, hash] of Object.entries({ ...inputs.frozenFiles, ...inputs.changedFiles })) if (sha256(readFileSync(safePath(repo, file))) !== hash) throw Error("D0_SOURCE_HASH: " + file);
  for (const [file, hash] of Object.entries(inputs.artifacts)) if (sha256(readFileSync(safePath(artifacts, file))) !== hash) throw Error("D0_ARTIFACT_HASH: " + file);
  git("diff", "--check"); git("apply", "--reverse", "--check", safePath(artifacts, "STAGE_D0_CUMULATIVE_REVIEW.patch"));
}
async function run(label, args, timeout = 35 * 60_000) {
  requireHeadroom(repo); requireHeadroom(environment.TEMP);
  const stdout = createWriteStream(join(evidence, label + ".stdout")), stderr = createWriteStream(join(evidence, label + ".stderr"));
  const started = new Date().toISOString(); let signal, pid, expired = false;
  const exit = await new Promise((done) => {
    const child = spawn(process.execPath, args, { cwd: repo, windowsHide: true, env: { ...environment, ROUTECAIRN_DASHBOARD_DIR: mkdtempSync(join(environment.TEMP, "rcd-default-")) }, stdio: ["ignore", "pipe", "pipe"] }); pid = child.pid;
    child.stdout.pipe(stdout); child.stderr.pipe(stderr);
    child.stdout.on("data", (bytes) => process.stdout.write(bytes)); child.stderr.on("data", (bytes) => process.stderr.write(bytes));
    const deadline = globalThis.setTimeout(() => { expired = true; child.kill(); }, timeout);
    child.once("error", (error) => { stderr.write(String(error) + "\n"); });
    child.once("close", (code, value) => { globalThis.clearTimeout(deadline); signal = value; done(code ?? 1); });
  });
  await Promise.all([new Promise((done) => stdout.end(done)), new Promise((done) => stderr.end(done))]);
  commands[label] = { started, finished: new Date().toISOString(), pid, exit, signal, deadlineExpired: expired };
  writeFileSync(join(evidence, label + ".exit"), String(exit)); return exit;
}
async function tests(label, files, lowerBounds, minimum) {
  const output = join(evidence, label + ".json");
  const exit = await run(label, [join(repo, "node_modules/vitest/vitest.mjs"), "run", ...files, "--pool=forks", "--maxWorkers=1", "--reporter=json", `--outputFile=${output}`]);
  try {
    const result = assertTestAccounting(json(output), lowerBounds, minimum);
    if (exit !== 0) throw Error("D0_TEST_EXIT"); record(label, "PASS", result); return true;
  } catch (error) { record(label, "HOLD", { reason: error.message, exit, result: existsSync(output) ? { total: json(output).numTotalTests, passed: json(output).numPassedTests, failed: json(output).numFailedTests, skipped: json(output).numPendingTests } : "MISSING" }); return false; }
}
try {
  if (!options.reviewed || !artifacts) throw Error("D0_INDEPENDENT_SOURCE_AND_SCRIPT_REVIEW_REQUIRED");
  if (!["windows", "linux"].includes(options.platform) || process.platform !== (options.platform === "windows" ? "win32" : "linux")) throw Error("D0_ACTUAL_PLATFORM_MISMATCH");
  if (options.platform === "linux") {
    const os = readFileSync("/etc/os-release", "utf8");
    if (!/^ID=\"?ubuntu\"?$/m.test(os) || /microsoft|wsl/i.test(execFileSync("uname", ["-r"], { encoding: "utf8" }))) throw Error("D0_REAL_UBUNTU_INSTALLATION_OR_VM_REQUIRED");
  }
  inputs = json(safePath(artifacts, "STAGE_D0_REVIEW_INPUTS.json"));
  if (inputs.schemaVersion !== 1 || inputs.frozenParent !== frozenParent) throw Error("D0_MANIFEST_VERSION_PIN");
  integrity();
  for (const name of ["ROUTECAIRN_DATABASE_URL", "ROUTECAIRN_DATABASE_URL_FILE", "ROUTECAIRN_EVIDENCE_S3_BUCKET", "OTEL_EXPORTER_OTLP_ENDPOINT"]) if (process.env[name]?.trim()) throw Error("D0_AMBIENT_REMOTE_INFRASTRUCTURE_REFUSED: " + name);
  if (process.env.ROUTECAIRN_CONTROL_PLANE_MODE && process.env.ROUTECAIRN_CONTROL_PLANE_MODE !== "local") throw Error("D0_AMBIENT_DISTRIBUTED_MODE_REFUSED");
  const manifest = json(join(repo, "package.json"));
  const { satisfies } = await import("semver");
  if (!satisfies(process.version, manifest.engines.node)) throw Error("D0_NODE_ENGINE_INSTALL_NOT_AUTHORIZED");
  for (const [name, version] of Object.entries(inputs.installedDependencies)) if (json(join(repo, "node_modules", name, "package.json")).version !== version) throw Error("D0_DEPENDENCY_MISMATCH_NO_AUTO_INSTALL: " + name);
  // An actual native open catches wrong-platform/ABI modules without rebuilding.
  const { default: Database } = await import("better-sqlite3"); const native = new Database(":memory:"); native.close();
  machine = machineProof(repo); requireHeadroom(repo); requireHeadroom(tmpdir());
  const lab = join(repo, ".routecairn-engineering-lab");
  if (existsSync(lab) && (lstatSync(lab).isSymbolicLink() || !lstatSync(lab).isDirectory())) throw Error("D0_LAB_CANONICAL_DIRECTORY_REQUIRED");
  mkdirSync(lab, { recursive: true, mode: 0o700 });
  evidence = mkdtempSync(join(lab, "d0-owner-")); const temp = mkdtempSync(join(realpathSync(tmpdir()), "rcd-"));
  environment = { ...process.env, TEMP: temp, TMP: temp, TMPDIR: temp, NODE_OPTIONS: "--max-old-space-size=4096", npm_config_offline: "true", npm_config_update_notifier: "false", NO_UPDATE_NOTIFIER: "1", ROUTECAIRN_STAGE_B_WIRE_EVIDENCE: join(evidence, "native-wire.jsonl"), ROUTECAIRN_OUTCOME_WIRE_EVIDENCE: join(evidence, "outcome-wire.jsonl"), ROUTECAIRN_STAGE_C_WIRE_EVIDENCE: join(evidence, "review-wire.jsonl"), ROUTECAIRN_D0_PROOF: join(evidence, "platform-proof.jsonl") };
  inventory = json(join(repo, "tests/acceptance/trusted-discovery-d0-inventory.json"));
  writeFileSync(join(evidence, "preflight.json"), JSON.stringify({ sourceHead: frozenParent, machine, temp, reviewed: true, generatedAt: new Date().toISOString(), inputsSha256: sha256(readFileSync(join(artifacts, "STAGE_D0_REVIEW_INPUTS.json"))) }, null, 2));
  const npm = [join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"), "/usr/share/nodejs/npm/bin/npm-cli.js", "/usr/lib/node_modules/npm/bin/npm-cli.js", "/usr/local/lib/node_modules/npm/bin/npm-cli.js"].find(existsSync);
  if (!npm) throw Error("D0_NPM_CLI_MISSING_NO_AUTO_INSTALL");
  for (const gate of ["build", "dashboard:typecheck", "dashboard:build", "lint", "format:check", "architecture:check", "runtime:lock:check", "release:verify", "package:verify"]) {
    const exit = await run(gate.replaceAll(":", "-"), [npm, "run", gate]); record(gate, exit === 0 ? "PASS" : "HOLD", { exit });
  }
  const required = { ...inventory.protectedTests, ...inventory.newTests };
  const protectedOk = await tests("protected", Object.keys(required), required, Object.values(required).reduce((a, b) => a + b, 0));
  const dashboard = Object.fromEntries(Object.entries(inputs.dashboardLowerBounds));
  const dashboardOk = await tests("dashboard-ui", ["tests/dashboard", "apps/dashboard-ui/src"], dashboard, inventory.historicalMinimums.dashboardTests);
  if (existsSync(join(evidence, "dashboard-ui.json")) && json(join(evidence, "dashboard-ui.json")).testResults.length < inventory.historicalMinimums.dashboardFiles) record("dashboard-file-count", "HOLD", "HISTORICAL_MINIMUM_82_REQUIRED");
  const standaloneOk = await tests("standalone", ["tests/integration/adaptive-attack-graph-runtime.test.ts"], { "tests/integration/adaptive-attack-graph-runtime.test.ts": 1 }, 1);
  const graphExit = await run("attack-graph", [join(repo, "scripts/attack-graph-lab.mjs"), "--output", join(evidence, "graph")]);
  const graph = json(join(evidence, "graph/attack-graph-lab-result.json"));
  const graphOk = graphExit === 0 && graph.status === "COMPLETED" && graph.sourcesUnchanged && graph.tests.total >= 536 && graph.tests.passed === graph.tests.total && graph.tests.failed === 0 && graph.tests.skipped === 0 && graph.runtime.checks === 12 && graph.runtime.cleanup === "CONFIRMED" && graph.runtime.executionOutcome === "VERIFIED";
  record("attack-graph", graphOk ? "PASS" : "HOLD", { exit: graphExit, tests: graph.tests, runtime: graph.runtime });
  if (!machine.browser.available) record("real-browser", "HOLD", "EXISTING_CHROMIUM_MISSING; optional separately reviewed: node node_modules/playwright/cli.js install chromium");
  else {
    const exit = await run("real-browser", [join(repo, "scripts/trusted-discovery-d0.mjs"), "--output", join(evidence, "browser")], 6 * 60_000);
    try { const browser = json(join(evidence, "browser/acceptance-result.json")); const result = assertBrowserAccounting(browser.browser, inventory.browserCases); if (exit !== 0 || !browser.sourceUnchanged || result.status !== "PASS") throw Error("D0_BROWSER_NOT_PASS"); record("real-browser", "PASS", { ...result, version: browser.browser.browserVersion, targetReceipts: browser.browser.targetReceipts }); }
    catch (error) { record("real-browser", "HOLD", { exit, reason: error.message }); }
  }
  const platform = existsSync(join(evidence, "platform-proof.jsonl")) ? readFileSync(join(evidence, "platform-proof.jsonl"), "utf8").trim().split("\n").map(JSON.parse) : [];
  const path = platform.find((v) => v.case === "P01");
  record("native-platform", path?.symbolicLink === "PASS" && (process.platform !== "linux" || path.posixModes === "PASS") ? "PASS" : "HOLD", platform);
  const wireFacts = {};
  try {
    for (const [kind, file] of [["native", "native-wire.jsonl"], ["outcome", "outcome-wire.jsonl"], ["review", "review-wire.jsonl"]]) {
      const rows = readFileSync(join(evidence, file), "utf8").trim().split("\n").map(JSON.parse);
      if (!rows.length || rows.some((v) => !Number.isInteger(v.wireReceipts ?? v.targetReceipts) || (v.wireReceipts ?? v.targetReceipts) < 0 || v.externalTargetsTested === true)) throw Error("D0_WIRE_RECEIPT_INVALID");
      const gets = rows.reduce((sum, v) => sum + (v.wireReceipts ?? v.targetReceipts), 0);
      if (kind === "review" ? gets !== 0 : gets < 1) throw Error("D0_REAL_WIRE_REQUIRED");
      wireFacts[kind] = { fixtures: rows.length, gets, sha256: sha256(readFileSync(join(evidence, file))) };
    }
    if (!["P01", "P02", "P03", "P04"].every((id) => platform.some((v) => v.case === id && v.targetReceipts === (id === "P01" ? 0 : 1)))) throw Error("D0_PROCESS_WIRE_REQUIRED");
    record("actual-wire-receipts", "PASS", wireFacts);
  } catch (error) { record("actual-wire-receipts", "HOLD", { reason: error.message, ...wireFacts }); }
  const packExit = await run("dry-pack", [npm, "pack", "--dry-run", "--ignore-scripts", "--json"]);
  record("dry-pack", packExit === 0 ? "PASS" : "HOLD", { exit: packExit, lifecycle: false, publishing: false });
  try {
    const packed = json(join(evidence, "dry-pack.stdout"));
    if (packExit !== 0 || packed.length !== 1 || !packed[0].files?.length || packed[0].files.some((v) => /(?:^tests\/|trusted-discovery-d0|stage-[abc]\.fixture|witness\.key|\.sqlite$|native-wire|outcome-wire)/i.test(v.path))) throw Error("D0_PACKAGE_FIXTURE_INPUT");
    for (const file of packed[0].files.filter((v) => /^apps\/dashboard-ui\/dist\/.*\.js$/.test(v.path))) if (/stageAFixture|stageBFixture|D0_FIXTURE_BIND_FAILED|witness\.key|\/api\/trusted-discovery\/execute/.test(readFileSync(safePath(repo, file.path), "utf8"))) throw Error("D0_REACT_BUNDLE_FIXTURE");
    record("bundle-file-audit", "PASS", { files: packed[0].files.length, supportingOnly: true });
  } catch (error) { record("bundle-file-audit", "HOLD", { reason: error.message }); }
  record("literal-package-native-tool-absence", "HOLD", "Frozen shipping Node class contains internal executeFresh. No HTTP bridge or witness bootstrap; literal method removal conflicts with frozen source and requires independent review.");
  record("package-smoke", "HOLD", "Frozen script installs dependencies; installation not authorized.");
  record("build-release", "HOLD", "Frozen script removes generated dist; reviewed preservation/isolation required.");
  if (protectedOk && dashboardOk && standaloneOk && graphOk && gates.every((v) => !["build", "dashboard:typecheck", "lint"].includes(v.id) || v.status === "PASS")) {
    const before = Date.now(); const exit = await run("test-complete", [join(repo, "scripts/test-recycled.mjs")], 90 * 60_000);
    // The unchanged recycled driver refuses partial shards. Require a new,
    // complete JSON result and all frozen/new test files; no skipped counts.
    const { readdirSync, statSync } = await import("node:fs");
    const root = join(repo, ".routecairn-engineering-lab/test-runs");
    const fresh = readdirSync(root).map((v) => join(root, v, "results.json")).filter((p) => existsSync(p) && statSync(p).mtimeMs >= before);
    try { if (exit !== 0 || fresh.length !== 1) throw Error("D0_COMPLETE_SUITE_EVIDENCE"); const bounds = Object.fromEntries(Object.keys(inputs.originalTests).map((p) => [p, 1])); Object.assign(bounds, inventory.newTests); record("test-complete", "PASS", assertTestAccounting(json(fresh[0]), bounds)); }
    catch (error) { record("test-complete", "HOLD", { exit, reason: error.message }); }
  } else record("test-complete", "HOLD", "Mandatory original gates failed; preserve failures and rerun original unchanged gates normally first.");
  integrity(); record("final-source-manifest", "PASS", { changedPaths: Object.keys(inputs.changedFiles).length, originalTests: Object.keys(inputs.originalTests).length });
  record("operational-custody", "HOLD", "D1 real OS custody/ACL/anchor/independent review not authorized or evidenced.");
  record("external-monotonic-anchor", "HOLD", "D2 separate approval/provider and genuine independent anchor proof required.");
  record("independent-signoff-and-other-platform", "HOLD", "This transcript alone does not satisfy D4 or both platform proofs.");
} catch (error) { record("owner-precondition-or-integrity", "HOLD", { reason: String(error.message) }); }
const result = gates.some((v) => v.status !== "PASS") ? "HOLD" : "PASS_FOR_REVIEW";
if (evidence) writeFileSync(join(evidence, "owner-result.json"), JSON.stringify({ schemaVersion: 1, result, sourceHead: frozenParent, machine, generatedAt: new Date().toISOString(), commands, gates, productExecutionEndpoint: "UNREGISTERED", defaultDiscovery: "OFF", externalMonotonicAnchor: "HOLD", linuxProof: process.platform === "linux" ? "ACTUAL_RUNTIME_CHECKS_SEE_GATES" : "HOLD", tempRetained: environment?.TEMP, publicActivation: false }, null, 2));
console.log(`OWNER_RESULT=${result}\nEVIDENCE=${evidence || "none; precondition denied before fixtures"}`);
process.exitCode = result === "PASS_FOR_REVIEW" ? 0 : 2;
