import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createServer, get } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { ContinuousAssuranceService } from "../../src/dashboard/execution/ContinuousAssuranceService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { syntheticAssuranceComparison } from "./continuous-assurance-comparison-result.js";

// Test-only seam proof: actual SQLite/service/processes/native HTTP, synthetic
// execution/adapter/comparison/export ports. Never starts the product scan worker.
export const interruptionCases = ["AFTER_ENQUEUE_DB_FAILURE", "KILL_BEFORE_SCAN_LINK", "RESERVED_CONCURRENT", "PARTIAL_TWO_LANES", "LOST_ACK_COMPLETE", "FINALIZE_IDEMPOTENCE", "FINALIZE_CONCURRENT", "ENQUEUE_REPLY_LOST", "CANCELLED", "LIVE_LAUNCH_RECONCILE", "LEASE_LOST_BEFORE_SUBMIT", "ENQUEUE_REPLY_LOST_TWO_LANES"] as const;
type Scenario = typeof interruptionCases[number];
type State = { policyId: string; token: string; targetId: string; adapters: string[]; baselines: string[]; versions: string[] };
type Message = Record<string, any>;
const fingerprint = "d".repeat(64), caseFingerprint = "c".repeat(64), adapterDigest = "a".repeat(64);
const helper = fileURLToPath(import.meta.url), repo = resolve(dirname(helper), "../.."), loader = pathToFileURL(join(repo, "node_modules/tsx/dist/loader.mjs")).href;
const unknownError = "CONTINUOUS_ASSURANCE_DEPLOYMENT_OUTCOME_UNKNOWN";

function nativeGet(origin: string): Promise<void> {
  const url = new URL("/fixture/canary", origin);
  assert.equal(url.hostname, "127.0.0.1"); assert.equal(url.protocol, "http:");
  return new Promise((done, reject) => {
    const request = get(url, { agent: false, timeout: 2000 }, response => {
      let bytes = 0;
      response.on("data", b => { bytes += b.length; if (bytes > 4096) request.destroy(Error("FIXTURE_RESPONSE_CAP")); });
      response.on("end", () => response.statusCode === 200 ? done() : reject(Error("FIXTURE_NATIVE_STATUS")));
      response.on("error", reject);
    });
    request.on("timeout", () => request.destroy(Error("FIXTURE_NATIVE_TIMEOUT")));
    request.on("error", reject);
  });
}
function fixtureRoot(root: string, marker: string) {
  assert.equal(realpathSync.native(root), resolve(root));
  assert(lstatSync(root).isDirectory() && !lstatSync(root).isSymbolicLink());
  assert.equal(readFileSync(join(root, "FIXTURE_OWNERSHIP"), "utf8"), marker);
}
function scan(database: DashboardDatabase, state: State, origin: string, status = "COMPLETED") {
  const id = randomUUID(); new ScanRepository(database).create({ id, source: "DASHBOARD", status: status as any, targetOrigin: origin, safeTargetLabel: "generated-loopback", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId: state.targetId }); return id;
}
function exactCase(database: DashboardDatabase, scanId: string) {
  database.db.prepare("INSERT INTO scan_workflow_case_executions (id,scan_id,workflow_id,module_id,safe_case_alias,safe_case_fingerprint,execution_state,request_transmitted,matched_expectation,evidence_strength,safe_semantics_json,safe_result_json,created_at) VALUES (?,?,?,?,?,?,'COMPLETED',1,1,'STRONG','{}','{}',?)").run(randomUUID(), scanId, "api-graphql-authorization", "api-graphql-authorization", "synthetic-contract", caseFingerprint, new Date().toISOString());
}
function input(state: State) {
  return { schemaVersion: 1, name: "Generated interruption fixture", targetId: state.targetId, authorization: { proofReference: "fixture://owned-loopback", proofDigest: "b".repeat(64), validFrom: new Date(Date.now() - 60000).toISOString(), expiresAt: new Date(Date.now() + 86400000).toISOString() }, triggers: { scheduleEnabled: false, intervalMinutes: 60, deploymentEnabled: true, quietWhenHealthy: true }, adapterProfileIds: state.adapters, baselines: state.adapters.map((adapterProfileId, i) => ({ adapterProfileId, scanId: state.baselines[i] })), requiredCases: state.adapters.map(adapterProfileId => ({ adapterProfileId, workflowId: "api-graphql-authorization", caseFingerprint })), gates: { failOnRegression: true, failOnNewFinding: true, failOnOpenDrift: true, requireExactCases: true, requireCleanupResolved: true }, evidence: { retentionDays: 90, autoExportOn: ["REGRESSION", "FAILED", "CLEANUP_REQUIRED", "APPROVAL_REQUIRED"], preserveFailures: true, preserveCleanupEvidence: true } };
}
function facts(database: DashboardDatabase, state: State) {
  return { deployments: database.db.prepare("SELECT deployment_id,build_fingerprint,run_id FROM continuous_assurance_deployments").all(), runs: database.db.prepare("SELECT id,status,gate_status,safe_summary_json,notification_required FROM continuous_assurance_runs ORDER BY created_at,id").all(), lanes: database.db.prepare("SELECT run_id,scan_id,status,safe_error_summary,ordinal FROM continuous_assurance_run_scans ORDER BY run_id,ordinal").all(), scanCount: (database.db.prepare("SELECT COUNT(*) n FROM scans WHERE id NOT IN (" + state.baselines.map(() => "?").join(",") + ")").get(...state.baselines) as any).n, notifications: database.db.prepare("SELECT category,safe_summary FROM continuous_assurance_notifications ORDER BY id").all(), exports: Number((database.db.prepare("SELECT value FROM dashboard_meta WHERE key='fixture_export_calls'").get() as any)?.value || 0), leases: database.db.prepare("SELECT lease_expires_at FROM continuous_assurance_leases").all() };
}
async function child(message: Message) {
  const { root, marker, origin, action, mode } = message; fixtureRoot(root, marker);
  // Per-process environment only; no owner-global environment or journal touched.
  process.env.ROUTECAIRN_MUTATION_DIR = join(root, "generated-mutations");
  const paths = resolveDashboardPaths(root), database = new DashboardDatabase(paths.databasePath); database.migrate();
  let state = message.state as State;
  if (action === "setup") {
    const targetId = new TargetRepository(database).create({ displayName: "Generated local fixture", baseOrigin: origin, tags: [], classification: "LOCAL", authorizationType: "OWNED", authorizationSummary: "Generated disposable localhost only", productionEnabled: false, approvedScope: { program: "Generated", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 2, concurrency: 1, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/InterruptionFixture" } });
    state = { policyId: "", token: "", targetId, adapters: [], baselines: [], versions: [] };
    for (let i = 0; i < message.lanes; i++) {
      const profile = randomUUID(), version = randomUUID(), now = new Date().toISOString(); state.adapters.push(profile); state.versions.push(version);
      database.db.prepare("INSERT INTO provider_adapters (id,name,target_id,provider,engine_id,enabled,active_version_id,created_by,created_at,updated_at) VALUES (?,?,?,'GENERIC_HTTP','api-graphql-authorization',1,?,'fixture',?,?)").run(profile, "Generated", targetId, version, now, now);
      database.db.prepare("INSERT INTO provider_adapter_versions (id,profile_id,revision,status,adapter_digest,target_row_version,credential_binding_json,algorithm,key_version,nonce,ciphertext,auth_tag,created_by,created_at,reviewed_by,reviewed_at) VALUES (?,?,1,'REVIEWED',?,1,'[]','aes-256-gcm','fixture','n','c','t','fixture',?,'fixture',?)").run(version, profile, adapterDigest, now, now);
      const id = scan(database, state, origin); state.baselines.push(id); exactCase(database, id);
      database.db.prepare("INSERT INTO scan_provider_adapter_bindings (scan_id,profile_id,version_id,adapter_digest,created_at) VALUES (?,?,?,?,?)").run(id, profile, version, adapterDigest, now);
    }
  }
  let submitting = false, enqueues = 0;
  const cut = async (name: string): Promise<never> => { process.send?.({ type: "cut", name }); return new Promise(() => {}); };
  const execution = {
    preview: async () => { if (submitting && mode === "RESERVED_CONCURRENT") await cut("RESERVED_BEFORE_RUN"); return { limits: { maxScanDurationMs: 60000, maxRequests: 2, cleanupReservedRequests: 0 }, credentialReadiness: { blockers: [], warnings: [], profiles: [] }, warnings: [] } as any; },
    enqueue: async () => {
      const id = scan(database, state, origin, "QUEUED"); await nativeGet(origin); enqueues++;
      if (mode === "ENQUEUE_REPLY_LOST" || mode === "ENQUEUE_REPLY_LOST_TWO_LANES") throw Error("CA_SYNTHETIC_SECRET_CANARY_DO_NOT_RETAIN");
      if (mode === "KILL_BEFORE_SCAN_LINK" || mode === "LIVE_LAUNCH_RECONCILE" || mode === "PARTIAL_TWO_LANES" && enqueues === 2) await cut("NATIVE_GET_BEFORE_SCAN_ID_RETURN");
      database.db.prepare("UPDATE scans SET status=?,completed_at=? WHERE id=?").run(mode === "CANCELLED" ? "CANCELLED" : "COMPLETED", new Date().toISOString(), id); exactCase(database, id); return id;
    }
  };
  const adapters = { materialize: (profileId: string) => ({ target: { id: state.targetId, rowVersion: 1 }, input: { targetId: state.targetId }, binding: { profileId, versionId: state.versions[state.adapters.indexOf(profileId)]!, adapterDigest } }), materializeScanRequest: () => ({ target: origin, targetId: state.targetId, profile: "full" } as any), assertExecutionBinding: async () => { if(submitting&&mode==="LEASE_LOST_BEFORE_SUBMIT")database.db.prepare("UPDATE continuous_assurance_leases SET lease_expires_at='2000-01-01T00:00:00.000Z'").run(); }, bindScan: (scanId: string, binding: any) => { database.db.prepare("INSERT INTO scan_provider_adapter_bindings (scan_id,profile_id,version_id,adapter_digest,created_at) VALUES (?,?,?,?,?)").run(scanId, binding.profileId, binding.versionId, binding.adapterDigest, new Date().toISOString()); } };
  const comparison = { compare: (older:string,newer:string) => syntheticAssuranceComparison(older,newer,mode.startsWith("FINALIZE_") ? 1 : 0) };
  const evidence = { available: () => true, createExport: () => { database.db.prepare("INSERT INTO dashboard_meta (key,value,updated_at) VALUES ('fixture_export_calls','1',?) ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1").run(new Date().toISOString()); return { id: "generated-export-reference" }; } };
  const service = new ContinuousAssuranceService(database, paths, execution, adapters, comparison, evidence, { startTimers: false });
  let result: any, error: string | undefined;
  try {
    if (action === "setup") { const value = input(state), preview = await service.preview(value), created = await service.create(value, "generated-owner") as any; state.policyId = created.policy.id; state.token = created.deploymentTriggerToken; await service.review(state.policyId, created.policy.pendingVersionId, preview.policyDigest, "generated-owner"); }
    else {
      if (message.expireLease) database.db.prepare("UPDATE continuous_assurance_leases SET lease_expires_at='2000-01-01T00:00:00.000Z'").run();
      if (action === "observe") await service.reconcileNow();
      if (action === "recover") { database.db.exec("DROP TRIGGER IF EXISTS fixture_after_enqueue"); database.recoverInterruptedScans(); if (mode === "FINALIZE_CONCURRENT") await Promise.all([service.reconcileNow(), service.reconcileNow()]); else await service.reconcileNow(); await service.reconcileNow(); }
      if (mode === "AFTER_ENQUEUE_DB_FAILURE" && action === "trigger") database.db.exec("CREATE TRIGGER fixture_after_enqueue BEFORE UPDATE OF status ON continuous_assurance_runs WHEN NEW.status='RUNNING' BEGIN SELECT RAISE(ABORT,'CA_FIXTURE_AFTER_ENQUEUE'); END");
      submitting = true;
      try { result = await service.deployment(state.policyId, message.wrongToken ? "wrong-generated-token" : state.token, message.deploymentId || "fixture-deployment", message.conflict ? "e".repeat(64) : fingerprint); } catch (e) { error = e instanceof Error ? e.message : "UNKNOWN_FIXTURE_ERROR"; }
      if (mode === "LOST_ACK_COMPLETE" && action === "trigger") await cut("COMPLETE_COMMIT_RESPONSE_LOST");
      if (action === "recover") { await service.reconcileNow(); await service.reconcileNow(); }
    }
    const truth = {...facts(database, state), unresolvedDeploymentReservations: service.get(state.policyId).unresolvedDeploymentReservations}; service.shutdown(); database.close();
    process.send?.({ type: "result", ...(action === "setup" ? { state } : {}), result, error, truth });
    process.disconnect?.();
  } catch (e) { service.shutdown(); if (database.db.open) database.close(); throw e; }
}

function launch(message: Message) {
  const env: NodeJS.ProcessEnv = {}; for (const k of ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"]) if (process.env[k]) env[k] = process.env[k];
  const processChild = spawn(process.execPath, ["--max-old-space-size=512", "--import", loader, helper, "--fixture-child"], { cwd: repo, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe", "ipc"] });
  let bytes = 0, stderr = "", cutName: string | undefined, stopped = false;
  const exit = new Promise<{ code: number | null; signal: string | null }>(done => processChild.once("close", (code, signal) => done({ code, signal })));
  for (const stream of [processChild.stdout, processChild.stderr]) stream?.on("data", b => { bytes += b.length; if (stream === processChild.stderr) stderr += b.toString(); if (bytes > 65536) processChild.kill(); });
  const next = new Promise<Message>((done, reject) => {
    const timer = setTimeout(() => { processChild.kill(); reject(Error("FIXTURE_CHILD_TIMEOUT")); }, 12000);
    processChild.once("error", e => { clearTimeout(timer); reject(e); });
    processChild.once("close", code => { clearTimeout(timer); if (!stopped) reject(Error("FIXTURE_CHILD_STARTUP_OR_RUNTIME_" + code + ":" + stderr.slice(0, 2000))); });
    processChild.on("message", (m: any) => { if (m.type === "result" || m.type === "cut") { stopped = true; cutName = m.name; clearTimeout(timer); done(m); } else if (m.type === "error") { clearTimeout(timer); processChild.kill(); reject(Error("FIXTURE_CHILD_RUNTIME:" + m.message)); } });
  });
  processChild.send(message);
  return { next, async finish() { const outcome = await exit; assert.equal(outcome.code, 0, stderr); return outcome; }, async kill() { processChild.kill(); return { ...(await exit), cut: cutName, ownedProcess: true }; } };
}

export async function runInterruptionScenario(name: Scenario): Promise<Record<string, any>> {
  const lab = process.env.ROUTECAIRN_CA_LAB; assert(lab && existsSync(lab), "CALLER_OWNED_CA_LAB_REQUIRED");
  assert.equal(readFileSync(join(lab, "LAB_OWNERSHIP"), "utf8"), "CA_WINDOWS_GENERATED_FIXTURES_ONLY_NO_UBUNTU\n");
  const root = mkdtempSync(join(resolve(lab), "ca-case-")), marker = randomUUID(); writeFileSync(join(root, "FIXTURE_OWNERSHIP"), marker, { flag: "wx" }); writeFileSync(join(root, "OUTSIDE_DB_SENTINEL"), "GENERATED_SENTINEL", { flag: "wx" });
  let gets = 0, other = 0; const server = createServer((request, response) => { if (request.method === "GET" && request.url === "/fixture/canary") gets++; else other++; if (gets > 4) { response.writeHead(429).end(); return; } response.writeHead(200).end("generated"); });
  await new Promise<void>((done, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", done); });
  const origin = "http://127.0.0.1:" + (server.address() as any).port, owned: ReturnType<typeof launch>[] = [], started = performance.now();
  const call = async (action: string, state?: State, extra: Message = {}, mode: string = name) => { const p = launch({ root, marker, origin, action, state, mode, ...extra }); owned.push(p); const message = await p.next; if (message.type === "result") await p.finish(); return { process: p, message }; };
  const timer = setTimeout(() => { for (const p of owned) void p.kill(); server.closeAllConnections(); }, 30000);
  try {
    const setup = await call("setup", undefined, { lanes: name === "PARTIAL_TWO_LANES" || name === "ENQUEUE_REPLY_LOST_TWO_LANES" ? 2 : 1 }), state = setup.message.state as State;
    const first = await call("trigger", state), firstGets = gets; let killed: any;
    const concurrent = name === "RESERVED_CONCURRENT" ? (await call("probe", state, {}, "normal")).message : undefined;
    const liveObservation = name === "LIVE_LAUNCH_RECONCILE" ? (await call("observe", state, {}, "normal")).message : undefined;
    const conflict = (await call("probe", state, { conflict: true }, "normal")).message;
    if (first.message.type === "cut") killed = await first.process.kill();
    const recovered = (await call("recover", state, { expireLease: true }, name.startsWith("FINALIZE_") ? name : "normal")).message;
    const wireAfterRecover = gets;
    const again = (await call("probe", state, {}, "normal")).message;
    const invalidToken = (await call("probe", state, { wrongToken: true }, "normal")).message;
    let nextDeployment: Message | undefined;
    if (name === "KILL_BEFORE_SCAN_LINK" || name === "PARTIAL_TWO_LANES" || name === "ENQUEUE_REPLY_LOST" || name === "ENQUEUE_REPLY_LOST_TWO_LANES" || name === "RESERVED_CONCURRENT" || name === "LIVE_LAUNCH_RECONCILE") nextDeployment = (await call("probe", state, { deploymentId: "next-generated-deployment" }, "normal")).message;
    fixtureRoot(root, marker); assert.equal(readFileSync(join(root, "OUTSIDE_DB_SENTINEL"), "utf8"), "GENERATED_SENTINEL");
    const truth = { name, platform: process.platform, node: process.version, mode: "REAL_CA_SQLITE_PROCESS_AND_HTTP_WITH_SYNTHETIC_PORTS", first: { type: first.message.type, error: first.message.error, result: first.message.result, truth: first.message.truth }, firstGets, concurrent, liveObservation, conflict, recovered, again, invalidToken, nextDeployment, wireAfterRecover, wireGetCount: gets, unexpectedRequests: other, killed, sentinelUnchanged: true, elapsedMs: performance.now() - started, retained: true, rootLabel: root.slice(root.lastIndexOf("ca-case-")), actualScanExecutionWorker: false, ubuntu: "NOT_TOUCHED" };
    const serialized = JSON.stringify(truth, null, 2); assert(serialized.length < 2097152); assert(!serialized.includes(state.token)); writeFileSync(join(root, "SCENARIO_TRUTH.json"), serialized + "\n", { flag: "wx" }); return truth;
  } finally { clearTimeout(timer); for (const p of owned) await p.kill(); await new Promise<void>(done => server.close(() => done())); }
}

export function assertInterruptionScenario(r: Record<string, any>) {
  assert(r.elapsedMs < 30000); assert.equal(r.unexpectedRequests, 0); assert(r.sentinelUnchanged);
  assert.equal(r.invalidToken.error, "CONTINUOUS_ASSURANCE_TRIGGER_REJECTED");
  if (r.name === "AFTER_ENQUEUE_DB_FAILURE") { assert.equal(r.first.error, "CA_FIXTURE_AFTER_ENQUEUE"); assert.equal(r.wireGetCount, 1, "REPLAY_CREATED_SECOND_NATIVE_GET_AFTER_ENQUEUE_COMMIT"); assert.equal(r.again.truth.scanCount, 1); assert.equal(r.again.truth.deployments.length, 1); }
  else if (["KILL_BEFORE_SCAN_LINK", "PARTIAL_TWO_LANES", "RESERVED_CONCURRENT", "ENQUEUE_REPLY_LOST", "LIVE_LAUNCH_RECONCILE", "ENQUEUE_REPLY_LOST_TWO_LANES"].includes(r.name)) {
    if (!r.name.startsWith("ENQUEUE_REPLY_LOST")) assert(r.killed?.ownedProcess); assert.equal(r.recovered.error, unknownError, "AMBIGUOUS_DEPLOYMENT_MUST_NOT_BE_QUIETLY_ACCEPTED"); assert.equal(r.again.error, unknownError);
    assert.equal(r.wireGetCount, r.name === "PARTIAL_TWO_LANES" ? 2 : r.name === "RESERVED_CONCURRENT" ? 0 : 1, "UNKNOWN_POLICY_MUST_NOT_LAUNCH_NEW_TRAFFIC");
    if (r.concurrent) assert.equal(r.concurrent.error, unknownError);
    if(r.name === "RESERVED_CONCURRENT")assert.equal(r.again.truth.unresolvedDeploymentReservations[0].outcome,"UNKNOWN");
    if(r.liveObservation){assert.equal(r.liveObservation.truth.runs[0].status,"LAUNCHING");assert.equal(r.liveObservation.truth.notifications.length,0);}
    if (r.name !== "RESERVED_CONCURRENT") { assert.equal(JSON.parse(r.recovered.truth.runs[0].safe_summary_json).launchOutcome, "UNKNOWN"); assert.notEqual(r.recovered.truth.runs[0].gate_status, "PASSED"); assert(r.recovered.truth.notifications.some((n: any) => n.safe_summary.includes("UNKNOWN"))); }
  } else if(r.name === "LEASE_LOST_BEFORE_SUBMIT"){assert.equal(r.wireGetCount,0);assert.equal(r.again.truth.scanCount,0);assert.equal(r.again.truth.runs[0].gate_status,"BLOCKED");assert.equal(r.again.truth.runs[0].status,"FAILED");}
  else { assert.equal(r.wireGetCount, 1); assert.equal(r.again.result.idempotentReplay, true); assert.equal(r.again.truth.scanCount, 1); assert.equal(r.again.result.runId, r.recovered.result.runId); }
  if (r.name.startsWith("FINALIZE_")) { assert.equal(r.again.truth.exports, 1, "CONCURRENT_FINALIZATION_DUPLICATED_EXPORT"); assert.deepEqual(r.again.truth.notifications, r.recovered.truth.notifications); assert.equal(r.again.truth.notifications.filter((n: any) => n.category === "REGRESSION").length, 1); assert.equal(r.again.truth.runs[0].gate_status, "REGRESSION"); }
  if (r.name === "CANCELLED") assert.equal(r.again.truth.runs[0].gate_status, "BLOCKED");
  assert.equal(r.conflict.error, "CONTINUOUS_ASSURANCE_DEPLOYMENT_REPLAY_MISMATCH");
  assert(!JSON.stringify(r).includes("CA_SYNTHETIC_SECRET_CANARY_DO_NOT_RETAIN"), "POST_ENQUEUE_ERROR_LEAKED_SYNTHETIC_SECRET");
}

if (process.argv.includes("--fixture-child")) {
  process.once("message", message => { void child(message as Message).catch(e => { process.send?.({ type: "error", message: e instanceof Error ? e.message : "FIXTURE_ERROR" }); process.exitCode = 1; process.disconnect?.(); }); });
} else if (process.argv.includes("--standalone-proof") || process.argv.includes("--supplemental-proof")) {
  let failed = 0; const cases = [];
  const selected=process.argv.includes("--supplemental-proof")?interruptionCases.filter(name=>name==="ENQUEUE_REPLY_LOST_TWO_LANES"):interruptionCases;
  for (const name of selected) { let truth: Record<string, any> | undefined; try { truth = await runInterruptionScenario(name); assertInterruptionScenario(truth); cases.push({ name, status: "PASS_NATIVE_SCENARIO_ASSERTIONS", truth }); } catch (e) { failed++; cases.push({ name, status: "FAIL", reason: e instanceof Error ? e.message : "UNKNOWN", truth }); } }
  const output = { kind: "STANDALONE_NATIVE_SCENARIO_PROOF_NOT_VITEST", passed: cases.length - failed, failed, cases, originalVitest: "BLOCKED_SAFE_RUNNER", originalTestsModified: false, filesystemCleanup: "NONE_ALL_RESIDUES_RETAINED" };
  const bytes = JSON.stringify(output) + "\n"; assert(bytes.length < 2097152); process.stdout.write(bytes); process.exitCode = failed ? 1 : 0;
}
