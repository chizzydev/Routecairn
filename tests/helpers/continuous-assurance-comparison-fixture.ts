import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { registerHooks } from "node:module";
import type { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";

// Retain-only native fixture. No original Vitest setup, workers, network, or fs deletion.
// Completed scan/case rows are SEEDED_NOT_EXECUTED, never a claim of target execution.
export const comparisonCases = ["C04", "C01", "ANALYZING", "PARTIAL", "INCOMPATIBLE", "EMPTY_SUMMARY", "INVALID_JSON", "NULL_SUMMARY", "STRING_COUNT", "NEGATIVE_COUNT", "FRACTIONAL_COUNT", "UNSAFE_COUNT", "MISSING_COVERAGE", "INCOMPLETE_MODULE", "CHANGED_IDENTITY", "REGRESSION", "PENDING", "STALE", "SUM_OVERFLOW", "SOURCE_PARTIAL", "INCOMPLETE_WORKFLOW", "INCOMPLETE_CASE", "PORT_FAILED", "PORT_PAIR_MISMATCH", "PORT_INVALID_SUMMARY", "API_WORKFLOW", "FRESH_COMPARISON", "OUTER_ROLLBACK"] as const;
export type ComparisonCase = typeof comparisonCases[number];
const origin = "https://ca-comparison.example.test";
const fingerprint = "c".repeat(64);
const sha = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

// Node's native TypeScript transform plus a source-only .js -> .ts resolver avoids
// tsx/esbuild disk caches entirely. Never substitute dist or intercept existing JS.
if (isMain) registerHooks({ resolve(specifier, context, nextResolve) {
  try { return nextResolve(specifier, context); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ERR_MODULE_NOT_FOUND" || !specifier.endsWith(".js") || !context.parentURL?.startsWith(pathToFileURL(sourceRoot).href + "/") || !specifier.startsWith(".")) throw error;
    const path = fileURLToPath(new URL(specifier.slice(0, -3) + ".ts", context.parentURL));
    if (!path.startsWith(sourceRoot + "\\") && !path.startsWith(sourceRoot + "/")) throw error;
    if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw error;
    return nextResolve(pathToFileURL(path).href, context);
  }
} });

function ordinaryDirectory(path: string): void {
  for (let p = resolve(path);; p = dirname(p)) {
    const s = lstatSync(p);
    assert(s.isDirectory() && !s.isSymbolicLink(), "FIXTURE_DIRECTORY_ALIAS");
    assert.equal(realpathSync.native(p).toLowerCase(), p.toLowerCase(), "FIXTURE_REALPATH");
    if (p === dirname(p)) break;
  }
}

function identity(path: string) {
  const s = lstatSync(path, { bigint: true });
  assert(!s.isSymbolicLink());
  if (s.isFile()) assert.equal(s.nlink, 1n);
  return { dev: String(s.dev), ino: String(s.ino), nlink: String(s.nlink), size: String(s.size) };
}

function inventory(root: string, base = ""): Array<Record<string, unknown>> {
  const rows: Array<Record<string, unknown>> = [];
  for (const name of readdirSync(join(root, base)).sort()) {
    const path = join(root, base, name), relative = base ? base + "/" + name : name, s = lstatSync(path);
    assert(!s.isSymbolicLink(), "FIXTURE_ALIAS");
    if (s.isDirectory()) rows.push(...inventory(root, relative));
    else { assert(s.isFile() && s.nlink === 1 && s.size <= 32 * 1024 * 1024, "FIXTURE_FILE_BOUND"); rows.push({ path: relative, ...identity(path), sha256: sha(readFileSync(path)) }); }
    assert(rows.length <= 512, "FIXTURE_INVENTORY_BOUND");
  }
  return rows;
}

export async function runComparisonCase(scenario: ComparisonCase, parent: string): Promise<Record<string, any>> {
  assert(comparisonCases.includes(scenario));
  parent = resolve(parent); ordinaryDirectory(parent);
  assert(existsSync(join(parent, "EVIDENCE_OWNERSHIP")), "CALLER_OWNERSHIP_REQUIRED");
  const started = performance.now(), root = join(parent, scenario + "_" + randomUUID());
  assert(!existsSync(root)); mkdirSync(root); ordinaryDirectory(root);
  const rootIdentity = identity(root), sentinel = join(root, "OUTSIDE_DATABASE_SENTINEL");
  writeFileSync(sentinel, "RETAINED_PRIVATE_FIXTURE\n", { flag: "wx" });
  const sentinelIdentity = identity(sentinel), sentinelHash = sha(readFileSync(sentinel));
  for (const dir of ["dashboard", "journals", "journals/primary", "temp", "evidence"]) mkdirSync(join(root, dir));
  const databasePath = join(root, "dashboard", "ca-comparison.sqlite");
  assert(!existsSync(databasePath));
  const receipt: Record<string, any> = { scenario, root, databasePath, fixtureProvenance: "SEEDED_NOT_EXECUTED", wholeScenarioLimitMs: 30000, targetGets: 0, outboundConnections: 0, trafficBasis: "NO_NETWORK_API_OR_WORKER_USED_NOT_PACKET_CAPTURE", filesystemAppDeletion: "NONE", nativeSqliteLifecycle: "NORMAL_NATIVE_JOURNAL_WAL_SHM_IN_EXCLUSIVELY_OWNED_NEW_FIXTURE", exportKind: "EXPORT_ELIGIBILITY_OBSERVED_NOT_REAL_ENCRYPTED_DELIVERY", rootIdentityBefore: rootIdentity };
  const write = (name: string, value: unknown) => writeFileSync(join(root, "evidence", name), JSON.stringify(value, null, 2) + "\n", { flag: "wx" });
  let database: DashboardDatabase | undefined, service: { shutdown(): void } | undefined, prerequisites = false, constructorAttempted = false;
  try {
    const [{ DashboardDatabase }, { ScanRepository, PlanRepository, TargetRepository }, { ScanComparisonService }, { ContinuousAssuranceService }, { resolveDashboardPaths }] = await Promise.all([
      import("../../src/dashboard/db/DashboardDatabase.js"), import("../../src/dashboard/db/DashboardRepositories.js"), import("../../src/dashboard/comparisons/ScanComparisonService.js"), import("../../src/dashboard/execution/ContinuousAssuranceService.js"), import("../../src/dashboard/services/DashboardPaths.js")
    ]);
    const paths = { ...resolveDashboardPaths(join(root, "dashboard")), databasePath, mutationJournalDir: join(root, "journals", "primary"), mutationJournalRegistryPath: join(root, "journals", "primary", "mutation-journals.json") };
    assert.equal(dirname(paths.mutationJournalDir), join(root, "journals"));
    write("preregistered-paths.json", { paths, legacyRegistry: join(root, "journals", "controlled-mutation-journals.json"), allowedNativeAuxiliaryPaths: [databasePath + "-journal", databasePath + "-wal", databasePath + "-shm"], immutableSentinel: sentinel });
    constructorAttempted = true; database = new DashboardDatabase(databasePath); database.migrate();
    const db = database.db, now = new Date().toISOString(), adapterId = randomUUID(), adapterVersion = randomUUID(), baseline = randomUUID(), current = randomUUID();
    const targetId = new TargetRepository(database).create({ displayName: "Synthetic comparison fixture", baseOrigin: origin, tags: [], classification: "LOCAL", authorizationType: "OWNED", authorizationSummary: "Disposable synthetic fixture; no traffic", productionEnabled: false, approvedScope: { program: "fixture", allowedDomains: ["ca-comparison.example.test"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/ComparisonFixture" } });
    db.prepare("INSERT INTO provider_adapters (id,name,target_id,provider,engine_id,enabled,active_version_id,created_by,created_at,updated_at) VALUES (?,?,?,'GENERIC_HTTP','object-pair-testing',1,?,'fixture',?,?)").run(adapterId, "SEEDED_NOT_EXECUTED", targetId, adapterVersion, now, now);
    db.prepare("INSERT INTO provider_adapter_versions (id,profile_id,revision,status,adapter_digest,target_row_version,credential_binding_json,algorithm,key_version,nonce,ciphertext,auth_tag,created_by,created_at,reviewed_by,reviewed_at) VALUES (?,?,1,'REVIEWED',?,1,'[]','aes-256-gcm','fixture','fixture','fixture','fixture','fixture',?,'fixture',?)").run(adapterVersion, adapterId, "a".repeat(64), now, now);
    for (const [index, scanId] of [baseline, current].entries()) {
      new ScanRepository(database).create({ id: scanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: origin, safeTargetLabel: "SEEDED_NOT_EXECUTED", profile: "full", evidenceLevel: "normal", safeConfigurationSummary: { fixtureProvenance: "SEEDED_NOT_EXECUTED" }, targetId });
      new PlanRepository(database).create(scanId, { plannerVersion: "1", profile: "full", modules: [{ id: "object-pair-testing" }], limits: { maxRequests: 4 }, evidencePolicy: { level: "normal" }, browserPolicySummary: {}, scopeSummary: { allowedDomains: ["ca-comparison.example.test"], disallowedPaths: [], includeSubdomains: false }, authenticationSummary: { mode: "public" }, controlledWorkflowSummary: {}, redactedPlan: { profile: "full", modules: ["object-pair-testing"] } });
      const time = new Date(Date.now() - (2 - index) * 60000).toISOString();
      db.prepare("UPDATE scans SET created_at=?,completed_at=? WHERE id=?").run(time, time, scanId);
      db.prepare("INSERT INTO scan_module_executions (id,scan_id,module_id,module_label,planned_order,status) VALUES (?,?,'object-pair-testing','SEEDED_NOT_EXECUTED',1,'COMPLETED')").run(randomUUID(), scanId);
      db.prepare("INSERT INTO scan_workflow_case_executions (id,scan_id,workflow_id,module_id,safe_case_alias,safe_case_fingerprint,execution_state,request_transmitted,matched_expectation,evidence_strength,safe_semantics_json,safe_result_json,created_at) VALUES (?,?,'object-pair','object-pair-testing','synthetic-exact-case',?,'COMPLETED',1,1,'STRONG',?, ?,?)").run(randomUUID(), scanId, fingerprint, JSON.stringify({ fixtureProvenance: "SEEDED_NOT_EXECUTED" }), JSON.stringify({ fixtureProvenance: "SEEDED_NOT_EXECUTED" }), time);
    }
    db.prepare("INSERT INTO scan_provider_adapter_bindings (scan_id,profile_id,version_id,adapter_digest,created_at) VALUES (?,?,?,?,?)").run(baseline, adapterId, adapterVersion, "a".repeat(64), now);
    const comparer = new ScanComparisonService(database);
    let exports = 0, enqueues = 0;
    const request = { target: origin, targetId, profile: "full" as const };
    const execution = { preview: async () => ({ limits: { maxScanDurationMs: 1000, maxRequests: 4, cleanupReservedRequests: 0 }, credentialReadiness: { blockers: [], warnings: [], profiles: [] } }), enqueue: async () => { enqueues++; return current; } };
    const adapters = { materialize: () => ({ target: { id: targetId, rowVersion: 1 }, input: { targetId }, binding: { profileId: adapterId, versionId: adapterVersion, adapterDigest: "a".repeat(64) } }), materializeScanRequest: () => request, assertExecutionBinding: async () => undefined, bindScan: (scanId: string) => db.prepare("INSERT INTO scan_provider_adapter_bindings (scan_id,profile_id,version_id,adapter_digest,created_at) VALUES (?,?,?,?,?)").run(scanId, adapterId, adapterVersion, "a".repeat(64), now) };
    const comparisonPort = scenario.startsWith("PORT_") ? { compare: (older: string, newer: string) => {
      const result = comparer.compare(older, newer);
      receipt.portFault = { kind: scenario, basis: "REAL_COMPARER_WITH_EXPLICIT_CONSUMER_BOUNDARY_FAULT_NOT_NATIVE_CACHE_CORRUPTION" };
      if (scenario === "PORT_FAILED") return { ...result, state: "FAILED" as const };
      if (scenario === "PORT_PAIR_MISMATCH") return { ...result, newScanId: baseline };
      return { ...result, summary: {} as typeof result.summary };
    } } : comparer;
    const assurance = new ContinuousAssuranceService(database, paths, execution as any, adapters, comparisonPort, { available: () => true, createExport: () => { exports++; return { fixture: true, kind: receipt.exportKind }; } }, { startTimers: false }); service = assurance;
    const input = { schemaVersion: 1, name: "Native comparison fixture", description: "SEEDED_NOT_EXECUTED", targetId, authorization: { proofReference: "fixture://owned/synthetic", proofDigest: "b".repeat(64), validFrom: new Date(Date.now() - 60000).toISOString(), expiresAt: new Date(Date.now() + 3600000).toISOString() }, triggers: { scheduleEnabled: false, intervalMinutes: 60, deploymentEnabled: true, quietWhenHealthy: true }, adapterProfileIds: [adapterId], baselines: [{ adapterProfileId: adapterId, scanId: baseline }], requiredCases: [{ adapterProfileId: adapterId, workflowId: "object-pair", caseFingerprint: fingerprint }], gates: { failOnRegression: true, failOnNewFinding: true, failOnOpenDrift: true, requireExactCases: true, requireCleanupResolved: true }, evidence: { retentionDays: 90, autoExportOn: ["REGRESSION", "FAILED", "CLEANUP_REQUIRED", "APPROVAL_REQUIRED"], preserveFailures: true, preserveCleanupEvidence: true } };
    if (scenario === "API_WORKFLOW") {
      db.prepare("UPDATE scan_workflow_case_executions SET workflow_id='api-graphql-authorization',module_id='api-graphql-authorization'").run();
      db.prepare("UPDATE scan_module_executions SET module_id='api-graphql-authorization'").run();
      // Both plans and observed module/case rows describe the additional native workflow.
      for (const scanId of [baseline, current]) db.prepare("UPDATE scan_plan_snapshots SET modules_json=?,redacted_plan_json=? WHERE scan_id=?").run(JSON.stringify([{ id: "api-graphql-authorization" }]), JSON.stringify({ profile: "full", modules: ["api-graphql-authorization"] }), scanId);
      input.requiredCases[0]!.workflowId = "api-graphql-authorization";
    }
    const preview = await assurance.preview(input); assert.deepEqual(preview.blockers, []);
    const created = await assurance.create(input, "fixture") as any;
    await assurance.review(created.policy.id, created.policy.pendingVersionId, preview.policyDigest, "fixture");
    if (scenario === "REGRESSION") {
      const [{ FindingNormalizer }, { FindingFingerprintService }] = await Promise.all([import("../../src/dashboard/findings/FindingNormalizer.js"), import("../../src/dashboard/findings/FindingFingerprintService.js")]);
      new FindingNormalizer(db, new FindingFingerprintService(paths.fingerprintKeyPath)).normalizeReport(current, { target: origin, findings: [{ id: "fixture", title: "Synthetic new finding", impact: "Synthetic fixture", recommendation: "Synthetic fixture", manualTestingSuggestions: [], tags: [], riskScore: 0, falsePositiveStatus: "likely-valid", timestamp: now, type: "Object Authorization Issue", severity: "High", confidence: "High", url: origin + "/fixture", method: "GET", sourceModule: "object-pair-testing", evidence: { url: origin + "/fixture", method: "GET", source: "fixture:SEEDED_NOT_EXECUTED" } }] });
    }
    if (scenario === "C04") {
      const trigger = `CREATE TRIGGER ca_fixture_fail_completion BEFORE UPDATE OF state ON scan_comparisons WHEN NEW.older_scan_id='${baseline}' AND NEW.newer_scan_id='${current}' AND NEW.state='COMPLETED' BEGIN SELECT RAISE(ABORT,'CA_FIXTURE_COMPLETION_ABORT'); END;`;
      write("trigger-before.json", db.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger'").all());
      write("trigger-sql.json", { create: trigger, drop: "DROP TRIGGER ca_fixture_fail_completion" }); db.exec(trigger);
      assert.throws(() => comparer.compare(baseline, current), /CA_FIXTURE_COMPLETION_ABORT/);
      const failed = db.prepare("SELECT * FROM scan_comparisons WHERE older_scan_id=? AND newer_scan_id=?").get(baseline, current) as any;
      assert.equal(failed.state, "FAILED"); assert.equal(failed.summary_json, "{}"); receipt.failedComparison = failed;
      write("actual-failed-comparison.json", failed); write("trigger-installed.json", db.prepare("SELECT name,sql FROM sqlite_master WHERE name='ca_fixture_fail_completion'").all());
      db.exec("DROP TRIGGER ca_fixture_fail_completion"); write("trigger-after.json", db.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger'").all());
    } else if (scenario !== "FRESH_COMPARISON" && scenario !== "OUTER_ROLLBACK") {
      const good = comparer.compare(baseline, current);
      assert.equal(good.state, "COMPLETED"); assert.equal(good.compatible, true); assert.equal(good.summary.incomparable, 0);
      assert.equal(good.coverage.cases.length, 1); assert.equal(good.coverage.cases[0]?.state, "CASE_MATCHED_EXECUTED");
      receipt.comparisonControl = good;
      const patchSummary = (value: unknown) => db.prepare("UPDATE scan_comparisons SET summary_json=? WHERE id=?").run(JSON.stringify(value), good.comparisonId);
      if (scenario === "ANALYZING") db.prepare("UPDATE scan_comparisons SET state='ANALYZING',compatibility_state='ANALYZING',summary_json='{}',completed_at=NULL WHERE id=?").run(good.comparisonId);
      if (scenario === "PENDING" || scenario === "STALE") db.prepare("UPDATE scan_comparisons SET state=? WHERE id=?").run(scenario, good.comparisonId);
      if (scenario === "PARTIAL") db.prepare("UPDATE scan_comparisons SET state='PARTIAL' WHERE id=?").run(good.comparisonId);
      if (scenario === "INCOMPATIBLE") db.prepare("UPDATE scan_comparisons SET compatibility_state='WEAK_COMPATIBILITY' WHERE id=?").run(good.comparisonId);
      if (scenario === "EMPTY_SUMMARY") patchSummary({});
      if (scenario === "INVALID_JSON") db.prepare("UPDATE scan_comparisons SET summary_json='not-json' WHERE id=?").run(good.comparisonId);
      if (scenario === "NULL_SUMMARY") patchSummary(null);
      if (scenario === "STRING_COUNT") patchSummary({ ...good.summary, new: "0" });
      if (scenario === "NEGATIVE_COUNT") patchSummary({ ...good.summary, new: -1 });
      if (scenario === "FRACTIONAL_COUNT") patchSummary({ ...good.summary, new: 0.1 });
      if (scenario === "UNSAFE_COUNT") patchSummary({ ...good.summary, new: Number.MAX_SAFE_INTEGER + 1 });
      if (scenario === "SUM_OVERFLOW") patchSummary({ ...good.summary, regressions: Number.MAX_SAFE_INTEGER, severityIncreases: 1 });
      if (scenario === "SOURCE_PARTIAL") db.prepare("UPDATE scan_comparisons SET source_quality_newer='NATIVE_PARTIAL' WHERE id=?").run(good.comparisonId);
      if (scenario === "INCOMPLETE_WORKFLOW") db.prepare("UPDATE scan_comparison_workflow_coverage SET comparable=0 WHERE comparison_id=? AND older_configured=1").run(good.comparisonId);
      if (scenario === "INCOMPLETE_CASE") db.prepare("UPDATE scan_comparison_case_coverage SET state='CASE_MISSING',compatibility='NOT_RETESTED' WHERE comparison_id=?").run(good.comparisonId);
      if (scenario === "MISSING_COVERAGE") db.prepare("UPDATE scan_comparisons SET coverage_summary_json='{}' WHERE id=?").run(good.comparisonId);
      if (scenario === "INCOMPLETE_MODULE") db.prepare("UPDATE scan_comparison_module_coverage SET comparable=0 WHERE comparison_id=?").run(good.comparisonId);
      if (scenario === "CHANGED_IDENTITY") db.prepare("UPDATE scan_comparisons SET coverage_summary_json=? WHERE id=?").run(JSON.stringify({ ...JSON.parse((db.prepare("SELECT coverage_summary_json FROM scan_comparisons WHERE id=?").get(good.comparisonId) as any).coverage_summary_json), identityState: "CHANGED" }), good.comparisonId);
    }
    prerequisites = true;
    const run = await assurance.runNow(created.policy.id, "fixture") as any;
    if (scenario === "OUTER_ROLLBACK") {
      assert.equal((db.prepare("SELECT COUNT(*) count FROM scan_comparisons").get() as any).count, 0);
      const sql = `CREATE TRIGGER ca_fixture_abort_finalization BEFORE UPDATE OF status ON continuous_assurance_runs WHEN NEW.id='${run.id}' AND NEW.status='COMPLETED' BEGIN SELECT RAISE(ABORT,'CA_FIXTURE_OUTER_ABORT'); END;`;
      write("outer-trigger-sql.json", { create: sql, drop: "DROP TRIGGER ca_fixture_abort_finalization" }); db.exec(sql);
      await assert.rejects(assurance.reconcileNow(), /CA_FIXTURE_OUTER_ABORT/);
      db.exec("DROP TRIGGER ca_fixture_abort_finalization");
    } else await assurance.reconcileNow();
    const first = db.prepare("SELECT * FROM continuous_assurance_runs WHERE id=?").get(run.id) as any;
    const notices = db.prepare("SELECT * FROM continuous_assurance_notifications WHERE run_id=? ORDER BY category").all(run.id);
    const comparisons = db.prepare("SELECT * FROM scan_comparisons WHERE older_scan_id=? AND newer_scan_id=?").all(baseline, current);
    const counts = Object.fromEntries(["scan_comparison_findings", "scan_comparison_module_coverage", "scan_comparison_workflow_coverage", "scan_comparison_case_coverage"].map(table => [table, db.prepare(`SELECT COUNT(*) count FROM ${table}`).get()]));
    if (scenario !== "OUTER_ROLLBACK") await assurance.reconcileNow();
    assert.deepEqual(db.prepare("SELECT * FROM continuous_assurance_runs WHERE id=?").get(run.id), first, "TERMINAL_RECONCILIATION_MUST_BE_IDEMPOTENT");
    assert.deepEqual(db.prepare("SELECT * FROM continuous_assurance_notifications WHERE run_id=? ORDER BY category").all(run.id), notices, "NO_DUPLICATE_NOTIFICATIONS");
    receipt.truth = { run: first, comparisons, notices, coverageCounts: counts, scans: db.prepare("SELECT id,organization_id,target_id,status FROM scans ORDER BY id").all(), exactCases: db.prepare("SELECT scan_id,workflow_id,safe_case_fingerprint,execution_state,request_transmitted,matched_expectation FROM scan_workflow_case_executions").all(), foreignKeyCheck: db.pragma("foreign_key_check"), integrityCheck: db.pragma("integrity_check"), enqueues, exports, sourceStatus: "SEEDED_NOT_EXECUTED" };
    write("native-sqlite-truth.json", receipt.truth);
    const summary = JSON.parse(first.safe_summary_json);
    if (scenario === "OUTER_ROLLBACK") { assert.equal(first.status, "RUNNING"); assert.equal(first.gate_status, "PENDING"); assert.equal(comparisons.length, 0); assert.equal(notices.length, 0); assert.equal(exports, 0); for (const value of Object.values(counts)) assert.equal((value as any).count, 0); }
    else if (scenario === "C01" || scenario === "API_WORKFLOW" || scenario === "FRESH_COMPARISON") { assert.equal(first.gate_status, "PASSED"); assert.equal(summary.quiet, true); assert.equal(first.notification_required, 0); assert.equal(exports, 0); }
    else if (scenario === "REGRESSION") { assert.equal(first.gate_status, "REGRESSION"); assert.equal(summary.newFindings, 1); assert.equal(summary.quiet, false); assert.equal(exports, 1); }
    else { assert.equal(first.gate_status, "INCONCLUSIVE", "UNUSABLE_COMPARISON_MUST_BE_EXPLICITLY_INCONCLUSIVE"); assert.equal(summary.quiet, false, "UNUSABLE_COMPARISON_MUST_NOT_BE_QUIET"); assert.equal(first.notification_required, 1); assert.equal(exports, 1); assert.equal(summary.comparisonTotalsComplete, false); assert.equal(summary.comparisonFailures.length, 1); }
    if (scenario !== "OUTER_ROLLBACK") {
      for (const field of ["regressions", "newFindings", "incomparable", "notRetested"]) assert(Number.isSafeInteger(summary[field]) && summary[field] >= 0, "INVALID_AGGREGATE:" + field);
      assert.equal(comparisons.length, 1, "NO_AUTOMATIC_RECOMPUTATION_OR_EVIDENCE_REPLACEMENT");
    }
    assert.equal(enqueues, 1); assert.deepEqual(receipt.truth.foreignKeyCheck, []); assert.deepEqual(receipt.truth.integrityCheck, [{ integrity_check: "ok" }]);
    receipt.status = "PASS";
  } catch (error) {
    receipt.status = prerequisites && error instanceof assert.AssertionError ? "RED" : "BLOCKED";
    receipt.error = { name: error instanceof Error ? error.name : "Error", message: error instanceof Error ? error.message : String(error), stack: error instanceof Error ? error.stack : undefined };
  } finally {
    try {
      service?.shutdown();
      receipt.beforeClose = inventory(root);
      if (existsSync(databasePath)) receipt.mainIdentityBeforeClose = identity(databasePath);
    } catch (error) { receipt.status = "OUTCOME_UNKNOWN"; receipt.preCloseEvidenceError = String(error); }
    finally {
      try {
        database?.close(); receipt.nativeHandlesClosed = Boolean(database) || !constructorAttempted;
        if (constructorAttempted && !database) { receipt.status = "OUTCOME_UNKNOWN"; receipt.constructorHandleStatus = "CONSTRUCTOR_THROW_NO_EXPOSED_HANDLE"; }
      } catch (error) { receipt.status = "OUTCOME_UNKNOWN"; receipt.closeError = String(error); }
    }
    receipt.beforeClose ??= [];
    receipt.afterClose = inventory(root);
    receipt.retainedRoot = existsSync(root); receipt.retainedMainDb = existsSync(databasePath);
    if (receipt.retainedMainDb) { receipt.mainIdentityAfterClose = identity(databasePath); if (receipt.mainIdentityBeforeClose) for (const key of ["dev", "ino", "nlink"]) assert.equal(receipt.mainIdentityAfterClose[key], receipt.mainIdentityBeforeClose[key]); }
    for (const key of ["dev", "ino", "nlink"]) { assert.equal(identity(root)[key as keyof typeof rootIdentity], rootIdentity[key as keyof typeof rootIdentity]); assert.equal(identity(sentinel)[key as keyof typeof sentinelIdentity], sentinelIdentity[key as keyof typeof sentinelIdentity]); }
    assert.equal(sha(readFileSync(sentinel)), sentinelHash);
    receipt.nativeAuxiliaryPresence = Object.fromEntries(["-journal", "-wal", "-shm"].map(suffix => [suffix, { beforeClose: receipt.beforeClose.some((v: any) => v.path === "dashboard/ca-comparison.sqlite" + suffix), afterClose: receipt.afterClose.some((v: any) => v.path === "dashboard/ca-comparison.sqlite" + suffix) }]));
    receipt.lifecycleObservationLimit = "BEFORE_AFTER_INVENTORY_NOT_COMPLETE_FILESYSTEM_EVENT_TRACE";
    receipt.elapsedMs = performance.now() - started;
    if (receipt.elapsedMs > 30000) { receipt.status = "OUTCOME_UNKNOWN"; receipt.deadlineExceeded = true; }
    write("receipt.json", receipt);
  }
  return receipt;
}

if (isMain) {
  const scenario = process.argv[2] as ComparisonCase, parent = process.argv[3];
  if (!parent) throw new Error("Explicit private caller-owned parent required");
  const receipt = await runComparisonCase(scenario, parent);
  console.log(JSON.stringify(receipt));
  process.exitCode = receipt.status === "PASS" ? 0 : receipt.status === "RED" ? 1 : 2;
}
