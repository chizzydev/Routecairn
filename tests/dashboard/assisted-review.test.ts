import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ArtifactRepository, PlanRepository, ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { FindingNormalizer } from "../../src/dashboard/findings/FindingNormalizer.js";
import { FindingCommandCenterService } from "../../src/dashboard/findings/FindingCommandCenterService.js";
import type { ReviewStatus } from "../../src/dashboard/types/DashboardTypes.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { FindingFingerprintService } from "../../src/dashboard/findings/FindingFingerprintService.js";
import { AssistedReviewService } from "../../src/dashboard/reviews/AssistedReviewService.js";
import { AssistedReviewModule } from "../../src/modules/assistedReview/AssistedReviewModule.js";
import { planAssistedReview } from "../../src/modules/assistedReview/AssistedReviewPlanner.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { ProofPackService } from "../../src/dashboard/proofPacks/ProofPackService.js";
import { ScanComparisonCoverageService } from "../../src/dashboard/comparisons/ScanComparisonCoverageService.js";
import { testPlan } from "../helpers/plan.js";
import { acceptedFinding, lifecycleResult, reportFixture, reviewManifest } from "../helpers/assisted-review.js";

describe("assisted review persistence and publication", () => {
  let directory: string;
  let database: DashboardDatabase;
  let paths: ReturnType<typeof resolveDashboardPaths>;
  let normalizer: FindingNormalizer;
  let service: AssistedReviewService;
  let scanId: string;

  beforeEach(async () => {
    directory = mkdtempSync(join(tmpdir(), "routecairn-review-db-")); paths = resolveDashboardPaths(directory);
    database = new DashboardDatabase(paths.databasePath); database.migrate();
    normalizer = new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath));
    service = new AssistedReviewService(database, paths); scanId = randomUUID();
    seedScan(scanId);
    const ctx = new ScanContext({ target: "https://app.test", scope: exampleScope, config: defaultConfig, outputDir: join(directory, "output"), plan: { ...testPlan("quick"), assistedReview: planAssistedReview(reviewManifest()) } });
    const finding = acceptedFinding(); const result = { ...lifecycleResult(), findings: [finding] }; ctx.state.recordModuleResult(result);
    const review = (await new AssistedReviewModule().run(ctx)).assistedReview!;
    normalizer.normalizeReport(scanId, { ...reportFixture([finding]), authenticationLifecycle: result.authenticationLifecycle, assistedReview: review });
  });
  afterEach(() => { database?.close(); if (directory) rmSync(directory, { recursive: true, force: true }); });

  function seedScan(id: string) {
    new ScanRepository(database).create({ id, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.test", safeTargetLabel: "disposable fixture", profile: "authenticated", evidenceLevel: "normal", safeConfigurationSummary: {} });
    new PlanRepository(database).create(id, { plannerVersion: "1", profile: "authenticated", modules: [{ id: "authentication-lifecycle" }], limits: {}, evidencePolicy: {}, browserPolicySummary: {}, scopeSummary: { allowedDomains: ["app.test"], disallowedPaths: [], includeSubdomains: false }, authenticationSummary: { mode: "public" }, controlledWorkflowSummary: {}, redactedPlan: {} });
    database.db.prepare("INSERT INTO scan_module_executions (id, scan_id, module_id, module_label, planned_order, status) VALUES (?, ?, 'authentication-lifecycle', 'Auth lifecycle', 1, 'COMPLETED')").run(randomUUID(), id);
  }

  function reviewFinding(newStatus: ReviewStatus = "CONFIRMED") {
    const command = new FindingCommandCenterService(database);
    const finding = command.list().findings[0]!;
    return command.review({ findingId: finding.id, newStatus, expectedVersion: finding.rowVersion, reason: "Reviewed the controlled fixture evidence.", principal: { userId: "local", login: "local", role: "OWNER", mode: "local" } });
  }

  it("preserves authorization coverage enums without disabling dashboard redaction", () => {
    const review = service.get(scanId);
    expect(review.report.coverageMatrix.AUTHORIZATION).toMatchObject({ selected: false, total: 0, outcomes: { NOT_ASSESSED: 0 } });
    expect(review.queue[0]).toMatchObject({ workflowId: "authentication-lifecycle", caseId: "logout", reviewState: "UNREVIEWED", evidenceIds: [expect.any(String)] });
    expect(review.gate.blockers).toContain("HUMAN_REVIEW_PENDING");
    expect(() => service.publish(scanId, "local")).toThrow("ASSISTED_REVIEW_NOT_READY");
    expect(database.db.prepare("SELECT COUNT(*) AS n FROM assisted_review_publications").get()).toEqual({ n: 0 });
  });

  it("carries the review through a real isolated worker and registers its coverage and evidence artifacts", async () => {
    const methods: string[] = [];
    const fixture = createServer((request, response) => { methods.push(request.method!); response.writeHead(request.url === "/" ? 200 : 404, { "content-type": "text/plain" }).end("disposable fixture"); });
    await new Promise<void>((resolve) => fixture.listen(0, "127.0.0.1", resolve));
    const execution = new ScanExecutionService(database, paths);
    try {
      const origin = `http://127.0.0.1:${(fixture.address() as AddressInfo).port}`;
      const scopeFile = join(directory, "worker-scope.json");
      writeFileSync(scopeFile, JSON.stringify({ ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 50, concurrency: 2 }));
      const jobId = await execution.enqueue({ target: origin, profile: "quick", scopeFile, includeModules: ["baseline"], assistedReview: reviewManifest(), authorizationDeclaration: "Owned disposable test fixture; GET only." });
      let row: { status: string; error_summary: string | null } | undefined;
      const deadline = Date.now() + 20_000;
      do {
        row = database.db.prepare("SELECT status, error_summary FROM scans WHERE id = ?").get(jobId) as typeof row;
        if (row && ["COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED"].includes(row.status)) break;
        await new Promise((resolve) => setTimeout(resolve, 50));
      } while (Date.now() < deadline);
      expect(row, row?.error_summary ?? undefined).toMatchObject({ status: "COMPLETED" });
      const review = service.get(jobId);
      expect(review.report.cases[0]!.assessmentOutcome).toBe("NOT_ASSESSED");
      expect(review.gate.blockers).toContain("AUTH_LIFECYCLE:NOT_ASSESSED");
      const artifacts = database.db.prepare("SELECT artifact_type FROM artifacts WHERE scan_id = ?").all(jobId);
      expect(artifacts).toEqual(expect.arrayContaining([{ artifact_type: "ASSISTED_OPERATOR_EVIDENCE" }, { artifact_type: "ASSISTED_COVERAGE_DRAFT" }]));
      expect(review.timeline).toEqual(expect.arrayContaining([expect.objectContaining({ eventType: "MODULE_COMPLETED", message: "Module assisted-review completed." })]));
      expect(methods.length).toBeGreaterThan(0);
      expect(methods.every((method) => method === "GET")).toBe(true);
    } finally {
      await execution.shutdown();
      await new Promise<void>((resolve, reject) => fixture.close((error) => error ? reject(error) : resolve()));
    }
  }, 30_000);

  it("enforces session and CSRF checks through the live dashboard API, then publishes after a human decision", async () => {
    const server = await startDashboardServer({ dataDir: directory, uiDistDir: join(directory, "ui") });
    try {
      const endpoint = `${server.url}/api/scans/${scanId}/assisted-review`;
      expect((await fetch(endpoint)).status).toBe(401);
      const boot = await fetch(`${server.url}/api/session/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: new URL(server.bootstrapUrl!).hash.replace("#bootstrap=", "") }) });
      const cookie = boot.headers.get("set-cookie")!.split(";")[0]!;
      const { csrfToken } = await boot.json() as { csrfToken: string };
      const headers = { cookie, origin: server.url, "content-type": "application/json", "x-csrf-token": csrfToken };
      expect((await fetch(`${endpoint}/publish`, { method: "POST", headers: { cookie, origin: server.url }, body: "{}" })).status).toBe(401);
      expect((await fetch(`${endpoint}/publish`, { method: "POST", headers, body: "{}" })).status).toBe(409);
      const queue = service.get(scanId).queue[0]!;
      const version = (database.db.prepare("SELECT row_version FROM findings WHERE id = ?").get(queue.findingId) as { row_version: number }).row_version;
      expect((await fetch(`${server.url}/api/findings/${queue.findingId}/review`, { method: "PATCH", headers, body: JSON.stringify({ newStatus: "CONFIRMED", expectedVersion: version, note: "Human checked the fixture evidence." }) })).status).toBe(200);
      const published = await fetch(`${endpoint}/publish`, { method: "POST", headers, body: "{}" });
      expect(published.status).toBe(201);
      const { artifactId } = await published.json() as { artifactId: string };
      const downloaded = await fetch(`${server.url}/api/artifacts/${artifactId}/download`, { headers: { cookie } });
      expect(downloaded.status).toBe(200);
      expect(await downloaded.json()).toMatchObject({ humanReviewEnforced: true, findings: [{ title: "Session remains valid" }] });
    } finally { await server.close(); }
  });

  it("publishes only human-confirmed remediation and authentic file hashes", () => {
    reviewFinding();
    const result = service.publish(scanId, "local");
    const artifact = new ArtifactRepository(database).get(result.artifactId)!;
    const bytes = readFileSync(artifact.path); const body = JSON.parse(bytes.toString("utf8"));
    expect(body.findings).toEqual([{ title: "Session remains valid", severity: "High", remediation: "Invalidate old sessions on logout." }]);
    expect(body.coverage.AUTHORIZATION.total).toBe(0);
    expect(body).toMatchObject({ operatorEvidenceIncluded: false, humanReviewEnforced: true });
    expect(bytes.toString()).not.toMatch(/bodyHash|evidenceRef|workflowId|session\?token/);
    expect(service.get(scanId).publications[0]!.contentSha256).toBe(createHash("sha256").update(bytes).digest("hex"));
    expect(service.get(scanId).timeline).toEqual(expect.arrayContaining([expect.objectContaining({ eventType: "ASSISTED_REVIEW_PUBLISHED" })]));
  });

  it.each(["FALSE_POSITIVE", "ACCEPTED_RISK"])("does not silently publish %s as a confirmed vulnerability", (status) => {
    reviewFinding(status as ReviewStatus);
    const result = service.publish(scanId, "local");
    const body = JSON.parse(readFileSync(new ArtifactRepository(database).get(result.artifactId)!.path, "utf8"));
    expect(body.findings).toEqual([]);
    expect(body.acceptedRiskCount).toBe(status === "ACCEPTED_RISK" ? 1 : 0);
  });

  it("re-evaluates review state and refuses unresolved cleanup even after confirmation", () => {
    reviewFinding();
    expect(service.get(scanId).gate.state).toBe("READY");
    database.db.prepare("UPDATE findings SET human_review_status = 'IN_REVIEW'").run();
    expect(() => service.publish(scanId, "local")).toThrow(/HUMAN_REVIEW_PENDING/);
    reviewFinding();
    database.db.prepare("UPDATE assisted_case_results SET cleanup_unresolved = 1 WHERE scan_id = ?").run(scanId);
    expect(() => service.publish(scanId, "local")).toThrow(/CLEANUP_UNRESOLVED/);
  });

  it("does not inherit occurrence confirmation from an older scan", () => {
    reviewFinding();
    const nextScan = randomUUID(); seedScan(nextScan);
    normalizer.normalizeReport(nextScan, { ...reportFixture([acceptedFinding()]), authenticationLifecycle: lifecycleResult().authenticationLifecycle });
    const findingId = service.get(scanId).queue[0]!.findingId;
    expect(() => new ProofPackService(database, paths).generate("Fresh proof", undefined, [findingId])).toThrow(/occurrence requires human confirmation/);
    const command = new FindingCommandCenterService(database);
    expect(command.refreshProofReadiness(findingId)).toBe("MISSING_REVIEW");
    expect(command.list({ scanId: nextScan }).total).toBe(1);
    expect(command.list({ scanId: randomUUID() }).total).toBe(0);
  });

  it("fails closed if retained evidence is missing", () => {
    reviewFinding();
    database.db.prepare("DELETE FROM evidence_records").run();
    expect(service.get(scanId).gate.blockers).toContain("EVIDENCE_LINKS_INCOMPLETE");
  });

  it("links real proof packs to the exact selected occurrence and excludes unrelated mutation proof", () => {
    reviewFinding();
    const otherScan = randomUUID(); seedScan(otherScan);
    database.db.prepare("INSERT INTO scan_workflow_case_executions (id,scan_id,workflow_id,module_id,safe_case_alias,safe_case_fingerprint,execution_state,request_transmitted,evidence_strength,safe_semantics_json,safe_result_json,created_at) VALUES (?,?,'privilege-mutation','privilege-mutation-testing','UNRELATED_CUSTOMER_PRIVATE_CASE','hash','COMPLETED',1,'PROOF','{}','{}',?)").run(randomUUID(), otherScan, new Date().toISOString());
    const findingId = service.get(scanId).queue[0]!.findingId;
    const packId = new ProofPackService(database, paths).generate("Review proof", undefined, [findingId]);
    expect(service.get(scanId).queue[0]!.proofPackIds).toEqual([packId]);
    const artifacts = database.db.prepare("SELECT canonical_path AS path, scoped_or_full_safe_hash AS hash FROM artifacts WHERE proof_pack_id = ?").all(packId) as Array<{ path: string; hash: string }>;
    for (const artifact of artifacts) {
      const bytes = readFileSync(artifact.path);
      expect(bytes.toString()).not.toContain("UNRELATED_CUSTOMER_PRIVATE_CASE");
      expect(bytes.toString()).toContain("authentication-lifecycle");
      expect(bytes.toString()).toContain("ROLLBACK_VERIFIED");
      expect(artifact.hash).toBe(createHash("sha256").update(bytes).digest("hex"));
    }
  });

  it("requires proven same-contract clean retests, not just module completion", () => {
    const nextScan = randomUUID(); seedScan(nextScan);
    const occurrence = database.db.prepare("SELECT * FROM finding_occurrences WHERE scan_id = ?").get(scanId) as Parameters<ScanComparisonCoverageService["evaluateFinding"]>[2];
    const coverage = new ScanComparisonCoverageService(database);
    expect(coverage.evaluateFinding(scanId, nextScan, occurrence).reasonCode).toBe("CASE_MISSING");
    normalizer.normalizeReport(nextScan, { ...reportFixture(), authenticationLifecycle: lifecycleResult("PASS").authenticationLifecycle });
    expect(coverage.evaluateFinding(scanId, nextScan, occurrence).disposition).toBe("ADEQUATE");
    database.db.prepare("UPDATE assisted_case_results SET assessment_outcome = 'INCONCLUSIVE' WHERE scan_id = ?").run(nextScan);
    expect(coverage.evaluateFinding(scanId, nextScan, occurrence).reasonCode).toBe("SECURITY_PROOF_INCOMPLETE");
    database.db.prepare("UPDATE assisted_case_results SET assessment_outcome = 'PROVEN', cleanup_unresolved = 1 WHERE scan_id = ?").run(nextScan);
    expect(coverage.evaluateFinding(scanId, nextScan, occurrence).reasonCode).toBe("CLEANUP_NOT_VERIFIED");
    database.db.prepare("UPDATE assisted_case_results SET comparison_fingerprint = 'changed' WHERE scan_id = ?").run(nextScan);
    expect(coverage.evaluateFinding(scanId, nextScan, occurrence).reasonCode).toBe("CASE_CHANGED");
  });
});
