import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Finding } from "../../core/findings/Finding.js";
import { DashboardDatabase, nowIso } from "../db/DashboardDatabase.js";
import { ArtifactRepository } from "../db/DashboardRepositories.js";
import { FindingFingerprintService } from "../findings/FindingFingerprintService.js";
import { FindingNormalizer } from "../findings/FindingNormalizer.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import { createSyntheticDashboardScreenshot } from "./SyntheticScreenshot.js";

const reviewStates = ["UNREVIEWED", "IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE", "RESOLVED", "REOPENED"] as const;
const remediationStates = ["OPEN", "ASSIGNED", "FIX_IN_PROGRESS", "FIXED_PENDING_RETEST", "FIXED_VERIFIED", "WONT_FIX"] as const;
const evidenceTypes = ["HTTP", "object-pair", "field-exposure", "authorization-matrix", "equivalent-route", "collection-authorization", "bulk-authorization", "file-download", "identity-verification", "browser-screenshot"];

export class DemoSeedService {
  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths) {}

  public seed(input: { ownerUserId?: string; analystUserId?: string; environment?: string }): { projectIds: string[]; targetIds: string[]; findingCount: number; screenshotArtifactId: string } {
    if ((input.environment ?? process.env.NODE_ENV) === "production") throw new Error("Demo seeding is disabled in production mode.");
    const marker = this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key = 'demo_seed_v1'").get();
    if (marker) throw new Error("Development demo data has already been seeded for this installation.");
    const now = nowIso();
    const projectIds = [randomUUID(), randomUUID()];
    const targetIds = [randomUUID(), randomUUID(), randomUUID()];
    this.database.transaction(() => {
      this.database.db.prepare("INSERT INTO projects (id, name, description, tags_json, default_profile, default_scope_json, created_by, created_at, updated_at) VALUES (?, ?, ?, '[]', 'authenticated', '{}', ?, ?, ?)")
        .run(projectIds[0], "Northstar Portal", "Synthetic authorized application fixture.", input.ownerUserId ?? null, now, now);
      this.database.db.prepare("INSERT INTO projects (id, name, description, tags_json, default_profile, default_scope_json, created_by, created_at, updated_at) VALUES (?, ?, ?, '[]', 'monitor', '{}', ?, ?, ?)")
        .run(projectIds[1], "Atlas Internal", "Synthetic controlled lab fixture.", input.ownerUserId ?? null, now, now);
      const insertTarget = this.database.db.prepare("INSERT INTO targets (id, project_id, display_name, base_origin, tags_json, classification, authorization_type, authorization_summary, approved_scope_json, default_profile, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, '[]', 'LOCAL', 'CONTROLLED_LAB', 'Synthetic development-only authorization.', '{}', 'authenticated', ?, ?, ?)");
      insertTarget.run(targetIds[0], projectIds[0], "Northstar Accounts", "http://127.0.0.1:43101", input.ownerUserId ?? null, now, now);
      insertTarget.run(targetIds[1], projectIds[0], "Northstar Files", "http://127.0.0.1:43102", input.ownerUserId ?? null, now, now);
      insertTarget.run(targetIds[2], projectIds[1], "Atlas API", "http://127.0.0.1:43103", input.ownerUserId ?? null, now, now);
    });
    const scanIds = [randomUUID(), randomUUID()];
    for (const scanId of scanIds) this.database.db.prepare("INSERT INTO scans (id, source, status, target_origin, safe_target_label, profile, evidence_level, created_at, completed_at, safe_configuration_summary, project_id, target_id, authorization_declaration) VALUES (?, 'DASHBOARD', 'COMPLETED', ?, ?, 'authenticated', 'strong', ?, ?, ?, ?, ?, 'CONTROLLED_LAB: Synthetic development fixture')")
      .run(scanId, "http://127.0.0.1:43101", "Northstar Accounts", now, now, JSON.stringify({ target: "http://127.0.0.1:43101", profile: "authenticated", studio: { scope: { program: "RouteCairn demo", allowedDomains: ["127.0.0.1"], allowedMethods: ["GET", "HEAD", "OPTIONS"], disallowedPaths: ["/delete"], rateLimitPerSecond: 2, concurrency: 2, sameOriginOnly: true, includeSubdomains: false }, authentication: { mode: "primary", primary: { source: "ephemeral", safeAlias: "Demo analyst" } }, evidenceLevel: "strong", outputs: { json: true, markdown: true, html: true }, reusableWorkflows: [] } }), projectIds[0], targetIds[0]);
    const normalizer = new FindingNormalizer(this.database.db, new FindingFingerprintService(this.paths.fingerprintKeyPath));
    normalizer.normalizeReport(scanIds[0]!, reportFixture());
    normalizer.normalizeReport(scanIds[1]!, reportFixture());
    const findings = this.database.db.prepare("SELECT id, latest_occurrence_id FROM findings ORDER BY canonical_title").all() as Array<{ id: string; latest_occurrence_id: string }>;
    findings.forEach((finding, index) => {
      const review = reviewStates[index % reviewStates.length]!;
      const remediation = remediationStates[index % remediationStates.length]!;
      this.database.db.prepare("UPDATE findings SET human_review_status = ?, remediation_state_v2 = ?, remediation_status = ?, assignee_user_id = ?, reviewer_user_id = ?, review_started_at = ?, retest_state = ?, proof_readiness = ?, new_occurrence_kind = ?, effective_severity = CASE WHEN ? = 2 THEN 'Critical' ELSE effective_severity END, row_version = row_version + 1 WHERE id = ?")
        .run(review, remediation, remediation === "ASSIGNED" ? "OPEN" : remediation, index % 3 === 0 ? input.analystUserId ?? null : null, review === "IN_REVIEW" ? input.analystUserId ?? null : null, review === "IN_REVIEW" ? now : null, remediation === "FIXED_VERIFIED" ? "RETEST_PASSED" : remediation === "FIXED_PENDING_RETEST" ? "RETEST_INCONCLUSIVE" : "NOT_RETESTED", index % 4 === 0 ? "READY" : index % 4 === 1 ? "MISSING_EVIDENCE" : "MISSING_REVIEW", review === "REOPENED" ? "RECURRENCE_REOPENED" : null, index, finding.id);
      this.database.db.prepare("UPDATE evidence_records SET evidence_type = ?, safe_structured_data_json = ? WHERE finding_occurrence_id = ?")
        .run(evidenceTypes[index % evidenceTypes.length], JSON.stringify(evidenceFixture(evidenceTypes[index % evidenceTypes.length]!)), finding.latest_occurrence_id);
      this.database.db.prepare("INSERT INTO finding_notes (id, finding_id, user_id, safe_text, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
        .run(randomUUID(), finding.id, input.analystUserId ?? null, "Synthetic remediation note for local dashboard exploration.", now, now);
      this.database.db.prepare("INSERT INTO finding_reviews (id, finding_id, previous_review_status, new_review_status, reason, created_at, local_reviewer_label, source, user_id, safe_metadata_json) VALUES (?, ?, 'UNREVIEWED', ?, 'Synthetic demo transition.', ?, 'demo-analyst', 'HUMAN', ?, '{}')")
        .run(randomUUID(), finding.id, review, now, input.analystUserId ?? null);
      this.database.db.prepare("INSERT INTO finding_remediation_history (id, finding_id, user_id, previous_state, new_state, assignee_user_id, safe_note, owner_override, source, created_at) VALUES (?, ?, ?, 'OPEN', ?, ?, 'Synthetic demo remediation history.', 0, 'HUMAN', ?)")
        .run(randomUUID(), finding.id, input.analystUserId ?? null, remediation, input.analystUserId ?? null, now);
    });
    if (findings.length > 5) this.database.db.prepare("UPDATE findings SET duplicate_of_finding_id = ? WHERE id = ?").run(findings[0]!.id, findings[5]!.id);
    mkdirSync(this.paths.artifactsDir, { recursive: true });
    const screenshotPath = resolve(this.paths.artifactsDir, "demo-screenshot.png");
    const screenshot = createSyntheticDashboardScreenshot();
    writeFileSync(screenshotPath, screenshot);
    const screenshotArtifactId = new ArtifactRepository(this.database).create({ scanId: scanIds[0]!, type: "SCREENSHOT", name: "Synthetic browser evidence.png", path: screenshotPath, size: screenshot.length, contentType: "image/png", hash: createHash("sha256").update(screenshot).digest("hex") });
    const browserEvidence = this.database.db.prepare("SELECT id FROM evidence_records WHERE evidence_type = 'browser-screenshot' LIMIT 1").get() as { id: string } | undefined;
    if (browserEvidence) this.database.db.prepare("UPDATE evidence_records SET artifact_id = ? WHERE id = ?").run(screenshotArtifactId, browserEvidence.id);
    const insertView = this.database.db.prepare("INSERT INTO saved_finding_views (id, owner_user_id, safe_name, query_json, columns_json, is_default, shared_installation_wide, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    insertView.run(randomUUID(), input.analystUserId ?? null, "My high priority queue", JSON.stringify({ severity: "High" }), JSON.stringify(["severity", "title", "review", "remediation", "target", "assignee"]), 1, 0, now, now);
    insertView.run(randomUUID(), input.ownerUserId ?? null, "Shared remediation queue", JSON.stringify({ remediationStatus: "FIXED_PENDING_RETEST" }), JSON.stringify(["severity", "title", "target", "retest"]), 0, 1, now, now);
    this.database.db.prepare("INSERT INTO dashboard_meta (key, value, updated_at) VALUES ('demo_seed_v1', ?, ?)").run(now, now);
    return { projectIds, targetIds, findingCount: findings.length, screenshotArtifactId };
  }
}

function reportFixture(): { target: string; findings: Finding[] } {
  return {
    target: "http://127.0.0.1:43101",
    findings: evidenceTypes.map((source, index) => ({
      id: `demo-${index}`,
      title: `Synthetic ${source} authorization observation`,
      type: "Authorization Matrix Issue",
      severity: index % 3 === 0 ? "High" : index % 3 === 1 ? "Medium" : "Low",
      confidence: index % 2 ? "Medium" : "High",
      url: `http://127.0.0.1:43101/demo/${index}?token=<redacted>`,
      method: "GET",
      sourceModule: source === "browser-screenshot" ? "browser-crawler" : `${source}-testing`,
      tags: ["authorization", `role:demo-${index}`, `case:demo-${index}`],
      evidence: { source, title: "Synthetic controlled evidence", method: "GET", url: `http://127.0.0.1:43101/demo/${index}`, bodyHash: `demo-hash-${index}` },
      impact: "Synthetic demo impact requiring manual verification.",
      recommendation: "Review the fictional authorization policy.",
      manualTestingSuggestions: ["Use only the controlled local fixture."],
      riskScore: 5,
      falsePositiveStatus: "likely-valid",
      timestamp: new Date(0).toISOString()
    }))
  };
}

function evidenceFixture(type: string): Record<string, unknown> {
  return { type, actor: "Demo Account A", object: "Synthetic object", expected: "Denied", observed: "Allowed", result: "Needs manual verification", completeness: "PARTIAL", proofMode: "PREFIX", bytesRead: 512, principalComparison: "different", pageUrl: "http://127.0.0.1:43101/demo", screenshotAvailable: type === "browser-screenshot" };
}
