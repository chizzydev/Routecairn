import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../../core/findings/Finding.js";
import type { AssistedReviewReport } from "../../reports/AssistedReviewReport.js";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { ArtifactRepository } from "../db/DashboardRepositories.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import { safeJson } from "../security/Redaction.js";
import { safeReviewCoverage } from "./AssistedReviewSerialization.js";
import { hasOccurrenceReview } from "./AssistedOccurrenceReview.js";

interface ReviewFinding {
  findingId: string;
  occurrenceId: string;
  scannerFindingId: string;
  title: string;
  severity: string;
  reviewState: string;
  occurrenceReviewed: boolean;
  evidenceIds: string[];
  proofPackIds: string[];
  comparisonIds: string[];
  workflowId: string;
  caseId: string;
  cleanupUnresolved: boolean;
  customerSafeRemediation: string;
}

export class AssistedReviewService {
  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths) {}

  public get(scanId: string) {
    const stored = this.database.db.prepare("SELECT r.safe_report_json, s.status FROM assisted_review_runs r JOIN scans s ON s.id = r.scan_id WHERE r.scan_id = ? AND s.deleted_at IS NULL").get(scanId) as { safe_report_json: string; status: string } | undefined;
    if (!stored) throw new Error("ASSISTED_REVIEW_NOT_FOUND");
    const report = JSON.parse(stored.safe_report_json) as AssistedReviewReport;
    const requested = new Set(report.humanReviewQueue.map((item) => item.findingId));
    const occurrences = this.database.db.prepare("SELECT o.id AS occurrence_id, o.finding_source_json, f.id, f.canonical_title, f.effective_severity, f.human_review_status FROM finding_occurrences o JOIN findings f ON f.id = o.finding_id WHERE o.scan_id = ?").all(scanId) as Array<{ occurrence_id: string; finding_source_json: string; id: string; canonical_title: string; effective_severity: string; human_review_status: string }>;
    const queue: ReviewFinding[] = [];
    for (const row of occurrences) {
      const finding = JSON.parse(row.finding_source_json) as Finding;
      if (!requested.has(finding.id) || !finding.workflow) continue;
      const evidenceIds = (this.database.db.prepare("SELECT id FROM evidence_records WHERE finding_occurrence_id = ?").all(row.occurrence_id) as Array<{ id: string }>).map((item) => item.id);
      const proofPackIds = (this.database.db.prepare("SELECT proof_pack_id FROM proof_pack_findings WHERE selected_occurrence_id = ?").all(row.occurrence_id) as Array<{ proof_pack_id: string }>).map((item) => item.proof_pack_id);
      const comparisonIds = (this.database.db.prepare("SELECT comparison_id FROM scan_comparison_findings WHERE older_occurrence_id = ? OR newer_occurrence_id = ?").all(row.occurrence_id, row.occurrence_id) as Array<{ comparison_id: string }>).map((item) => item.comparison_id);
      queue.push({ findingId: row.id, occurrenceId: row.occurrence_id, scannerFindingId: finding.id, title: row.canonical_title, severity: row.effective_severity, reviewState: row.human_review_status, occurrenceReviewed: hasOccurrenceReview(this.database, row.id, row.occurrence_id, row.human_review_status), evidenceIds, proofPackIds, comparisonIds, workflowId: finding.workflow.workflowId, caseId: finding.workflow.caseId, cleanupUnresolved: finding.workflow.cleanupFailed, customerSafeRemediation: finding.customerSafeRemediation ?? finding.recommendation });
    }
    const blockers = [...report.completionGate.blockers];
    if (!["COMPLETED", "IMPORTED"].includes(stored.status)) blockers.push("SCAN_NOT_COMPLETE");
    if (requested.size !== new Set(queue.map((item) => item.scannerFindingId)).size) blockers.push("FINDING_LINKS_INCOMPLETE");
    if (queue.some((item) => ["UNREVIEWED", "IN_REVIEW", "REOPENED"].includes(item.reviewState))) blockers.push("HUMAN_REVIEW_PENDING");
    if (queue.some((item) => !item.occurrenceReviewed)) blockers.push("OCCURRENCE_REVIEW_REQUIRED");
    if (queue.some((item) => item.evidenceIds.length === 0)) blockers.push("EVIDENCE_LINKS_INCOMPLETE");
    const cleanup = this.database.db.prepare("SELECT 1 FROM assisted_case_results WHERE scan_id = ? AND cleanup_unresolved = 1 LIMIT 1").get(scanId);
    if (cleanup || queue.some((item) => item.cleanupUnresolved)) blockers.push("CLEANUP_UNRESOLVED");
    const publications = this.database.db.prepare("SELECT id, artifact_id AS artifactId, content_sha256 AS contentSha256, created_at AS createdAt FROM assisted_review_publications WHERE scan_id = ? ORDER BY created_at DESC").all(scanId) as Array<{ id: string; artifactId: string; contentSha256: string; createdAt: string }>;
    const timeline = this.database.db.prepare("SELECT seq, event_type AS eventType, safe_message AS message, created_at AS createdAt FROM scan_events WHERE scan_id = ? ORDER BY seq").all(scanId);
    return { scanId, report, queue, timeline, publications, gate: { state: blockers.length ? "BLOCKED" as const : "READY" as const, blockers: [...new Set(blockers)] } };
  }

  /** Publication re-evaluates current human decisions inside the same database transaction. */
  public publish(scanId: string, actorId: string): { publicationId: string; artifactId: string } {
    return this.database.transaction(() => {
      const review = this.get(scanId);
      if (review.gate.state !== "READY") throw new Error(`ASSISTED_REVIEW_NOT_READY:${review.gate.blockers.join(",")}`);
      const publicationId = randomUUID();
      const findings = review.queue.filter((item) => item.reviewState === "CONFIRMED").map((item) => ({ title: item.title, severity: item.severity, remediation: item.customerSafeRemediation }));
      const safeContent = JSON.parse(safeJson({ schemaVersion: 1, publicationId, reviewId: review.report.reviewId, title: review.report.title, findings, acceptedRiskCount: review.queue.filter((item) => item.reviewState === "ACCEPTED_RISK").length, limitations: review.report.notes, operatorEvidenceIncluded: false, humanReviewEnforced: true })) as Record<string, unknown>;
      const body = JSON.stringify({ ...safeContent, coverage: safeReviewCoverage(review.report.coverageMatrix) });
      const hash = createHash("sha256").update(`${body}\n`).digest("hex");
      const directory = join(this.paths.artifactsDir, "assisted-reviews", publicationId);
      mkdirSync(directory, { recursive: true });
      const path = join(directory, "customer-review.json");
      writeFileSync(path, `${body}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
      const artifactId = new ArtifactRepository(this.database).create({ scanId, type: "ASSISTED_CUSTOMER_REPORT", name: "customer-review.json", path, size: Buffer.byteLength(`${body}\n`), contentType: "application/json", hash: createHash("sha256").update(`${body}\n`).digest("hex") });
      this.database.db.prepare("INSERT INTO assisted_review_publications (id, scan_id, artifact_id, content_sha256, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(publicationId, scanId, artifactId, hash, actorId, new Date().toISOString());
      this.database.appendEvent(scanId, "ASSISTED_REVIEW_PUBLISHED", "Human-reviewed customer report published.", { publicationId, artifactId, confirmedFindings: findings.length });
      return { publicationId, artifactId };
    });
  }
}
