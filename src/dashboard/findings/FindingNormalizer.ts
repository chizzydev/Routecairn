import { randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import type { Finding } from "../../core/findings/Finding.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { redactDashboardValue, safeJson } from "../security/Redaction.js";
import { FindingFingerprintService } from "./FindingFingerprintService.js";
import { recordWorkflowCaseExecutions } from "../comparisons/WorkflowCaseExecutionRecorder.js";

export class FindingNormalizer {
  public constructor(private readonly db: Database, private readonly fingerprints: FindingFingerprintService) {}

  public normalizeReport(scanId: string, report: Pick<import("../../reports/ReportTypes.js").RouteCairnReport, "target" | "findings"> & Partial<import("../../reports/ReportTypes.js").RouteCairnReport>): number {
    const targetOrigin = new URL(report.target).origin;
    const tx = this.db.transaction(() => {
      for (const finding of report.findings) {
        this.normalizeFinding(scanId, targetOrigin, finding);
      }
      recordWorkflowCaseExecutions(this.db, scanId, report);
    });
    tx();
    return report.findings.length;
  }

  private normalizeFinding(scanId: string, targetOrigin: string, finding: Finding): void {
    const fingerprint = this.fingerprints.fingerprint(targetOrigin, finding);
    const now = nowIso();
    const existing = this.db.prepare("SELECT id, human_review_status, remediation_state_v2 FROM findings WHERE fingerprint = ?").get(fingerprint) as
      | { id: string; human_review_status: string; remediation_state_v2: string }
      | undefined;
    const findingId = existing?.id ?? randomUUID();
    const safeEndpoint = this.fingerprints.routeIdentity(finding.url);
    const scan = this.db.prepare("SELECT project_id, target_id, source FROM scans WHERE id = ?").get(scanId) as
      | { project_id: string | null; target_id: string | null; source: string }
      | undefined;

    if (existing && this.db.prepare("SELECT 1 FROM finding_occurrences WHERE finding_id = ? AND scan_id = ? LIMIT 1").get(findingId, scanId)) {
      return;
    }

    if (!existing) {
      this.db
        .prepare(
          `INSERT INTO findings (id, fingerprint, target_identity, module, finding_category,
           safe_endpoint_identity, safe_authorization_boundary_identity, canonical_title,
           current_scanner_severity, current_scanner_confidence, human_review_status,
           remediation_status, first_seen_at, last_seen_at, last_occurrence_scan_id,
           occurrence_count, project_id, target_id, http_method, canonical_description,
           first_scan_id, effective_severity, remediation_state_v2, proof_readiness,
           row_version, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'UNREVIEWED', 'OPEN', ?, ?, ?, 1,
           ?, ?, ?, ?, ?, ?, 'OPEN', 'MISSING_REVIEW', 1, ?, ?)`
        )
        .run(
          findingId,
          fingerprint,
          targetOrigin,
          finding.sourceModule ?? "unknown-module",
          finding.type,
          safeEndpoint,
          boundaryFromFinding(finding),
          finding.title,
          finding.severity,
          finding.confidence,
          now,
          now,
          scanId,
          scan?.project_id ?? null,
          scan?.target_id ?? null,
          finding.method ?? "GET",
          finding.evidence.title ?? finding.title,
          scanId,
          finding.severity,
          now,
          now
        );
    } else {
      this.db
        .prepare(
          `UPDATE findings
           SET current_scanner_severity = ?, current_scanner_confidence = ?, last_seen_at = ?,
               last_occurrence_scan_id = ?, occurrence_count = occurrence_count + 1,
               project_id = COALESCE(project_id, ?), target_id = COALESCE(target_id, ?),
               new_occurrence_kind = CASE
                 WHEN human_review_status = 'FALSE_POSITIVE' THEN 'AFTER_FALSE_POSITIVE'
                 WHEN human_review_status = 'ACCEPTED_RISK' THEN 'ACCEPTED_RISK_RECURRENCE'
                 ELSE 'NEW_OCCURRENCE'
               END,
               updated_at = ?, row_version = row_version + 1
           WHERE id = ?`
        )
        .run(finding.severity, finding.confidence, now, scanId, scan?.project_id ?? null,
          scan?.target_id ?? null, now, findingId);
      if (existing.human_review_status === "RESOLVED" || existing.remediation_state_v2 === "FIXED_VERIFIED") {
        this.db.prepare(
          `UPDATE findings SET human_review_status = 'REOPENED', remediation_state_v2 = 'OPEN',
           remediation_status = 'OPEN', retest_state = 'RETEST_FAILED',
           new_occurrence_kind = 'RECURRENCE_REOPENED', updated_at = ?, row_version = row_version + 1
           WHERE id = ?`
        ).run(now, findingId);
        this.db
          .prepare(
            "INSERT INTO finding_reviews (id, finding_id, previous_review_status, new_review_status, reason, review_note, created_at, source) VALUES (?, ?, 'RESOLVED', 'REOPENED', ?, ?, ?, 'SYSTEM_REOPEN')"
          )
          .run(randomUUID(), findingId, "Comparable finding appeared in a later scan.", "Automatically reopened after compatible recurrence.", now);
        this.db.prepare(
          `INSERT INTO finding_remediation_history
           (id, finding_id, previous_state, new_state, safe_note, related_scan_id,
            owner_override, source, created_at)
           VALUES (?, ?, ?, 'OPEN', ?, ?, 0, 'SYSTEM_REOPEN', ?)`
        ).run(randomUUID(), findingId, existing.remediation_state_v2,
          "New compatible scanner occurrence reopened remediation.", scanId, now);
      }
    }

    const occurrenceId = randomUUID();
    this.db
      .prepare(
        `INSERT INTO finding_occurrences (id, finding_id, scan_id, module, finding_category,
         severity, confidence, title, safe_endpoint, safe_actor_relationship,
         safe_tenant_or_role_boundary, safe_state_boundary, description, impact,
         reproduction_steps, remediation, limitations, evidence_summary, finding_source_json,
         created_at, project_id, target_id, source_kind, workflow_case_alias,
         coverage_reference_json, safe_reproduction_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        occurrenceId,
        findingId,
        scanId,
        finding.sourceModule ?? "unknown-module",
        finding.type,
        finding.severity,
        finding.confidence,
        finding.title,
        safeEndpoint,
        actorBoundary(finding),
        tenantRoleBoundary(finding),
        stateBoundary(finding),
        finding.evidence.title ?? finding.title,
        finding.impact ?? null,
        finding.manualTestingSuggestions?.join("\n") ?? finding.evidence.reproductionNotes ?? null,
        finding.recommendation ?? null,
        finding.evidence.severityReason ?? null,
        evidenceSummary(finding, safeEndpoint),
        safeJson(finding),
        now,
        scan?.project_id ?? null,
        scan?.target_id ?? null,
        scan?.source === "DASHBOARD" ? "NATIVE" : "IMPORTED",
        workflowCaseAlias(finding),
        safeJson({ module: finding.sourceModule ?? "unknown-module", workflowCaseAlias: workflowCaseAlias(finding) }),
        safeJson({ method: finding.method ?? "GET", endpoint: safeEndpoint, notes: finding.evidence.reproductionNotes ?? null })
      );

    this.db.prepare("UPDATE findings SET latest_occurrence_id = ?, updated_at = ? WHERE id = ?")
      .run(occurrenceId, now, findingId);

    this.db
      .prepare(
        "INSERT INTO evidence_records (id, finding_occurrence_id, evidence_type, evidence_level, safe_summary, safe_structured_data_json, scoped_fingerprint, byte_count, retention_classification, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .run(
        randomUUID(),
        occurrenceId,
        finding.evidence.source ?? "scanner",
        "report",
        evidenceSummary(finding, safeEndpoint),
        safeJson(redactDashboardValue(finding.evidence)),
        finding.evidence.bodyHash ?? null,
        finding.evidence.contentLength ?? null,
        "REDACTED_REPORT_EVIDENCE",
        now
      );
  }
}

function workflowCaseAlias(finding: Finding): string | null {
  const tag = finding.tags?.find((value) => /^(?:case|workflow-case):/i.test(value));
  if (tag) return tag.slice(tag.indexOf(":") + 1).slice(0, 160);
  const source = finding.evidence.source ?? "";
  for (const pattern of [/Object pair ([^;]+?)(?:\s+(?:A_TO_A|B_TO_B|A_TO_B|B_TO_A));/i, /Field exposure ([^;]+);/i, /Authorization matrix ([^;]+);/i, /Equivalent route (?:set )?([^;]+);/i, /Collection (?:authorization )?([^;]+);/i, /Bulk (?:authorization )?([^;]+);/i, /File (?:authorization )?([^;]+);/i]) {
    const matched = pattern.exec(source)?.[1];
    if (matched) return matched.replace(/\s+/g, " ").slice(0, 160);
  }
  return null;
}

function evidenceSummary(finding: Finding, safeEndpoint: string): string {
  const parts = [finding.method ?? "GET", safeEndpoint, finding.evidence.statusCode ? `status ${finding.evidence.statusCode}` : "", finding.evidence.bodyHash ? `hash ${finding.evidence.bodyHash.slice(0, 12)}` : ""];
  return parts.filter(Boolean).join(" ");
}

function boundaryFromFinding(finding: Finding): string {
  return finding.tags?.filter((tag) => /auth|role|tenant|object|file|collection|bulk|state/i.test(tag)).sort().join("|") || "general";
}

function actorBoundary(finding: Finding): string | null {
  return finding.tags?.find((tag) => /account|actor|principal|role/i.test(tag)) ?? null;
}

function tenantRoleBoundary(finding: Finding): string | null {
  return finding.tags?.find((tag) => /tenant|role/i.test(tag)) ?? null;
}

function stateBoundary(finding: Finding): string | null {
  return finding.tags?.find((tag) => /state|workflow/i.test(tag)) ?? null;
}
