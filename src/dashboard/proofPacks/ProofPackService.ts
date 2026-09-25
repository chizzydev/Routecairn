import { randomUUID, createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import type { Finding } from "../../core/findings/Finding.js";
import { hasOccurrenceReview } from "../reviews/AssistedOccurrenceReview.js";
import { resolve } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { ArtifactRepository } from "../db/DashboardRepositories.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import { escapeHtml } from "../security/Redaction.js";
import {
  extractSafeValuePresenceAttestations,
  type SafeValuePresenceAttestation
} from "../security/ValuePresenceAttestations.js";
import { writePdfProofPack } from "./PdfProofPackWriter.js";

export class ProofPackService {
  private readonly artifacts: ArtifactRepository;

  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths) {
    this.artifacts = new ArtifactRepository(database);
  }

  public generate(title: string, description: string | undefined, findingIds: readonly string[], organizationId = this.defaultOrganizationId()): string {
    const findings = this.database.db
      .prepare(`SELECT * FROM findings WHERE organization_id=? AND id IN (${findingIds.map(() => "?").join(",")})`)
      .all(organizationId,...findingIds) as ProofFindingRow[];
    if (findings.length !== findingIds.length) throw new Error("One or more findings were not found.");
    const excluded = findings.filter((finding) => finding.human_review_status !== "CONFIRMED");
    if (excluded.length > 0) throw new Error("Proof packs include confirmed findings only by default.");
    const selected = findings.map((finding, index) => {
      const occurrence = this.database.db.prepare("SELECT id, scan_id, workflow_case_alias, finding_source_json FROM finding_occurrences WHERE finding_id = ? ORDER BY (id = (SELECT latest_occurrence_id FROM findings WHERE findings.id = finding_occurrences.finding_id)) DESC, created_at DESC, id DESC LIMIT 1").get(finding.id) as { id: string; scan_id: string; workflow_case_alias: string | null; finding_source_json: string } | undefined;
      if (!occurrence) {
        throw new Error(`Finding ${finding.id} has no occurrence for proof-pack generation.`);
      }
      const evidence = this.database.db
        .prepare("SELECT id, safe_structured_data_json FROM evidence_records WHERE finding_occurrence_id = ? ORDER BY created_at DESC")
        .all(occurrence.id) as Array<{ id: string; safe_structured_data_json: string }>;
      if (evidence.length === 0) {
        throw new Error(`Finding ${finding.id} has no retained eligible evidence for proof-pack generation.`);
      }
      const attestations = deduplicateAttestations(
        evidence.flatMap((record) => extractSafeValuePresenceAttestations(parseJson(record.safe_structured_data_json)))
      );
      const source = parseJson(occurrence.finding_source_json) as Finding | undefined;
      if (source?.workflow && !hasOccurrenceReview(this.database, finding.id, occurrence.id, "CONFIRMED")) throw new Error("The selected assisted finding occurrence requires human confirmation before proof-pack generation.");
      return { finding, occurrence, evidence, attestations, workflow: source?.workflow, sortOrder: index + 1 };
    });

    const mutationProof = selected.filter((item) => item.finding.module === "privilege-mutation-testing" && item.occurrence.workflow_case_alias).flatMap((item) =>
      this.database.db.prepare("SELECT safe_case_alias, safe_semantics_json, safe_result_json, evidence_strength FROM scan_workflow_case_executions WHERE scan_id = ? AND workflow_id = 'privilege-mutation' AND safe_case_alias = ? AND execution_state = 'COMPLETED' AND request_transmitted = 1").all(item.occurrence.scan_id, item.occurrence.workflow_case_alias) as MutationProofRow[]
    );

    const proofPackId = randomUUID();
    const dir = resolve(this.paths.proofPacksDir, proofPackId);
    mkdirSync(dir, { recursive: true });
    const markdown = renderMarkdown(title, description, selected, mutationProof);
    const html = renderHtml(title, description, selected, mutationProof);
    const markdownPath = resolve(dir, "proof-pack.md");
    const htmlPath = resolve(dir, "proof-pack.html");
    const pdfPath = resolve(dir, "proof-pack.pdf");
    writeFileSync(markdownPath, markdown, "utf8");
    writeFileSync(htmlPath, html, "utf8");
    writePdfProofPack(pdfPath, markdown);
    const versionRow = this.database.db.prepare("SELECT COALESCE(MAX(version), 0) + 1 AS version FROM proof_packs WHERE organization_id=? AND safe_title = ?").get(organizationId,title) as { version: number };
    this.database.transaction(() => {
      this.database.db
        .prepare(
          "INSERT INTO proof_packs (id, organization_id, safe_title, description, status, version, created_at, generated_at, source_scan_ids_json, scope_summary, included_finding_count, output_artifact_ids_json, immutable_snapshot_metadata_json) VALUES (?, ?, ?, ?, 'READY', ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .run(
          proofPackId,
          organizationId,
          title,
          description ?? null,
          versionRow.version,
          nowIso(),
          nowIso(),
          JSON.stringify([...new Set(selected.map((item) => item.occurrence.scan_id))]),
          "Generated from confirmed local dashboard findings.",
          findings.length,
          "[]",
          JSON.stringify({ findingIds, valuePresenceAttestationCount: selected.reduce((total, item) => total + item.attestations.length, 0) })
        );
      const markdownArtifact = this.recordArtifact(proofPackId, markdownPath, "PROOF_PACK_MARKDOWN", "text/markdown; charset=utf-8",organizationId);
      const htmlArtifact = this.recordArtifact(proofPackId, htmlPath, "PROOF_PACK_HTML", "text/html; charset=utf-8",organizationId);
      const pdfArtifact = this.recordArtifact(proofPackId, pdfPath, "PROOF_PACK_PDF", "application/pdf",organizationId);
      this.database.db.prepare("UPDATE proof_packs SET output_artifact_ids_json=? WHERE id=?").run(JSON.stringify([markdownArtifact,htmlArtifact,pdfArtifact]),proofPackId);
      const insert = this.database.db.prepare(
        "INSERT INTO proof_pack_findings (proof_pack_id, finding_id, selected_occurrence_id, sort_order, included_evidence_ids_json, snapshot_content_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
      );
      for (const item of selected) {
        insert.run(
          proofPackId,
          item.finding.id,
          item.occurrence.id,
          item.sortOrder,
          JSON.stringify(item.evidence.map((evidence) => evidence.id)),
          JSON.stringify({ finding: item.finding, workflow: item.workflow, valuePresenceAttestations: item.attestations }),
          nowIso()
        );
      }
    });
    return proofPackId;
  }

  public list(organizationId = this.defaultOrganizationId()): Array<{ id: string; title: string; status: string; version: number; generatedAt?: string; includedFindingCount: number; artifacts: string[] }> {
    const rows = this.database.db
      .prepare("SELECT id, safe_title, status, version, generated_at, included_finding_count, output_artifact_ids_json FROM proof_packs WHERE organization_id=? ORDER BY created_at DESC LIMIT 100")
      .all(organizationId) as Array<{ id: string; safe_title: string; status: string; version: number; generated_at: string | null; included_finding_count: number; output_artifact_ids_json: string }>;
    return rows.map((row) => ({
      id: row.id,
      title: row.safe_title,
      status: row.status,
      version: row.version,
      ...(row.generated_at ? { generatedAt: row.generated_at } : {}),
      includedFindingCount: row.included_finding_count,
      artifacts: JSON.parse(row.output_artifact_ids_json) as string[]
    }));
  }

  private recordArtifact(proofPackId: string, path: string, type: string, contentType: string, organizationId:string): string {
    const stat = statSync(path);
    return this.artifacts.create({ organizationId,proofPackId, type, name: path.split(/[\\/]/).pop() ?? type, path, size: stat.size, contentType, hash: createHash("sha256").update(readFileSync(path)).digest("hex") });
  }
  private defaultOrganizationId():string { return (this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key='default_organization_id'").get() as {value:string}).value; }
}

interface ProofFindingRow {
  id: string;
  module: string;
  canonical_title: string;
  current_scanner_severity: string;
  current_scanner_confidence: string;
  safe_endpoint_identity: string;
  human_review_status: string;
  last_occurrence_scan_id: string;
}

interface MutationProofRow { safe_case_alias: string; safe_semantics_json: string; safe_result_json: string; evidence_strength: string; }

interface SelectedProofFinding {
  readonly finding: ProofFindingRow;
  readonly attestations: readonly SafeValuePresenceAttestation[];
  readonly workflow?: Finding["workflow"];
}

function renderMarkdown(title: string, description: string | undefined, selected: readonly SelectedProofFinding[], mutationProof: readonly MutationProofRow[]): string {
  const lines = [`# ${safeMarkdown(title)}`, "", description ? safeMarkdown(description) : "Generated by RouteCairn Dashboard.", ""];
  for (const item of selected) {
    const finding = item.finding;
    lines.push(`## ${safeMarkdown(finding.canonical_title)}`, "");
    lines.push(`- Severity: ${safeMarkdown(finding.current_scanner_severity)}`);
    lines.push(`- Confidence: ${safeMarkdown(finding.current_scanner_confidence)}`);
    if (item.workflow) lines.push(`- Workflow: ${safeMarkdown(item.workflow.workflowId)}; case: ${safeMarkdown(item.workflow.caseId)}; assessment: ${item.workflow.assessmentOutcome}; cleanup: ${safeMarkdown(item.workflow.cleanupOutcome ?? "NOT_APPLICABLE")}${item.workflow.cleanupFailed ? " (UNRESOLVED)" : ""}.`, `- Evidence: ${safeMarkdown(item.workflow.evidenceRef)}; comparison fingerprint: ${safeMarkdown(item.workflow.comparisonFingerprint ?? "UNAVAILABLE")}.`);
    lines.push(`- Endpoint: \`${safeMarkdown(finding.safe_endpoint_identity)}\``);
    lines.push("");
    appendMarkdownAttestations(lines, item.attestations);
  }
  appendMutationProofMarkdown(lines, mutationProof);
  return lines.join("\n");
}

function appendMutationProofMarkdown(lines: string[], rows: readonly MutationProofRow[]): void { if (rows.length === 0) return; lines.push("## Controlled mutation proof", "", "Raw request bodies, credentials, and recovery material are intentionally excluded.", ""); for (const row of rows) { const result = parseSafeJson(row.safe_result_json); const semantics = parseSafeJson(row.safe_semantics_json); lines.push(`- Case \`${safeMarkdown(row.safe_case_alias)}\`: ${safeMarkdown(String(result.securityOutcome ?? "INCONCLUSIVE"))}; cleanup ${safeMarkdown(String(result.cleanupOutcome ?? "UNKNOWN"))}; transmitted ${result.requestTransmitted ? "yes" : "no"}; authority-change verified ${result.authorityChangeVerified ? "yes" : "no"}; evidence ${safeMarkdown(row.evidence_strength)}; endpoint ${safeMarkdown(String(semantics.endpoint ?? "<redacted>"))}`); } lines.push(""); }
function parseSafeJson(value: string): Record<string, unknown> { try { const parsed = JSON.parse(value) as unknown; return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : {}; } catch { return {}; } }

function renderHtml(title: string, description: string | undefined, selected: readonly SelectedProofFinding[], mutationProof: readonly MutationProofRow[]): string {
  const items = selected
    .map(
      ({ finding, attestations, workflow }) =>
        `<section><h2>${safeProofHtml(finding.canonical_title)}</h2><dl><dt>Severity</dt><dd>${safeProofHtml(finding.current_scanner_severity)}</dd><dt>Confidence</dt><dd>${safeProofHtml(finding.current_scanner_confidence)}</dd><dt>Endpoint</dt><dd><code>${safeProofHtml(finding.safe_endpoint_identity)}</code></dd></dl>${workflow ? `<p>Workflow: ${safeProofHtml(workflow.workflowId)}; case: ${safeProofHtml(workflow.caseId)}; assessment: ${workflow.assessmentOutcome}; cleanup: ${safeProofHtml(workflow.cleanupOutcome ?? "NOT_APPLICABLE")}${workflow.cleanupFailed ? " (UNRESOLVED)" : ""}.</p><p>Evidence: ${safeProofHtml(workflow.evidenceRef)}; comparison fingerprint: ${safeProofHtml(workflow.comparisonFingerprint ?? "UNAVAILABLE")}.</p>` : ""}${renderHtmlAttestations(attestations)}</section>`
    )
    .join("");
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>${safeProofHtml(title)}</title><style>body{font-family:system-ui;margin:2rem;line-height:1.5}code{background:#f4f4f4;padding:.1rem .25rem}</style></head><body><h1>${safeProofHtml(title)}</h1><p>${safeProofHtml(description ?? "Generated by RouteCairn Dashboard.")}</p>${items}${renderHtmlMutationProof(mutationProof)}</body></html>`;
}

function renderHtmlMutationProof(rows: readonly MutationProofRow[]): string { if (rows.length === 0) return ""; return `<section><h2>Controlled mutation proof</h2><p>Raw request bodies, credentials, and recovery material are intentionally excluded.</p><ul>${rows.map((row) => { const result = parseSafeJson(row.safe_result_json); const semantics = parseSafeJson(row.safe_semantics_json); return `<li>Case <code>${safeProofHtml(row.safe_case_alias)}</code>: ${safeProofHtml(String(result.securityOutcome ?? "INCONCLUSIVE"))}; cleanup ${safeProofHtml(String(result.cleanupOutcome ?? "UNKNOWN"))}; transmitted ${result.requestTransmitted ? "yes" : "no"}; authority-change verified ${result.authorityChangeVerified ? "yes" : "no"}; endpoint <code>${safeProofHtml(String(semantics.endpoint ?? "<redacted>"))}</code></li>`; }).join("")}</ul></section>`; }

function appendMarkdownAttestations(lines: string[], attestations: readonly SafeValuePresenceAttestation[]): void {
  if (attestations.length === 0) return;
  lines.push("### Sensitive value presence attestations", "", "Raw values are intentionally excluded.", "");
  for (const attestation of attestations) {
    lines.push(`- ${safeMarkdown(attestation.location)} \`${safeMarkdown(attestation.name)}\`: ${safeMarkdown(attestation.classification)}, ${attestation.valueLength} characters, fingerprint \`${attestation.correlationFingerprint}\``);
    lines.push(`  Request ${safeMarkdown(attestation.requestId)} at ${safeMarkdown(attestation.observedAt)}; ${safeMarkdown(attestation.transportOutcome)}${attestation.statusCode ? `; status ${attestation.statusCode}` : ""}${attestation.responseHash ? `; response hash \`${safeMarkdown(attestation.responseHash)}\`` : ""}.`);
  }
  lines.push("");
}

function renderHtmlAttestations(attestations: readonly SafeValuePresenceAttestation[]): string {
  if (attestations.length === 0) return "";
  const items = attestations.map((attestation) => `<li><strong>${safeProofHtml(attestation.location)} ${safeProofHtml(attestation.name)}</strong>: ${safeProofHtml(attestation.classification)}, ${attestation.valueLength} characters; fingerprint <code>${safeProofHtml(attestation.correlationFingerprint)}</code><br>Request ${safeProofHtml(attestation.requestId)} at ${safeProofHtml(attestation.observedAt)}; ${safeProofHtml(attestation.transportOutcome)}${attestation.statusCode ? `; status ${attestation.statusCode}` : ""}${attestation.responseHash ? `; response hash <code>${safeProofHtml(attestation.responseHash)}</code>` : ""}</li>`).join("");
  return `<h3>Sensitive value presence attestations</h3><p>Raw values are intentionally excluded.</p><ul>${items}</ul>`;
}

function deduplicateAttestations(attestations: readonly SafeValuePresenceAttestation[]): SafeValuePresenceAttestation[] {
  const seen = new Set<string>();
  return attestations.filter((attestation) => {
    const identity = `${attestation.requestId}\0${attestation.location}\0${attestation.name}\0${attestation.correlationFingerprint}`;
    if (seen.has(identity)) return false;
    seen.add(identity);
    return true;
  });
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function safeMarkdown(value: string): string {
  return value.replace(/[<>]/g, "");
}

function safeProofHtml(value: string): string {
  return escapeHtml(value.replace(/\bon[a-z]+\s*=/gi, "event-handler="));
}
