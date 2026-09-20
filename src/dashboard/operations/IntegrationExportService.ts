import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, statSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import { ArtifactRepository } from "../db/DashboardRepositories.js";

export type IntegrationExportFormat = "SARIF" | "JUNIT" | "BURP_XML" | "JSON";

export class IntegrationExportService {
  private readonly artifacts: ArtifactRepository;
  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths) { this.artifacts = new ArtifactRepository(database); }

  public create(input: { organizationId: string; scanId: string; format: IntegrationExportFormat }, actor: string): { exportId: string; artifactId: string } {
    const scan = this.database.db.prepare("SELECT id,target_origin,status,created_at,completed_at FROM scans WHERE id=?").get(input.scanId) as ScanRow | undefined;
    if (!scan) throw new Error("INTEGRATION_EXPORT_SCAN_NOT_FOUND");
    const findings = this.database.db.prepare(`SELECT f.id,f.canonical_title,f.module,f.finding_category AS category,f.http_method AS method,f.safe_endpoint_identity,f.current_scanner_severity,f.current_scanner_confidence,f.canonical_description AS description,fo.evidence_summary
      FROM finding_occurrences fo JOIN findings f ON f.id=fo.finding_id WHERE fo.scan_id=? ORDER BY f.current_scanner_severity,f.canonical_title`).all(input.scanId) as FindingRow[];
    const rendered = render(input.format, scan, findings); const id = randomUUID(); const dir = resolve(this.paths.integrationsDir, id); mkdirSync(dir, { recursive: true });
    const filename = `routecairn-${input.scanId}.${rendered.extension}`; const path = resolve(dir, filename); writeFileSync(path, rendered.content, "utf8");
    const hash = createHash("sha256").update(rendered.content).digest("hex");
    const artifactId = this.artifacts.create({ scanId: input.scanId, type: `INTEGRATION_${input.format}`, name: filename, path, size: statSync(path).size, contentType: rendered.contentType, hash });
    this.database.db.prepare("INSERT INTO integration_exports (id,organization_id,format,scan_id,path,artifact_id,item_count,content_hash,created_by,created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(id, input.organizationId, input.format, input.scanId, path, artifactId, findings.length, hash, actor, nowIso());
    return { exportId: id, artifactId };
  }

  public list(organizationId: string): unknown[] { return this.database.db.prepare("SELECT id,format,scan_id AS scanId,artifact_id AS artifactId,item_count AS itemCount,content_hash AS contentHash,created_by AS createdBy,created_at AS createdAt FROM integration_exports WHERE organization_id=? ORDER BY created_at DESC LIMIT 200").all(organizationId); }
}

function render(format: IntegrationExportFormat, scan: ScanRow, findings: FindingRow[]): { extension: string; contentType: string; content: string } {
  if (format === "SARIF") return { extension: "sarif.json", contentType: "application/sarif+json", content: `${JSON.stringify(sarif(scan, findings), null, 2)}\n` };
  if (format === "JUNIT") return { extension: "junit.xml", contentType: "application/xml", content: junit(scan, findings) };
  if (format === "BURP_XML") return { extension: "burp.xml", contentType: "application/xml", content: burp(scan, findings) };
  return { extension: "json", contentType: "application/json", content: `${JSON.stringify({ schemaVersion: 1, scan, findings }, null, 2)}\n` };
}

function sarif(scan: ScanRow, findings: FindingRow[]) { const rules = [...new Map(findings.map((item) => [`${item.module}:${item.category}`, { id: ruleId(item), name: item.category, shortDescription: { text: item.canonical_title }, help: { text: item.description ?? item.evidence_summary } }])).values()]; return { version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{ tool: { driver: { name: "RouteCairn", version: "0.1.0", informationUri: "https://github.com/routecairn/routecairn", rules } }, automationDetails: { id: scan.id }, results: findings.map((item) => ({ ruleId: ruleId(item), level: sarifLevel(item.current_scanner_severity), message: { text: item.description ?? item.evidence_summary }, locations: [{ physicalLocation: { artifactLocation: { uri: safeUri(scan.target_origin, item.safe_endpoint_identity) } } }], partialFingerprints: { routeCairnFindingId: item.id }, properties: { confidence: item.current_scanner_confidence, module: item.module, method: item.method } })) }] }; }
function junit(scan: ScanRow, findings: FindingRow[]): string { const failures = findings.filter((item) => !["Info"].includes(item.current_scanner_severity)); const cases = findings.map((item) => `<testcase classname="${xml(item.module)}" name="${xml(item.canonical_title)}" time="0">${item.current_scanner_severity === "Info" ? `<system-out>${xml(item.evidence_summary)}</system-out>` : `<failure type="${xml(item.category)}" message="${xml(item.current_scanner_severity)}">${xml(item.description ?? item.evidence_summary)}</failure>`}</testcase>`).join(""); return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites><testsuite name="RouteCairn ${xml(scan.id)}" tests="${findings.length}" failures="${failures.length}" errors="0" skipped="0">${cases}</testsuite></testsuites>\n`; }
function burp(scan: ScanRow, findings: FindingRow[]): string { return `<?xml version="1.0" encoding="UTF-8"?>\n<issues burpVersion="RouteCairn 0.1.0" exportTime="${xml(nowIso())}">${findings.map((item) => `<issue><serialNumber>${xml(item.id)}</serialNumber><type>0</type><name>${xml(item.canonical_title)}</name><host ip="">${xml(scan.target_origin)}</host><path>${xml(item.safe_endpoint_identity)}</path><location>${xml(item.method)} ${xml(item.safe_endpoint_identity)}</location><severity>${xml(burpSeverity(item.current_scanner_severity))}</severity><confidence>${xml(item.current_scanner_confidence)}</confidence><issueBackground>${xml(item.description ?? "")}</issueBackground><issueDetail>${xml(item.evidence_summary)}</issueDetail></issue>`).join("")}</issues>\n`; }
function ruleId(item: FindingRow): string { return `${item.module}/${item.category}`.replace(/[^A-Za-z0-9_./-]/g, "-").slice(0, 200); }
function sarifLevel(value: string): string { return ["Critical", "High"].includes(value) ? "error" : value === "Medium" ? "warning" : "note"; }
function burpSeverity(value: string): string { return value === "Critical" ? "High" : ["High", "Medium", "Low", "Information"].includes(value) ? value : value === "Info" ? "Information" : "Low"; }
function safeUri(origin: string, endpoint: string): string { try { return new URL(endpoint, origin).toString().replace(/[?#].*$/, ""); } catch { return origin; } }
function xml(value: unknown): string { return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, ""); }
interface ScanRow { id: string; target_origin: string; status: string; created_at: string; completed_at: string | null }
interface FindingRow { id: string; canonical_title: string; module: string; category: string; method: string; safe_endpoint_identity: string; current_scanner_severity: string; current_scanner_confidence: string; description: string | null; evidence_summary: string }
