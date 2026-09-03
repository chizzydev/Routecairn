import { createHash, randomUUID } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { ArtifactRepository, ScanRepository } from "../db/DashboardRepositories.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { ImportResult } from "../types/DashboardTypes.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { FindingNormalizer } from "../findings/FindingNormalizer.js";
import { FindingFingerprintService } from "../findings/FindingFingerprintService.js";
import { safeHash } from "../security/Redaction.js";

const maxImportBytes = 10 * 1024 * 1024;

export class HistoricalReportImporter {
  private readonly scans: ScanRepository;
  private readonly artifacts: ArtifactRepository;
  private readonly normalizer: FindingNormalizer;

  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths) {
    this.scans = new ScanRepository(database);
    this.artifacts = new ArtifactRepository(database);
    this.normalizer = new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath));
  }

  public importReport(reportPath: string): ImportResult {
    const canonical = safeContainedPath(reportPath, [resolve("reports"), this.paths.reportsDir]);
    const stat = statSync(canonical);
    if (stat.size > maxImportBytes) throw new Error("Report file is too large to import safely.");
    const raw = readFileSync(canonical, "utf8");
    const report = JSON.parse(raw) as RouteCairnReport;
    const reportFingerprint = safeHash(raw);
    const sourceFingerprint = safeHash(canonical);
    const existing = this.database.db
      .prepare("SELECT imported_scan_id FROM import_records WHERE source_path_fingerprint = ? AND report_fingerprint = ?")
      .get(sourceFingerprint, reportFingerprint) as { imported_scan_id: string } | undefined;
    if (existing) return { scanId: existing.imported_scan_id, warnings: ["Report was already imported; returning existing dashboard scan."] };

    const scanId = randomUUID();
    const targetOrigin = new URL(report.target).origin;
    this.database.transaction(() => {
      this.scans.create({
        id: scanId,
        source: "REPORT_IMPORTED",
        status: report.execution?.partial ? report.execution.status === "CANCELLED" ? "CANCELLED" : report.execution.status === "FAILED" ? "FAILED" : "INTERRUPTED" : "IMPORTED",
        targetOrigin,
        safeTargetLabel: targetOrigin,
        profile: report.profile?.name ?? report.mode,
        evidenceLevel: report.scanPlan?.evidence.level ?? "imported",
        safeConfigurationSummary: { imported: true, source: canonical }
      });
      const artifactId = this.artifacts.create({
        scanId,
        type: "JSON_REPORT",
        name: "imported-report.json",
        path: canonical,
        size: stat.size,
        contentType: "application/json",
        hash: createHash("sha256").update(raw).digest("hex")
      });
      this.scans.attachArtifacts(scanId, { json: artifactId });
      this.database.db
        .prepare("INSERT INTO import_records (id, source_path_fingerprint, report_fingerprint, imported_scan_id, import_status, import_warnings_json, imported_at) VALUES (?, ?, ?, ?, 'IMPORTED', ?, ?)")
        .run(randomUUID(), sourceFingerprint, reportFingerprint, scanId, JSON.stringify(["Progress and module timing history are unavailable for imported reports."]), nowIso());
    });
    this.normalizer.normalizeReport(scanId, report);
    this.scans.updateCounters(scanId);
    return { scanId, warnings: ["Imported reports have limited progress and event history."] };
  }
}

function safeContainedPath(input: string, roots: readonly string[]): string {
  const candidate = resolve(input);
  const link = lstatSync(candidate);
  if (link.isSymbolicLink()) throw new Error("Symlink imports are rejected.");
  const real = realpathSync(candidate);
  const allowed = roots.map((root) => realpathSync(resolve(root))).some((root) => real === root || real.startsWith(`${root}\\`) || real.startsWith(`${root}/`));
  if (!allowed) throw new Error("Report import path is outside approved RouteCairn output roots.");
  if (dirname(real) === real) throw new Error("Import path must be a file.");
  return real;
}
