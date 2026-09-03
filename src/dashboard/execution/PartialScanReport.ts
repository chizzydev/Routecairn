import { lstat, readFile, realpath } from "node:fs/promises";
import { join, relative, resolve, isAbsolute } from "node:path";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { JsonReportWriter } from "../../reports/JsonReportWriter.js";
import { MarkdownReportWriter } from "../../reports/MarkdownReportWriter.js";
import { HtmlReportWriter } from "../../reports/HtmlReportWriter.js";
import { readMutationCleanupStatus } from "../../core/offensive/MutationCleanupStatus.js";

export interface ScanReportPaths { reportPath: string; markdownReportPath: string; htmlReportPath: string }

/** Only this job's canonical directory is eligible. Worker-provided arbitrary
 * paths, symlinks, and checkpoints for another target are never imported. */
export function canonicalScanReportPaths(paths: DashboardPaths, scanId: string): ScanReportPaths {
  if (!/^[a-f0-9-]{36}$/i.test(scanId)) throw new Error("Invalid scan identifier.");
  const directory = resolve(paths.reportsDir, scanId);
  return { reportPath: join(directory, "report.json"), markdownReportPath: join(directory, "report.md"), htmlReportPath: join(directory, "report.html") };
}

export async function preservePartialScanReport(paths: DashboardPaths, scanId: string, target: string, status: "CANCELLED" | "FAILED" | "INTERRUPTED"): Promise<ScanReportPaths | undefined> {
  const expected = canonicalScanReportPaths(paths, scanId);
  const directory = resolve(paths.reportsDir, scanId);
  try {
    const root = await realpath(paths.reportsDir);
    const realDirectory = await realpath(directory);
    const within = relative(root, realDirectory);
    if (within.startsWith("..") || isAbsolute(within) || (await lstat(directory)).isSymbolicLink()) throw new Error("Unsafe report directory.");
  } catch (error) { if (isMissing(error)) return; throw error; }
  let report: RouteCairnReport | undefined;
  for (const path of [expected.reportPath, join(directory, "report.partial.json")]) {
    try {
      const info = await lstat(path);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 64 * 1024 * 1024) throw new Error("Unsafe partial report.");
      const value: unknown = JSON.parse(await readFile(path, "utf8"));
      if (!validCheckpoint(value, target)) throw new Error("Invalid or mismatched partial report.");
      report = value;
      break;
    } catch (error) { if (!isMissing(error)) throw error; }
  }
  if (!report?.execution) return;
  report.execution = { ...report.execution, status, partial: true, reason: status === "INTERRUPTED" ? "Worker terminated before completion. Evidence is limited to the last durable checkpoint; missing coverage is not a pass." : status === "CANCELLED" ? "Execution cancelled. Partial evidence and independent cleanup state are retained." : "Execution failed. Partial evidence and independent cleanup state are retained." };
  try {
    const cleanup = await readMutationCleanupStatus(paths.mutationJournalDir, paths.mutationJournalRegistryPath);
    report.execution.cleanup = { state: cleanup.cases.length ? "REQUIRED" : "CLEAR", cases: cleanup.cases.map(({ caseId, stage, recoveryBundleAvailable }) => ({ caseId, stage, recoveryBundleAvailable })) };
  } catch { report.execution.cleanup = { state: "UNKNOWN", cases: [] }; }
  // Never rewrite the last durable checkpoint. It remains available if report
  // rendering or ingestion itself is interrupted and retried after restart.
  await new JsonReportWriter().write(directory, report);
  await new MarkdownReportWriter().write(directory, report);
  await new HtmlReportWriter().write(directory, report);
  return expected;
}

function isMissing(error: unknown): boolean { return Boolean(error && typeof error === "object" && "code" in error && error.code === "ENOENT"); }
function validCheckpoint(value: unknown, target: string): value is RouteCairnReport {
  if (!value || typeof value !== "object") return false;
  const report = value as RouteCairnReport;
  let sameTarget = false;
  try { sameTarget = new URL(report.target).origin === new URL(target).origin; } catch { return false; }
  return sameTarget && Boolean(report.execution && typeof report.execution.partial === "boolean" && report.metadata && report.scanPlan && report.scope) && Array.isArray(report.findings) && Array.isArray(report.responses) && Array.isArray(report.discoveredUrls) && Array.isArray(report.requestAudit);
}
