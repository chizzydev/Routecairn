import { Command } from "commander";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { ReportDiffer, type ReportDiff } from "../../modules/changeMonitor/ReportDiffer.js";
import { loadReport } from "../../reports/ReportSummary.js";
import { defaultConfig } from "../../config/defaults.js";
import { loadScanIndex, resolveReportReference, scanIndexPath } from "../../storage/ScanIndex.js";

export function registerDiffCommand(program: Command): void {
  program
    .command("diff")
    .description("Compare two RouteCairn report.json files.")
    .argument("<oldReport>", "Older report.json.")
    .argument("<newReport>", "Newer report.json or scan ID from history.")
    .option("--reports-dir <dir>", "Reports directory containing scan-index.json.", defaultConfig.reportsDir)
    .action(async (oldReportPath: string, newReportPath: string, options: { reportsDir?: string }) => {
      const output = await diffReports(oldReportPath, newReportPath, options.reportsDir);
      console.log(output);
    });
}

export async function diffReports(oldReportPath: string, newReportPath: string, reportsDir = defaultConfig.reportsDir): Promise<string> {
  const oldResolved = await resolveReportPath(oldReportPath, reportsDir);
  const newResolved = await resolveReportPath(newReportPath, reportsDir);
  const oldReport = await loadReport(oldResolved);
  const newReport = await loadReport(newResolved);
  const diff = new ReportDiffer().diff(oldReport, newReport);

  return renderDiff(diff);
}

async function resolveReportPath(reference: string, reportsDir: string): Promise<string> {
  const direct = resolve(reference);
  if (existsSync(direct)) return direct;

  const index = await loadScanIndex(scanIndexPath(reportsDir));
  const indexed = resolveReportReference(reference, index);
  if (indexed) return indexed;

  return direct;
}

function renderDiff(diff: ReportDiff): string {
  return [
    "RouteCairn Report Diff",
    "",
    section("URLs", [
      `New URLs: ${diff.urls.new.length}`,
      ...list(diff.urls.new),
      `Removed URLs: ${diff.urls.removed.length}`,
      ...list(diff.urls.removed),
      `Changed statuses: ${diff.urls.changedStatuses.length}`,
      ...diff.urls.changedStatuses.map((item) => `- ${item.url}: ${item.oldStatus ?? "none"} -> ${item.newStatus ?? "none"}`)
    ]),
    section("Findings", [
      `New findings: ${diff.findings.new.length}`,
      ...diff.findings.new.map((finding) => `- [${finding.severity} risk ${finding.riskScore}] ${finding.title} - ${finding.url}`),
      `Resolved findings: ${diff.findings.resolved.length}`,
      ...diff.findings.resolved.map((finding) => `- [${finding.severity}] ${finding.title} - ${finding.url}`),
      `Severity changes: ${diff.findings.severityChanges.length}`,
      ...diff.findings.severityChanges.map((item) => `- ${item.title} - ${item.url}: ${item.oldSeverity} -> ${item.newSeverity}`)
    ]),
    section("Technologies", [`New: ${inline(diff.technologies.new)}`, `Removed: ${inline(diff.technologies.removed)}`]),
    section("JS Endpoints", [`New: ${diff.jsEndpoints.new.length}`, ...list(diff.jsEndpoints.new), `Removed: ${diff.jsEndpoints.removed.length}`, ...list(diff.jsEndpoints.removed)]),
    section("API Endpoints", [
      `New: ${diff.apiEndpoints.new.length}`,
      ...list(diff.apiEndpoints.new),
      `Removed: ${diff.apiEndpoints.removed.length}`,
      ...list(diff.apiEndpoints.removed)
    ]),
    section("Auth Surfaces", [
      `New: ${diff.authSurfaces.new.length}`,
      ...list(diff.authSurfaces.new),
      `Removed: ${diff.authSurfaces.removed.length}`,
      ...list(diff.authSurfaces.removed)
    ])
  ].join("\n");
}

function section(title: string, lines: string[]): string {
  return [`## ${title}`, ...lines].join("\n");
}

function list(items: string[]): string[] {
  return items.length === 0 ? ["- none"] : items.map((item) => `- ${item}`);
}

function inline(items: string[]): string {
  return items.length > 0 ? items.join(", ") : "none";
}
