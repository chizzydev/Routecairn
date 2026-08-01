import { Command } from "commander";
import { resolve } from "node:path";
import { loadReport, summarizeReport } from "../../reports/ReportSummary.js";

export function registerShowCommand(program: Command): void {
  program
    .command("show")
    .description("Show a clean summary of a RouteCairn report.json file.")
    .argument("<report>", "Path to report.json.")
    .action(async (reportPath: string) => {
      const output = await showReport(reportPath);
      console.log(output);
    });
}

export async function showReport(reportPath: string): Promise<string> {
  const report = await loadReport(resolve(reportPath));
  const summary = summarizeReport(report);

  return [
    "RouteCairn Report Summary",
    "",
    `Target: ${summary.target}`,
    `Program: ${summary.program}`,
    `Mode: ${summary.mode}`,
    `Started: ${summary.startedAt}`,
    `Completed: ${summary.completedAt}`,
    `Requests: ${summary.totalRequests}`,
    `URLs checked: ${summary.urlsChecked}`,
    `Findings: ${summary.findingsTotal}`,
    `Severity: Critical ${summary.findingsBySeverity.Critical}, High ${summary.findingsBySeverity.High}, Medium ${summary.findingsBySeverity.Medium}, Low ${summary.findingsBySeverity.Low}, Info ${summary.findingsBySeverity.Informational}`,
    `Technologies: ${summary.technologies.length > 0 ? summary.technologies.join(", ") : "none"}`,
    `API endpoints: ${summary.apiEndpoints.length}`,
    `JS endpoints: ${summary.jsEndpoints.length}`,
    `Auth surfaces: ${summary.authSurfaces.length}`,
    `Vulnerability workflows: ${summary.vulnerabilityWorkflows.length}`,
    "",
    "Top Findings:",
    ...topFindingLines(summary.highSignalFindings)
  ].join("\n");
}

function topFindingLines(findings: Array<{ severity: string; riskScore: number; title: string; url: string }>): string[] {
  if (findings.length === 0) {
    return ["- none"];
  }

  return findings.map((finding) => `- [${finding.severity} risk ${finding.riskScore}] ${finding.title} - ${finding.url}`);
}
