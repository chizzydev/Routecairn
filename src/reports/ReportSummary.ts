import { readFile } from "node:fs/promises";
import type { Finding } from "../core/findings/Finding.js";
import type { Severity } from "../core/findings/Severity.js";
import type { RouteCairnReport } from "./ReportTypes.js";

export interface ReportSummary {
  target: string;
  program: string;
  mode: string;
  startedAt: string;
  completedAt: string;
  totalRequests: number;
  urlsChecked: number;
  findingsTotal: number;
  findingsBySeverity: Record<Severity, number>;
  technologies: string[];
  apiEndpoints: string[];
  jsEndpoints: string[];
  authSurfaces: string[];
  vulnerabilityWorkflows: string[];
  highSignalFindings: Finding[];
}

export async function loadReport(filePath: string): Promise<RouteCairnReport> {
  return JSON.parse(await readFile(filePath, "utf8")) as RouteCairnReport;
}

export function summarizeReport(report: RouteCairnReport): ReportSummary {
  return {
    target: report.target,
    program: report.program,
    mode: report.mode,
    startedAt: report.metadata.startedAt,
    completedAt: report.metadata.completedAt,
    totalRequests: report.metadata.totalRequests,
    urlsChecked: report.discoveredUrls.length,
    findingsTotal: report.findings.length,
    findingsBySeverity: countFindingsBySeverity(report.findings),
    technologies: report.technologies.map((technology) => technology.name).sort(),
    apiEndpoints: [...new Set(report.apiMapper?.endpoints.map((endpoint) => endpoint.endpoint) ?? [])].sort(),
    jsEndpoints: [...new Set(report.jsIntelligence?.queuedEndpoints.map((endpoint) => endpoint.path) ?? [])].sort(),
    authSurfaces: [...new Set(report.authSurface?.surfaces.map((surface) => surface.endpoint) ?? [])].sort(),
    vulnerabilityWorkflows: report.vulnerabilityWorkflows?.workflows.map((workflow) => workflow.title).sort() ?? [],
    highSignalFindings: report.findings
      .filter((finding) => ["Critical", "High", "Medium"].includes(finding.severity))
      .sort((left, right) => right.riskScore - left.riskScore)
      .slice(0, 10)
  };
}

function countFindingsBySeverity(findings: Finding[]): Record<Severity, number> {
  return findings.reduce<Record<Severity, number>>(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    {
      Informational: 0,
      Low: 0,
      Medium: 0,
      High: 0,
      Critical: 0
    }
  );
}
