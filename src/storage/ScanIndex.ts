import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type { RouteCairnReport } from "../reports/ReportTypes.js";

export const scanIndexFileName = "scan-index.json";

export interface ScanIndexEntry {
  id: string;
  target: string;
  domain: string;
  program: string;
  mode: string;
  profile?: string;
  startedAt: string;
  completedAt: string;
  outputDir: string;
  reportPath: string;
  markdownReportPath?: string;
  htmlReportPath?: string;
  counts: {
    requests: number;
    urls: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
    technologies: number;
    apiEndpoints: number;
    jsEndpoints: number;
    authSurfaces: number;
  };
  technologies: string[];
  findingTypes: string[];
  endpoints: string[];
}

export interface ScanIndex {
  schemaVersion: 1;
  updatedAt: string;
  scans: ScanIndexEntry[];
}

export interface ScanIndexSearchQuery {
  domain?: string;
  findingType?: string;
  technology?: string;
  endpoint?: string;
  target?: string;
}

export function scanIndexPath(reportsDir: string): string {
  return join(resolve(reportsDir), scanIndexFileName);
}

export async function loadScanIndex(indexPath: string): Promise<ScanIndex> {
  try {
    const raw = await readFile(indexPath, "utf8");
    const parsed = JSON.parse(raw) as ScanIndex;
    return {
      schemaVersion: 1,
      updatedAt: parsed.updatedAt ?? new Date().toISOString(),
      scans: Array.isArray(parsed.scans) ? parsed.scans : []
    };
  } catch (error) {
    if (isMissingFileError(error)) {
      return { schemaVersion: 1, updatedAt: new Date().toISOString(), scans: [] };
    }
    if (error instanceof SyntaxError) {
      return { schemaVersion: 1, updatedAt: new Date().toISOString(), scans: [] };
    }
    throw error;
  }
}

export async function saveScanIndex(indexPath: string, index: ScanIndex): Promise<void> {
  await mkdir(dirname(indexPath), { recursive: true });
  await writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8");
}

export async function recordScan(indexPath: string, entry: ScanIndexEntry): Promise<ScanIndex> {
  const index = await loadScanIndex(indexPath);
  const scans = [entry, ...index.scans.filter((scan) => scan.id !== entry.id && scan.reportPath !== entry.reportPath)];
  const next = { schemaVersion: 1 as const, updatedAt: new Date().toISOString(), scans };
  await saveScanIndex(indexPath, next);
  return next;
}

export function entryFromReport(report: RouteCairnReport, paths: { outputDir: string; reportPath: string; markdownReportPath?: string; htmlReportPath?: string }): ScanIndexEntry {
  const severityCounts = countSeverity(report);
  const technologies = [...new Set(report.technologies.map((technology) => technology.name))].sort();
  const findingTypes = [...new Set(report.findings.map((finding) => finding.type))].sort();
  const endpoints = [
    ...(report.apiMapper?.endpoints.map((endpoint) => endpoint.endpoint) ?? []),
    ...(report.jsIntelligence?.queuedEndpoints.map((endpoint) => endpoint.path) ?? []),
    ...(report.authSurface?.surfaces.map((surface) => surface.endpoint) ?? [])
  ];

  return {
    id: scanId(report),
    target: report.target,
    domain: domainForTarget(report.target),
    program: report.program,
    mode: report.mode,
    ...(report.profile ? { profile: report.profile.name } : {}),
    startedAt: report.metadata.startedAt,
    completedAt: report.metadata.completedAt,
    outputDir: paths.outputDir,
    reportPath: paths.reportPath,
    ...(paths.markdownReportPath ? { markdownReportPath: paths.markdownReportPath } : {}),
    ...(paths.htmlReportPath ? { htmlReportPath: paths.htmlReportPath } : {}),
    counts: {
      requests: report.metadata.totalRequests,
      urls: report.discoveredUrls.length,
      findings: report.findings.length,
      critical: severityCounts.Critical,
      high: severityCounts.High,
      medium: severityCounts.Medium,
      low: severityCounts.Low,
      informational: severityCounts.Informational,
      technologies: technologies.length,
      apiEndpoints: report.apiMapper?.endpoints.length ?? 0,
      jsEndpoints: report.jsIntelligence?.queuedEndpoints.length ?? 0,
      authSurfaces: report.authSurface?.surfaces.length ?? 0
    },
    technologies,
    findingTypes,
    endpoints: [...new Set(endpoints)].sort()
  };
}

export function searchScanIndex(index: ScanIndex, query: ScanIndexSearchQuery): ScanIndexEntry[] {
  const { domain, target, findingType, technology, endpoint } = query;

  return index.scans.filter((scan) => {
    if (domain && !includes(scan.domain, domain) && !includes(scan.target, domain)) return false;
    if (target && !includes(scan.target, target)) return false;
    if (findingType && !scan.findingTypes.some((type) => includes(type, findingType))) return false;
    if (technology && !scan.technologies.some((item) => includes(item, technology))) return false;
    if (endpoint && !scan.endpoints.some((item) => includes(item, endpoint))) return false;
    return true;
  });
}

export function resolveReportReference(reference: string, index: ScanIndex): string | undefined {
  const exact = index.scans.find((scan) => scan.id === reference);
  if (exact) return exact.reportPath;

  const prefixMatches = index.scans.filter((scan) => scan.id.startsWith(reference));
  if (prefixMatches.length === 1) return prefixMatches[0]?.reportPath;

  return undefined;
}

export function latestScansForDomain(index: ScanIndex, domain: string, count = 2): ScanIndexEntry[] {
  return index.scans.filter((scan) => includes(scan.domain, domain) || includes(scan.target, domain)).slice(0, count);
}

export function timestampedOutputDir(reportsDir: string, target: string, profileName: string, date = new Date()): string {
  return join(resolve(reportsDir), `${safeDomainLabel(domainForTarget(target))}-${profileName}-${timestampLabel(date)}`);
}

function scanId(report: RouteCairnReport): string {
  return `${safeDomainLabel(domainForTarget(report.target))}-${report.profile?.name ?? report.mode}-${compactTimestamp(report.metadata.completedAt)}`;
}

function domainForTarget(target: string): string {
  try {
    return new URL(target).hostname.toLowerCase();
  } catch {
    return target.toLowerCase();
  }
}

function safeDomainLabel(value: string): string {
  return value.replace(/^www\./, "").replace(/[^a-z0-9.-]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "scan";
}

function compactTimestamp(value: string): string {
  return value.replace(/[^0-9]/g, "").slice(0, 14) || timestampLabel(new Date());
}

function timestampLabel(date: Date): string {
  return date.toISOString().replace(/[^0-9]/g, "").slice(0, 14);
}

function includes(value: string, needle: string): boolean {
  return value.toLowerCase().includes(needle.toLowerCase());
}

function countSeverity(report: RouteCairnReport): Record<"Critical" | "High" | "Medium" | "Low" | "Informational", number> {
  return report.findings.reduce(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 }
  );
}

function isMissingFileError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
