import type { Finding } from "../../core/findings/Finding.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";

export interface ReportDiff {
  urls: {
    new: string[];
    removed: string[];
    changedStatuses: Array<{ url: string; oldStatus?: number; newStatus?: number }>;
  };
  findings: {
    new: Finding[];
    resolved: Finding[];
    severityChanges: Array<{ id: string; title: string; url: string; oldSeverity: string; newSeverity: string }>;
  };
  technologies: {
    new: string[];
    removed: string[];
  };
  jsEndpoints: {
    new: string[];
    removed: string[];
  };
  apiEndpoints: {
    new: string[];
    removed: string[];
  };
  authSurfaces: {
    new: string[];
    removed: string[];
  };
}

export class ReportDiffer {
  public diff(oldReport: RouteCairnReport, newReport: RouteCairnReport): ReportDiff {
    const oldUrlMap = mapUrls(oldReport);
    const newUrlMap = mapUrls(newReport);
    const oldFindingMap = mapFindings(oldReport.findings);
    const newFindingMap = mapFindings(newReport.findings);

    return {
      urls: {
        new: difference([...newUrlMap.keys()], [...oldUrlMap.keys()]),
        removed: difference([...oldUrlMap.keys()], [...newUrlMap.keys()]),
        changedStatuses: changedStatuses(oldUrlMap, newUrlMap)
      },
      findings: {
        new: difference([...newFindingMap.keys()], [...oldFindingMap.keys()]).map((key) => newFindingMap.get(key)).filter((finding): finding is Finding => Boolean(finding)),
        resolved: difference([...oldFindingMap.keys()], [...newFindingMap.keys()]).map((key) => oldFindingMap.get(key)).filter((finding): finding is Finding => Boolean(finding)),
        severityChanges: severityChanges(oldFindingMap, newFindingMap)
      },
      technologies: diffSets(technologyNames(oldReport), technologyNames(newReport)),
      jsEndpoints: diffSets(jsEndpoints(oldReport), jsEndpoints(newReport)),
      apiEndpoints: diffSets(apiEndpoints(oldReport), apiEndpoints(newReport)),
      authSurfaces: diffSets(authSurfaces(oldReport), authSurfaces(newReport))
    };
  }
}

function mapUrls(report: RouteCairnReport): Map<string, number | undefined> {
  return new Map(report.discoveredUrls.map((item) => [item.url, item.statusCode]));
}

function mapFindings(findings: Finding[]): Map<string, Finding> {
  return new Map(findings.map((finding) => [findingKey(finding), finding]));
}

function findingKey(finding: Finding): string {
  return `${finding.type}:${finding.url}:${finding.title}`;
}

function changedStatuses(oldUrls: Map<string, number | undefined>, newUrls: Map<string, number | undefined>): ReportDiff["urls"]["changedStatuses"] {
  const changes = [];

  for (const [url, oldStatus] of oldUrls) {
    if (!newUrls.has(url)) {
      continue;
    }

    const newStatus = newUrls.get(url);
    if (oldStatus !== newStatus) {
      changes.push({
        url,
        ...(typeof oldStatus === "number" ? { oldStatus } : {}),
        ...(typeof newStatus === "number" ? { newStatus } : {})
      });
    }
  }

  return changes;
}

function severityChanges(oldFindings: Map<string, Finding>, newFindings: Map<string, Finding>): ReportDiff["findings"]["severityChanges"] {
  const changes = [];

  for (const [key, oldFinding] of oldFindings) {
    const newFinding = newFindings.get(key);

    if (newFinding && oldFinding.severity !== newFinding.severity) {
      changes.push({
        id: newFinding.id,
        title: newFinding.title,
        url: newFinding.url,
        oldSeverity: oldFinding.severity,
        newSeverity: newFinding.severity
      });
    }
  }

  return changes;
}

function diffSets(oldItems: string[], newItems: string[]): { new: string[]; removed: string[] } {
  return {
    new: difference(newItems, oldItems),
    removed: difference(oldItems, newItems)
  };
}

function difference(left: string[], right: string[]): string[] {
  const rightSet = new Set(right);
  return [...new Set(left)].filter((item) => !rightSet.has(item)).sort();
}

function technologyNames(report: RouteCairnReport): string[] {
  return report.technologies.map((technology) => technology.name);
}

function jsEndpoints(report: RouteCairnReport): string[] {
  return report.jsIntelligence?.queuedEndpoints.map((endpoint) => endpoint.path) ?? [];
}

function apiEndpoints(report: RouteCairnReport): string[] {
  return report.apiMapper?.endpoints.map((endpoint) => endpoint.endpoint) ?? [];
}

function authSurfaces(report: RouteCairnReport): string[] {
  return report.authSurface?.surfaces.map((surface) => surface.endpoint) ?? [];
}
