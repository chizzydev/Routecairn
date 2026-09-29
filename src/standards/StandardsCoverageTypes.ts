export const standardsFrameworks = ["OWASP_WSTG", "OWASP_ASVS", "OWASP_API_TOP_10", "CWE", "CAPEC"] as const;
export type StandardsFramework = (typeof standardsFrameworks)[number];

export type StandardsCoverageOutcome = "FINDING" | "NO_FINDING" | "INCONCLUSIVE" | "BLOCKED" | "OBSERVED";
export type StandardsCoverageStrength = "DIRECT" | "SUPPORTING";

export interface StandardsReference {
  framework: StandardsFramework;
  id: string;
  title: string;
  url: string;
  strength: StandardsCoverageStrength;
}

export interface StandardsCoverageCase {
  moduleId: string;
  caseId: string;
  label: string;
  outcome: StandardsCoverageOutcome;
  executed: true;
  requestTransmitted?: boolean;
  findingIds: readonly string[];
  evidenceRefs: readonly string[];
  references: readonly StandardsReference[];
}

export interface StandardsRequirementCoverage {
  framework: StandardsFramework;
  id: string;
  title: string;
  url: string;
  directCases: number;
  supportingCases: number;
  findings: number;
  noFindings: number;
  inconclusive: number;
  blocked: number;
  observed: number;
  caseIds: readonly string[];
}

export interface WstgAreaCoverage {
  id: string;
  title: string;
  status: "COVERED" | "PARTIAL" | "NOT_ASSESSED";
  executedCases: number;
  conclusiveCases: number;
  requirementIds: readonly string[];
}

export interface StandardsCoverageGap {
  id: string;
  title: string;
  framework: StandardsFramework;
  priority: "HIGH" | "MEDIUM" | "LOW";
  status: "NOT_ASSESSED" | "INCONCLUSIVE_ONLY" | "SUPPORTING_ONLY";
  reason: string;
}

export interface StandardsCoverageReport {
  schemaVersion: 1;
  generatedAt: string;
  catalog: {
    wstg: "latest";
    wstgSnapshotDate: string;
    asvs: "5.0.0";
    apiSecurityTop10: "2023";
    cwe: "current";
    capec: "current";
  };
  accounting: {
    plannedModules: number;
    executedCases: number;
    directlyMappedCases: number;
    supportingOnlyCases: number;
    unmappedCases: number;
    findings: number;
    noFindings: number;
    inconclusive: number;
    blocked: number;
    observed: number;
  };
  cases: readonly StandardsCoverageCase[];
  requirements: readonly StandardsRequirementCoverage[];
  wstgAreas: readonly WstgAreaCoverage[];
  apiRiskObjectives: readonly {
    id: "API4:2023" | "API6:2023" | "API10:2023";
    title: string;
    engineIds: readonly string[];
    executedCases: number;
    conclusiveCases: number;
    status: "COVERED" | "PARTIAL" | "NOT_ASSESSED";
  }[];
  gaps: readonly StandardsCoverageGap[];
  notes: readonly string[];
}
