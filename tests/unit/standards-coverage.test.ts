import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { activeVulnerabilityClasses } from "../../src/modules/activeVulnerability/ActiveVulnerabilityTypes.js";
import { protocolSecurityKinds } from "../../src/modules/protocolSecurity/ProtocolSecurityTypes.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { buildStandardsCoverage } from "../../src/standards/StandardsCoverage.js";
import { StandardsCoverageWriter } from "../../src/standards/StandardsCoverageWriter.js";
import { mappingFor } from "../../src/standards/StandardsMappings.js";
import { referencesFor, wstgAreas } from "../../src/standards/StandardsCatalog.js";
import { validateStandardsCoverage } from "../../src/standards/StandardsCoverageValidation.js";
import { validateBuiltInStandardsMappings } from "../../src/standards/StandardsMappingValidation.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("standards-native coverage accounting", () => {
  it("retains source-module mappings for proof observations without asserting verification", () => {
    const coverage = buildStandardsCoverage(report({
      findings: [{ id: "finding-proof-header", sourceModule: "header-review", type: "Nonstandard header observation", title: "Header observation", tags: [] }],
      proofMode: { blocks: [{ id: "proof-finding-proof-header", source: "finding", title: "Header observation", comparisons: [] }] }
    }));
    const observed = coverage.cases.find((item) => item.moduleId === "proof-mode");
    expect(observed?.outcome).toBe("OBSERVED");
    expect(observed?.references.length).toBeGreaterThan(0);
  });
  it("maps every active-vulnerability and protocol case kind to validated standards references", () => {
    for (const vulnerabilityClass of activeVulnerabilityClasses) {
      const references = referencesFor(mappingFor("active-vulnerability-validation", vulnerabilityClass));
      expect(references.length, vulnerabilityClass).toBeGreaterThan(0);
      expect(references.some((item) => item.strength === "DIRECT"), vulnerabilityClass).toBe(true);
    }
    for (const kind of protocolSecurityKinds) {
      const references = referencesFor(mappingFor("protocol-security", kind));
      expect(references.length, kind).toBeGreaterThan(0);
      expect(references.some((item) => item.strength === "DIRECT"), kind).toBe(true);
    }
  });

  it("accounts for direct, supporting, unresolved, gap, and all 12 WSTG-area states", () => {
    const coverage = buildStandardsCoverage(report({
      activeVulnerability: {
        enabled: true,
        plannedCases: 3,
        explicitCases: 3,
        discoveredCases: 0,
        provenCases: 1,
        secureCases: 1,
        inconclusiveCases: 1,
        blockedCases: 0,
        cases: [
          { caseId: "sql-1", label: "SQL differential", vulnerabilityClass: "SQL_INJECTION", outcome: "PROVEN", strategiesExecuted: 2, strategiesPlanned: 2 },
          { caseId: "dom-1", label: "DOM source sink", vulnerabilityClass: "DOM_XSS", outcome: "SECURE_FOR_CASE", strategiesExecuted: 1, strategiesPlanned: 1 },
          { caseId: "ssrf-1", label: "Blind SSRF", vulnerabilityClass: "SSRF", outcome: "INCONCLUSIVE", strategiesExecuted: 1, strategiesPlanned: 1 }
        ]
      },
      businessInvariant: {
        observations: [{ caseId: "flow-1", label: "Ticket purchase limit", category: "USAGE_LIMIT", outcome: "PASS", actions: [{ attemptsTransmitted: 1 }] }]
      },
      protocolSecurity: {
        observations: [{ caseId: "gzip-1", label: "Bounded decompression", kind: "COMPRESSION_BOUNDARY", outcome: "BLOCKED" }]
      }
    }));
    expect(coverage.accounting.executedCases).toBe(6);
    expect(coverage.accounting.directlyMappedCases).toBe(6);
    expect(coverage.accounting.findings).toBe(1);
    expect(coverage.accounting.noFindings).toBe(2);
    expect(coverage.accounting.observed).toBe(1);
    expect(coverage.accounting.inconclusive).toBe(1);
    expect(coverage.accounting.blocked).toBe(1);
    expect(coverage.wstgAreas).toHaveLength(12);
    expect(coverage.wstgAreas.find((item) => item.id === "BUSL")).toMatchObject({ executedCases: 2, conclusiveCases: 1 });
    expect(coverage.requirements.some((item) => item.id === "API6:2023" && item.noFindings === 1)).toBe(true);
    expect(coverage.requirements.some((item) => item.id === "API4:2023" && item.blocked === 1)).toBe(true);
    expect(coverage.apiRiskObjectives.find((item) => item.id === "API6:2023")).toMatchObject({ status: "COVERED", engineIds: ["business-invariant"] });
    expect(coverage.gaps.some((item) => item.id === "API4:2023" && item.status === "INCONCLUSIVE_ONLY")).toBe(true);
    expect(coverage.gaps.some((item) => item.id === "API10:2023" && item.status === "NOT_ASSESSED")).toBe(true);
  });

  it("does not infer completed-module passes into partial reports", () => {
    const coverage = buildStandardsCoverage(report({}, "FAILED"));
    expect(coverage.cases).toEqual([]);
    expect(coverage.accounting.executedCases).toBe(0);
  });

  it("writes deterministic secret-free JSON and normalized CSV exports", async () => {
    const coverage = buildStandardsCoverage(report({ activeVulnerability: { enabled: true, plannedCases: 1, explicitCases: 1, discoveredCases: 0, provenCases: 0, secureCases: 1, inconclusiveCases: 0, blockedCases: 0, cases: [{ caseId: "quoted,case", label: "Quoted \"label\"\nline", vulnerabilityClass: "NOSQL_INJECTION", outcome: "SECURE_FOR_CASE", strategiesExecuted: 1, strategiesPlanned: 1 }] } }));
    const directory = await mkdtemp(join(tmpdir(), "routecairn-standards-"));
    directories.push(directory);
    const paths = await new StandardsCoverageWriter().write(directory, coverage);
    const json = JSON.parse(await readFile(paths.jsonPath, "utf8"));
    const csv = await readFile(paths.csvPath, "utf8");
    expect(json.catalog.asvs).toBe("5.0.0");
    expect(json.cases[0].label).toBe('Quoted "label" line');
    expect(csv).toContain('"quoted,case"');
    expect(csv).toContain('"Quoted ""label"" line"');
    expect(csv).toContain('"WSTG-v42-INPV-05"');
  });

  it("keeps the WSTG accounting taxonomy fixed to the 12 published testing areas", () => {
    expect(wstgAreas.map((item) => item.id)).toEqual(["INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS", "INPV", "ERRH", "CRYP", "BUSL", "CLNT", "APIT"]);
  });

  it("validates all declared built-in cases and never maps unknown engine kinds by a substring fallback", () => {
    expect(validateBuiltInStandardsMappings()).toHaveLength(111);
    for (const id of ["active-vulnerability-validation", "protocol-security", "authentication-lifecycle", "unknown-detector"]) expect(referencesFor(mappingFor(id, "FUTURE_SQL_GRAPHQL_MFA"))).toEqual([]);
  });

  it("fails accounting for unmapped cases and missing case identities", () => {
    for (const item of [{ caseId: "new", vulnerabilityClass: "UNKNOWN", outcome: "PROVEN" }, { caseId: "", vulnerabilityClass: "SQL_INJECTION", outcome: "PROVEN" }]) expect(() => buildStandardsCoverage(report({ activeVulnerability: { cases: [{ ...item, strategiesExecuted: 1 }] } }))).toThrow(/STANDARDS_(UNMAPPED_CASES|CASE_ID_REQUIRED)/);
    expect(() => buildStandardsCoverage(report({ findings: [{ id: "new-finding", sourceModule: "community-detector", type: "Unmapped community result", title: "New finding" }] }))).toThrow("STANDARDS_UNMAPPED_CASES");
  });

  it("counts a partial area against the complete official denominator", () => {
    const coverage = buildStandardsCoverage(report({ activeVulnerability: { cases: [{ caseId: "sql", vulnerabilityClass: "SQL_INJECTION", outcome: "SECURE_FOR_CASE", strategiesExecuted: 1 }] } }));
    expect(coverage.wstgAreas.find((item) => item.id === "INPV")).toMatchObject({ status: "PARTIAL", catalogRequirements: 19, mappedRequirements: 1, conclusiveRequirements: 1 });
    expect(coverage.frameworkTotals.find((item) => item.framework === "OWASP_ASVS")).toMatchObject({ activeEntries: 345, mappedEntries: 4, conclusiveEntries: 1, unassessedEntries: 344 });
    expect(() => validateStandardsCoverage(coverage)).not.toThrow();
  });

  it("preserves finding linkage for findings synthesized outside workflow cases", () => {
    const coverage = buildStandardsCoverage(report({ findings: [{ id: "cookie-finding", sourceModule: "cookie-review", type: "Session cookie missing HttpOnly", title: "HttpOnly missing" }] }));
    expect(coverage.cases.find((item) => item.caseId === "finding/cookie-finding")?.findingIds).toEqual(["cookie-finding"]);
    expect(() => validateStandardsCoverage(coverage)).not.toThrow();
  });

  it.each(["catalog", "reference", "strength", "accounting", "requirement", "denominator", "area", "objective", "gap", "duplicate", "unmapped", "legacy"])("rejects edited %s evidence before writing any file", async (change) => {
    const coverage = structuredClone(buildStandardsCoverage(report({ activeVulnerability: { cases: [{ caseId: "sql", vulnerabilityClass: "SQL_INJECTION", outcome: "SECURE_FOR_CASE", strategiesExecuted: 1 }] } }))) as any;
    if (change === "catalog") coverage.catalog.sha256 = "0".repeat(64);
    if (change === "reference") coverage.cases[0].references[0].id = "WSTG-v42-APIT-99";
    if (change === "strength") coverage.cases[0].references[0].strength = "SUPPORTING";
    if (change === "accounting") coverage.accounting.noFindings++;
    if (change === "requirement") coverage.requirements[0].noFindings++;
    if (change === "denominator") coverage.frameworkTotals[0].activeEntries++;
    if (change === "area") coverage.wstgAreas[0].status = "COVERED";
    if (change === "objective") coverage.apiRiskObjectives[0].status = "COVERED";
    if (change === "gap") coverage.gaps = [];
    if (change === "duplicate") coverage.cases.push(coverage.cases[0]);
    if (change === "unmapped") coverage.cases[0].references = [];
    if (change === "legacy") coverage.schemaVersion = 1;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-standards-invalid-")); directories.push(directory);
    await expect(new StandardsCoverageWriter().write(directory, coverage)).rejects.toThrow();
    await expect(readFile(join(directory, "standards-coverage.json"))).rejects.toThrow();
  });

  it.each(["=HYPERLINK(\"https://example.test\")", "+SUM(1,2)", "-1+1", "@SUM(1,2)"])("neutralizes spreadsheet formula label %s", async (label) => {
    const coverage = buildStandardsCoverage(report({ activeVulnerability: { cases: [{ caseId: "csv", label, vulnerabilityClass: "SQL_INJECTION", outcome: "INCONCLUSIVE", strategiesExecuted: 1 }] } }));
    const directory = await mkdtemp(join(tmpdir(), "routecairn-standards-csv-")); directories.push(directory);
    const { csvPath } = await new StandardsCoverageWriter().write(directory, coverage);
    expect(await readFile(csvPath, "utf8")).toContain(`"'${label.replaceAll('"', '""')}"`);
  });
});

function report(overrides: Record<string, unknown> = {}, status: "COMPLETED" | "FAILED" = "COMPLETED"): Omit<RouteCairnReport, "standardsCoverage"> {
  return {
    routeCairnVersion: "0.1.0",
    target: "https://example.test",
    mode: "safe",
    program: "test",
    scanPlan: {
      schemaVersion: 1,
      profile: "quick",
      displayName: "Quick",
      description: "test",
      metadata: { requestedProfile: "quick", resolvedProfile: "quick", createdAt: "2026-09-28T00:00:00.000Z" },
      modules: [{ id: "header-review", phase: "analysis", settings: {}, limits: {}, includedBecause: ["test"] }],
      skippedModules: [],
      limits: { maxDepth: 1, rateLimitPerSecond: 1, concurrency: 1, requestTimeoutMs: 1000, bodyPreviewBytes: 0, maxResponseBytes: 1024, maxRequests: 10, cleanupReservedRequests: 0, maxScanDurationMs: 1000, retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1, retryStatusCodes: [] } },
      authentication: { required: false, level: "none", requireSingleProfile: false, requireAccountPair: false, hasSingleProfile: false, hasAccountPair: false },
      evidence: { level: "minimal", collectRequestAudit: false, collectBodyPreview: false, requireReproducibleEvidence: false, retainProofBlocks: false },
      output: { json: true, markdown: true, html: true, stableForDiff: true, includePlan: true, includeRequestAudit: true },
      failurePolicy: "continue-on-module-error",
      optionalModulesMayBeSkipped: true,
      reportFocus: []
    },
    scope: { allowedDomains: ["example.test"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, sameOriginOnly: true, includeSubdomains: false },
    metadata: { startedAt: "2026-09-28T00:00:00.000Z", completedAt: "2026-09-28T00:00:01.000Z", durationMs: 1000, totalRequests: 1, failedRequests: 0 },
    execution: { status, partial: status !== "COMPLETED", reason: "test", checkpointAt: "2026-09-28T00:00:01.000Z", cleanup: { state: "CLEAR", cases: [] } },
    scopeDecisions: [], requestAudit: [], responses: [], technologies: [], discoveredUrls: [], findings: [],
    ...overrides
  } as unknown as Omit<RouteCairnReport, "standardsCoverage">;
}
