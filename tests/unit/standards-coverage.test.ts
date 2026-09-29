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

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("standards-native coverage accounting", () => {
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
    expect(coverage.accounting.noFindings).toBe(3);
    expect(coverage.accounting.inconclusive).toBe(1);
    expect(coverage.accounting.blocked).toBe(1);
    expect(coverage.wstgAreas).toHaveLength(12);
    expect(coverage.wstgAreas.find((item) => item.id === "BUSL")).toMatchObject({ executedCases: 2, conclusiveCases: 1 });
    expect(coverage.requirements.some((item) => item.id === "API6:2023" && item.noFindings === 1)).toBe(true);
    expect(coverage.requirements.some((item) => item.id === "API4:2023" && item.blocked === 1)).toBe(true);
    expect(coverage.apiRiskObjectives.find((item) => item.id === "API6:2023")).toMatchObject({ status: "COVERED", engineIds: ["business-invariant"] });
    expect(coverage.gaps.some((item) => item.id === "API4:2023" && item.status === "INCONCLUSIVE_ONLY")).toBe(true);
    expect(coverage.gaps.some((item) => item.id === "API10:2023" && item.status === "INCONCLUSIVE_ONLY")).toBe(true);
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
    expect(csv).toContain('"WSTG-INJT-05"');
  });

  it("keeps the WSTG accounting taxonomy fixed to the 12 published testing areas", () => {
    expect(wstgAreas.map((item) => item.id)).toEqual(["INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS", "INJT", "ERRH", "CRYP", "BUSL", "CLNT", "APIT"]);
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
