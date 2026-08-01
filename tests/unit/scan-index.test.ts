import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { diffReports } from "../../src/cli/commands/diff.js";
import { showHistory } from "../../src/cli/commands/history.js";
import { searchHistory } from "../../src/cli/commands/search.js";
import {
  entryFromReport,
  loadScanIndex,
  recordScan,
  scanIndexPath,
  searchScanIndex,
  timestampedOutputDir
} from "../../src/storage/ScanIndex.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("scan index", () => {
  it("records searchable scan summaries", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-index-"));
    tempDirs.push(tempDir);
    const indexPath = scanIndexPath(tempDir);
    const report = sampleReport({ target: "https://app.example.com/", technology: "Next.js", findingType: "API Endpoint", endpoint: "https://app.example.com/api/users/123" });
    const entry = entryFromReport(report, { outputDir: join(tempDir, "scan-one"), reportPath: join(tempDir, "scan-one", "report.json") });

    await recordScan(indexPath, entry);
    const index = await loadScanIndex(indexPath);

    expect(index.scans).toHaveLength(1);
    expect(index.scans[0]?.domain).toBe("app.example.com");
    expect(searchScanIndex(index, { domain: "example.com" })).toHaveLength(1);
    expect(searchScanIndex(index, { technology: "next" })).toHaveLength(1);
    expect(searchScanIndex(index, { findingType: "api" })).toHaveLength(1);
    expect(searchScanIndex(index, { endpoint: "/api/users" })).toHaveLength(1);
  });

  it("renders history/search and lets diff use scan IDs", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-history-"));
    tempDirs.push(tempDir);
    const oldDir = join(tempDir, "old");
    const newDir = join(tempDir, "new");
    const oldReport = sampleReport({ completedAt: "2026-01-01T00:00:00.000Z", url: "https://example.com/old" });
    const newReport = sampleReport({ completedAt: "2026-01-02T00:00:00.000Z", url: "https://example.com/new", technology: "Cloudflare" });
    const oldPath = join(oldDir, "report.json");
    const newPath = join(newDir, "report.json");
    await writeReport(oldPath, oldReport);
    await writeReport(newPath, newReport);

    const oldEntry = entryFromReport(oldReport, { outputDir: oldDir, reportPath: oldPath });
    const newEntry = entryFromReport(newReport, { outputDir: newDir, reportPath: newPath });
    await recordScan(scanIndexPath(tempDir), oldEntry);
    await recordScan(scanIndexPath(tempDir), newEntry);

    await expect(showHistory({ reportsDir: tempDir })).resolves.toContain(newEntry.id);
    await expect(searchHistory({ reportsDir: tempDir, technology: "cloud" })).resolves.toContain(newEntry.id);
    await expect(diffReports(oldEntry.id, newEntry.id, tempDir)).resolves.toContain("New URLs: 1");
  });

  it("creates timestamped monitor output folders", () => {
    expect(timestampedOutputDir("./reports", "https://www.example.com", "monitor", new Date("2026-06-29T10:11:12.000Z"))).toMatch(/example\.com-monitor-20260629101112$/);
  });
});

async function writeReport(reportPath: string, report: RouteCairnReport): Promise<void> {
  const { mkdir } = await import("node:fs/promises");
  const { dirname } = await import("node:path");
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}

function sampleReport(options: { target?: string; completedAt?: string; url?: string; technology?: string; findingType?: "API Endpoint" | "Interesting But Needs Manual Testing"; endpoint?: string } = {}): RouteCairnReport {
  const target = options.target ?? "https://example.com/";
  const completedAt = options.completedAt ?? "2026-01-01T00:00:00.000Z";
  const url = options.url ?? "https://example.com/api/users/123";
  const technology = options.technology ?? "Next.js";
  const findingType = options.findingType ?? "API Endpoint";
  const endpoint = options.endpoint ?? url;

  return {
    routeCairnVersion: "0.1.0",
    target,
    mode: "quick",
    profile: {
      name: "quick",
      displayName: "Quick Recon",
      description: "test",
      mode: "quick",
      modules: [],
      limits: {},
      browserUse: "off",
      authComparisonDepth: "none",
      proofMode: false,
      reportFocus: []
    },
    program: "Test Program",
    scope: {
      allowedDomains: ["example.com"],
      disallowedPaths: [],
      allowedMethods: ["GET"],
      rateLimitPerSecond: 2,
      concurrency: 1,
      sameOriginOnly: true,
      includeSubdomains: true
    },
    metadata: {
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt,
      durationMs: 1000,
      totalRequests: 2,
      failedRequests: 0
    },
    scopeDecisions: [],
    responses: [],
    technologies: [{ name: technology, category: "framework", confidence: "High", signals: [] }],
    apiMapper: {
      endpoints: [
        {
          endpoint,
          method: "GET",
          routeType: "identity-api",
          riskTags: ["api", "object-id"],
          likelyManualTests: [],
          authRelevance: "high",
          hasObjectId: true,
          privilegeSensitivity: "medium",
          dataExposureSensitivity: "high",
          rateLimitSensitivity: "medium"
        }
      ],
      graphQlEndpoints: [],
      notes: []
    },
    jsIntelligence: { scripts: [], queuedEndpoints: [{ path: "/api/users/123", source: "test" }], sourceMaps: [], notes: [] },
    authSurface: { surfaces: [{ endpoint: "/login", purpose: "login", abuseCategories: ["auth"], rateLimitSensitivity: "high", accountEnumerationRelevance: "medium", suggestedTests: [] }], notes: [] },
    discoveredUrls: [
      {
        url,
        method: "GET",
        source: "test",
        statusCode: 200,
        responseTimeMs: 1,
        falsePositiveStatus: "likely-valid",
        classificationReason: "status 200"
      }
    ],
    findings: [
      {
        id: `finding-${completedAt.replace(/[^0-9]/g, "")}`,
        title: "API endpoint discovered",
        type: findingType,
        severity: "Low",
        confidence: "Medium",
        url,
        method: "GET",
        statusCode: 200,
        evidence: { url, method: "GET", statusCode: 200 },
        impact: "Manual review target.",
        recommendation: "Review authorization.",
        manualTestingSuggestions: [],
        tags: ["api"],
        riskScore: 21,
        sourceModule: "test",
        falsePositiveStatus: "likely-valid",
        timestamp: completedAt
      }
    ]
  };
}