import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { triageFinding } from "../../src/cli/commands/triage.js";
import { loadTriageState, markFinding, saveTriageState, triagePathForReport } from "../../src/triage/TriageStore.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("triage", () => {
  it("persists finding status beside the report", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-triage-store-"));
    tempDirs.push(tempDir);
    const report = sampleReport();
    const triagePath = join(tempDir, "triage.json");

    const state = markFinding(await loadTriageState(triagePath, report), "finding-1", "reviewed", "Checked manually", "tester");
    await saveTriageState(triagePath, state);

    const loaded = await loadTriageState(triagePath, report);
    expect(loaded.entries["finding-1"]?.status).toBe("reviewed");
    expect(loaded.entries["finding-1"]?.note).toBe("Checked manually");
    expect(loaded.entries["finding-1"]?.updatedBy).toBe("tester");
  });

  it("triages through CLI helper without modifying raw scan evidence", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-triage-cli-"));
    tempDirs.push(tempDir);
    const reportPath = join(tempDir, "report.json");
    const rawReport = `${JSON.stringify(sampleReport(), null, 2)}\n`;
    await writeFile(reportPath, rawReport, "utf8");

    const result = await triageFinding(reportPath, "finding-1", { status: "confirmed", note: "Reproduced with account A", by: "tester" });

    expect(result.triagePath).toBe(triagePathForReport(reportPath));
    expect(await readFile(reportPath, "utf8")).toBe(rawReport);

    const triage = JSON.parse(await readFile(result.triagePath, "utf8")) as { entries: Record<string, { status: string; note: string }> };
    expect(triage.entries["finding-1"]?.status).toBe("confirmed");
    expect(triage.entries["finding-1"]?.note).toBe("Reproduced with account A");

    const html = await readFile(result.htmlReportPath, "utf8");
    expect(html).toContain("All triage statuses");
    expect(html).toContain("confirmed");
    expect(html).toContain("Reproduced with account A");
  });
});

function sampleReport(): RouteCairnReport {
  return {
    routeCairnVersion: "0.1.0",
    target: "https://example.com/",
    mode: "quick",
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
      completedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
      totalRequests: 1,
      failedRequests: 0
    },
    scopeDecisions: [],
    responses: [],
    technologies: [],
    discoveredUrls: [],
    findings: [
      {
        id: "finding-1",
        title: "Interesting route discovered",
        type: "Interesting But Needs Manual Testing",
        severity: "Low",
        confidence: "Medium",
        url: "https://example.com/account/123",
        method: "GET",
        statusCode: 200,
        evidence: {
          url: "https://example.com/account/123",
          method: "GET",
          statusCode: 200,
          source: "test",
          contentType: "text/html",
          contentLength: 42,
          bodyPreview: "preview",
          curlCommand: "curl -i https://example.com/account/123",
          severityReason: "Test reason."
        },
        impact: "Manual review target.",
        recommendation: "Review authorization.",
        manualTestingSuggestions: ["Check access control."],
        tags: ["manual-review"],
        riskScore: 21,
        sourceModule: "test",
        falsePositiveStatus: "likely-valid",
        timestamp: "2026-01-01T00:00:00.000Z"
      }
    ]
  };
}