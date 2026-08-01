import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { diffReports } from "../../src/cli/commands/diff.js";
import { showReport } from "../../src/cli/commands/show.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("report CLI command helpers", () => {
  it("renders show and diff text from report files", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-report-"));
    tempDirs.push(tempDir);
    const oldPath = join(tempDir, "old.json");
    const newPath = join(tempDir, "new.json");

    await writeFile(oldPath, JSON.stringify(report(["https://example.com/old"], ["Next.js"]), null, 2), "utf8");
    await writeFile(newPath, JSON.stringify(report(["https://example.com/new"], ["Next.js", "Cloudflare"]), null, 2), "utf8");

    await expect(showReport(newPath)).resolves.toContain("RouteCairn Report Summary");
    await expect(showReport(newPath)).resolves.toContain("Technologies: Cloudflare, Next.js");
    await expect(diffReports(oldPath, newPath)).resolves.toContain("New URLs: 1");
    await expect(diffReports(oldPath, newPath)).resolves.toContain("New: Cloudflare");
  });
});

function report(urls: string[], technologies: string[]): RouteCairnReport {
  return {
    routeCairnVersion: "0.1.0",
    target: "https://example.com/",
    mode: "quick",
    program: "Test",
    scope: {
      allowedDomains: ["example.com"],
      disallowedPaths: [],
      allowedMethods: ["GET"],
      rateLimitPerSecond: 10,
      concurrency: 2,
      sameOriginOnly: true,
      includeSubdomains: true
    },
    metadata: {
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
      totalRequests: urls.length,
      failedRequests: 0
    },
    scopeDecisions: [],
    responses: [],
    technologies: technologies.map((name) => ({ name, category: "framework", confidence: "High", signals: [] })),
    discoveredUrls: urls.map((url) => ({
      url,
      method: "GET",
      source: "test",
      statusCode: 200,
      responseTimeMs: 1,
      falsePositiveStatus: "likely-valid",
      classificationReason: "status 200"
    })),
    findings: []
  };
}
