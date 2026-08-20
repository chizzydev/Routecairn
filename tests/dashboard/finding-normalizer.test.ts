import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { FindingFingerprintService } from "../../src/dashboard/findings/FindingFingerprintService.js";
import { FindingNormalizer } from "../../src/dashboard/findings/FindingNormalizer.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";

describe("dashboard finding normalization", () => {
  it("keeps Next.js finding identity stable across build IDs and chunk hashes", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "routecairn-nextjs-fingerprint-"));
    try {
      const fingerprints = new FindingFingerprintService(resolve(dir, "key"));
      const base = { sourceModule: "nextjs-review", type: "Next.js Source Map Sensitive Data Exposure", method: "GET", tags: ["nextjs", "source-map", "exposure"] } as any;
      const first = fingerprints.fingerprint("https://app.test", { ...base, url: "https://app.test/_next/static/build-a/chunks/app-abc123def456.js.map" });
      const second = fingerprints.fingerprint("https://app.test", { ...base, url: "https://app.test/_next/static/build-b/chunks/app-def456abc123.js.map" });
      expect(second).toBe(first);
      const dataA = fingerprints.routeIdentity("https://app.test/_next/data/build-a/account.json");
      const dataB = fingerprints.routeIdentity("https://app.test/_next/data/build-b/account.json");
      expect(dataB).toBe(dataA);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("creates a stable logical finding with multiple occurrences and preserves review state", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "routecairn-dashboard-findings-"));
    try {
      const database = new DashboardDatabase(resolve(dir, "dashboard.sqlite"));
      database.migrate();
      const scans = new ScanRepository(database);
      for (const scanId of ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]) {
        scans.create({
          id: scanId,
          source: "DASHBOARD",
          status: "COMPLETED",
          targetOrigin: "https://app.test",
          safeTargetLabel: "https://app.test",
          profile: "quick",
          evidenceLevel: "minimal",
          safeConfigurationSummary: {}
        });
      }
      const normalizer = new FindingNormalizer(database.db, new FindingFingerprintService(resolve(dir, "key")));
      normalizer.normalizeReport("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", report());
      const finding = database.db.prepare("SELECT id FROM findings").get() as { id: string };
      database.db.prepare("UPDATE findings SET human_review_status = 'CONFIRMED' WHERE id = ?").run(finding.id);
      normalizer.normalizeReport("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", report());
      const row = database.db.prepare("SELECT occurrence_count, human_review_status FROM findings WHERE id = ?").get(finding.id) as { occurrence_count: number; human_review_status: string };
      expect(row).toEqual({ occurrence_count: 2, human_review_status: "CONFIRMED" });
      expect(database.db.prepare("SELECT COUNT(*) AS count FROM finding_occurrences").get()).toEqual({ count: 2 });
      database.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function report(): RouteCairnReport {
  return {
    routeCairnVersion: "0.1.0",
    target: "https://app.test",
    mode: "quick",
    program: "fixture",
    scope: {
      allowedDomains: ["app.test"],
      disallowedPaths: [],
      allowedMethods: ["GET"],
      rateLimitPerSecond: 1,
      concurrency: 1,
      sameOriginOnly: true,
      includeSubdomains: false
    },
    metadata: { startedAt: new Date(0).toISOString(), completedAt: new Date(1).toISOString(), durationMs: 1, totalRequests: 1, failedRequests: 0 },
    scopeDecisions: [],
    requestAudit: [],
    responses: [],
    technologies: [],
    discoveredUrls: [],
    findings: [
      {
        id: "f1",
        title: "Missing authorization check",
        type: "Authorization",
        severity: "High",
        confidence: "Medium",
        url: "https://app.test/api/orders/123",
        method: "GET",
        evidence: { url: "https://app.test/api/orders/123", method: "GET", source: "fixture", title: "Observed", bodyHash: "abc" },
        sourceModule: "authorization-matrix-testing",
        tags: ["authorization", "role:user-admin"]
      }
    ]
  };
}
