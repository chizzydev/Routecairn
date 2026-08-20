import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { DemoSeedService } from "../../src/dashboard/demo/DemoSeedService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { inspectImageDimensions } from "../../src/dashboard/security/ImageDimensions.js";

describe("development demo seed", () => {
  it("creates bounded fictional lifecycle, evidence, view, and screenshot examples once", () => {
    withSeed((database, service) => {
      const result = service.seed({ environment: "development" });
      expect(result).toMatchObject({ findingCount: 10 });
      expect(database.db.prepare("SELECT COUNT(DISTINCT human_review_status) AS count FROM findings").get()).toEqual({ count: 8 });
      expect(database.db.prepare("SELECT COUNT(DISTINCT remediation_state_v2) AS count FROM findings").get()).toEqual({ count: 6 });
      expect(database.db.prepare("SELECT COUNT(DISTINCT evidence_type) AS count FROM evidence_records").get()).toEqual({ count: 10 });
      expect(database.db.prepare("SELECT COUNT(*) AS count FROM finding_occurrences").get()).toEqual({ count: 20 });
      expect(database.db.prepare("SELECT COUNT(*) AS count FROM saved_finding_views").get()).toEqual({ count: 2 });
      expect(database.db.prepare("SELECT COUNT(DISTINCT target_id) AS count FROM scans").get()).toEqual({ count: 1 });
      expect(database.db.prepare("SELECT DISTINCT target_id FROM scans").get()).toEqual({ target_id: result.targetIds[0] });
      const artifact = database.db.prepare("SELECT canonical_path, content_type, size, missing_file_flag FROM artifacts WHERE id = ?").get(result.screenshotArtifactId) as { canonical_path: string; content_type: string; size: number; missing_file_flag: number };
      expect(artifact).toMatchObject({ content_type: "image/png", missing_file_flag: 0 });
      expect(artifact.size).toBeGreaterThan(1_000);
      expect(inspectImageDimensions(artifact.canonical_path, artifact.content_type)).toMatchObject({ width: 960, height: 540, contentType: "image/png" });
      expect(() => service.seed({ environment: "development" })).toThrow(/already been seeded/i);
    });
  });

  it("fails closed in production", () => {
    withSeed((_database, service) => expect(() => service.seed({ environment: "production" })).toThrow(/disabled in production/i));
  });
});

function withSeed(run: (database: DashboardDatabase, service: DemoSeedService) => void): void {
  const dir = mkdtempSync(resolve(tmpdir(), "routecairn-demo-seed-"));
  const paths = resolveDashboardPaths(dir);
  const database = new DashboardDatabase(paths.databasePath);
  try { database.migrate(); run(database, new DemoSeedService(database, paths)); }
  finally { database.close(); rmSync(dir, { recursive: true, force: true }); }
}
