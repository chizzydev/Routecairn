import { it, expect } from "vitest";
import { discoveryApplicationFixture } from "../helpers/discovery-application-fixture.js";
import { EvidenceGovernanceService } from "../../src/dashboard/execution/EvidenceGovernanceService.js";
it("protects immutable discovery provenance from retention preview without invoking purge", async () => {
  const f = await discoveryApplicationFixture();
  try {
    const seed = await f.acquire(f.seedInput),
      p = f.propose(seed.revision.revisionId);
    f.database.db
      .prepare("UPDATE artifacts SET created_at='2020-01-01T00:00:00Z' WHERE scan_id=?")
      .run(seed.run.scanId);
    const service = new EvidenceGovernanceService(f.database, f.paths, { bytes: f.key, version: "1" }),
      preview = service.purgePreview();
    f.capture("RETENTION_PREVIEW_BEFORE_ASSERT", { p, preview, destructivePurgeCalled: false });
    expect(preview.candidates.some((c) => c.scanId === seed.run.scanId)).toBe(false);
    expect(preview.protectedCounts.discovery).toBeGreaterThan(0);
    f.capture("DISCOVERY_RETENTION_PREVIEW_ONLY", { p, preview, destructivePurgeCalled: false });
  } finally {
    await f.close();
  }
});
