import { it, expect } from "vitest";
import { discoveryApplicationFixture } from "../helpers/discovery-application-fixture.js";
it("discovers actual nested scoped routes, binds native provenance and separately reviews one bounded expansion", async () => {
  const f = await discoveryApplicationFixture();
  try {
    expect(f.wire).toHaveLength(0);
    const seed = await f.acquire(f.seedInput),
      wire = f.wire.length,
      p = f.propose(seed.revision.revisionId);
    expect(p.candidates).toHaveLength(8);
    expect(f.wire).toHaveLength(wire);
    expect(p.executionAuthority).toBe("NONE");
    expect(p.candidates.every((c) => c.provenance.every((e) => e.responseFingerprint.length === 64))).toBe(true);
    expect(p.excluded.some((e) => e.reason === "OUTSIDE_REVIEWED_SCOPE")).toBe(true);
    const input = f.select(p),
      preview = await f.mapping.preview(f.org, input);
    expect(preview.proofBudget.totalRequestCeiling).toBe(36);
    expect(f.wire).toHaveLength(wire);
    const later = await f.acquire(input);
    expect(later.result.observations).toHaveLength(8);
    expect(
      later.result.observations.every((r) => r.provenance === "REVIEWED_NATIVE_LINK_WITH_NATIVE_RESPONSE_EVIDENCE")
    ).toBe(true);
    expect(f.wire).toHaveLength(44);
    expect(
      f.wire.every(
        (r) => r.method === "GET" && (r.path === "/" || r.path === "/identity" || r.path.startsWith(f.prefix))
      )
    ).toBe(true);
    const next = f.propose(later.revision.revisionId);
    expect(next.round).toBe(2);
    expect(next.candidates.map((c) => c.path)).toEqual([f.prefix + "collections/17/retention/95"]);
    expect(() =>
      f.database.db.prepare("DELETE FROM application_discovery_proposals WHERE id=?").run(p.proposalId)
    ).toThrow("IMMUTABLE_DISCOVERY_PROPOSAL");
    f.capture("NATIVE_DISCOVERY_COVERAGE", { seed, p, later: later.result, next, wire: f.wire.length });
  } finally {
    await f.close();
  }
});
