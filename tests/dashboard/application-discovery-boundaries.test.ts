import { it, expect } from "vitest";
import { discoveryApplicationFixture } from "../helpers/discovery-application-fixture.js";
it("rejects exact context, selection, budget and expired credential changes without dispatch", async () => {
  const f = await discoveryApplicationFixture();
  try {
    const seed = await f.acquire(f.seedInput),
      p = f.propose(seed.revision.revisionId),
      input = f.select(p),
      wire = f.wire.length;
    await expect(
      f.mapping.preview(f.org, {
        ...input,
        routes: input.routes.map((r, i) => (i ? r : { ...r, url: f.origin + f.prefix + "invented" }))
      })
    ).rejects.toThrow("EXACT_SELECTION");
    const low = f.discovery.create(f.org, { ...p.input, maxRequests: 8 }, "operator");
    await expect(
      f.mapping.preview(f.org, {
        ...input,
        discoveryBinding: { ...input.discoveryBinding!, proposalId: low.proposalId, digest: low.digest }
      })
    ).rejects.toThrow("REQUEST_BUDGET");
    expect(() => f.discovery.get("00000000-0000-4000-8000-000000000099", p.proposalId)).toThrow("NOT_FOUND");
    f.database.db
      .prepare("UPDATE credential_profiles SET expires_at=? WHERE id=?")
      .run("2000-01-01T00:00:00Z", f.credentials.account_b);
    await expect(f.mapping.preview(f.org, input)).rejects.toThrow("CREDENTIAL_BINDING");
    expect(f.wire).toHaveLength(wire);
    f.capture("DISCOVERY_REVIEW_BOUNDARIES", { wire, p, input });
  } finally {
    await f.close();
  }
});
