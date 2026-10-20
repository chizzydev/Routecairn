import { it, expect } from "vitest";
import { discoveryApplicationFixture } from "../helpers/discovery-application-fixture.js";
it("discovers one reviewed pagination hop and never automatically follows an advertised next page", async () => {
  const f = await discoveryApplicationFixture();
  try {
    const a = await f.acquire(f.seedInput),
      p = f.propose(a.revision.revisionId),
      page = f.select(p, (path) => path.endsWith("/catalog/pages/2"));
    expect(f.wire.some((w) => w.path.endsWith("/catalog/pages/2"))).toBe(false);
    const b = await f.acquire(page),
      q = f.propose(b.revision.revisionId);
    expect(q.round).toBe(2);
    expect(q.candidates.map((c) => c.path)).toEqual([f.prefix + "collections/17/retention/95"]);
    const count = f.wire.length;
    await f.mapping.preview(f.org, f.select(q));
    expect(f.wire).toHaveLength(count);
    f.capture("PAGINATION_REVIEW_RECEIPT", { p, q, count });
  } finally {
    await f.close();
  }
});
