import { it, expect } from "vitest";
import { discoveryApplicationFixture } from "../helpers/discovery-application-fixture.js";
it("refuses a fourth reviewed discovery round without sending any new target requests", async () => {
  const f = await discoveryApplicationFixture();
  try {
    const a = await f.acquire(f.seedInput),
      p = f.propose(a.revision.revisionId),
      b = await f.acquire(f.select(p, (path) => path.endsWith("/catalog/pages/2"))),
      q = f.propose(b.revision.revisionId),
      c = await f.acquire(f.select(q)),
      r = f.propose(c.revision.revisionId);
    expect(r.round).toBe(3);
    expect(r.candidates.map((c) => c.path)).toEqual([f.prefix + "catalog/pages/3"]);
    const d = await f.acquire(f.select(r)),
      count = f.wire.length;
    expect(() => f.propose(d.revision.revisionId)).toThrow("ROUND_LIMIT");
    expect(f.wire).toHaveLength(count);
    f.capture("NATIVE_ROUND_LIMIT", { p, q, r, count });
  } finally {
    await f.close();
  }
});
