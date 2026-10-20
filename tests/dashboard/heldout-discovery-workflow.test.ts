import { it, expect } from "vitest";
import { heldOutApplicationFixture } from "../helpers/heldout-application-fixture.js";
it("requires separate reviewed native rounds across a deeper read-only pagination workflow", async () => {
  const f = await heldOutApplicationFixture("ledger");
  try {
    let m = await f.acquire(f.seedInput);
    const trace: unknown[] = [];
    for (const suffix of ["catalog/pages/2", "catalog/pages/3", "workflow/summary/18"]) {
      const n = f.wire.length,
        p = f.propose(m.revision.revisionId);
      expect(f.wire.length).toBe(n);
      const input = f.select(p, (path) => path === f.prefix + suffix);
      expect(input.routes.length).toBe(1);
      m = await f.acquire(input);
      trace.push({ p, sourceHash: m.result.sourceHash });
    }
    expect(() => f.propose(m.revision.revisionId)).toThrow("ROUND_LIMIT");
    expect(f.wire.length).toBe(32);
    f.capture("HELDOUT_DEEP_WORKFLOW", { trace, explicitRounds: 3 });
  } finally {
    await f.close();
  }
});
