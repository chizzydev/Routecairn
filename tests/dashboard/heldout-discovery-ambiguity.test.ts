import { it, expect } from "vitest";
import { heldOutApplicationFixture } from "../helpers/heldout-application-fixture.js";
it("abstains on HTML base ambiguity and refuses off-origin redirects using real native workers", async () => {
  const f = await heldOutApplicationFixture("helpdesk");
  try {
    const receipts: unknown[] = [];
    for (const path of ["ambiguous", "redirect"]) {
      const input = {
          ...f.seedInput,
          routes: [{ ...f.seedInput.routes[0]!, url: f.origin + f.prefix + path, pathTemplate: f.prefix + path }]
        },
        m = await f.acquire(input),
        before = f.wire.length,
        p = f.propose(m.revision.revisionId);
      expect(p.candidates.length).toBe(0);
      expect(f.wire.length).toBe(before);
      receipts.push({ path, p, observations: m.result.observations });
    }
    expect(f.wire.every((w) => !w.path.includes("external.invalid"))).toBe(true);
    f.capture("HELDOUT_ORIGIN_AMBIGUITY", { receipts });
  } finally {
    await f.close();
  }
});
