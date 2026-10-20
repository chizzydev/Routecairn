import { it, expect } from "vitest";
import { practicalPythonFixture } from "../helpers/practical-python-application.js";

for (const mode of ["html", "jsonapi"] as const)
  it(`observes Python ${mode} pagination only after exact native review, without following the next advertisement`, async () => {
    const f = await practicalPythonFixture(mode);
    try {
      const seed = await f.acquire(f.seedInput),
        first = f.propose(seed.revision.revisionId),
        before = f.wire.length;
      expect(f.wire).toHaveLength(before);
      const page = await f.acquire(f.select(first, (path) => path.endsWith("/catalog/pages/2"))),
        after = f.wire.length,
        next = f.propose(page.revision.revisionId);
      expect(next.round).toBe(2);
      expect(next.candidates.map((c) => c.path)).toEqual(["/ledger/catalog/pages/3"]);
      expect(next.candidates.every((c) => c.provenance.length === 4)).toBe(true);
      expect(f.wire).toHaveLength(after);
      expect(f.wire.some((w) => w.path.endsWith("/catalog/pages/3"))).toBe(false);
      expect(after).toBe(16);
      f.capture("PRACTICAL_NATIVE_PAGINATION", { mode, first, next, separatelyMeasuredFromResourceBenchmark: true });
    } finally {
      await f.close();
    }
  });
