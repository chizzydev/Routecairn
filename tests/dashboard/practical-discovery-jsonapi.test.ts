import { retainPracticalPrediction } from "../helpers/practical-evaluation.js";
import { it, expect } from "vitest";
import { practicalPythonFixture } from "../helpers/practical-python-application.js";
it("maps Python SQLite jsonapi navigation and cross-role concrete resources with reviewed native evidence", async () => {
  const started = Date.now();
  const f = await practicalPythonFixture("jsonapi");
  try {
    const seed = await f.acquire(f.seedInput),
      before = f.wire.length,
      p = f.propose(seed.revision.revisionId);
    expect(f.wire).toHaveLength(before);
    expect(p.candidates).toHaveLength(7);
    expect(p.policyInferred).toBe(false);
    expect(p.candidates.find((c) => c.path.endsWith("/entries/41"))?.routePattern.suggestedTemplate).toBe(
      "/ledger/entries/{observed1}"
    );
    expect(p.candidates.every((c) => c.accessPolicyInferred === false)).toBe(true);
    const input = f.select(p, (c) => f.cases.some((r) => r.path === c)),
      map = await f.acquire(input),
      count = f.wire.length;
    const h = f.hypotheses.generate(f.org, { mapRevisionId: map.revision.revisionId }, "operator");
    expect(f.wire).toHaveLength(count);
    expect(h.findingsInferred).toBe(false);
    expect(h.candidates.some((c) => c.missingControls.length > 0)).toBe(true);
    const matrix = await f.mapping.createMatrix(f.org, map.revision.revisionId, f.policy(input), "operator"),
      run = await f.workbench.execute(f.org, matrix.revisionId, matrix.digest, "operator");
    await f.wait(run.scanId!);
    const result = f.workbench.result(f.org, matrix.revisionId);
    expect(result.findings!.length).toBe(1);
    retainPracticalPrediction("jsonapi", f.root, f.wire.length, Date.now() - started, result);
    expect(result.checks?.some((c) => c.outcome === "PASS")).toBe(true);
    expect(f.database.db.pragma("integrity_check")).toEqual([{ integrity_check: "ok" }]);
    expect(f.wire.every((w) => w.method === "GET")).toBe(true);
    f.capture("PRACTICAL_PYTHON_JSONAPI", {
      proposal: p,
      hypotheses: h,
      result,
      unblinded: true,
      independentAcceptance: false
    });
  } finally {
    await f.close();
  }
});
