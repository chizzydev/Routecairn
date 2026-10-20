import { it, expect } from "vitest";
import { readFileSync, appendFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { transitionApplicationFixture } from "../helpers/transition-application-fixture.js";
it("revalidates immutable before evidence at native admission without dispatch after source drift", async () => {
  const f = await transitionApplicationFixture("membership");
  try {
    const before = await f.acquire(),
      event = await f.apply("account-b"),
      after = await f.acquire(),
      p = f.hypotheses.generate(
        f.org,
        {
          mapRevisionId: after.revision.revisionId,
          workflow: f.workflow,
          transition: f.declaration(before.revision.revisionId, event)
        },
        "operator"
      ),
      d = await f.hypotheses.decide(f.org, p.proposalId, f.transitionReviewFor(p), "operator");
    if (!d.matrix) throw Error("matrix");
    const artifact = f.database.db
      .prepare("SELECT a.canonical_path FROM artifacts a JOIN scans s ON s.json_report_artifact_id=a.id WHERE s.id=?")
      .get(before.run.scanId) as { canonical_path: string };
    writeFileSync(join(f.root, "AUTHENTIC_BEFORE_REPORT_BEFORE_FAULT.json"), readFileSync(artifact.canonical_path), {
      flag: "wx"
    });
    appendFileSync(artifact.canonical_path, " ");
    const requests = f.wire.length;
    await expect(f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator")).rejects.toThrow(
      "SOURCE_CHANGED"
    );
    expect(f.wire.length).toBe(requests);
    const h = f.hypotheses.get(f.org, p.proposalId);
    expect(h.freshness).toContain("SOURCE_CHANGED");
    expect(h.decisions).toHaveLength(1);
    expect(h.matrices).toHaveLength(1);
    f.capture("BEFORE_TRANSITION_CUSTODY_FAULT_RETAINED");
  } finally {
    await f.close();
  }
});
