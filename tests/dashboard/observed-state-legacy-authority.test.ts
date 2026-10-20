import { it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { observedStateRegressionFixture } from "../helpers/observed-state-regression-fixture.js";
import { adaptiveDigest } from "../../src/dashboard/execution/AdaptiveCanonical.js";
import { freshHypothesisProposal } from "../../src/dashboard/execution/ApplicationHypothesisBinding.js";
it("retains synthetic legacy v1 history but refuses it as current reviewed authority", async () => {
  const f = await observedStateRegressionFixture("procurement");
  try {
    const p = await f.prepare(),
      old = structuredClone(p.proposal) as unknown as { transition: { version: string } },
      row = f.database.db
        .prepare("SELECT * FROM application_hypothesis_proposals WHERE id=?")
        .get(p.proposal.proposalId) as Record<string, string>,
      snapshot = JSON.parse(row.snapshot_json!);
    expect(old.transition).toBeTruthy();
    snapshot.transition.version = "target-attested-read-only-transition-v1";
    const id = randomUUID(),
      digest = adaptiveDigest(snapshot);
    f.database.db
      .prepare("INSERT INTO application_hypothesis_proposals VALUES(?,?,?,?,?,?,?,?,?,?)")
      .run(
        id,
        row.organization_id,
        row.target_id,
        row.map_revision_id,
        row.context_digest,
        digest,
        JSON.stringify(snapshot),
        null,
        "synthetic-legacy-fixture",
        new Date().toISOString()
      );
    const history = f.hypotheses.get(f.org, id);
    expect(history.decisions).toHaveLength(0);
    expect(() => freshHypothesisProposal(f.database, f.org, id)).toThrow("TRANSITION_ALGORITHM_CHANGED");
    const wire = f.wire.length;
    await expect(
      f.hypotheses.decide(f.org, id, { ...f.transitionReviewFor(p.proposal), proposalDigest: digest }, "operator")
    ).rejects.toThrow();
    expect(f.wire.length).toBe(wire);
    expect(() =>
      f.database.db.prepare("UPDATE application_hypothesis_proposals SET snapshot_json='{}' WHERE id=?").run(id)
    ).toThrow("IMMUTABLE_HYPOTHESIS_PROPOSAL");
    expect(f.hypotheses.get(f.org, p.proposal.proposalId).decisions).toHaveLength(1);
    f.receipt("LEGACY_ALGORITHM_HISTORY_NO_AUTHORITY", {
      syntheticLegacyRow: true,
      id,
      digest,
      history,
      existingReviewPreserved: p.decision
    });
  } finally {
    await f.close();
  }
});
