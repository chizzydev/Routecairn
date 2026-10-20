import { it, expect } from "vitest";
import { observedStateRegressionFixture } from "../helpers/observed-state-regression-fixture.js";
it("supersedes all older approved policy ancestors after an approved descendant, without fallback after revocation", async () => {
  const f = await observedStateRegressionFixture("procurement");
  try {
    const p = await f.prepare(),
      draft = f.states.create(
        f.org,
        { ...p.policy.snapshot.input, name: "Unapproved intermediate policy", supersedes: p.policy.id },
        "operator"
      ),
      successor = f.states.create(
        f.org,
        { ...p.policy.snapshot.input, name: "Reviewed descendant observation policy", supersedes: draft.id },
        "operator"
      );
    f.states.decide(
      f.org,
      successor.id,
      {
        action: "APPROVE",
        digest: successor.digest,
        authorityConfirmed: true,
        expectationsConfirmed: true,
        scopeConfirmation: "OBSERVATIONS_ONLY_TRANSITION_AUTHORIZATION_NOT_TESTED"
      },
      "operator"
    );
    const later = await f.acquire(),
      wire = f.wire.length,
      run = await f.ca.runNow(p.assurancePolicyId, "operator", later.revision.revisionId);
    f.receipt("POLICY_LINEAGE_ANCESTOR_AUTHORITY", {
      old: f.states.get(f.org, p.policy.id),
      draft: f.states.get(f.org, draft.id),
      successor: f.states.get(f.org, successor.id),
      run
    });
    expect(run.gateStatus).toBe("INCONCLUSIVE");
    expect(f.states.get(f.org, p.policy.id).status).toBe("SUPERSEDED");
    expect(f.states.get(f.org, draft.id).status).toBe("SUPERSEDED");
    f.states.decide(
      f.org,
      successor.id,
      { action: "REVOKE", digest: successor.digest, reason: "Withdraw newest reviewed lineage authority" },
      "operator"
    );
    expect(f.states.get(f.org, p.policy.id).status).toBe("SUPERSEDED");
    expect(f.states.get(f.org, successor.id).status).toBe("REVOKED");
    const revoked = await f.ca.runNow(p.assurancePolicyId, "operator");
    expect(revoked.gateStatus).toBe("INCONCLUSIVE");
    expect(f.wire.length).toBe(wire);
    f.receipt("POLICY_LINEAGE_REVOKED_NO_FALLBACK", { run, revoked });
  } finally {
    await f.close();
  }
});
