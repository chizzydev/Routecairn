import { it, expect, vi } from "vitest";
import { collectionApplicationFixture } from "../helpers/collection-application-fixture.js";
import { ApplicationAssessmentReadiness } from "../../src/dashboard/execution/ApplicationAssessmentReadiness.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
import { ApplicationAnalystHandoff } from "../../src/dashboard/execution/ApplicationAnalystHandoff.js";
import { hypothesisSource } from "../../src/dashboard/execution/ApplicationHypothesisBinding.js";
import { readCollectionObservation } from "../../src/dashboard/execution/CollectionMappingEvidence.js";
it.each(["TENANT_AWARE", "PRINCIPAL_ROLE"] as const)(
  "native %s collection mapping, explicit review, proof and handoff",
  async (model) => {
    const f = await collectionApplicationFixture(model);
    try {
      const spy = vi.spyOn(f.vault, "decryptForHealthCheck"),
        before = f.wire.length;
      const ready = new ApplicationAssessmentReadiness(f.database).get(f.org, {
        targetId: f.onboard.targetId,
        ...f.onboard.credentials
      });
      expect(ready.actorsReady).toBe(true);
      expect(spy).not.toHaveBeenCalled();
      expect(f.wire.length).toBe(before);
      spy.mockRestore();
      f.setBehavior("late-foreign");
      const a = await f.acquire(),
        source = hypothesisSource(f.database, f.org, a.revision.revisionId);
      const v = readCollectionObservation(source, "operation-1", "account-a");
      f.capture("COLLECTION_NATIVE_SOURCE", { a, v });
      const route = f.onboard.input.routes[0]!.id;
      const native = readCollectionObservation(source, route, "account-a");
      expect(native.valid).toBe(true);
      expect(native.evidence?.mismatchCount).toBe(1);
      const p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator"),
        c = p.candidates[0]!;
      expect(c.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
      const reviewed = await f.hypotheses.decide(
        f.org,
        p.proposalId,
        {
          action: "REVIEW",
          digest: p.digest,
          candidateId: c.candidateId,
          policyConfirmed: true,
          ownershipConfirmed: true,
          explanation: "Owner requires each returned entry to belong to the exact requesting principal",
          decisions: { primary: "ALLOW", "account-a": "ALLOW", "account-b": "ALLOW", anonymous: "DENY" }
        },
        "operator"
      );
      expect(reviewed.matrix).toBeTruthy();
      const m = reviewed.matrix!,
        run = await f.workbench.execute(f.org, m.revisionId, m.digest, "operator");
      await f.wait(run.scanId!);
      const proof = f.workbench.result(f.org, m.revisionId);
      expect(proof.status).toBe("FINDINGS");
      expect(proof.verifiedPass).toBe(false);
      const handoff = new ApplicationAnalystHandoff(
        f.database,
        new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench),
        f.workbench
      ).export(f.org, p.proposalId);
      expect(handoff.fullApplicationAcceptance).toBe(false);
      f.capture("COLLECTION_REVIEW_PROOF_HANDOFF", { proposal: p, reviewed, proof, handoff });
    } finally {
      await f.close();
    }
  }
);
it.each(["healthy", "empty", "beyond-cap", "duplicate", "unknown-owner", "partial", "link-next", "oversize"])(
  "native collection %s does not invent a finding",
  async (behavior) => {
    const f = await collectionApplicationFixture();
    try {
      f.setBehavior(behavior);
      const a = await f.acquire(),
        p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator");
      expect(p.candidates.every((c) => c.eligibility === "ABSTAIN")).toBe(true);
      if (behavior === "healthy")
        expect(
          a.result.observations[0]!.cells.filter((c) => c.actorId !== "anonymous").every(
            (c) => c.collection?.status === "SELF_COLLECTION_OBSERVED"
          )
        ).toBe(true);
      else
        expect(
          a.result.observations[0]!.cells.filter((c) => c.actorId !== "anonymous").every(
            (c) => c.nativeOutcome === "INCONCLUSIVE"
          )
        ).toBe(true);
      f.capture("COLLECTION_NEGATIVE", { behavior, a, p });
    } finally {
      await f.close();
    }
  }
);
it("observes denial only from a real reviewed foreign-resource endpoint", async () => {
  const f = await collectionApplicationFixture();
  try {
    f.onboard.input.routes[0]!.url = f.origin + "/foreign";
    f.onboard.input.routes[0]!.pathTemplate = "/foreign";
    const a = await f.acquire(),
      foreign = a.result.observations[0]!.cells.filter((c) => ["account-a", "account-b"].includes(c.actorId));
    expect(foreign.every((c) => c.nativeDecision === "DENIED" && c.statusCode === 403)).toBe(true);
    const p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator");
    expect(p.candidates.every((c) => c.eligibility === "ABSTAIN")).toBe(true);
    expect(a.report.findings.filter((f) => f.sourceModule === "api-graphql-authorization")).toEqual([]);
    f.capture("REAL_FOREIGN_ENDPOINT_DENIAL", { a, p });
  } finally {
    await f.close();
  }
});
it("propagates empty later proof to inconclusive triage and handoff", async () => {
  const f = await collectionApplicationFixture();
  try {
    f.setBehavior("late-foreign");
    const a = await f.acquire(),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator"),
      c = p.candidates[0]!,
      reviewed = await f.hypotheses.decide(
        f.org,
        p.proposalId,
        {
          action: "REVIEW",
          digest: p.digest,
          candidateId: c.candidateId,
          policyConfirmed: true,
          ownershipConfirmed: true,
          explanation: "Owner explicitly requires exact requesting-principal ownership for every entry",
          decisions: { primary: "ALLOW", "account-a": "ALLOW", "account-b": "ALLOW", anonymous: "DENY" }
        },
        "operator"
      );
    f.setBehavior("empty");
    const m = reviewed.matrix!,
      run = await f.workbench.execute(f.org, m.revisionId, m.digest, "operator");
    await f.wait(run.scanId!);
    const result = f.workbench.result(f.org, m.revisionId);
    expect(result.status).toBe("INCONCLUSIVE");
    expect(result.verifiedPass).toBe(false);
    expect(result.findings).toEqual([]);
    const triage = new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench),
      handoff = new ApplicationAnalystHandoff(f.database, triage, f.workbench).export(f.org, p.proposalId);
    expect(handoff.nativeProofs[0]?.status).toBe("INCONCLUSIVE");
    f.capture("COLLECTION_LATER_INCONCLUSIVE", { result, handoff });
  } finally {
    await f.close();
  }
});
