import { it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { ownedResourceFixture } from "../helpers/owned-resource-fixture.js";
import { ApplicationAssessmentReadiness } from "../../src/dashboard/execution/ApplicationAssessmentReadiness.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
import { ApplicationAnalystHandoff } from "../../src/dashboard/execution/ApplicationAnalystHandoff.js";
for (const steps of [3, 4] as const)
  it(
    "corroborates owner context and abstains on conflicting declarations across " + steps + " native steps",
    async () => {
      const f = await ownedResourceFixture(steps);
      try {
        const readiness = new ApplicationAssessmentReadiness(f.database),
          q = { targetId: f.targetId, ...f.credentials },
          before = f.wire.length;
        expect(readiness.get(f.org, q)).toMatchObject({
          actorsReady: true,
          observation: { status: "UNTESTED" },
          requestsSent: 0
        });
        expect(f.wire.length).toBe(before);
        expect(() => readiness.get(randomUUID(), q)).toThrow();
        expect(readiness.get(f.org, { targetId: f.targetId })).toMatchObject({ actorsReady: false });
        const a = await f.acquire(f.input),
          source = { ...q, mapRevisionId: a.revision.revisionId },
          ready = readiness.get(f.org, source),
          wire = f.wire.length;
        expect(ready).toMatchObject({
          observation: { status: "NATIVE_OBSERVED_REVIEW_REQUIRED", nativeActorRoutePairs: steps * 4 },
          credentialDecryption: false
        });
        expect(readiness.get(f.org, { ...source, account_a: f.credentials.primary }).observation.status).toBe(
          "CONTEXT_MISMATCH"
        );
        const p = f.hypotheses.generate(
            f.org,
            { mapRevisionId: a.revision.revisionId, workflow: f.workflow },
            "operator"
          ),
          edge = p.relationships!.relationships[0]!;
        expect(edge).toMatchObject({
          ownership: "DECLARED_OWNER_CORROBORATED",
          ownerContext: { policyInferred: false },
          eligibility: "EVIDENCE_READY_FOR_POLICY_REVIEW"
        });
        expect(edge.cells.map((c) => c.ownerRelationship)).toEqual([
          "DECLARED_OWNER_IDENTITY",
          "SAME_TENANT_NONOWNER",
          "OTHER_TENANT",
          "ANONYMOUS"
        ]);
        for (const patch of [
          { principalId: "billing-reviewer", actorId: "account-a" },
          { tenantId: "south" },
          { path: "record.version" },
          { principalId: "unobserved" }
        ]) {
          const workflow = structuredClone(f.workflow);
          workflow.relationships[0]!.ownership = { ...workflow.relationships[0]!.ownership!, ...patch } as NonNullable<
            (typeof workflow.relationships)[number]["ownership"]
          >;
          const bad = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow }, "operator");
          expect(bad.relationships!.eligibility).toBe("ABSTAIN");
          expect(bad.relationships!.relationships[0]!.ownerContext.missing.length).toBeGreaterThan(0);
          expect(bad.relationships!.questions.every((q) => !q.findingInferred)).toBe(true);
        }
        const handoff = new ApplicationAnalystHandoff(
          f.database,
          new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench),
          f.workbench
        ).export(f.org, p.proposalId);
        expect(handoff.analystBrief).toMatchObject({
          verified: { latestStatus: "UNTESTED" },
          stateMutationProved: false,
          nativeCompletionIsSecurityPass: false
        });
        expect(JSON.stringify(handoff)).not.toContain("request-owner");
        expect(JSON.stringify(handoff)).not.toContain("Bearer");
        expect(f.wire.length).toBe(wire);
        f.capture("READINESS_NATIVE_OWNER_" + steps, { ready, proposal: p, handoff, wire });
      } finally {
        await f.close();
      }
    }
  );
