import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
import { schemaApplicationFixture } from "../helpers/schema-application-fixture.js";
import { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
for (const application of ["document", "numeric"])
  it("grounds, reviews, proves and remediates hypotheses on the owned " + application + " application", async () => {
    const f = application === "document" ? await applicationMappingFixture() : await schemaApplicationFixture();
    try {
      const input = "makeInput" in f ? f.makeInput().mappingInput : f.mappingInput,
        r = await f.mapping.create(f.org, input, "operator"),
        a = await f.mapping.execute(f.org, r.revisionId, r.digest, "operator");
      await f.wait(a.scanId!);
      const service = new ApplicationHypothesisService(f.database, f.vault, f.execution),
        p = service.generate(f.org, { mapRevisionId: r.revisionId }, "operator"),
        c = p.candidates.find((c) => c.eligibility === "EVIDENCE_READY_FOR_POLICY_REVIEW")!;
      expect(p.candidates).toHaveLength(4);
      expect(p.candidates.filter((c) => c.eligibility === "ABSTAIN")).toHaveLength(3);
      expect(c.supportingActors).toEqual(["account-a", "account-b"]);
      expect(c.irCaseIds.length).toBeGreaterThan(0);
      expect(f.wire).toHaveLength(20);
      const q = service.generate(f.org, { mapRevisionId: r.revisionId }, "operator");
      expect(q.digest).toBe(p.digest);
      expect(q.candidates.map((c) => c.candidateId)).toEqual(p.candidates.map((c) => c.candidateId));
      const decision = await service.decide(
        f.org,
        p.proposalId,
        {
          action: "REVIEW",
          digest: p.digest,
          candidateId: c.candidateId,
          policyConfirmed: true,
          ownershipConfirmed: true,
          identity: application === "numeric" ? 42 : "doc-a",
          tenant: application === "numeric" ? "workspace-red" : "tenant-a",
          explanation: "Owner declares this exact disposable object is private to its publisher.",
          decisions: { primary: "ALLOW", "account-a": "DENY", "account-b": "DENY", anonymous: "DENY" }
        },
        "operator"
      );
      if (!decision.matrix) throw Error("No matrix");
      expect(f.wire).toHaveLength(20);
      expect(decision.matrix.classification).toBe("READY_READ_ONLY");
      const b = await f.service.execute(f.org, decision.matrix.revisionId, decision.matrix.digest, "operator");
      await f.wait(b.scanId!);
      const before = f.service.result(f.org, decision.matrix.revisionId);
      expect(before.findings).toHaveLength(2);
      f.setFixed();
      const after = await f.service.create(f.org, decision.matrix.input, "operator"),
        run = await f.service.execute(f.org, after.revisionId, after.digest, "operator");
      await f.wait(run.scanId!);
      const fixed = f.service.result(f.org, after.revisionId);
      expect(fixed.findings).toHaveLength(0);
      const compare = new ScanComparisonService(f.database).compare(b.scanId!, run.scanId!, {
        createdByUserId: "operator"
      });
      expect(compare.summary.resolved).toBe(2);
      expect(f.wire).toHaveLength(36);
      expect(f.wire.every((r) => r.method === "GET")).toBe(true);
      expect(() =>
        f.database.db.prepare("DELETE FROM application_hypothesis_decisions WHERE id=?").run(decision.decisionId)
      ).toThrow("IMMUTABLE_HYPOTHESIS_DECISION");
      expect(() =>
        f.database.db.prepare("UPDATE application_hypothesis_proposals SET digest='x' WHERE id=?").run(p.proposalId)
      ).toThrow("IMMUTABLE_HYPOTHESIS_PROPOSAL");
      writeFileSync(
        join(f.root, "HYPOTHESIS_METRICS.json"),
        JSON.stringify(
          {
            application,
            candidates: 4,
            evidenceReady: 1,
            abstained: 3,
            falseVulnerabilityClaims: 0,
            proofsAuthorized: 2,
            findingsVerified: 2,
            remediationFindings: 0,
            resolved: compare.summary.resolved,
            requests: f.wire.length,
            noWireGenerationAndReview: true,
            proposal: p,
            decisionId: decision.decisionId,
            integrity: f.database.db.pragma("integrity_check")
          },
          null,
          2
        ),
        { flag: "wx" }
      );
    } finally {
      await f.close();
    }
  });
it("treats legitimate shared access as a policy question and supports rejection without execution", async () => {
  const f = await applicationMappingFixture({ sharedPolicy: true });
  try {
    const a = await f.acquire(),
      service = new ApplicationHypothesisService(f.database, f.vault, f.execution),
      p = service.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator"),
      c = p.candidates.find((c) => c.priority > 0)!;
    const decision = await service.decide(
      f.org,
      p.proposalId,
      { action: "REJECT", digest: p.digest, candidateId: c.candidateId, reason: "EXPECTED_SHARED_ACCESS" },
      "operator"
    );
    expect(decision.status).toBe("REJECTED");
    expect(f.wire).toHaveLength(20);
    expect(service.get(f.org, p.proposalId).decisions).toHaveLength(1);
    await expect(
      service.decide(
        f.org,
        p.proposalId,
        { action: "REJECT", digest: p.digest, candidateId: c.candidateId, reason: "NOT_A_SECURITY_BOUNDARY" },
        "operator"
      )
    ).rejects.toThrow("ALREADY_RECORDED");
    writeFileSync(
      join(f.root, "LEGITIMATE_SHARED_POLICY_CONTROL.json"),
      JSON.stringify(
        {
          policyDeclaredPublicToAuthenticatedActors: true,
          observedCandidate: 1,
          rejected: 1,
          proofsAuthorized: 0,
          findingsInferred: 0,
          requests: 20
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  } finally {
    await f.close();
  }
});

it("verifies explicitly permitted shared access without manufacturing a finding", async () => {
  const f = await applicationMappingFixture({ sharedPolicy: true });
  try {
    const a = await f.acquire(),
      s = new ApplicationHypothesisService(f.database, f.vault, f.execution),
      p = s.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator"),
      c = p.candidates.find((c) => c.priority > 0)!;
    const d = await s.decide(
      f.org,
      p.proposalId,
      {
        action: "REVIEW",
        digest: p.digest,
        candidateId: c.candidateId,
        policyConfirmed: true,
        ownershipConfirmed: true,
        identity: "doc-a",
        tenant: "tenant-a",
        explanation: "This disposable published resource intentionally permits all authenticated actors.",
        decisions: { primary: "ALLOW", "account-a": "ALLOW", "account-b": "ALLOW", anonymous: "DENY" }
      },
      "operator"
    );
    if (!d.matrix) throw Error("Matrix missing");
    const run = await f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
    await f.wait(run.scanId!);
    expect(f.service.result(f.org, d.matrix.revisionId).findings).toHaveLength(0);
    expect(f.wire).toHaveLength(28);
    writeFileSync(
      join(f.root, "LEGITIMATE_SHARED_NATIVE_PROOF.json"),
      JSON.stringify(
        { predeclaredExpectedShared: true, candidates: 1, proofsAuthorized: 1, findingsVerified: 0, requests: 28 },
        null,
        2
      ),
      { flag: "wx" }
    );
  } finally {
    await f.close();
  }
});
