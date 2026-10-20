import { it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
import { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
import type { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
it("keeps incomplete maps UNKNOWN, history source-bound and explicit supersession fail-closed", async () => {
  const f = await applicationMappingFixture();
  try {
    const s = new ApplicationHypothesisService(f.database, f.vault, f.execution),
      r = await f.mapping.create(f.org, f.mappingInput, "operator"),
      p = s.generate(f.org, { mapRevisionId: r.revisionId }, "operator");
    expect(p.candidates.every((c) => c.eligibility === "ABSTAIN")).toBe(true);
    const run = await f.mapping.execute(f.org, r.revisionId, r.digest, "operator");
    await f.wait(run.scanId!);
    expect(s.get(f.org, p.proposalId).freshness).toContain("SOURCE_CHANGED");
    const fresh = s.generate(f.org, { mapRevisionId: r.revisionId, supersedes: p.proposalId }, "operator");
    expect(s.get(f.org, p.proposalId).freshness).toContain("SUPERSEDED");
    expect(() => s.get(randomUUID(), fresh.proposalId)).toThrow("NOT_FOUND");
    expect(() => s.generate(randomUUID(), { mapRevisionId: r.revisionId }, "operator")).toThrow();
    f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.mappingInput.targetId);
    expect(s.get(f.org, fresh.proposalId).freshness).toContain("AUTHORITY_CHANGED");
    expect(() => s.generate(f.org, { mapRevisionId: r.revisionId }, "operator")).toThrow("AUTHORITY_CHANGED");
    expect(f.wire).toHaveLength(20);
  } finally {
    await f.close();
  }
});
it("invalidates policy edits and supersession at actual native admission before new HTTP", async () => {
  const f = await applicationMappingFixture();
  try {
    const a = await f.acquire(),
      s = new ApplicationHypothesisService(f.database, f.vault, f.execution),
      p = s.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator"),
      c = p.candidates.find((c) => c.priority > 0)!;
    const value = {
      action: "REVIEW",
      digest: p.digest,
      candidateId: c.candidateId,
      policyConfirmed: true,
      ownershipConfirmed: true,
      identity: "doc-a",
      tenant: "tenant-a",
      explanation: "Owner declares the exact object private to the primary actor.",
      decisions: { primary: "ALLOW", "account-a": "DENY", "account-b": "DENY", anonymous: "DENY" }
    };
    await expect(s.decide(f.org, p.proposalId, { ...value, identity: 42 }, "operator")).rejects.toThrow(
      "TYPED_PRIMARY"
    );
    const d = await s.decide(f.org, p.proposalId, value, "operator");
    if (!d.matrix) throw Error("Matrix missing");
    await expect(
      f.service.preview(f.org, {
        ...d.matrix.input,
        expectations: d.matrix.input.expectations.map((e) => ({ ...e, explanation: "Changed human policy rationale" }))
      })
    ).rejects.toThrow("POLICY_OR_SOURCE_CHANGED");
    const workers = (f.execution as unknown as { workers: ScanWorkerManager }).workers,
      run = workers.run.bind(workers);
    workers.run = (...args: Parameters<ScanWorkerManager["run"]>) => {
      s.generate(f.org, { mapRevisionId: a.revision.revisionId, supersedes: p.proposalId }, "operator");
      return run(...args);
    };
    const b = await f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
    await expect(f.wait(b.scanId!)).rejects.toThrow("INTERRUPTED");
    expect(f.wire).toHaveLength(20);
    expect(f.status(b.scanId!).error_summary).toContain("HYPOTHESIS_SUPERSEDED");
  } finally {
    await f.close();
  }
});
