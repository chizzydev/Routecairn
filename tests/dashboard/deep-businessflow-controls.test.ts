import { it, expect } from "vitest";
import { retainDeepFlowPrediction } from "../helpers/deep-flow-prediction.js";
import { deepBusinessFixture, type DeepMode } from "../helpers/deep-businessflow-fixture.js";
for (const mode of [
  "missing-producer",
  "stale-version",
  "tenant-drift",
  "typed-disagreement",
  "duplicate-reference",
  "missing-reference",
  "shared"
] as DeepMode[])
  it("keeps four-step " + mode + " counterevidence explicit without inferred policy or execution", async () => {
    const started = Date.now(),
      cpu = process.cpuUsage(),
      f = await deepBusinessFixture(4, mode);
    try {
      const a = await f.acquire(f.input),
        p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
        wire = f.wire.length;
      const pairReady =
        p.relationships!.eligibility === "EVIDENCE_READY_FOR_POLICY_REVIEW" &&
        p.relationships!.relationships.every((e) =>
          e.cells.filter((c) => c.actorId !== "anonymous").every((c) => c.relationshipObserved)
        );
      if (!pairReady)
        retainDeepFlowPrediction(
          f.root,
          "procurement4",
          mode,
          f.wire.length,
          Date.now() - started,
          process.cpuUsage(cpu),
          p.source.sourceHash!,
          undefined,
          "ABSTAIN"
        );
      if (["missing-producer", "typed-disagreement", "missing-reference", "duplicate-reference"].includes(mode)) {
        expect(p.relationships!.eligibility).toBe("ABSTAIN");
        await expect(f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator")).rejects.toThrow("ABSTAIN");
      } else if (mode === "shared") {
        expect(p.relationships!.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
        const d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
        if (!d.matrix) throw Error("MATRIX");
        const r = await f.workbench.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
        await f.wait(r.scanId!);
        const native = f.workbench.result(f.org, d.matrix.revisionId);
        retainDeepFlowPrediction(
          f.root,
          "procurement4",
          mode,
          f.wire.length,
          Date.now() - started,
          process.cpuUsage(cpu),
          p.source.sourceHash!,
          native
        );
        expect(native.findings).toHaveLength(0);
      } else {
        expect(
          p.relationships!.relationships.some((e) =>
            e.cells.some((c) => c.actorId === "account-a" && c.reasons.length > 0)
          )
        ).toBe(true);
        expect(
          p
            .relationships!.questions.filter((q) => q.actorId === "account-a" && q.producer === "invoice")
            .every((q) => q.eligibility === "ABSTAIN_OR_COUNTEREVIDENCE")
        ).toBe(true);
      }
      if (mode !== "shared") expect(f.wire.length).toBe(wire);
      f.capture("DEEP_CONTROL_" + mode, { proposal: p, mode });
    } finally {
      await f.close();
    }
  });
