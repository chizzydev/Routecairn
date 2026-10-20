import { retainBusinessPrediction } from "../helpers/businessflow-prediction.js";
import { it, expect } from "vitest";
import { businessFlowFixture } from "../helpers/businessflow-fixture.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
for (const kind of ["orders", "care"] as const)
  for (const mode of [
    "secure",
    "shared",
    "wrong-object",
    "stale-version",
    "missing-positive",
    "missing-reference",
    "type-confusion"
  ] as const)
    it(
      "preserves " + kind + " negative control " + mode + " as exact evidence, abstention or explicit untested outcome",
      async () => {
        const cpuStart = process.cpuUsage(),
          started = Date.now(),
          f = await businessFlowFixture(kind, mode);
        try {
          const a = await f.acquire(f.input),
            p = f.hypotheses.generate(
              f.org,
              { mapRevisionId: a.revision.revisionId, workflow: f.workflow },
              "operator"
            ),
            edge = p.relationships!.relationships[0]!,
            before = f.wire.length;
          let outcome = "ABSTAIN";
          if (["missing-positive", "missing-reference", "type-confusion"].includes(mode)) {
            retainBusinessPrediction(
              f.root,
              kind,
              mode,
              f.wire.length,
              Date.now() - started,
              process.cpuUsage(cpuStart),
              p.source.sourceHash!,
              undefined,
              edge.eligibility
            );
            expect(edge.eligibility).toBe("ABSTAIN");
            await expect(f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator")).rejects.toThrow();
            expect(f.wire.length).toBe(before);
          } else {
            expect(edge.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
            if (mode === "wrong-object") expect(edge.cells[1]!.reasons.join(",")).toContain("REFERENCE_MISMATCH");
            if (mode === "stale-version") expect(edge.cells[1]!.reasons).toContain("STALE_OR_DIFFERENT_ENTITY_VERSION");
            const d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
            if (!d.matrix) throw Error("MATRIX");
            const run = await f.workbench.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
            await f.wait(run.scanId!);
            const r = f.workbench.result(f.org, d.matrix.revisionId);
            retainBusinessPrediction(
              f.root,
              kind,
              mode,
              f.wire.length,
              Date.now() - started,
              process.cpuUsage(cpuStart),
              p.source.sourceHash!,
              r
            );
            expect(r.findings).toHaveLength(0);
            if (mode === "wrong-object" || mode === "stale-version") {
              expect(r.status).toBe("INCONCLUSIVE");
              outcome = "ABSTAIN";
            } else {
              expect(r.verifiedPass).toBe(true);
              outcome = "NO_FINDING";
            }
          }
          const t = new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench).get(f.org, p.proposalId);
          expect(t.executionAuthority).toBe("NONE");
          expect(t.comparisons).toHaveLength(0);
          expect(f.wire.every((r) => r.method === "GET")).toBe(true);
          f.capture("BUSINESSFLOW_NEGATIVE_PREDICTION", {
            kind,
            mode,
            outcome,
            sourceHash: a.result.sourceHash,
            proposal: p,
            triage: t,
            requests: f.wire.length,
            independent: false,
            blinded: false
          });
        } finally {
          await f.close();
        }
      }
    );
