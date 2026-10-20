import { retainBusinessPrediction } from "../helpers/businessflow-prediction.js";
import { it, expect } from "vitest";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { businessFlowFixture } from "../helpers/businessflow-fixture.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
import { timedAssessmentPhase } from "../helpers/native-assessment-timings.js";
for (const kind of ["orders", "care"] as const)
  it(
    "links exact native " +
      kind +
      " producer/consumer evidence, reviews policy and proves remediation without implicit execution",
    async () => {
      const cpuStart = process.cpuUsage(),
        started = Date.now(),
        f = await businessFlowFixture(kind);
      const time = Date.now();
      try {
        const a = await f.acquire(f.input),
          wire = f.wire.length,
          p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator");
        expect(p.relationships!.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
        expect(p.relationships!.questions[0]!.actorId).toBe("account-b");
        expect(p.relationships!.questions[0]!.findingInferred).toBe(false);
        expect(p.relationships!.relationships[0]!.cells.filter((c) => c.relationshipObserved)).toHaveLength(3);
        expect(p.relationships!.source.sourceScanId).toBe(a.run.scanId);
        expect(p.flow!.steps.every((s) => s.irCaseIds.length)).toBe(true);
        expect(f.wire.length).toBe(wire);
        const d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
        if (!d.matrix) throw Error("REVIEWED_MATRIX_REQUIRED");
        expect(f.wire.length).toBe(wire);
        const triage = new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench),
          untested = triage.get(f.org, p.proposalId);
        expect(untested.proofs[0]!.status).toBe("REVIEW_REQUIRED");
        const run = await timedAssessmentPhase(f.root, "FLOW_NATIVE_PROOF", () =>
          f.workbench.execute(f.org, d.matrix!.revisionId, d.matrix!.digest, "operator")
        );
        await f.wait(run.scanId!);
        const result = f.workbench.result(f.org, d.matrix.revisionId);
        retainBusinessPrediction(
          f.root,
          kind,
          "vulnerable",
          f.wire.length,
          Date.now() - started,
          process.cpuUsage(cpuStart),
          p.source.sourceHash!,
          result
        );
        expect(result.findings).toHaveLength(2);
        expect(result.checks!.filter((c) => c.checkId.startsWith("source-")).every((c) => c.outcome === "PASS")).toBe(
          true
        );
        const proven = triage.get(f.org, p.proposalId);
        expect(proven.nextAction).toBe("TRIAGE_VERIFIED_NATIVE_DEVIATIONS");
        expect(() =>
          triage.note(
            f.org,
            p.proposalId,
            {
              digest: untested.digest,
              disposition: "INVESTIGATE",
              rationale: "This context changed after native proof was executed.",
              reviewConfirmed: true
            },
            "operator"
          )
        ).toThrow("STALE_EVIDENCE");
        const note = triage.note(
          f.org,
          p.proposalId,
          {
            digest: proven.digest,
            disposition: "OWNER_EXPECTED_BEHAVIOR",
            rationale: "Owner context is retained separately and cannot suppress the native findings.",
            reviewConfirmed: true
          },
          "operator"
        );
        expect(note.scannerOutcomeChanged).toBe(false);
        expect(triage.get(f.org, p.proposalId).proofs[0]!.findings).toHaveLength(2);
        expect(() =>
          f.database.db
            .prepare("UPDATE application_triage_notes SET disposition=? WHERE id=?")
            .run("INVESTIGATE", note.noteId)
        ).toThrow("IMMUTABLE");
        const beforeReplay = f.wire.length;
        expect((await f.workbench.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator")).replayed).toBe(
          false
        );
        expect(f.wire.length).toBe(beforeReplay);
        await expect(f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator")).rejects.toThrow(
          "ALREADY_RECORDED"
        );
        await f.fix();
        const fixed = await f.workbench.create(f.org, d.matrix.input, "operator"),
          after = await f.workbench.execute(f.org, fixed.revisionId, fixed.digest, "operator");
        await f.wait(after.scanId!);
        expect(f.workbench.result(f.org, fixed.revisionId).verifiedPass).toBe(true);
        const comparison = new ScanComparisonService(f.database).compare(run.scanId!, after.scanId!, {
          createdByUserId: "operator"
        });
        expect(comparison.summary.resolved).toBe(2);
        expect(comparison.summary.notRetested).toBe(0);
        const final = triage.get(f.org, p.proposalId);
        expect(final.comparisons).toHaveLength(1);
        expect(final.comparisons[0]!.state).toBe("COMPLETED");
        expect(f.wire.every((r) => r.method === "GET")).toBe(true);
        f.capture("BUSINESSFLOW_NATIVE_END_TO_END", {
          kind,
          elapsedMs: Date.now() - time,
          proposal: p,
          decision: d,
          triage: final,
          comparison,
          truthProvenance: "SELF_MAINTAINED_UNBLINDED",
          noTargetMutation: true
        });
        writeFileSync(
          join(f.root, "FLOW_NOTE_SQLITE.json"),
          JSON.stringify({
            notes: f.database.db.prepare("SELECT * FROM application_triage_notes").all(),
            decisions: f.database.db.prepare("SELECT * FROM application_hypothesis_decisions").all(),
            integrity: f.database.db.pragma("integrity_check")
          }),
          { flag: "wx" }
        );
      } finally {
        await f.close();
      }
    }
  );
