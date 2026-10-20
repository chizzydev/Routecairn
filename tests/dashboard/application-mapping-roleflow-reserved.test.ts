import { it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { roleflowApplicationFixture } from "../helpers/roleflow-application-fixture.js";
const bytes = readFileSync(new URL("../fixtures/roleflow-reserved-final-evaluation.json", import.meta.url)),
  data = JSON.parse(bytes.toString()) as {
    cases: {
      id: string;
      application: "procurement" | "membership";
      mode: "shared" | "vulnerable";
      resource: string | number;
      state: string | number;
      roles: [string, string, string];
      expectedFindings: number;
    }[];
  };
for (const c of data.cases)
  it("evaluates reserved typed role/state data without exposing policy labels to the engine " + c.id, async () => {
    const f = await roleflowApplicationFixture(c.application, c.mode, c);
    try {
      const a = await f.acquire(),
        p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator");
      expect(p.flow!.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
      const before = f.wire.length,
        d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
      expect(f.wire.length).toBe(before);
      if (!d.matrix) throw Error("matrix");
      const run = await f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
      await f.wait(run.scanId!);
      const result = f.service.result(f.org, d.matrix.revisionId);
      expect(result.findings).toHaveLength(c.expectedFindings);
      expect(result.verifiedPass).toBe(c.expectedFindings === 0);
      writeFileSync(
        join(f.root, "RESERVED_FINAL_RESULT.json"),
        JSON.stringify(
          {
            caseId: c.id,
            dataSha256: createHash("sha256").update(bytes).digest("hex"),
            expectedFindings: c.expectedFindings,
            result,
            requests: f.wire.length,
            externalTargets: false,
            independentlyBlinded: false
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
