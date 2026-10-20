import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  commitPracticalRun,
  scorePracticalRun,
  practicalBenchmarkSchema
} from "../../src/benchmark/PracticalAssessmentBenchmark.js";
import type { AuthorizationWorkbenchService } from "../../src/dashboard/execution/AuthorizationWorkbenchService.js";
export function retainPracticalPrediction(
  app: "html" | "jsonapi",
  root: string,
  requests: number,
  wallMs: number,
  result: ReturnType<AuthorizationWorkbenchService["result"]>
) {
  const path = process.env.ROUTECAIRN_PRACTICAL_BENCHMARK;
  if (!path) throw Error("PRECOMMITTED_PRACTICAL_MANIFEST_REQUIRED");
  const manifest = practicalBenchmarkSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  const predictions = ["restricted", "shared", "personal", "missing", "sealed", "untyped"].map((id) => {
    const checks = result.checks?.filter((c) => c.routeIds?.includes(id)) ?? [];
    return {
      id: app + ":" + id,
      outcome: checks.some((c) => c.outcome === "FAIL")
        ? "FINDING"
        : checks.length && checks.every((c) => c.outcome === "PASS")
          ? "NO_FINDING"
          : "ABSTAIN",
      sourceHash: result.sourceHash!,
      reason:
        checks
          .map((c) => c.reasonCode)
          .join(",")
          .slice(0, 200) || "INCOMPLETE_NATIVE_CONTROL"
    };
  });
  const receipt = commitPracticalRun(manifest, app + "-" + process.env.ROUTECAIRN_PRACTICAL_REPEAT, [
    {
      applicationId: app,
      predictions,
      observedSources: 4,
      discoveredRoutes: 7,
      requests,
      wallMs,
      parentCpuMicros: process.cpuUsage()
    }
  ]);
  writeFileSync(join(root, "PRACTICAL_PREDICTIONS_COMMITTED.json"), JSON.stringify(receipt, null, 2), { flag: "wx" });
  const oracle = readFileSync(new URL("../fixtures/practical-assessment-oracle-v1.json", import.meta.url));
  const score = scorePracticalRun(manifest, receipt, oracle);
  writeFileSync(join(root, "PRACTICAL_ORACLE_REVEAL.json"), oracle, { flag: "wx" });
  writeFileSync(join(root, "PRACTICAL_SCORE.json"), JSON.stringify(score, null, 2), { flag: "wx" });
  writeFileSync(
    join(root, "PRACTICAL_ORDER_RECEIPT.json"),
    JSON.stringify({
      manifestPath: path,
      manifestSha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
      predictionOpenedBeforeOracle: true,
      trustedTime: false,
      independentAcceptance: false,
      cpuScope: "PARENT_PROCESS_CUMULATIVE_EXCLUDES_WORKERS_NOT_PER_ASSESSMENT_DELTA"
    }),
    { flag: "wx" }
  );
}
