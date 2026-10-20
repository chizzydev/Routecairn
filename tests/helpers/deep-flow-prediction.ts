import { writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AuthorizationWorkbenchService } from "../../src/dashboard/execution/AuthorizationWorkbenchService.js";
/** Persist actual observations before correctness assertions. Failures never remove a fixed case opportunity. */
export function retainDeepFlowPrediction(
  root: string,
  kind: string,
  mode: string,
  requests: number,
  wallMs: number,
  cpu: NodeJS.CpuUsage,
  sourceHash: string,
  result?: ReturnType<AuthorizationWorkbenchService["result"]>,
  eligibility?: string
) {
  const outcome = result
    ? result.findings?.length && result.checks?.some((c) => c.outcome === "FAIL")
      ? "FINDING"
      : result.verifiedPass && result.checks?.every((c) => c.outcome === "PASS")
        ? "NO_FINDING"
        : result.status === "INCONCLUSIVE"
          ? "ABSTAIN"
          : "UNTESTED"
    : eligibility === "ABSTAIN"
      ? "ABSTAIN"
      : "UNTESTED";
  const receipt = {
    version: 1,
    applicationId: kind,
    caseId: kind + ":" + mode,
    outcome,
    sourceHash: result?.sourceHash ?? sourceHash,
    requests,
    wallMs,
    parentCpuMicros: cpu,
    cpuScope: "PARENT_DELTA_EXCLUDES_NATIVE_WORKERS_AND_PYTHON",
    wallScope: "SETUP_THROUGH_PREDICTION_EXCLUDES_CLOSE",
    nativeResult: result ?? null,
    relationshipEligibility: eligibility ?? null,
    truthOpenedByThisFunction: false,
    independent: false,
    blinded: false
  };
  writeFileSync(join(root, "DEEP_FLOW_PREDICTION_COMMITTED.json"), JSON.stringify(receipt, null, 2), { flag: "wx" });
  return receipt;
}
