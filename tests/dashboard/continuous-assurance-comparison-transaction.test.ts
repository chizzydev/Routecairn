import { describe, it, expect } from "vitest";
import { comparisonCases, runComparisonCase } from "../helpers/continuous-assurance-comparison-fixture.js";

// Run only with an isolated, retain-only test configuration. The repository's
// original mutation-isolation teardown is intentionally not used by this gate.
describe("native Continuous Assurance comparison integrity", () => {
  for (const scenario of comparisonCases) it(scenario, async () => {
    const parent = process.env.ROUTECAIRN_CA_COMPARISON_FIXTURE_PARENT;
    if (!parent) throw new Error("An explicitly owned private fixture parent is required");
    const receipt = await runComparisonCase(scenario, parent);
    expect(receipt.status, JSON.stringify({ root: receipt.root, error: receipt.error })).toBe("PASS");
    expect(receipt.retainedMainDb).toBe(true);
    expect(receipt.nativeHandlesClosed).toBe(true);
  });
});
