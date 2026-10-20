import { describe, it } from "vitest";
import { assertInterruptionScenario, interruptionCases, runInterruptionScenario } from "../helpers/continuous-assurance-interruption-fixture.js";

// Requires an explicitly caller-owned ROUTECAIRN_CA_LAB. The isolated comparison
// config runs these unchanged assertions without the original global deletion hook.
describe("continuous assurance Windows interruption and replay", () => {
  for (const name of interruptionCases) {
    it(name, async () => assertInterruptionScenario(await runInterruptionScenario(name)));
  }
});
