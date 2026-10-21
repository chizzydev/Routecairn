import { it, expect } from "vitest";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it("registry assessments retain evidence-only parameter and manual hypothesis modules", async () => {
  const f = await flexibleFixture(0, { staticIntelligence: true });
  try {
    const r = await f.run();
    expect(r.report.parameterAnalysis).toBeDefined();
    expect(r.report.vulnerabilityWorkflows).toBeDefined();
    expect(r.report.scanPlan.modules.some((m: { id: string }) => m.id === "parameter-analysis")).toBe(true);
    expect(r.report.findings).toEqual([]);
  } finally {
    await f.close();
  }
});
