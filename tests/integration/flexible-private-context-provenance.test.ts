import { it, expect } from "vitest";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it("does not manufacture transmitted-value evidence from a private redaction context", async () => {
  const f = await flexibleFixture(1);
  try {
    const { report } = await f.run();
    const fabricated = report.requestAudit
      .flatMap((a: { valueAttestations?: Array<{ name: string }> }) => a.valueAttestations ?? [])
      .filter((a: { name: string }) => a.name === "private-credential-context");
    expect(fabricated).toEqual([]);
  } finally {
    await f.close();
  }
});
