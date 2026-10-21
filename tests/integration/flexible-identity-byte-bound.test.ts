import { it, expect } from "vitest";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it("does not admit higher-assurance checks from a real oversized chunked identity response", async () => {
  const f = await flexibleFixture(2, { oversizeIdentity: true });
  try {
    const { report } = await f.run();
    expect(report.identityVerification.actors.actor0.verified).toBe(false);
    expect(report.identityVerification.actors.actor0.category).toBe("RESPONSE_TOO_LARGE");
    expect(f.wire.filter((r) => r.path === "/object/actor0")).toEqual([]);
    expect(report.apiGraphql.checks.find((c: { checkId: string }) => c.checkId === "compare-actor1").outcome).toBe(
      "BLOCKED"
    );
  } finally {
    await f.close();
  }
});
