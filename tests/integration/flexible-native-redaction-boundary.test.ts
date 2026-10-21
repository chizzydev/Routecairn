import { it, expect } from "vitest";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it("rejects incomplete native identity despite a valid bounded JSON prefix", async () => {
  const f = await flexibleFixture(2, { oversizeIdentity: true, identityResponseCap: 4096 });
  try {
    const { report } = await f.run();
    expect(report.identityVerification.actors.actor0.verified).toBe(false);
    expect(f.wire.filter((r) => r.path === "/object/actor0")).toEqual([]);
  } finally {
    await f.close();
  }
});
it("keeps arbitrary API-key header material out of the native portable report", async () => {
  const f = await flexibleFixture(1, { mechanism: "API_KEY" });
  try {
    const { report } = await f.run();
    expect(JSON.stringify(report)).not.toContain(f.tokens[0]);
  } finally {
    await f.close();
  }
});
