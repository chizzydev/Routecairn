import { it, expect } from "vitest";
import { discoveryApplicationFixture } from "../helpers/discovery-application-fixture.js";
it("abstains when real native identity verification expires rather than promoting advertised routes", async () => {
  const f = await discoveryApplicationFixture();
  try {
    f.setExpiredIdentity();
    const observed = await f.acquire(f.seedInput),
      p = f.propose(observed.revision.revisionId);
    expect(p.candidates).toHaveLength(0);
    expect(p.missingControls.some((m) => m.includes("IDENTITY"))).toBe(true);
    expect(f.wire.every((w) => w.path === "/" || w.path === "/identity" || w.path === f.prefix + "catalog/start")).toBe(
      true
    );
    f.capture("EXPIRED_NATIVE_IDENTITY_ABSTENTION", p);
  } finally {
    await f.close();
  }
});
