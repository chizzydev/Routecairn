import { it, expect } from "vitest";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it.each(["role", "tenant"] as const)(
  "does not promote principal evidence into an independently verified %s",
  async (identityAlias) => {
    const f = await flexibleFixture(1, { identityAlias });
    try {
      await expect(f.run()).rejects.toThrow("INDEPENDENT_IDENTITY");
      expect(f.wire).toEqual([]);
    } finally {
      await f.close();
    }
  }
);
