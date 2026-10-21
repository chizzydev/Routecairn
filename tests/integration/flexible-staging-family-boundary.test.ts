import { it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it("staging authority cannot let an anonymous actor bypass a principal-assured workflow", async () => {
  const f = await flexibleFixture(1, { noIdentity: true });
  try {
    const wrapper = JSON.parse(readFileSync(f.registryPath, "utf8")),
      api = JSON.parse(readFileSync(f.apiPath, "utf8"));
    wrapper.registry.actors.push({ id: "public", label: "Public", authentication: { mechanism: "ANONYMOUS" } });
    wrapper.registry.workflows[0].family = "PRINCIPAL_OBSERVATION";
    wrapper.registry.workflows[0].actorIds.push("public");
    api.actors.push({ id: "public", safeAlias: "Public", authSlot: "anonymous", relationship: "PUBLIC" });
    api.checks[0].actorId = "public";
    writeFileSync(f.registryPath, JSON.stringify(wrapper));
    writeFileSync(f.apiPath, JSON.stringify(api));
    writeFileSync(
      f.authorizationPath,
      JSON.stringify({
        schemaVersion: 1,
        mode: "INTERNAL_STAGING",
        targetOrigin: f.origin,
        proof: f.authorization.proof
      })
    );
    let error: string | undefined;
    try {
      await f.run();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    writeFileSync(
      f.root + "/STAGING_FAMILY_ADMISSION.json",
      JSON.stringify(
        { error, wire: f.wire, requestScope: "Owned synthetic GET only; no finding or external-scope bypass claimed" },
        null,
        2
      ),
      { flag: "wx" }
    );
    expect(error).toContain("ANONYMOUS_WORKFLOW_FAMILY_CONFLICT");
    expect(f.wire.some((w) => w.path === "/private")).toBe(false);
  } finally {
    await f.close();
  }
});
