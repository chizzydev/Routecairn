import { it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it("a reviewed stronger workflow cannot bypass native assurance by selecting an anonymous manifest actor", async () => {
  const f = await flexibleFixture(1, { noIdentity: true });
  try {
    const wrapper = JSON.parse(readFileSync(f.registryPath, "utf8")),
      api = JSON.parse(readFileSync(f.apiPath, "utf8")),
      authorization = JSON.parse(readFileSync(f.authorizationPath, "utf8"));
    wrapper.registry.actors.push({
      id: "public",
      label: "Declared public actor",
      authentication: { mechanism: "ANONYMOUS" }
    });
    wrapper.registry.workflows[0].family = "PRINCIPAL_OBSERVATION";
    wrapper.registry.workflows[0].actorIds.push("public");
    api.actors.push({ id: "public", safeAlias: "Public", authSlot: "anonymous", relationship: "PUBLIC" });
    api.checks[0].actorId = "public";
    authorization.productionCampaign.workflowAuthorizations = wrapper.registry.workflows;
    writeFileSync(f.registryPath, JSON.stringify(wrapper));
    writeFileSync(f.apiPath, JSON.stringify(api));
    writeFileSync(f.authorizationPath, JSON.stringify(authorization));
    let error: string | undefined;
    try {
      await f.run();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    writeFileSync(f.root + "/ANONYMOUS_FAMILY_ADMISSION.json", JSON.stringify({ error, wire: f.wire }, null, 2), {
      flag: "wx"
    });
    expect(error).toContain("ANONYMOUS_WORKFLOW_FAMILY_CONFLICT");
    expect(f.wire.some((w) => w.path === "/private")).toBe(false);
  } finally {
    await f.close();
  }
});
