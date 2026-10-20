import { authorizationWorkbenchFixture } from "./authorization-workbench-fixture.js";
import { ApplicationMappingService } from "../../src/dashboard/execution/ApplicationMappingService.js";
import type { ApplicationMappingInput } from "../../src/dashboard/contracts/ApplicationMappingContracts.js";
export async function applicationMappingFixture(options: { sharedPolicy?: boolean } = {}) {
  const f = await authorizationWorkbenchFixture({ prepareObservation: false, ...options });
  const input: ApplicationMappingInput = {
    targetId: f.input.targetId,
    credentials: {
      primary: f.input.credentials.primary!,
      account_a: f.input.credentials.account_a!,
      account_b: f.input.credentials.account_b!
    },
    identityContextConfirmed: true,
    readOnlyRoutesConfirmed: true,
    routes: f.input.expectations.map((e) => ({
      id: e.routeId,
      kind: e.routeId === "admin" ? "FUNCTION" : "OBJECT",
      url: e.url!,
      pathTemplate:
        e.routeId === "admin"
          ? "/api/admin/summary"
          : "/api/" + (e.routeId === "document" ? "documents" : e.routeId) + "/:id",
      method: "GET",
      identityPath: "id",
      tenantPath: "tenant"
    }))
  };
  const policy = {
    policyConfirmed: true as const,
    expectations: f.input.expectations.map((e) => ({
      ...e,
      decisions: {
        primary: "ALLOW" as const,
        "account-a": "DENY" as const,
        "account-b": "DENY" as const,
        anonymous: "DENY" as const
      }
    }))
  };
  const mapping = new ApplicationMappingService(f.database, f.vault, f.execution);
  const acquire = async () => {
    const revision = await mapping.create(f.org, input, "operator"),
      run = await mapping.execute(f.org, revision.revisionId, revision.digest, "operator");
    await f.wait(run.scanId!);
    return { revision, run, result: mapping.result(f.org, revision.revisionId) };
  };
  return { ...f, mapping, mappingInput: input, policy, acquire };
}
