import { it, expect } from "vitest";
import { applicationMappingInputSchema } from "../../src/dashboard/contracts/ApplicationMappingContracts.js";
import { hypothesisGenerateSchema } from "../../src/dashboard/contracts/ApplicationHypothesisContracts.js";
const uuid = "123e4567-e89b-42d3-a456-426614174000";
const input = {
  targetId: uuid,
  credentials: { primary: uuid, account_a: uuid, account_b: uuid },
  routes: [
    {
      id: "source",
      kind: "OBJECT",
      url: "http://127.0.0.1/test",
      pathTemplate: "/test",
      method: "GET",
      identityPath: "record.id",
      tenantPath: "record.tenant",
      statePaths: ["workflow.phase"]
    }
  ],
  identityContextConfirmed: true,
  readOnlyRoutesConfirmed: true
};
it("accepts bounded explicit state markers without changing existing route contracts", () => {
  expect(applicationMappingInputSchema.safeParse(input).success).toBe(true);
  const legacy = structuredClone(input);
  delete (legacy.routes[0] as { statePaths?: string[] }).statePaths;
  expect(applicationMappingInputSchema.safeParse(legacy).success).toBe(true);
});
for (const paths of [
  ["record.id"],
  ["record.tenant"],
  ["workflow.phase", "workflow.phase"],
  ["session.secret"],
  ["workflow.phase", "workflow.other", "workflow.third"]
])
  it("refuses unsafe or non-independent state fields " + paths.join(","), () => {
    expect(
      applicationMappingInputSchema.safeParse({ ...input, routes: [{ ...input.routes[0], statePaths: paths }] }).success
    ).toBe(false);
  });
for (const ids of [["source"], ["source", "source"], ["a", "b", "c", "d", "e"]])
  it("refuses invalid bounded ordered flow " + ids.join(","), () => {
    expect(
      hypothesisGenerateSchema.safeParse({ mapRevisionId: uuid, workflow: { name: "Owned flow", routeIds: ids } })
        .success
    ).toBe(false);
  });
