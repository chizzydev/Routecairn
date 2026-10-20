import { it, expect } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { apiGraphqlInputSchema, planApiGraphqlReview } from "../../src/modules/apiGraphql/ApiGraphqlPlanner.js";
import { observedMarkerFingerprint } from "../../src/modules/apiGraphql/ObservedMarker.js";
const seed = () => ({
  schemaVersion: 1,
  actors: [{ id: "public", safeAlias: "public", authSlot: "anonymous", relationship: "PUBLIC" }],
  routes: [
    {
      id: "read",
      safeAlias: "read",
      protocol: "REST",
      kind: "OBJECT",
      objectType: "object",
      url: "http://127.0.0.1/api/object/a",
      pathTemplate: "/api/object/:id",
      documentedMethods: ["GET"]
    }
  ],
  checks: [
    {
      id: "observe",
      matrixId: "observe",
      label: "Observe scoped fields",
      kind: "OBJECT_AUTHORIZATION",
      routeId: "read",
      actorId: "public",
      requireVerifiedIdentity: false,
      request: { method: "GET" },
      response: { expectedDecision: "OBSERVE", observationPaths: ["id", "tenant"] }
    }
  ]
});
const context = {
  target: "http://127.0.0.1",
  scope: { ...exampleScope, allowedDomains: ["127.0.0.1"], allowedMethods: ["GET"] as ["GET"], disallowedPaths: [] }
};
it("does not conflate string and numeric observed identities", () => {
  expect(observedMarkerFingerprint("42")).not.toBe(observedMarkerFingerprint(42));
  expect(observedMarkerFingerprint("42")).toHaveLength(64);
});
it("retains only explicit bounded observation paths and refuses capture on assertion contracts", () => {
  const input = apiGraphqlInputSchema.parse(seed()),
    plan = planApiGraphqlReview(input, context);
  expect(plan.checks[0]).toMatchObject({ response: { observationPaths: ["id", "tenant"] } });
  const changed = seed();
  changed.checks[0]!.response.expectedDecision = "DENY";
  expect(() => planApiGraphqlReview(apiGraphqlInputSchema.parse(changed), context)).toThrow("observation-only");
  const excessive = seed();
  excessive.checks[0]!.response.observationPaths = Array(5).fill("id");
  expect(apiGraphqlInputSchema.safeParse(excessive).success).toBe(false);
});
it.each(["password", "access_token", "__proto__.id", "constructor.name"])(
  "refuses unsafe selected marker path %s",
  (path) => {
    const input = seed();
    input.checks[0]!.response.observationPaths = [path];
    expect(() => planApiGraphqlReview(apiGraphqlInputSchema.parse(input), context)).toThrow();
  }
);
