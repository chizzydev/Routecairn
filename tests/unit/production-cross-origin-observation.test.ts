import { it, expect } from "vitest";
import { prepareProductionWebCampaign } from "../../src/cli/commands/webAssessment.js";
import { apiGraphqlInputSchema, planApiGraphqlReview } from "../../src/modules/apiGraphql/ApiGraphqlPlanner.js";
import { exampleScope } from "../../src/config/defaults.js";
const fixture = () => {
  const campaign = prepareProductionWebCampaign("https://entry.example.test/", "Owner exact two-origin public control"),
    p = campaign.authorization.productionCampaign!;
  p.inScope.push({ origin: "https://canonical.example.test", pathPrefix: "/" });
  p.requests.push({
    origin: "https://canonical.example.test",
    path: "/",
    method: "GET",
    effect: "READ",
    expectedStatuses: [200]
  });
  const input = apiGraphqlInputSchema.parse({
    actors: [{ id: "public", safeAlias: "public", authSlot: "anonymous", relationship: "PUBLIC" }],
    routes: [
      {
        id: "canonical",
        safeAlias: "canonical",
        protocol: "REST",
        kind: "FUNCTION",
        functionName: "public-http-observation",
        url: "https://canonical.example.test/",
        documentedMethods: ["GET"]
      }
    ],
    checks: [
      {
        id: "canonical",
        matrixId: "canonical",
        label: "Explicit canonical public observation",
        kind: "FUNCTION_AUTHORIZATION",
        actorId: "public",
        routeId: "canonical",
        request: { method: "GET" },
        response: { expectedDecision: "OBSERVE" }
      }
    ]
  });
  const context = {
    target: campaign.entryUrl,
    scope: {
      ...exampleScope,
      allowedDomains: ["entry.example.test", "canonical.example.test"],
      disallowedPaths: [],
      sameOriginOnly: false
    },
    targetAuthorization: campaign.authorization
  };
  return { input, context };
};
it("requires explicit production campaign authority for a public second origin", () => {
  const { input, context } = fixture();
  expect(planApiGraphqlReview(input, context).routes[0]?.url).toBe("https://canonical.example.test/");
  const { targetAuthorization: _, ...ordinary } = context;
  expect(() => planApiGraphqlReview(input, ordinary)).toThrow("target origin");
});
it.each(["policy", "field-proof", "object", "unapproved-route", "query"])(
  "does not widen existing proof authority for %s",
  (fault) => {
    const { input, context } = fixture();
    const check = input.checks[0]!;
    if (!("response" in check)) throw Error("fixture");
    if (fault === "policy") check.response.expectedDecision = "DENY";
    if (fault === "field-proof")
      check.response.fieldRules = [{ path: "secret", classification: "SECRET", expectation: "MUST_BE_ABSENT" }];
    if (fault === "object") {
      input.routes[0]!.kind = "OBJECT";
      input.routes[0]!.objectType = "object";
      input.routes[0]!.pathTemplate = "/";
    }
    if (fault === "unapproved-route") input.routes[0]!.url = "https://canonical.example.test/unapproved";
    if (fault === "query") input.routes[0]!.url = "https://canonical.example.test/?change=true";
    expect(() => planApiGraphqlReview(input, context)).toThrow();
  }
);
