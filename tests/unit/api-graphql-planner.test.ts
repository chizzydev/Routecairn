import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";
import { apiGraphqlInputSchema, planApiGraphqlReview } from "../../src/modules/apiGraphql/ApiGraphqlPlanner.js";

const authProfile: AuthProfile = { label: "member", safeAlias: "member", headers: { Authorization: "Bearer planner-secret" }, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { object_id: "object-1" }, notes: [] };
const scope = { ...exampleScope, allowedDomains: ["api.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const };
const context = { target: "https://api.example.test/", scope, authProfile };

describe("API and GraphQL planner", () => {
  it("changes comparison identity when a route, actor boundary, or expected value changes", () => {
    const input = apiGraphqlInputSchema.parse(validInput());
    const original = planApiGraphqlReview(input, context).checks[0]!.comparisonFingerprint;
    const routed = structuredClone(input); routed.routes[0]!.url = "https://api.example.test/graphql-v2";
    expect(planApiGraphqlReview(routed, context).checks[0]!.comparisonFingerprint).not.toBe(original);
    const actor = structuredClone(input); actor.actors[0]!.relationship = "OWNER";
    expect(planApiGraphqlReview(actor, context).checks[0]!.comparisonFingerprint).not.toBe(original);
    const variables = structuredClone(input);
    if (variables.checks[0]!.kind === "FIELD_AUTHORIZATION") variables.checks[0]!.request.graphql!.variables = { id: "another-controlled-object" };
    expect(planApiGraphqlReview(variables, context).checks[0]!.comparisonFingerprint).not.toBe(original);
  });

  it("builds a bounded structural plan without persisting authentication material", () => {
    const plan = planApiGraphqlReview(apiGraphqlInputSchema.parse(validInput()), context);
    expect(plan).toMatchObject({ enabled: true, maxRequests: 20, actors: [{ authSlot: "primary" }], routes: [{ protocol: "GRAPHQL" }], checks: [{ kind: "FIELD_AUTHORIZATION" }, { kind: "GRAPHQL_INTROSPECTION" }, { kind: "GRAPHQL_ALIAS_LIMIT" }] });
    expect(plan.checks[0]?.comparisonFingerprint).toHaveLength(64);
    expect(JSON.stringify(plan)).not.toContain("planner-secret");
  });

  it("rejects GraphQL mutations, alias count mismatches, literal secrets, and unsafe REST POST", () => {
    const mutation: any = validInput(); mutation.checks[0].request.graphql.document = "mutation Update { updateUser { id } }";
    expect(() => planApiGraphqlReview(apiGraphqlInputSchema.parse(mutation), context)).toThrow(/query operation/i);

    const aliases: any = validInput(); aliases.checks[2].operationCount = 3;
    expect(() => planApiGraphqlReview(apiGraphqlInputSchema.parse(aliases), context)).toThrow(/declared count/i);

    const secret: any = validInput(); secret.checks[0].request.graphql.variables = { access_token: "Bearer literal-secret" };
    expect(() => planApiGraphqlReview(apiGraphqlInputSchema.parse(secret), context)).toThrow(/literal secret/i);

    const post: any = validInput(); post.routes.push({ id: "preview", safeAlias: "preview", protocol: "REST", kind: "FUNCTION", functionName: "preview", url: "https://api.example.test/preview", documentedMethods: ["POST"] }); post.checks.push({ id: "preview-check", matrixId: "preview-function", label: "preview", kind: "FUNCTION_AUTHORIZATION", routeId: "preview", actorId: "member", requireVerifiedIdentity: false, request: { method: "POST", body: { dryRun: true } }, response: { expectedDecision: "ALLOW" } });
    expect(() => planApiGraphqlReview(apiGraphqlInputSchema.parse(post), context)).toThrow(/non-mutating attestations/i);
  });

  it("rejects unsafe object inventory and inconsistent authorization matrices", () => {
    const objectRoute: any = validInput();
    objectRoute.routes.push({ id: "account", safeAlias: "account", protocol: "REST", kind: "OBJECT", objectType: "account", url: "https://api.example.test/accounts/object-1", documentedMethods: ["GET"] });
    expect(() => planApiGraphqlReview(apiGraphqlInputSchema.parse(objectRoute), context)).toThrow(/safe pathTemplate/i);

    const matrix: any = validInput();
    matrix.routes.push({ id: "admin", safeAlias: "admin", protocol: "REST", kind: "FUNCTION", functionName: "admin.summary", url: "https://api.example.test/admin", documentedMethods: ["GET"] });
    matrix.checks.push({ id: "admin-access", matrixId: "viewer-fields", label: "admin access", kind: "FUNCTION_AUTHORIZATION", routeId: "admin", actorId: "member", requireVerifiedIdentity: false, request: { method: "GET" }, response: { expectedDecision: "DENY" } });
    expect(() => planApiGraphqlReview(apiGraphqlInputSchema.parse(matrix), context)).toThrow(/one check kind and route/i);
  });
});

function validInput(): unknown {
  return {
    schemaVersion: 1,
    maxRequests: 20,
    maxGraphqlAliases: 3,
    actors: [{ id: "member", safeAlias: "member", authSlot: "primary", relationship: "SELF" }],
    routes: [{ id: "graphql", safeAlias: "graphql", protocol: "GRAPHQL", kind: "FUNCTION", functionName: "graphql.query", url: "https://api.example.test/graphql", documentedMethods: ["POST"] }],
    checks: [
      { id: "fields", matrixId: "viewer-fields", label: "field policy", kind: "FIELD_AUTHORIZATION", routeId: "graphql", actorId: "member", requireVerifiedIdentity: false, request: { method: "POST", graphql: { operationName: "Viewer", document: "query Viewer($id: ID!) { viewer(id: $id) { id email secret } }", variables: { id: "{{SECRET:object_id}}" } } }, response: { expectedDecision: "ALLOW", fieldRules: [{ path: "data.viewer.secret", classification: "SECRET", expectation: "MUST_BE_ABSENT" }] } },
      { id: "introspection", label: "introspection policy", kind: "GRAPHQL_INTROSPECTION", routeId: "graphql", actorId: "member", requireVerifiedIdentity: false, expectedClassification: "RESTRICTED" },
      { id: "aliases", label: "alias policy", kind: "GRAPHQL_ALIAS_LIMIT", routeId: "graphql", actorId: "member", requireVerifiedIdentity: false, operationCount: 2, documents: [{ operationName: "Aliases", document: "query Aliases { first: viewer { id } second: viewer { id } }", variables: {} }], expectation: "MUST_ALLOW" }
    ]
  };
}
