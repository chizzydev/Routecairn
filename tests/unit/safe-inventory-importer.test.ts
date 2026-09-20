import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { compileSafeInventoryImport } from "../../src/intelligence/inventory/SafeInventoryImporter.js";
import { planApiGraphqlReview } from "../../src/modules/apiGraphql/ApiGraphqlPlanner.js";
import { planCollectionAuthorizationTesting } from "../../src/modules/collectionAuthorization/CollectionAuthorizationPlanner.js";
import { planFileAuthorizationTesting } from "../../src/modules/fileAuthorization/FileAuthorizationPlanner.js";
import { planSupabaseAuthorization } from "../../src/modules/supabaseAuthorization/SupabaseAuthorizationPlanner.js";

describe("safe inventory importer", () => {
  it("compiles supported inventories into executable read-only plans and withholds writes", () => {
    const target = "https://app.example.com/";
    const result = compileSafeInventoryImport({
      schemaVersion: 1,
      maxRoutes: 20,
      maxGraphqlOperations: 10,
      maxFiles: 10,
      maxCollections: 3,
      sources: [
        {
          id: "openapi",
          kind: "OPENAPI",
          document: {
            openapi: "3.1.0",
            servers: [{ url: "https://app.example.com" }],
            paths: {
              "/api/projects": {
                get: {
                  summary: "List projects",
                  security: [],
                  responses: {
                    "200": {
                      content: {
                        "application/json": {
                          schema: { type: "array", items: { type: "object", properties: { id: { type: "string" } } } }
                        }
                      }
                    }
                  }
                },
                post: { summary: "Create project", security: [], responses: { "201": {} } }
              },
              "/api/projects/{id}": { get: { security: [], responses: { "200": {} } } }
            }
          }
        },
        { id: "postman", kind: "POSTMAN", document: { item: [{ name: "Health", request: { method: "GET", url: "https://app.example.com/health" } }, { name: "Delete", request: { method: "DELETE", url: "https://app.example.com/api/projects/1" } }] } },
        {
          id: "har",
          kind: "HAR",
          document: { log: { entries: [
            { request: { method: "GET", url: "https://app.example.com/api/events", headers: [] }, response: { status: 200, headers: [{ name: "Link", value: "</api/events?page=2>; rel=next" }], content: { mimeType: "application/json", text: JSON.stringify({ items: [] }) } } },
            { request: { method: "GET", url: "https://app.example.com/files/report.pdf", headers: [] }, response: { status: 200, headers: [], content: { mimeType: "application/pdf" } } },
            { request: { method: "GET", url: "https://app.example.com/private", headers: [{ name: "Authorization", value: "Bearer hidden" }] }, response: { status: 200, headers: [], content: { mimeType: "application/json", text: "{}" } } }
          ] } }
        },
        {
          id: "graphql",
          kind: "GRAPHQL_SCHEMA",
          endpoint: "https://app.example.com/graphql",
          document: { data: { __schema: { queryType: { name: "Query" }, mutationType: { name: "Mutation" }, types: [
            { name: "Query", fields: [{ name: "status", args: [], type: { kind: "SCALAR", name: "String" } }, { name: "project", args: [], type: { kind: "OBJECT", name: "Project" } }, { name: "byId", args: [{ name: "id", defaultValue: null, type: { kind: "NON_NULL", ofType: { kind: "SCALAR", name: "ID" } } }], type: { kind: "OBJECT", name: "Project" } }] },
            { name: "Mutation", fields: [{ name: "deleteProject" }] }
          ] } } }
        },
        {
          id: "supabase",
          kind: "SUPABASE_CATALOG",
          projectUrl: "https://app.example.com",
          anonKeyEnv: "SUPABASE_ANON_KEY",
          document: { tables: [{ schema: "public", name: "profiles", exposed: true, rlsEnabled: true, columns: [{ name: "id" }, { name: "email", sensitive: true }] }], functions: [{ schema: "public", name: "dangerous_rpc", securityDefiner: true }], buckets: [{ id: "avatars", public: true }], storageObjects: [{ bucket: "avatars", path: "public/avatar.png", public: true, mimeType: "image/png" }], relationships: [{ name: "profile_team", from: "profiles", to: "teams" }] }
        }
      ]
    }, target);

    expect(result.summary).toMatchObject({ sources: 5, graphqlOperations: 2, files: 2, collections: 1, supabaseResources: 4 });
    expect(result.summary.blockedMutations).toBeGreaterThanOrEqual(3);
    expect(result.apiGraphql?.routes.every((route) => route.protocol === "GRAPHQL" || route.documentedMethods.every((method) => ["GET", "HEAD", "OPTIONS"].includes(method)))).toBe(true);
    expect(result.apiGraphql?.checks.some((check) => check.kind === "FUNCTION_AUTHORIZATION" && check.request.method === "POST")).toBe(true);
    expect(result.supabaseAuthorization?.cases.every((testCase) => testCase.operation === "SELECT" && testCase.actor === "ANONYMOUS")).toBe(true);
    expect(result.supabaseAuthorization?.cases.map((testCase) => testCase.surface)).toEqual(expect.arrayContaining(["TABLE", "RELATIONSHIP", "STORAGE"]));

    const readScope = { ...exampleScope, allowedMethods: [...new Set([...exampleScope.allowedMethods, "POST" as const])] };
    expect(() => planApiGraphqlReview(result.apiGraphql!, { target, scope: readScope })).not.toThrow();
    expect(() => planCollectionAuthorizationTesting(result.collectionAuthorization!, { target, scope: exampleScope })).not.toThrow();
    expect(() => planFileAuthorizationTesting(result.fileAuthorization!, { target, scope: exampleScope })).not.toThrow();
    expect(() => planSupabaseAuthorization(result.supabaseAuthorization!, { target, scope: exampleScope })).not.toThrow();
  });

  it("rejects cross-origin routes and secret-bearing HAR requests", () => {
    const result = compileSafeInventoryImport({
      schemaVersion: 1,
      maxRoutes: 10,
      maxGraphqlOperations: 5,
      maxFiles: 5,
      maxCollections: 2,
      sources: [{ id: "har", kind: "HAR", document: { log: { entries: [
        { request: { method: "GET", url: "https://evil.example/data", headers: [] }, response: { status: 200, headers: [], content: { mimeType: "application/json", text: "{}" } } },
        { request: { method: "GET", url: "https://app.example.com/data?access_token=secret", headers: [] }, response: { status: 200, headers: [], content: { mimeType: "application/json", text: "{}" } } },
        { request: { method: "GET", url: "https://app.example.com/private", headers: [{ name: "Cookie", value: "session=secret" }] }, response: { status: 200, headers: [], content: { mimeType: "application/json", text: "{}" } } }
      ] } } }]
    }, "https://app.example.com/");

    expect(result.apiGraphql).toBeUndefined();
    expect(result.summary.routes).toBe(0);
    expect(result.summary.skipped).toBe(3);
  });
});
