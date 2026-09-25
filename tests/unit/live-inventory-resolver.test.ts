import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { reserveInventoryAcquisitionBudget, resolveSafeInventoryImport } from "../../src/intelligence/inventory/LiveInventoryResolver.js";
import { safeInventoryImportInputSchema } from "../../src/intelligence/inventory/SafeInventoryImporter.js";
import { targetAuthorizationSchema } from "../../src/core/authorization/TargetAuthorization.js";
import { planObjectPairTesting } from "../../src/modules/objectPairTesting/ObjectPairPlanner.js";
import { planCollectionAuthorizationTesting } from "../../src/modules/collectionAuthorization/CollectionAuthorizationPlanner.js";
import { planFileAuthorizationTesting } from "../../src/modules/fileAuthorization/FileAuthorizationPlanner.js";

const servers: Array<ReturnType<typeof createServer>> = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

describe("live inventory resolution", () => {
  it("fetches authenticated documents, resolves Postman environments, and introspects GraphQL", async () => {
    const observed: Array<{ url: string; authorization?: string }> = [];
    const server = createServer(async (request, response) => {
      observed.push({ url: request.url ?? "", ...(request.headers.authorization ? { authorization: request.headers.authorization } : {}) });
      if (request.url === "/collection") return json(response, { collection: {
        item: [{ name: "Projects", request: { method: "GET", url: "{{baseUrl}}/api/projects" } }]
      } });
      if (request.url === "/environment") return json(response, { environment: { values: [{ key: "baseUrl", value: origin(server), enabled: true }] } });
      if (request.url === "/openapi.json") return json(response, {
        openapi: "3.1.0",
        paths: { "/health": { get: { security: [], responses: { "200": {} } } } }
      });
      if (request.url === "/graphql" && request.method === "POST") {
        let body = "";
        for await (const chunk of request) body += String(chunk);
        expect(body).toContain("RouteCairnInventoryIntrospection");
        return json(response, { data: { __schema: { queryType: { name: "Query" }, mutationType: null, types: [{ name: "Query", fields: [{ name: "status", args: [], type: { kind: "SCALAR", name: "String" } }] }] } } });
      }
      response.statusCode = 404;
      response.end("not found");
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const target = origin(server);
    const input = safeInventoryImportInputSchema.parse({
      schemaVersion: 1,
      acquisition: { maxFetches: 8, maxDocumentBytes: 131072, timeoutMs: 5000, concurrency: 2, rateLimitPerSecond: 5 },
      sources: [
        { id: "postman-live", kind: "POSTMAN_URL", collectionUrl: `${target}/collection`, environmentUrl: `${target}/environment`, actor: "primary" },
        { id: "graphql-live", kind: "GRAPHQL_INTROSPECTION", endpoint: `${target}/graphql`, actor: "primary" },
        { id: "discovery", kind: "SERVICE_DISCOVERY", baseUrl: target, paths: ["/openapi.json"], actor: "anonymous" }
      ]
    });
    const result = await resolveSafeInventoryImport(input, target, {
      scope: {
        program: "test",
        allowedDomains: ["127.0.0.1"],
        disallowedPaths: [],
        allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"],
        rateLimitPerSecond: 10,
        concurrency: 4,
        maxDepth: 2,
        sameOriginOnly: true,
        includeSubdomains: false,
        respectRobotsTxt: false,
        userAgent: "RouteCairn-Test"
      },
      authProfile: {
        label: "catalog reader",
        headers: { Authorization: "Bearer test-only" },
        cookies: [],
        identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] },
        lifecycleSecrets: {},
        notes: []
      }
    });

    expect(result.summary).toMatchObject({ sources: 3, routes: 2, graphqlOperations: 1 });
    expect(result.summary.warnings.join(" ")).toContain("fetched 4 document(s)");
    expect(observed.filter((item) => item.url !== "/openapi.json").every((item) => item.authorization === "Bearer test-only")).toBe(true);
    expect(result.apiGraphql?.routes.map((route) => route.url)).toEqual(expect.arrayContaining([`${target}/api/projects`, `${target}/health`, `${target}/graphql`]));
  });

  it("does not substitute secret-named Postman environment values", async () => {
    const input = safeInventoryImportInputSchema.parse({
      sources: [{
        id: "postman",
        kind: "POSTMAN",
        document: { item: [{ request: { method: "GET", url: "https://app.example.test/{{apiToken}}/profile" } }] },
        environment: { values: [{ key: "apiToken", value: "sensitive" }] }
      }]
    });
    const result = await resolveSafeInventoryImport(input, "https://app.example.test", {
      scope: { program: "test", allowedDomains: ["app.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 3, concurrency: 2, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "test" }
    });
    expect(result.summary.routes).toBe(0);
    expect(result.summary.skipped).toBe(1);
  });

  it("charges acquisition attempts against a bug-bounty execution grant", () => {
    const authorization = targetAuthorizationSchema.parse({
      schemaVersion: 1,
      mode: "BUG_BOUNTY_AUTHORIZED",
      targetOrigin: "https://app.example.test",
      proof: { reference: "authorized-test", sha256: "a".repeat(64) },
      bugBounty: {
        program: "test program",
        platform: "private",
        scopeDocumentSha256: "b".repeat(64),
        inScope: [{ origin: "https://app.example.test", pathPrefix: "/" }],
        outOfScope: [],
        rules: ["read only"],
        prohibitedActions: ["no mutation"],
        startsAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2027-01-01T00:00:00.000Z",
        maxRequests: 10,
        rateLimitPerSecond: 2,
        authenticationPermitted: true,
        mutationPermitted: false,
        destructivePermitted: false,
        racePermitted: false,
        disposableAccountsSupplied: false,
        requests: [],
        reportMode: "BUG_BOUNTY_SAFE"
      }
    });
    const result = {
      summary: {
        sources: 1, routes: 0, graphqlOperations: 0, files: 0, collections: 0, supabaseResources: 0,
        blockedMutations: 0, skipped: 0, warnings: [],
        acquisition: { fetches: 3, authenticatedFetches: 1, discoveredItems: 1, resolvedEnvironments: 0 }
      }
    };
    expect(reserveInventoryAcquisitionBudget(authorization, result)?.bugBounty?.maxRequests).toBe(7);
  });

  it("enumerates a live Supabase PostgREST catalog, buckets, RPCs, and bounded public objects", async () => {
    const previousKey = process.env.ROUTECAIRN_TEST_SUPABASE_KEY;
    process.env.ROUTECAIRN_TEST_SUPABASE_KEY = "test-anon-key";
    const server = createServer(async (request, response) => {
      if (request.url === "/rest/v1/") return json(response, {
        openapi: "3.0.0",
        paths: { "/profiles": { get: {} }, "/rpc/ping": { post: {} } },
        components: { schemas: { profiles: { properties: { id: { type: "string" }, access_token: { type: "string" } } } } }
      });
      if (request.url === "/storage/v1/bucket") return json(response, [{ id: "avatars", name: "avatars", public: true }]);
      if (request.url === "/storage/v1/object/list/avatars" && request.method === "POST") {
        let body = "";
        for await (const chunk of request) body += String(chunk);
        expect(JSON.parse(body)).toMatchObject({ prefix: "", limit: 5, offset: 0 });
        return json(response, [{ name: "public/avatar.png", metadata: { mimetype: "image/png" } }]);
      }
      response.statusCode = 404;
      response.end();
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const target = origin(server);
    try {
      const input = safeInventoryImportInputSchema.parse({
        sources: [{
          id: "supabase-live",
          kind: "SUPABASE_LIVE",
          projectUrl: target,
          anonKeyEnv: "ROUTECAIRN_TEST_SUPABASE_KEY",
          actor: "anonymous",
          enumeratePublicObjects: true,
          maxObjectsPerBucket: 5
        }]
      });
      const result = await resolveSafeInventoryImport(input, target, {
        scope: { program: "test", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"], rateLimitPerSecond: 5, concurrency: 2, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "test" }
      });
      expect(result.summary).toMatchObject({ supabaseResources: 3, files: 1, blockedMutations: 1 });
      expect(result.supabaseAuthorization?.catalog.tables[0]).toMatchObject({ name: "profiles", rlsEnabled: true });
      expect(result.supabaseAuthorization?.catalog.functions[0]).toMatchObject({ name: "ping" });
      expect(result.fileAuthorization?.definitions[0]?.files[0]?.fileRef).toBe("avatar.png");
    } finally {
      if (previousKey === undefined) delete process.env.ROUTECAIRN_TEST_SUPABASE_KEY;
      else process.env.ROUTECAIRN_TEST_SUPABASE_KEY = previousKey;
    }
  });

  it("discovers authenticated objects, tenant boundaries, pagination, required route parameters, and file references", async () => {
    const server = createServer((request, response) => {
      const authorization = request.headers.authorization;
      if (request.url?.startsWith("/api/projects")) {
        const account = authorization === "Bearer account-a" ? "a" : authorization === "Bearer account-b" ? "b" : undefined;
        if (!account) { response.statusCode = 401; return response.end(); }
        const cursor = new URL(request.url, origin(server)).searchParams.get("cursor");
        const object = {
          id: `${account}-project-${cursor ? "2" : "1"}`,
          ownerId: `principal-${account}`,
          tenantId: `tenant-${account}`,
          fileUrl: `${origin(server)}/files/${account}-evidence.pdf`
        };
        return json(response, cursor ? { data: [object] } : { data: [object], next: `${origin(server)}/api/projects?cursor=page-2` });
      }
      response.statusCode = 404;
      response.end();
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const target = origin(server);
    const scope = { program: "test", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"] as Array<"GET" | "HEAD" | "OPTIONS">, rateLimitPerSecond: 10, concurrency: 2, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "test" };
    const authProfileSet = {
      accountA: { label: "Account A", safeAlias: "Account A", principalId: "principal-a", tenantId: "tenant-a", headers: { Authorization: "Bearer account-a" }, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: {}, notes: [] },
      accountB: { label: "Account B", safeAlias: "Account B", principalId: "principal-b", tenantId: "tenant-b", headers: { Authorization: "Bearer account-b" }, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: {}, notes: [] }
    };
    const result = await resolveSafeInventoryImport(safeInventoryImportInputSchema.parse({
      acquisition: {
        maxFetches: 12,
        authorizationDiscovery: { enabled: true, maxRoutes: 3, maxPages: 2, maxObjectsPerActor: 4 }
      },
      sources: [{
        id: "authenticated-api",
        kind: "OPENAPI",
        document: {
          openapi: "3.1.0",
          servers: [{ url: target }],
          security: [{ bearerAuth: [] }],
          components: { parameters: { PageLimit: { name: "limit", in: "query", required: true, schema: { type: "integer", default: 2 } } } },
          paths: {
            "/api/projects": { get: { summary: "Projects", parameters: [{ $ref: "#/components/parameters/PageLimit" }], responses: { "200": {} } } },
            "/api/projects/{projectId}": { get: { parameters: [{ name: "projectId", in: "path", required: true, schema: { type: "string" } }], responses: { "200": {} } } }
          }
        }
      }]
    }), target, {
      scope,
      authProfileSet
    });

    expect(result.objectPairTesting?.cases[0]).toMatchObject({
      expectedVisibility: "PRIVATE_TO_OWNER",
      template: { url: `${target}/api/projects/{{OBJECT_ID}}` },
      accountAObject: { id: "a-project-1", expectedOwnerField: "ownerId", expectedTenantField: "tenantId" },
      accountBObject: { id: "b-project-1", expectedOwnerField: "ownerId", expectedTenantField: "tenantId" }
    });
    expect(result.collectionAuthorization?.collections[0]).toMatchObject({
      url: `${target}/api/projects?limit=2`,
      resultArrayPath: "data",
      objectIdPath: "id",
      objectOwnerPath: "ownerId",
      objectTenantPath: "tenantId",
      pagination: { mode: "JSON_URL", nextPath: "next", maxPages: 2 }
    });
    expect(result.fileAuthorization?.definitions.flatMap((definition) => definition.files)).toHaveLength(2);
    expect(result.fileAuthorization?.definitions.flatMap((definition) => definition.cases)).toHaveLength(4);
    expect(result.summary.acquisition).toMatchObject({ fetches: 4, authenticatedFetches: 4, discoveredItems: 4 });
    expect(result.summary.warnings.join(" ")).toContain("followed 2 bounded page(s)");
    expect(planObjectPairTesting(result.objectPairTesting!, { target, scope, authProfileSet }).requestMatrix).toHaveLength(4);
    expect(planCollectionAuthorizationTesting(result.collectionAuthorization!, { target, scope, authProfileSet }).requestMatrix).toHaveLength(4);
    expect(planFileAuthorizationTesting(result.fileAuthorization!, { target, scope, authProfileSet }).requestMatrix).toHaveLength(4);
  });

  it("materializes tenant-scoped OpenAPI paths from declared actor tenant evidence", async () => {
    const server = createServer((request, response) => {
      const actor = request.headers.authorization === "Bearer account-a" ? "a" : request.headers.authorization === "Bearer account-b" ? "b" : undefined;
      if (actor && request.url === `/tenants/tenant-${actor}/projects`) return json(response, { items: [{ id: `project-${actor}`, ownerId: `principal-${actor}`, tenantId: `tenant-${actor}` }] });
      response.statusCode = 404; response.end();
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const target = origin(server);
    const profile = (actor: "a" | "b") => ({ label: actor, principalId: `principal-${actor}`, tenantId: `tenant-${actor}`, headers: { Authorization: `Bearer account-${actor}` }, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: {}, notes: [] });
    const result = await resolveSafeInventoryImport(safeInventoryImportInputSchema.parse({
      acquisition: { maxFetches: 4, authorizationDiscovery: { enabled: true, maxRoutes: 2, maxPages: 1 } },
      sources: [{ id: "tenant-api", kind: "OPENAPI", document: { openapi: "3.1.0", servers: [{ url: target }], paths: {
        "/tenants/{tenantId}/projects": { get: { parameters: [{ name: "tenantId", in: "path", required: true, schema: { type: "string" } }], responses: { "200": {} } } },
        "/tenants/{tenantId}/projects/{id}": { get: { parameters: [{ name: "tenantId", in: "path", required: true, schema: { type: "string" } }, { name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { "200": {} } } }
      } } }]
    }), target, {
      scope: { program: "test", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 10, concurrency: 2, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "test" },
      authProfileSet: { accountA: profile("a"), accountB: profile("b") }
    });

    expect(result.objectPairTesting?.cases[0]?.template.url).toBe(`${target}/tenants/{{TENANT_ID}}/projects/{{OBJECT_ID}}`);
    expect(result.objectPairTesting?.cases[0]?.accountAObject.tenantId).toBe("tenant-a");
    expect(result.objectPairTesting?.cases[0]?.accountBObject.tenantId).toBe("tenant-b");
    expect(result.summary.acquisition).toMatchObject({ fetches: 2, authenticatedFetches: 2, discoveredItems: 2 });
  });
});

function json(response: ServerResponse<IncomingMessage>, value: unknown): void {
  response.statusCode = 200;
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify(value));
}

function origin(server: ReturnType<typeof createServer>): string {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Server is not listening.");
  return `http://127.0.0.1:${address.port}`;
}
