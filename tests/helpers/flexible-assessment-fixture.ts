import { createServer } from "node:http";
import { randomUUID, randomBytes } from "node:crypto";
import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { authProfileSchema, type AuthProfile } from "../../src/core/auth/AuthProfile.js";
import {
  actorRegistrySchema,
  actorRegistryDigest,
  credentialDigest,
  identityFingerprint
} from "../../src/core/auth/ActorRegistry.js";
import { prepareProductionWebCampaign } from "../../src/cli/commands/webAssessment.js";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
export async function flexibleFixture(
  count: number,
  options: {
    mechanism?: "BEARER" | "COOKIE" | "API_KEY";
    assurance?: "ROLE" | "TENANT";
    identityMismatch?: "principal" | "role" | "tenant";
    samePrincipal?: boolean;
    revokeAfterIdentity?: boolean;
    redirect?: boolean;
    networkError?: boolean;
    identityAlias?: "role" | "tenant";
    identityResponseCap?: number;
    oversizeIdentity?: boolean;
    noIdentity?: boolean;
    vulnerable?: boolean;
    revoked?: boolean;
  } = {}
) {
  const actorBindingKey = randomBytes(32).toString("base64url"),
    root = createOwnedTestDirectory("flexible-v24"),
    tokens = Array.from({ length: count }, () => "fixture-private-" + randomUUID()),
    wire: Array<{ path: string; actor: string; method: string }> = [],
    profiles: Record<string, AuthProfile> = Object.create(null),
    mechanism = options.mechanism ?? "BEARER";
  const server = createServer((q, r) => {
    const key = String(q.headers.authorization ?? q.headers.cookie ?? q.headers["x-fixture-key"] ?? ""),
      i = tokens.findIndex((t) => key === t || key === "Bearer " + t || key === "sid=" + t),
      actor = i < 0 ? "anonymous" : "actor" + i;
    wire.push({ path: q.url ?? "", actor, method: q.method ?? "" });
    r.setHeader("content-type", "application/json");
    if (q.url === "/") {
      r.end(JSON.stringify({ public: true }));
      return;
    }
    if (i < 0 || options.revoked) {
      r.writeHead(401).end('{"error":"unauthenticated"}');
      return;
    }
    if (q.url !== "/who" && options.revokeAfterIdentity) {
      r.writeHead(401).end('{"error":"revoked"}');
      return;
    }
    if (q.url === "/private" && options.redirect) {
      r.writeHead(302, { location: "http://127.0.0.1:9/foreign" }).end();
      return;
    }
    if (q.url === "/private" && options.networkError) {
      q.socket.destroy();
      return;
    }
    if (q.url === "/who") {
      if (options.noIdentity) {
        r.writeHead(404).end("{}");
        return;
      }
      if (options.oversizeIdentity) {
        r.write(JSON.stringify({ id: actor }));
        r.end(" ".repeat(20000));
        return;
      }
      r.end(
        JSON.stringify({
          id:
            options.identityMismatch === "principal"
              ? "wrong-principal"
              : options.samePrincipal
                ? "shared-principal"
                : actor,
          ...(options.assurance === "ROLE"
            ? { role: options.identityMismatch === "role" ? "wrong-role" : "role" + i }
            : {}),
          ...(options.assurance === "TENANT"
            ? { tenant: options.identityMismatch === "tenant" ? "wrong-tenant" : "tenant" + i }
            : {})
        })
      );
      return;
    }
    if (q.url === "/object/actor0" && i !== 0 && !options.vulnerable) {
      r.writeHead(403).end('{"error":"forbidden"}');
      return;
    }
    r.end(JSON.stringify({ owner: q.url === "/object/actor0" ? "actor0" : actor, feature: true }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const a = server.address();
  if (!a || typeof a === "string") throw Error("fixture");
  const origin = "http://127.0.0.1:" + a.port;
  for (let i = 0; i < count; i++)
    profiles["actor" + i] = authProfileSchema.parse({
      label: "actor" + i,
      ...(options.identityAlias === "role"
        ? { role: "actor" + i }
        : options.identityAlias === "tenant"
          ? { tenantId: "actor" + i }
          : {}),
      ...(options.assurance === "ROLE" ? { role: "role" + i } : {}),
      ...(options.assurance === "TENANT" ? { tenantId: "tenant" + i } : {}),
      principalId: options.noIdentity ? undefined : options.samePrincipal ? "shared-principal" : "actor" + i,
      headers:
        mechanism === "BEARER"
          ? { Authorization: "Bearer " + tokens[i] }
          : mechanism === "API_KEY"
            ? { "X-Fixture-Key": tokens[i] }
            : {},
      cookies: mechanism === "COOKIE" ? [{ name: "sid", value: tokens[i] }] : [],
      identityVerification: options.noIdentity
        ? { mode: "disabled" }
        : {
            mode: "required",
            endpoint: origin + "/who",
            principalIdField: "id",
            ...(options.assurance === "ROLE" ? { roleField: "role" } : {}),
            ...(options.assurance === "TENANT" ? { tenantIdField: "tenant" } : {}),
            ...(options.identityAlias === "role"
              ? { roleField: "id" }
              : options.identityAlias === "tenant"
                ? { tenantIdField: "id" }
                : {}),
            ...(options.identityResponseCap ? { maxResponseBytes: 65536 } : {})
          }
    });
  const workflows = count
    ? Array.from({ length: count }, (_, i) => ({
        id: "observeactor" + i,
        family: "AUTHENTICATED_OBSERVATION",
        actorIds: ["actor" + i],
        reviewed: true
      }))
    : [{ id: "public", family: "PUBLIC_OBSERVATION", actorIds: [], reviewed: true }];
  if (count >= 2)
    workflows.push({
      id: "compare",
      family:
        options.assurance === "ROLE"
          ? "ROLE_COMPARISON"
          : options.assurance === "TENANT"
            ? "TENANT_COMPARISON"
            : "OWNERSHIP_COMPARISON",
      actorIds: registryActors(count),
      reviewed: true,
      ownerPolicySha256: "a".repeat(64)
    } as (typeof workflows)[number]);
  const registry = actorRegistrySchema.parse({
    contractVersion: 2,
    registryId: randomUUID(),
    organizationId: "owned-fixture",
    targetOrigin: origin,
    actors: Object.entries(profiles).map(([id, p]) => ({
      id,
      label: id,
      authentication: {
        mechanism,
        credentialRef: id,
        credentialDigest: credentialDigest(p, actorBindingKey),
        credentialExpiresAt: new Date(Date.now() + 3600000).toISOString(),
        accountProvenance: "OWNER_APPROVED_EXISTING_TEST",
        suitableForTesting: true
      },
      ...(p.principalId ? { principalFingerprint: identityFingerprint(p.principalId) } : {}),
      ...(p.role ? { roleFingerprint: identityFingerprint(p.role) } : {}),
      ...(p.tenantId ? { tenantFingerprint: identityFingerprint(p.tenantId) } : {})
    })),
    workflows
  });
  const actorInput = count
      ? registry.actors.map((a) => ({
          id: a.id,
          safeAlias: a.id,
          authSlot: "registry",
          relationship: "OWNER_REVIEWED_TEST_ACTOR"
        }))
      : [{ id: "public", safeAlias: "Public", authSlot: "anonymous", relationship: "PUBLIC" }],
    routes = [
      {
        id: "feature",
        safeAlias: "feature",
        protocol: "REST",
        kind: "FUNCTION",
        functionName: "feature",
        url: origin + (count ? "/private" : "/"),
        documentedMethods: ["GET"]
      },
      ...(count >= 2
        ? [
            {
              id: "object",
              safeAlias: "object",
              protocol: "REST",
              kind: "OBJECT",
              objectType: "fixture-object",
              pathTemplate: "/object/:id",
              url: origin + "/object/actor0",
              documentedMethods: ["GET"]
            }
          ]
        : [])
    ];
  const checks = count
    ? registry.actors.map((a) => ({
        id: "read-" + a.id,
        matrixId: "observe" + a.id,
        label: "Reviewed authenticated observation",
        kind: "FUNCTION_AUTHORIZATION",
        routeId: "feature",
        actorId: a.id,
        requireVerifiedIdentity: false,
        request: { method: "GET" },
        response: { expectedDecision: "OBSERVE" }
      }))
    : [
        {
          id: "read-public",
          matrixId: "public",
          label: "Public observation",
          kind: "FUNCTION_AUTHORIZATION",
          routeId: "feature",
          actorId: "public",
          requireVerifiedIdentity: false,
          request: { method: "GET" },
          response: { expectedDecision: "OBSERVE" }
        }
      ];
  if (count >= 2)
    for (const [actorId, expected] of registry.actors.map((a, i) => [a.id, i === 0 ? "ALLOW" : "DENY"]))
      checks.push({
        id: "compare-" + actorId,
        matrixId: "compare",
        label: "Explicit synthetic resource ownership",
        kind: "OBJECT_AUTHORIZATION",
        routeId: "object",
        actorId,
        requireVerifiedIdentity: true,
        request: { method: "GET" },
        response: { expectedDecision: expected, identity: { path: "owner", expectedValue: "actor0" } }
      } as (typeof checks)[number]);
  const old = prepareProductionWebCampaign(origin + "/", "Owned synthetic v24 authorization").authorization,
    legacy = old.productionCampaign!;
  const {
    identities: _,
    disposableAccountsSupplied: __,
    ...common
  } = legacy as typeof legacy & { identities: unknown; disposableAccountsSupplied: unknown };
  const authorization = {
    ...old,
    productionCampaign: {
      ...common,
      contractVersion: 2,
      actorRegistryDigest: actorRegistryDigest(registry),
      actorIds: registry.actors.map((a) => a.id),
      workflowAuthorizations: registry.workflows,
      authenticationPermitted: count > 0,
      maxRequests: 60,
      ...(options.identityResponseCap ? { maxResponseBytes: options.identityResponseCap } : {}),
      rateLimitPerSecond: 3,
      concurrency: 1,
      maxDurationMs: 120000,
      workflows: [count ? "AUTHENTICATED_READ_ONLY" : "PUBLIC_READ_ONLY"],
      effects: {
        sessionHousekeeping: count ? "SESSION_LAST_USED_AT_UPDATE" : "NONE_PUBLIC_UNAUTHENTICATED",
        approved: true
      },
      requests: [
        ...new Set([
          "/",
          ...(count ? ["/private", ...(options.noIdentity ? [] : ["/who"])] : []),
          ...(count >= 2 ? ["/object/actor0"] : [])
        ])
      ].map((path) => ({ origin, path, method: "GET", effect: "READ", expectedStatuses: [200, 401, 403] }))
    }
  };
  const save = (name: string, v: unknown) => {
    const p = join(root, name);
    writeFileSync(p, JSON.stringify(v, null, 2), { flag: "wx" });
    return p;
  };
  const profilePaths: Record<string, string> = Object.create(null);
  for (const [id, p] of Object.entries(profiles)) profilePaths[id] = save(id + ".profile.json", p);
  const registryPath = save("actors.json", { registry, bindingKey: actorBindingKey, profiles: profilePaths }),
    scopePath = save("scope.json", {
      ...exampleScope,
      allowedDomains: ["127.0.0.1"],
      allowedMethods: ["GET"],
      disallowedPaths: [],
      sameOriginOnly: true
    }),
    apiPath = save("api.json", { actors: actorInput, routes, checks, maxRequests: 50, maxResponseBytes: 8192 }),
    authorizationPath = save("authorization.json", authorization);
  return {
    root,
    origin,
    registry,
    profiles,
    tokens,
    wire,
    authorization,
    actorInput,
    routes,
    checks,
    registryPath,
    authorizationPath,
    apiPath,
    scopePath,
    async run(signal?: AbortSignal) {
      const result = await runScanCommand(
        origin + "/",
        {
          scope: scopePath,
          actorRegistry: registryPath,
          organization: registry.organizationId,
          targetAuthorization: authorizationPath,
          apiGraphql: apiPath,
          profile: "quick",
          includeModules: ["baseline"],
          replaceProfileModules: true,
          maxRequests: "60",
          cleanupReservedRequests: "0",
          rate: "3",
          concurrency: "1",
          output: join(root, "reports"),
          historyDirectory: join(root, "history"),
          suppressProcessExitCode: true
        },
        signal
      );
      const report = JSON.parse(readFileSync(result.reportPath, "utf8"));
      save("FLEXIBLE_NATIVE_RECEIPT.json", {
        platform: process.platform,
        count,
        mechanism,
        wire,
        result,
        report,
        synthetic: true,
        independentAccuracy: false
      });
      return { result, report };
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
      retainOwnedTestDirectory(root);
    }
  };
}

function registryActors(count: number) {
  return Array.from({ length: count }, (_, i) => "actor" + i);
}
