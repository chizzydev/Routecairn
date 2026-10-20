import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { AuthorizationWorkbenchService } from "../../src/dashboard/execution/AuthorizationWorkbenchService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { scanStudioSchema } from "../../src/dashboard/contracts/ScanStudioSchemas.js";
import { apiGraphqlInputSchema } from "../../src/modules/apiGraphql/ApiGraphqlPlanner.js";
import { exampleScope } from "../../src/config/defaults.js";
import type { AuthorizationWorkbenchInput } from "../../src/dashboard/contracts/AuthorizationWorkbenchContracts.js";
export async function authorizationWorkbenchFixture(
  options: { prepareObservation?: boolean; sharedPolicy?: boolean } = {}
) {
  if (process.platform !== "win32" || !process.env.ROUTECAIRN_WORKER_LAB)
    throw Error("Owned Windows native lab required");
  const root = createOwnedTestDirectory("application-authorization"),
    wire: Array<{ method: string; path: string; actor: string; status: number; object?: string }> = [],
    key = Buffer.alloc(32, 28);
  let fixed = false,
    missingAllowControl = false;
  const actors = [
    {
      id: "owner",
      safeAlias: "Owner A",
      authSlot: "primary" as const,
      relationship: "OWNER",
      principalId: "owner-a",
      tenantId: "tenant-a",
      role: "admin"
    },
    {
      id: "member",
      safeAlias: "Member A",
      authSlot: "account_a" as const,
      relationship: "SAME_TENANT_NON_OWNER",
      principalId: "member-a",
      tenantId: "tenant-a",
      role: "member"
    },
    {
      id: "outsider",
      safeAlias: "Member B",
      authSlot: "account_b" as const,
      relationship: "OTHER_TENANT",
      principalId: "member-b",
      tenantId: "tenant-b",
      role: "member"
    },
    { id: "anonymous", safeAlias: "Anonymous", authSlot: "anonymous" as const, relationship: "PUBLIC" }
  ];
  const server = createServer((req, res) => {
    const actor =
      actors.find((a) => a.id !== "anonymous" && req.headers.authorization === "Bearer fixture-" + a.id) ?? actors[3]!;
    let status = 200;
    let body: Record<string, unknown> = {};
    const p = req.url!;
    if (req.method !== "GET") status = 405;
    else if (missingAllowControl && actor.id === "owner" && p === "/api/documents/doc-a") status = 503;
    else if (p === "/identity") {
      if (actor.id === "anonymous") status = 401;
      else body = { id: actor.principalId, tenant: actor.tenantId, role: actor.role };
    } else if (p === "/api/admin/summary") {
      if (actor.id !== "owner") status = 403;
      else body = { id: "admin-summary", tenant: "tenant-a", count: 2 };
    } else if (["/api/documents/doc-a", "/api/secure/doc-a", "/api/masked/doc-a"].includes(p)) {
      if (actor.id === "anonymous") status = 401;
      else if (actor.id === "owner" || (p === "/api/documents/doc-a" && !fixed))
        body = { id: "doc-a", tenant: "tenant-a", content: "GENERATED_DISPOSABLE_DOCUMENT" };
      else if (p === "/api/masked/doc-a")
        body = {
          id: actor.id === "member" ? "member-document" : "doc-b",
          tenant: actor.tenantId,
          content: "OWN_GENERATED_DOCUMENT"
        };
      else status = 403;
    } else if (p !== "/") status = 404;
    wire.push({
      method: req.method!,
      path: p,
      actor: actor.id,
      status,
      ...(typeof body.id === "string" ? { object: body.id } : {})
    });
    res.writeHead(status, { "content-type": "application/json", connection: "close" });
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + (server.address() as AddressInfo).port,
    paths = resolveDashboardPaths(root),
    database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  const org = new OrganizationService(database).defaultOrganizationId();
  const scope = {
    ...exampleScope,
    program: "owned-two-tenant-authorization",
    allowedDomains: ["127.0.0.1"],
    disallowedPaths: [],
    allowedMethods: ["GET"] as const,
    rateLimitPerSecond: 20,
    concurrency: 1
  };
  const targetId = new TargetRepository(database).create({
    displayName: "Generated two-tenant application",
    baseOrigin: origin,
    tags: ["disposable"],
    classification: "LOCAL",
    authorizationType: "OWNED",
    authorizationSummary: "Owner-authorized generated loopback read-only fixture",
    approvedScope: scope
  });
  const vault = new CredentialVault(database, { bytes: key, version: "1" }),
    credentials: AuthorizationWorkbenchInput["credentials"] = {};
  for (const a of actors.filter((a) => a.id !== "anonymous")) {
    credentials[a.authSlot as keyof typeof credentials] = vault.create({
      organizationId: org,
      name: a.safeAlias,
      safeAlias: a.safeAlias,
      targetId,
      expiresAt: "2099-01-01T00:00:00.000Z",
      safeIdentitySummary: { principalId: a.principalId, tenantId: a.tenantId, role: a.role },
      secret: {
        authorizationHeader: "Bearer fixture-" + a.id,
        identityVerification: {
          endpoint: origin + "/identity",
          principalFieldPath: "id",
          tenantFieldPath: "tenant",
          roleFieldPath: "role"
        }
      }
    });
  }
  const execution = new ScanExecutionService(database, paths, vault),
    service = new AuthorizationWorkbenchService(database, vault, execution);
  const routes = [
    {
      id: "document",
      safeAlias: "tenant-document",
      protocol: "REST",
      kind: "OBJECT",
      objectType: "document",
      url: origin + "/api/documents/doc-a",
      pathTemplate: "/api/documents/:id",
      documentedMethods: ["GET"]
    },
    {
      id: "secure",
      safeAlias: "secure-document",
      protocol: "REST",
      kind: "OBJECT",
      objectType: "document",
      url: origin + "/api/secure/doc-a",
      pathTemplate: "/api/secure/:id",
      documentedMethods: ["GET"]
    },
    {
      id: "masked",
      safeAlias: "masked-document",
      protocol: "REST",
      kind: "OBJECT",
      objectType: "document",
      url: origin + "/api/masked/doc-a",
      pathTemplate: "/api/masked/:id",
      documentedMethods: ["GET"]
    },
    {
      id: "admin",
      safeAlias: "admin-summary",
      protocol: "REST",
      kind: "FUNCTION",
      functionName: "summary",
      url: origin + "/api/admin/summary",
      pathTemplate: "/api/admin/summary",
      documentedMethods: ["GET"]
    }
  ];
  const observedInput = apiGraphqlInputSchema.parse({
    schemaVersion: 1,
    maxRequests: 24,
    actors,
    routes,
    checks: routes.flatMap((r) =>
      actors.map((a) => ({
        id: r.id + "-observe-" + a.id,
        matrixId: r.id,
        label: "Observe fixed application route",
        kind: r.id === "admin" ? "FUNCTION_AUTHORIZATION" : "OBJECT_AUTHORIZATION",
        routeId: r.id,
        actorId: a.id,
        request: { method: "GET" },
        response: { expectedDecision: "OBSERVE" }
      }))
    )
  });
  const frozen = {
    actors: actors.map((a) => ({ id: a.id, role: a.role, tenant: a.tenantId })),
    routes,
    expectations: {
      document: options.sharedPolicy ? "EXPECTED_SHARED_AUTHENTICATED_ACCESS" : "VULNERABLE_THEN_FIXED",
      secure: "DENIES_FOREIGN_OBJECT",
      masked: "WRONG_OBJECT_200_NOT_PROOF",
      admin: "ROLE_RESTRICTED"
    },
    missingAllowControl: "Owner control can be made unavailable; no bypass may then be confirmed",
    preparedObservation: options.prepareObservation !== false,
    maximumRequests: 40
  };
  writeFileSync(join(root, "FROZEN_FIXTURE_GROUND_TRUTH.json"), JSON.stringify(frozen, null, 2), { flag: "wx" });
  const sourceScanId =
    options.prepareObservation === false
      ? randomUUID()
      : await execution.enqueue(
          {
            target: origin,
            targetId,
            profile: "quick",
            includeModules: ["api-graphql-authorization"],
            maxRequests: 40,
            rateLimitPerSecond: 20,
            concurrency: 1,
            cleanupReservedRequests: 0,
            credentialProfileId: credentials.primary,
            credentialProfileAId: credentials.account_a,
            credentialProfileBId: credentials.account_b,
            apiGraphql: observedInput,
            studio: scanStudioSchema.parse({
              version: 1,
              scanName: "Observe owned application",
              authorization: { category: "OWNED", confirmed: true },
              scope,
              authentication: { mode: "public" }
            })
          },
          undefined,
          undefined,
          org
        );
  const status = (id: string) =>
    database.db.prepare("SELECT status,error_summary FROM scans WHERE id=?").get(id) as {
      status: string;
      error_summary: string | null;
    };
  const wait = async (id: string) => {
    const end = Date.now() + 20000;
    while (Date.now() < end) {
      const s = status(id);
      if (s.status === "COMPLETED") return;
      if (["FAILED", "INTERRUPTED", "CANCELLED"].includes(s.status))
        throw Error("FIXTURE_NATIVE_SCAN_" + s.status + ":" + s.error_summary);
      await new Promise((r) => setTimeout(r, 50));
    }
    throw Error("FIXTURE_NATIVE_SCAN_DEADLINE");
  };
  const input: AuthorizationWorkbenchInput = {
    targetId,
    sourceScanId,
    credentials,
    expectations: routes.map((r) => ({
      routeId: r.id,
      url: r.url,
      kind: r.id === "admin" ? "FUNCTION_AUTHORIZATION" : "TENANT_ISOLATION",
      explanation:
        r.id === "admin"
          ? "Only the owner admin role may read the administrative summary."
          : "Only the declared owner may read this exact tenant-a object.",
      decisions: { owner: "ALLOW", member: "DENY", outsider: "DENY", anonymous: "DENY" },
      identity: { path: "id", expectedValue: r.id === "admin" ? "admin-summary" : "doc-a" },
      tenant: { path: "tenant", expectedValue: "tenant-a" }
    }))
  };
  const capture = (label: string) =>
    writeFileSync(
      join(root, label + ".json"),
      JSON.stringify(
        {
          wire,
          integrity: database.db.pragma("integrity_check"),
          foreignKeys: database.db.pragma("foreign_key_check"),
          workers: database.db.prepare("SELECT id,state,process_id,failure_category FROM scan_workers").all(),
          plans: database.db
            .prepare(
              "SELECT scan_id,plan_binding,worker_verified_binding,worker_verified_at FROM scan_executable_plans"
            )
            .all(),
          scans: database.db.prepare("SELECT id,status,error_summary FROM scans").all(),
          revisions: database.db.prepare("SELECT * FROM authorization_workbench_revisions").all(),
          mappingRevisions: database.db.prepare("SELECT * FROM application_mapping_revisions").all(),
          mappingDispatches: database.db.prepare("SELECT * FROM application_mapping_dispatches").all(),
          mappingAcks: database.db.prepare("SELECT * FROM application_mapping_acknowledgements").all(),
          dispatches: database.db.prepare("SELECT * FROM authorization_workbench_dispatches").all(),
          acks: database.db.prepare("SELECT * FROM authorization_workbench_acknowledgements").all(),
          comparison: database.db.prepare("SELECT id,state,summary_json FROM scan_comparisons").all(),
          historicalAssuranceGates: database.db.prepare("SELECT id,gate_status FROM continuous_assurance_runs").all()
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  try {
    if (options.prepareObservation !== false) await wait(sourceScanId);
  } catch (e) {
    capture("FAILED_OBSERVATION");
    await execution.shutdown();
    database.close();
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    retainOwnedTestDirectory(root);
    throw e;
  }
  if (options.prepareObservation !== false)
    writeFileSync(join(root, "EXPECTATIONS.json"), JSON.stringify(input, null, 2), { flag: "wx" });
  return {
    root,
    paths,
    database,
    vault,
    execution,
    service,
    org,
    input,
    origin,
    key,
    wire,
    status,
    wait,
    sourceScanId,
    setMissingAllowControl(value = true) {
      missingAllowControl = value;
    },
    setFixed() {
      fixed = true;
    },
    capture,
    async close() {
      try {
        await execution.shutdown();
        capture("NATIVE_HTTP_SQLITE_RECEIPT");
      } finally {
        database.close();
        server.closeAllConnections();
        await new Promise<void>((r) => server.close(() => r()));
        retainOwnedTestDirectory(root);
      }
    }
  };
}
