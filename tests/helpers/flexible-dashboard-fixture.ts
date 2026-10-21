import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { flexibleFixture } from "./flexible-assessment-fixture.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { prepareAssessmentActors } from "../../src/dashboard/execution/AssessmentActorRegistry.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { actorRegistryDigest } from "../../src/core/auth/ActorRegistry.js";
import { scopeSchema } from "../../src/config/ConfigSchema.js";
import { exampleScope } from "../../src/config/defaults.js";
import { scanStudioSchema } from "../../src/dashboard/contracts/ScanStudioSchemas.js";
import type { DashboardScanCreateRequest } from "../../src/dashboard/types/DashboardTypes.js";
export async function flexibleDashboardFixture(count: number, noIdentity = false) {
  if (process.platform !== "win32") throw Error("OWNED_WINDOWS_NATIVE_LAB_REQUIRED");
  const f = await flexibleFixture(count, { noIdentity }),
    paths = resolveDashboardPaths(f.root),
    database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  const org = new OrganizationService(database).defaultOrganizationId(),
    key = randomBytes(32),
    vault = new CredentialVault(database, { bytes: key, version: "1" }),
    scope = scopeSchema.parse({
      ...exampleScope,
      allowedDomains: ["127.0.0.1"],
      disallowedPaths: [],
      allowedMethods: ["GET"],
      rateLimitPerSecond: 3,
      concurrency: 1,
      sameOriginOnly: true
    }),
    targetId = new TargetRepository(database).create({
      organizationId: org,
      displayName: "Owned flexible app",
      baseOrigin: f.origin,
      tags: ["synthetic"],
      classification: "LOCAL",
      authorizationType: "OWNED",
      authorizationSummary: "Owner approves exact synthetic read-only GET observations and session-housekeeping",
      approvedScope: scope
    });
  const actors = Object.entries(f.profiles).map(([id, p]) => {
    const credentialProfileId = vault.create({
      organizationId: org,
      targetId,
      name: id,
      safeAlias: id,
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      safeIdentitySummary: { ...(p.principalId ? { principalId: p.principalId } : {}) },
      secret: {
        headers: p.headers,
        cookies: Object.fromEntries(p.cookies.map((c) => [c.name, c.value])),
        ...(p.identityVerification.endpoint
          ? { identityVerification: { endpoint: p.identityVerification.endpoint, principalFieldPath: "id" } }
          : {})
      }
    });
    return {
      id,
      label: id,
      credentialProfileId,
      mechanism: "BEARER",
      accountProvenance: "OWNER_APPROVED_EXISTING_TEST"
    };
  });
  const input = {
      targetId,
      readPath: count ? "/private" : "/",
      actors,
      credentialValidUntil: new Date(Date.now() + 3500000).toISOString(),
      ownerTestAccountsConfirmed: true,
      readOnlyEffectConfirmed: true,
      sessionHousekeepingApproved: count > 0
    },
    prepared = prepareAssessmentActors(database, vault, org, input),
    registry = prepared.registry;
  const authorization = {
    ...f.authorization,
    productionCampaign: {
      ...f.authorization.productionCampaign,
      actorRegistryDigest: actorRegistryDigest(registry),
      actorIds: registry.actors.map((a) => a.id),
      workflowAuthorizations: registry.workflows
    }
  };
  const request: DashboardScanCreateRequest = {
    target: f.origin + "/",
    targetId,
    profile: "quick",
    includeModules: ["baseline", "api-graphql-authorization"],
    maxRequests: 60,
    rateLimitPerSecond: 3,
    concurrency: 1,
    cleanupReservedRequests: 0,
    actorRegistry: registry,
    actorCredentials: prepared.actorCredentials,
    apiGraphql: prepared.apiGraphql as DashboardScanCreateRequest["apiGraphql"],
    targetAuthorization: authorization as DashboardScanCreateRequest["targetAuthorization"],
    studio: scanStudioSchema.parse({
      version: 1,
      scanName: "Flexible native worker",
      authorization: { category: "OWNED", confirmed: true },
      scope,
      authentication: { mode: "public" }
    })
  };
  const execution = new ScanExecutionService(database, paths, vault),
    capture = (name: string, value: unknown) =>
      writeFileSync(join(f.root, name + ".json"), JSON.stringify(value, null, 2), { flag: "wx" });
  return {
    ...f,
    key,
    database,
    org,
    vault,
    targetId,
    actors,
    input,
    prepared,
    request,
    execution,
    async run() {
      const preview = await execution.preview(request),
        reviewed = { ...request, studio: { ...request.studio!, previewIdentity: preview.previewIdentity } },
        id = await execution.enqueue(reviewed, undefined, undefined, org),
        end = Date.now() + 20000;
      let row: { status: string; error_summary: string | null } | undefined;
      while (Date.now() < end) {
        row = database.db.prepare("SELECT status,error_summary FROM scans WHERE id=?").get(id) as typeof row;
        if (row && ["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"].includes(row.status)) break;
        await new Promise((r) => setTimeout(r, 40));
      }
      const receipts = {
        id,
        row,
        wire: f.wire,
        integrity: database.db.pragma("integrity_check"),
        foreignKeys: database.db.pragma("foreign_key_check"),
        workers: database.db.prepare("SELECT id,state,process_id,failure_category FROM scan_workers").all(),
        plans: database.db
          .prepare("SELECT scan_id,plan_binding,worker_verified_binding,worker_verified_at FROM scan_executable_plans")
          .all() as Array<{
          scan_id: string;
          plan_binding: string;
          worker_verified_binding: string | null;
          worker_verified_at: string | null;
        }>
      };
      capture("FLEXIBLE_WORKER_RECEIPT", receipts);
      if (row?.status !== "COMPLETED") throw Error("NATIVE_WORKER_" + row?.status + ":" + row?.error_summary);
      const artifact = database.db
        .prepare("SELECT canonical_path FROM artifacts WHERE scan_id=? AND artifact_type='JSON_REPORT'")
        .get(id) as { canonical_path: string };
      return { id, preview, receipts, report: JSON.parse(readFileSync(artifact.canonical_path, "utf8")) };
    },
    capture,
    async close() {
      try {
        await execution.shutdown();
        capture("FLEXIBLE_SQLITE_FINAL_RECEIPT", {
          integrity: database.db.pragma("integrity_check"),
          foreignKeys: database.db.pragma("foreign_key_check"),
          wire: f.wire
        });
      } finally {
        database.close();
        await f.close();
      }
    }
  };
}
