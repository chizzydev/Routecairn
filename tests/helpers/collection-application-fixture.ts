import type { ApplicationMappingInput } from "../../src/dashboard/contracts/ApplicationMappingContracts.js";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { ApplicationOnboardingService } from "../../src/dashboard/execution/ApplicationOnboardingService.js";
import { ApplicationMappingService } from "../../src/dashboard/execution/ApplicationMappingService.js";
import { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
import { AuthorizationWorkbenchService } from "../../src/dashboard/execution/AuthorizationWorkbenchService.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
export async function collectionApplicationFixture(
  identityModel: "PRINCIPAL_ROLE" | "TENANT_AWARE" = "PRINCIPAL_ROLE"
) {
  if (process.platform !== "win32" || !process.env.ROUTECAIRN_WORKER_LAB)
    throw Error("EXPLICIT_OWNED_WINDOWS_LAB_REQUIRED");
  const root = createOwnedTestDirectory("collection-native"),
    paths = resolveDashboardPaths(root),
    database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  const org = new OrganizationService(database).defaultOrganizationId(),
    vault = new CredentialVault(database, { bytes: Buffer.alloc(32, 113), version: "1" }),
    wire: Array<{ path: string; actor: string; status: number }> = [];
  let behavior = "healthy";
  const server = createServer((req, res) => {
    const slot = ["primary", "account_a", "account_b"].find(
        (s) => req.headers.authorization === "Bearer generated-" + s
      ),
      index = ["primary", "account_a", "account_b"].indexOf(slot ?? "");
    let status = 200;
    let body: Record<string, unknown> = {};
    if (req.method !== "GET") status = 405;
    else if (req.url === "/identity") {
      if (!slot || behavior === "revoked") status = 401;
      else {
        body = {
          id: "person-" + index,
          role: index === 0 ? "admin" : "user",
          ...(identityModel === "TENANT_AWARE" ? { tenant: "tenant-" + index } : {})
        };
        if (slot === "primary") {
          if (behavior === "missing-principal") delete body.id;
          if (behavior === "missing-role") delete body.role;
          if (behavior === "conflicting-principal") body.id = "other-person";
          if (behavior === "conflicting-role") body.role = "other-role";
        }
      }
    } else if (req.url === "/object" || req.url === "/foreign") {
      if (!slot) status = 401;
      else
        body = {
          data: Array.from({ length: behavior === "empty" ? 0 : behavior === "beyond-cap" ? 5 : 4 }, (_, i) => ({
            id: "entry-" + index + "-" + i,
            owner:
              (behavior === "late-foreign" && slot === "account_a" && i === 3) || (behavior === "beyond-cap" && i === 4)
                ? "person-0"
                : "person-" + index,
            public_id: "same-public-object"
          })),
          hasMore: behavior === "partial"
        };
      if (req.url === "/foreign" && index > 0) {
        status = 403;
        body = {};
      }
      if (behavior === "duplicate" && Array.isArray(body.data)) body.data[3] = body.data[0];
      if (behavior === "unknown-owner" && Array.isArray(body.data))
        delete (body.data[3] as Record<string, unknown>).owner;
      if (behavior === "link-next") res.setHeader("Link", "</object?page=2>; rel=next");
      if (behavior === "oversize") body.padding = "x".repeat(9000);
    } else if (req.url !== "/") status = 404;
    wire.push({ path: req.url ?? "", actor: slot ?? "anonymous", status });
    res.writeHead(status, { "content-type": "application/json", connection: "close" });
    res.end(behavior === "invalid-json" && req.url === "/object" ? "{" : JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + (server.address() as AddressInfo).port;
  const onboard = new ApplicationOnboardingService(database, vault).create(
    org,
    {
      displayName: "Generated owned native identity fixture",
      origin,
      identityModel,
      authorizationSummary: "Owner separately reviews synthetic local GET observations",
      identityPath: "/identity",
      principalField: "id",
      roleField: "role",
      seedPath: "/object",
      objectField: "id",
      ...(identityModel === "TENANT_AWARE" ? { tenantField: "tenant", objectTenantField: "tenant" } : {}),
      actors: Object.fromEntries(
        ["primary", "account_a", "account_b"].map((s, i) => [
          s,
          {
            principal: "person-" + i,
            role: i === 0 ? "admin" : "user",
            authorizationHeader: "Bearer generated-" + s,
            expiresAt: "2099-01-01T00:00:00Z",
            ...(identityModel === "TENANT_AWARE" ? { tenant: "tenant-" + i } : {})
          }
        ])
      ),
      ownedReadOnlyConfirmed: true
    },
    "operator"
  );
  const input: ApplicationMappingInput = onboard.input;
  input.routes[0]!.observation = {
    kind: "COLLECTION",
    algorithm: "bounded-native-collection-v1",
    collectionPath: "data",
    itemIdentityPath: "id",
    ownerPath: "owner",
    ownerRule: "EXACT_VERIFIED_ACTOR_PRINCIPAL_STRING",
    maxItems: 4,
    maxResponseBytes: 8192,
    coverage: "THIS_RESPONSE_ONLY",
    pagination: { kind: "HAS_MORE_BOOLEAN", path: "hasMore" }
  };
  delete input.routes[0]!.tenantPath;
  const execution = new ScanExecutionService(database, paths, vault),
    mapping = new ApplicationMappingService(database, vault, execution),
    hypotheses = new ApplicationHypothesisService(database, vault, execution),
    workbench = new AuthorizationWorkbenchService(database, vault, execution);
  const wait = async (id: string) => {
    const end = Date.now() + 20000;
    while (Date.now() < end) {
      const r = database.db.prepare("SELECT status,error_summary FROM scans WHERE id=?").get(id) as {
        status: string;
        error_summary: string;
      };
      if (r.status === "COMPLETED") return;
      if (["FAILED", "CANCELLED", "INTERRUPTED"].includes(r.status)) throw Error(r.status + ":" + r.error_summary);
      await new Promise((r) => setTimeout(r, 50));
    }
    throw Error("ORIGINAL_20S_NATIVE_WAIT");
  };
  const report = (id: string) => {
    const a = database.db
      .prepare("SELECT canonical_path FROM artifacts a JOIN scans s ON s.json_report_artifact_id=a.id WHERE s.id=?")
      .get(id) as { canonical_path: string };
    return JSON.parse(readFileSync(a.canonical_path, "utf8")) as RouteCairnReport;
  };
  const capture = (name: string, value: unknown) =>
    writeFileSync(
      join(root, name + ".json"),
      JSON.stringify(
        {
          wire,
          value,
          integrity: database.db.pragma("integrity_check"),
          foreignKeys: database.db.pragma("foreign_key_check")
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  return {
    root,
    org,
    origin,
    database,
    vault,
    execution,
    mapping,
    hypotheses,
    workbench,
    onboard: { ...onboard, input },
    wire,
    wait,
    report,
    capture,
    setBehavior: (v: string) => {
      behavior = v;
    },
    acquire: async () => {
      const revision = await mapping.create(org, onboard.input, "operator"),
        run = await mapping.execute(org, revision.revisionId, revision.digest, "operator");
      await wait(run.scanId!);
      return { revision, run, result: mapping.result(org, revision.revisionId), report: report(run.scanId!) };
    },
    close: async () => {
      await execution.shutdown();
      await new Promise<void>((r, j) => server.close((e) => (e ? j(e) : r())));
      database.close();
      retainOwnedTestDirectory(root);
    }
  };
}
