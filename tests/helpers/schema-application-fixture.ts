import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { ApplicationMappingService } from "../../src/dashboard/execution/ApplicationMappingService.js";
import { ApplicationSchemaService } from "../../src/dashboard/execution/ApplicationSchemaService.js";
import { ApplicationMapComparisonService } from "../../src/dashboard/execution/ApplicationMapComparison.js";
import { AuthorizationWorkbenchService } from "../../src/dashboard/execution/AuthorizationWorkbenchService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { exampleScope } from "../../src/config/defaults.js";
import type { ApplicationMappingInput } from "../../src/dashboard/contracts/ApplicationMappingContracts.js";
export async function schemaApplicationFixture() {
  if (process.platform !== "win32" || !process.env.ROUTECAIRN_WORKER_LAB) throw Error("Owned Windows lab required");
  const root = createOwnedTestDirectory("numeric-records-schema-application"),
    key = Buffer.alloc(32, 51),
    wire: { method: string; path: string; actor: string; status: number }[] = [];
  const users = [
    { slot: "primary" as const, subject: "publisher-7", workspace: "workspace-red", level: "manager" },
    { slot: "account_a" as const, subject: "editor-8", workspace: "workspace-red", level: "editor" },
    { slot: "account_b" as const, subject: "reader-9", workspace: "workspace-blue", level: "reader" }
  ];
  let fixed = false,
    wrongPrimary = false,
    identitySpoof = false,
    missing = false,
    stringNumber = false;
  const handlers = new Map<string, (slot: string) => { status: number; body: unknown }>([
    [
      "/v2/records/42",
      (slot) =>
        missing && slot === "primary"
          ? { status: 503, body: {} }
          : slot === "primary" || !fixed
            ? {
                status: 200,
                body: { record: { number: wrongPrimary ? 73 : stringNumber ? "42" : 42, workspace: "workspace-red" } }
              }
            : { status: 403, body: {} }
    ],
    [
      "/v2/vault/42",
      (slot) =>
        slot === "primary"
          ? { status: 200, body: { record: { number: 42, workspace: "workspace-red" } } }
          : { status: 403, body: {} }
    ],
    [
      "/v2/self/42",
      (slot) => ({
        status: 200,
        body: {
          record: {
            number: slot === "primary" ? 42 : 73,
            workspace: slot === "account_b" ? "workspace-blue" : "workspace-red"
          }
        }
      })
    ],
    [
      "/v2/reports/summary",
      (slot) =>
        slot === "primary"
          ? { status: 200, body: { record: { number: 900, workspace: "workspace-red" } } }
          : { status: 403, body: {} }
    ]
  ]);
  const server = createServer((req, res) => {
    const user = users.find((u) => req.headers.authorization === "Bearer numeric-" + u.slot),
      path = req.url ?? "/";
    let result: { status: number; body: unknown };
    if (req.method !== "GET") result = { status: 405, body: {} };
    else if (path === "/") result = { status: 200, body: { application: "Generated Numeric Records v2" } };
    else if (path === "/whoami")
      result = user
        ? {
            status: 200,
            body: {
              subject: identitySpoof ? "spoofed-subject" : user.subject,
              workspace: user.workspace,
              level: user.level
            }
          }
        : { status: 401, body: {} };
    else if (!user) result = { status: 401, body: {} };
    else result = handlers.get(path)?.(user.slot) ?? { status: 404, body: {} };
    wire.push({ method: req.method ?? "", path, actor: user?.slot ?? "anonymous", status: result.status });
    res.writeHead(result.status, { "content-type": "application/json", connection: "close" });
    res.end(JSON.stringify(result.body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + (server.address() as AddressInfo).port,
    paths = resolveDashboardPaths(root),
    database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  const org = new OrganizationService(database).defaultOrganizationId();
  const targetId = new TargetRepository(database).create({
    displayName: "Generated numeric records application v2",
    baseOrigin: origin,
    tags: ["disposable", "schema-application-2"],
    classification: "LOCAL",
    authorizationType: "OWNED",
    authorizationSummary: "Owned synthetic non-mutating native schema assessment",
    approvedScope: {
      ...exampleScope,
      program: "numeric-records",
      allowedDomains: ["127.0.0.1"],
      disallowedPaths: [],
      allowedMethods: ["GET"],
      rateLimitPerSecond: 20,
      concurrency: 1
    }
  });
  const vault = new CredentialVault(database, { bytes: key, version: "1" }),
    credentials = {} as ApplicationMappingInput["credentials"];
  for (const u of users)
    credentials[u.slot] = vault.create({
      organizationId: org,
      name: u.subject,
      safeAlias: u.subject,
      targetId,
      expiresAt: "2099-01-01T00:00:00.000Z",
      safeIdentitySummary: { principalId: u.subject, tenantId: u.workspace, role: u.level },
      secret: {
        authorizationHeader: "Bearer numeric-" + u.slot,
        identityVerification: {
          endpoint: origin + "/whoami",
          principalFieldPath: "subject",
          tenantFieldPath: "workspace",
          roleFieldPath: "level"
        }
      }
    });
  const propertySchema = {
    type: "object",
    properties: {
      record: {
        type: "object",
        properties: {
          number: { type: "integer" },
          workspace: { type: "string" },
          secretToken: { type: "string", writeOnly: true }
        }
      }
    }
  };
  const operations = Object.fromEntries(
    ["records", "vault", "self"].map((p) => [
      "/v2/" + p + "/{number}",
      {
        parameters: [{ name: "number", in: "path", required: true, schema: { type: "integer" } }],
        get: {
          responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/Record" } } } } }
        },
        delete: { responses: { "204": { description: "Excluded mutation" } } }
      }
    ])
  );
  const document = JSON.stringify(
    {
      openapi: "3.1.0",
      info: { title: "Owned numeric-record application", version: "2.0" },
      servers: [{ url: "https://ignored.invalid" }],
      components: { schemas: { Record: propertySchema } },
      paths: {
        ...operations,
        "/v2/reports/summary": {
          get: { responses: { "200": { content: { "application/json": { schema: propertySchema } } } } },
          post: { responses: { "200": { description: "Excluded mutation" } } }
        }
      }
    },
    null,
    2
  );
  writeFileSync(join(root, "OPENAPI.json"), document, { flag: "wx" });
  writeFileSync(
    join(root, "FROZEN_GROUND_TRUTH.json"),
    JSON.stringify(
      {
        application: "INDEPENDENT_NUMERIC_RECORD_ROUTER",
        users,
        routes: [...handlers.keys()],
        vulnerable: "records leaks same/foreign workspace record until setFixed",
        secure: "vault",
        nearMiss: "self returns different numeric object despite HTTP200",
        function: "manager-only summary",
        mutations: "Always405; never approved",
        faults: ["missingControl", "wrongPrimary", "identitySpoof", "markerTypeChange"],
        initialRequests: 0
      },
      null,
      2
    ),
    { flag: "wx" }
  );
  const execution = new ScanExecutionService(database, paths, vault),
    mapping = new ApplicationMappingService(database, vault, execution),
    schemaService = new ApplicationSchemaService(database),
    comparisons = new ApplicationMapComparisonService(database),
    service = new AuthorizationWorkbenchService(database, vault, execution);
  const makeInput = () => {
    const schema = schemaService.create(org, { targetId, document }, "operator");
    const mappingInput: ApplicationMappingInput = {
      targetId,
      credentials,
      identityContextConfirmed: true,
      readOnlyRoutesConfirmed: true,
      schemaBinding: {
        revisionId: schema.revisionId,
        digest: schema.digest,
        selections: schema.candidates.map((c) => ({
          routeId: c.id,
          candidateId: c.id,
          slots: c.slots.length ? { number: "42" } : {}
        }))
      },
      routes: schema.candidates.map((c) => ({
        id: c.id,
        kind: c.kind,
        url: origin + c.path.replace("{number}", "42"),
        pathTemplate: c.template,
        method: "GET",
        identityPath: "record.number",
        tenantPath: "record.workspace"
      }))
    };
    return { schema, mappingInput };
  };
  const policyFor = (input: ApplicationMappingInput) => ({
    policyConfirmed: true as const,
    expectations: input.routes.map((r) => ({
      routeId: r.id,
      url: r.url,
      kind: r.kind === "FUNCTION" ? ("FUNCTION_AUTHORIZATION" as const) : ("TENANT_ISOLATION" as const),
      explanation: "Owner declares only the publisher manager may read this exact workspace-red record.",
      decisions: {
        primary: "ALLOW" as const,
        "account-a": "DENY" as const,
        "account-b": "DENY" as const,
        anonymous: "DENY" as const
      },
      identity: { path: r.identityPath, expectedValue: r.kind === "FUNCTION" ? 900 : 42 },
      tenant: { path: "record.workspace", expectedValue: "workspace-red" }
    }))
  });
  const wait = async (id: string) => {
    const until = Date.now() + 20000;
    while (Date.now() < until) {
      const s = database.db.prepare("SELECT status,error_summary FROM scans WHERE id=?").get(id) as {
        status: string;
        error_summary: string;
      };
      if (s.status === "COMPLETED") return;
      if (["FAILED", "CANCELLED", "INTERRUPTED"].includes(s.status))
        throw Error("NATIVE_" + s.status + ":" + s.error_summary);
      await new Promise((r) => setTimeout(r, 50));
    }
    throw Error("NATIVE_20S_DEADLINE");
  };
  const capture = (label: string) =>
    writeFileSync(
      join(root, label + ".json"),
      JSON.stringify(
        {
          wire,
          integrity: database.db.pragma("integrity_check"),
          foreignKeys: database.db.pragma("foreign_key_check"),
          scans: database.db.prepare("SELECT id,status,error_summary FROM scans").all(),
          workers: database.db.prepare("SELECT id,state,process_id,failure_category FROM scan_workers").all(),
          plans: database.db
            .prepare(
              "SELECT scan_id,plan_binding,worker_verified_binding,worker_verified_at FROM scan_executable_plans"
            )
            .all(),
          schema: database.db.prepare("SELECT * FROM application_schema_revisions").all(),
          maps: database.db.prepare("SELECT * FROM application_mapping_revisions").all(),
          dispatch: database.db.prepare("SELECT * FROM application_mapping_dispatches").all(),
          ack: database.db.prepare("SELECT * FROM application_mapping_acknowledgements").all(),
          mapComparisons: database.db.prepare("SELECT * FROM application_map_comparisons").all(),
          comparisons: database.db.prepare("SELECT id,state,summary_json FROM scan_comparisons").all()
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  return {
    root,
    key,
    wire,
    origin,
    paths,
    database,
    vault,
    execution,
    mapping,
    schemaService,
    comparisons,
    service,
    org,
    targetId,
    credentials,
    document,
    makeInput,
    policyFor,
    wait,
    capture,
    setFixed() {
      fixed = true;
    },
    setWrongPrimary() {
      wrongPrimary = true;
    },
    setIdentitySpoof() {
      identitySpoof = true;
    },
    setMissingControl() {
      missing = true;
    },
    setStringMarker() {
      stringNumber = true;
    },
    async close() {
      try {
        await execution.shutdown();
        capture("NATIVE_SQLITE_HTTP_RECEIPT");
      } finally {
        database.close();
        server.closeAllConnections();
        await new Promise<void>((r) => server.close(() => r()));
        retainOwnedTestDirectory(root);
      }
    }
  };
}
