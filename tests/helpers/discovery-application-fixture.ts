import { timedAssessmentPhase } from "./native-assessment-timings.js";
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { ApplicationMappingService } from "../../src/dashboard/execution/ApplicationMappingService.js";
import { ApplicationDiscoveryService } from "../../src/dashboard/execution/ApplicationDiscoveryService.js";
import { AuthorizationWorkbenchService } from "../../src/dashboard/execution/AuthorizationWorkbenchService.js";
import { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { exampleScope } from "../../src/config/defaults.js";
import type { ApplicationMappingInput } from "../../src/dashboard/contracts/ApplicationMappingContracts.js";
type Truth = {
  actors: Record<string, { principal: string; tenant: string; role: string }>;
  cases: {
    id: string;
    suffix: string;
    policy: string[];
    bug: string[];
    expected: string;
    counterexample?: string;
    kind?: string;
  }[];
};
export async function discoveryApplicationFixture(seed = "cedar") {
  if (process.platform !== "win32" || !process.env.ROUTECAIRN_WORKER_LAB || !["cedar", "quartz"].includes(seed))
    throw Error("OWNED_WINDOWS_DISCOVERY_LAB_REQUIRED");
  const truthBytes = readFileSync(new URL("../fixtures/discovery-ground-truth-v1.json", import.meta.url)),
    truth = JSON.parse(truthBytes.toString()) as Truth,
    root = createOwnedTestDirectory("independent-archive-hub-" + seed),
    prefix = "/hub/" + seed + "/",
    wire: { method: string; path: string; actor: string; status: number }[] = [];
  writeFileSync(join(root, "FROZEN_ORACLE.json"), truthBytes, { flag: "wx" });
  writeFileSync(
    join(root, "ORACLE_BINDING.json"),
    JSON.stringify({
      sha256: createHash("sha256").update(truthBytes).digest("hex"),
      requestsBeforeFreeze: 0,
      source: "tests/fixtures/discovery-ground-truth-v1.json",
      independentMaintainer: false
    }),
    { flag: "wx" }
  );
  let fixed = false,
    expired = false;
  const cases = truth.cases.map((c, i) => ({ ...c, path: prefix + c.suffix, ref: seed + "-asset-" + (100 + i) }));
  const server = createServer((req, res) => {
    const path = req.url ?? "/",
      actor =
        Object.keys(truth.actors).find((a) => req.headers.authorization === "Bearer archive-" + seed + "-" + a) ??
        "anonymous",
      person = truth.actors[actor];
    let status = 200,
      body: unknown = { application: "ArchiveHub" };
    if (req.method !== "GET") {
      status = 405;
      body = {};
    } else if (path === "/identity") {
      status = person && !expired ? 200 : 401;
      body = status === 200 ? person : {};
    } else if (path === prefix + "catalog/start")
      body = {
        asset: { ref: "directory", realm: "north" },
        links: [
          ...cases.map((c) => ({ href: c.path })),
          { href: prefix + "catalog/pages/2" },
          { href: cases[0]!.path },
          { href: "https://outside.invalid/" },
          { href: "//127.0.0.1/escape" },
          { href: "../escape" },
          { href: "/not-reviewed/protected" },
          { href: prefix + "remove" },
          { href: prefix + "x?session=secret" },
          { href: prefix + "mutate", method: "POST" }
        ]
      };
    else if (path === prefix + "catalog/pages/2")
      body = {
        asset: { ref: "page-2", realm: "north" },
        links: [{ href: prefix + "collections/17/retention/95" }, { href: prefix + "catalog/start" }]
      };
    else if (path === prefix + "collections/17/retention/95") {
      status = actor === "primary" ? 200 : 403;
      body =
        status === 200
          ? { asset: { ref: "retention-95", realm: "north" }, links: [{ href: prefix + "catalog/pages/3" }] }
          : {};
    } else if (path !== "/") {
      const c = cases.find((c) => c.path === path);
      if (!c) {
        status = 404;
        body = {};
      } else if (!person || expired) {
        status = 401;
        body = {};
      } else if (c.counterexample === "PRIMARY_UNAVAILABLE" && actor === "primary") {
        status = 503;
        body = {};
      } else if (c.counterexample === "DIFFERENT_OBJECT") {
        body = { asset: { ref: actor === "primary" ? c.ref : seed + "-own-" + actor, realm: person.tenant } };
      } else if (c.counterexample === "MISSING_TYPED_MARKER") {
        body = { asset: { description: "not enough object evidence" } };
      } else if (c.policy.includes(actor) || (!fixed && c.bug.includes(actor))) {
        body = { asset: { ref: c.ref, realm: "north" } };
      } else {
        status = 403;
        body = {};
      }
    }
    wire.push({ method: req.method ?? "", path, actor, status });
    res.writeHead(status, { "content-type": "application/json", connection: "close" });
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + (server.address() as AddressInfo).port,
    paths = resolveDashboardPaths(root),
    database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  const org = new OrganizationService(database).defaultOrganizationId(),
    key = Buffer.alloc(32, 71),
    vault = new CredentialVault(database, { bytes: key, version: "1" }),
    targetId = new TargetRepository(database).create({
      organizationId: org,
      displayName: "Owned ArchiveHub " + seed,
      baseOrigin: origin,
      tags: ["owned-disposable"],
      classification: "LOCAL",
      authorizationType: "OWNED",
      authorizationSummary: "Explicit owned fixture read-only discovery",
      approvedScope: {
        ...exampleScope,
        allowedDomains: ["127.0.0.1"],
        disallowedPaths: ["/not-reviewed"],
        allowedMethods: ["GET"],
        rateLimitPerSecond: 20,
        concurrency: 1
      }
    }),
    credentials = {} as ApplicationMappingInput["credentials"];
  for (const [slot, person] of Object.entries(truth.actors))
    credentials[slot as keyof typeof credentials] = vault.create({
      organizationId: org,
      targetId,
      name: person.principal,
      safeAlias: person.principal,
      expiresAt: "2099-01-01T00:00:00Z",
      safeIdentitySummary: { principalId: person.principal, tenantId: person.tenant, role: person.role },
      secret: {
        authorizationHeader: "Bearer archive-" + seed + "-" + slot,
        identityVerification: {
          endpoint: origin + "/identity",
          principalFieldPath: "principal",
          tenantFieldPath: "tenant",
          roleFieldPath: "role"
        }
      }
    });
  const execution = new ScanExecutionService(database, paths, vault),
    mapping = new ApplicationMappingService(database, vault, execution),
    discovery = new ApplicationDiscoveryService(database),
    workbench = new AuthorizationWorkbenchService(database, vault, execution),
    hypotheses = new ApplicationHypothesisService(database, vault, execution);
  const seedInput: ApplicationMappingInput = {
    targetId,
    credentials,
    identityContextConfirmed: true,
    readOnlyRoutesConfirmed: true,
    routes: [
      {
        id: "directory",
        kind: "OBJECT",
        url: origin + prefix + "catalog/start",
        pathTemplate: prefix + "catalog/start",
        method: "GET",
        identityPath: "asset.ref",
        tenantPath: "asset.realm"
      }
    ]
  };
  const wait = async (id: string) => {
    const end = Date.now() + 20000;
    while (Date.now() < end) {
      const row = database.db.prepare("SELECT status,error_summary FROM scans WHERE id=?").get(id) as {
        status: string;
        error_summary: string;
      };
      if (row.status === "COMPLETED") return;
      if (["FAILED", "INTERRUPTED", "CANCELLED"].includes(row.status))
        throw Error("NATIVE_" + row.status + ":" + row.error_summary);
      await new Promise((r) => setTimeout(r, 50));
    }
    throw Error("ORIGINAL_NATIVE_20S_DEADLINE");
  };
  const acquire = async (input: ApplicationMappingInput) => {
    const revision = await timedAssessmentPhase(root, "MAP_CREATE", () => mapping.create(org, input, "operator")),
      run = await timedAssessmentPhase(root, "MAP_DISPATCH", () =>
        mapping.execute(org, revision.revisionId, revision.digest, "operator")
      );
    await timedAssessmentPhase(root, "MAP_NATIVE_WAIT", () => wait(run.scanId!));
    return { revision, run, result: mapping.result(org, revision.revisionId) };
  };
  const propose = (id: string) =>
    discovery.create(
      org,
      { mapRevisionId: id, allowedPathPrefixes: [prefix], maxRoutes: 8, maxRequests: 36, scopeConfirmed: true },
      "operator"
    );
  const select = (
    p: ReturnType<typeof propose>,
    filter = (path: string) => path.startsWith(prefix)
  ): ApplicationMappingInput => {
    const selected = p.candidates.filter((c) => filter(c.path));
    return {
      ...seedInput,
      discoveryBinding: {
        proposalId: p.proposalId,
        digest: p.digest,
        selections: selected.map((c, i) => ({
          routeId: cases.find((r) => r.path === c.path)?.id ?? "page-" + i,
          candidateId: c.candidateId
        }))
      },
      routes: selected.map((c, i) => ({
        id: cases.find((r) => r.path === c.path)?.id ?? "page-" + i,
        kind: cases.find((r) => r.path === c.path)?.kind === "FUNCTION" ? "FUNCTION" : "OBJECT",
        url: c.url,
        pathTemplate: c.path,
        method: "GET",
        identityPath: "asset.ref",
        tenantPath: "asset.realm"
      }))
    };
  };
  const policy = (input: ApplicationMappingInput) => ({
    policyConfirmed: true as const,
    expectations: input.routes
      .filter((r) => cases.some((c) => origin + c.path === r.url && !["ABSTAIN"].includes(c.expected)))
      .map((r) => {
        const c = cases.find((c) => origin + c.path === r.url)!;
        return {
          routeId: r.id,
          url: r.url,
          kind: r.kind === "FUNCTION" ? ("FUNCTION_AUTHORIZATION" as const) : ("TENANT_ISOLATION" as const),
          explanation: "Independent fixture owner declares exact principal and tenant resource access policy.",
          identity: { path: "asset.ref", expectedValue: c.ref },
          tenant: { path: "asset.realm", expectedValue: "north" },
          decisions: Object.fromEntries(
            ["primary", "account-a", "account-b", "anonymous"].map((a) => [
              a,
              c.policy.includes(a.replaceAll("-", "_")) ? "ALLOW" : "DENY"
            ])
          ) as Record<string, "ALLOW" | "DENY">
        };
      })
  });
  const capture = (label: string, extra: unknown = {}) =>
    writeFileSync(
      join(root, label + ".json"),
      JSON.stringify(
        {
          extra,
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
          discovery: database.db.prepare("SELECT * FROM application_discovery_proposals").all(),
          maps: database.db.prepare("SELECT * FROM application_mapping_revisions").all(),
          hypotheses: database.db.prepare("SELECT * FROM application_hypothesis_proposals").all(),
          matrices: database.db.prepare("SELECT * FROM authorization_workbench_revisions").all(),
          comparisons: database.db.prepare("SELECT id,state,summary_json FROM scan_comparisons").all()
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  return {
    root,
    origin,
    prefix,
    org,
    key,
    paths,
    database,
    targetId,
    credentials,
    vault,
    execution,
    mapping,
    discovery,
    workbench,
    hypotheses,
    seedInput,
    cases,
    truth,
    wire,
    wait,
    acquire,
    propose,
    select,
    policy,
    capture,
    setFixed() {
      fixed = true;
    },
    setExpiredIdentity() {
      expired = true;
    },
    async close() {
      try {
        await timedAssessmentPhase(root, "SHUTDOWN_CUSTODY_DRAIN", () => execution.shutdown());
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
