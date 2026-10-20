import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { writeFileSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { ApplicationMappingService } from "../../src/dashboard/execution/ApplicationMappingService.js";
import { AuthorizationWorkbenchService } from "../../src/dashboard/execution/AuthorizationWorkbenchService.js";
import { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { exampleScope } from "../../src/config/defaults.js";
import type { ApplicationMappingInput } from "../../src/dashboard/contracts/ApplicationMappingContracts.js";
export async function roleflowApplicationFixture(
  application: "procurement" | "membership" = "procurement",
  mode: "vulnerable" | "shared" | "missing-state" | "wrong-object" = "vulnerable",
  reserved?: { resource: string | number; state: string | number; roles: readonly [string, string, string] },
  transition?: {
    revision: number;
    values: Record<string, string | number>;
    events: Map<string, unknown>;
    resourceTenant?: string;
    actorRoles?: Record<string, string>;
    actorValues?: Record<string, Record<string, string | number>>;
    delayBusinessResponseMs?: number;
  }
) {
  if (process.platform !== "win32" || !process.env.ROUTECAIRN_WORKER_LAB) throw Error("Owned Windows lab required");
  const root = createOwnedTestDirectory("roleflow-" + application),
    key = Buffer.alloc(32, 51),
    wire: { method: string; path: string; actor: string; status: number }[] = [];
  const users = [
    {
      slot: "primary" as const,
      subject: "reviewer-7",
      workspace: "workspace-red",
      level: reserved?.roles[0] ?? (application === "procurement" ? "approver" : "registrar")
    },
    {
      slot: "account_a" as const,
      subject: "requester-8",
      workspace: "workspace-red",
      level: reserved?.roles[1] ?? (application === "procurement" ? "requester" : "member")
    },
    {
      slot: "account_b" as const,
      subject: "partner-9",
      workspace: "workspace-blue",
      level: reserved?.roles[2] ?? (application === "procurement" ? "collaborator" : "sponsor")
    }
  ];
  const resource: string | number = reserved?.resource ?? (application === "procurement" ? 42 : "member-7"),
    initialState: string | number = reserved?.state ?? (application === "procurement" ? 1 : "ENROLLED"),
    pathsByRole =
      application === "procurement"
        ? ["/purchase/requests/42", "/finance/approvals/42/preview", "/catalog/shared/rules"]
        : ["/clubs/red/roster/member-7", "/sponsor/endorsements/member-7", "/benefits/member-7/entitlement-preview"];
  const evaluationMatrix = readFileSync(new URL("../fixtures/roleflow-heldout-cases.json", import.meta.url));
  writeFileSync(join(root, "PREREGISTERED_EVALUATION_MATRIX.json"), evaluationMatrix, { flag: "wx" });
  const truth = {
    evaluationMatrixSha256: createHash("sha256").update(evaluationMatrix).digest("hex"),
    application,
    mode,
    resource,
    initialState,
    structure:
      application === "procurement"
        ? "request -> approver decision preview; requester and external collaborator may read request"
        : "member-visible roster -> external sponsor endorsement -> registrar entitlement preview; member cannot read sponsor endorsement and sponsor cannot read private roster",
    setup: "Fixture-only in-memory assignment, separate from GET scan traffic; no scan performs transition or mutation",
    actors: users,
    orderedSteps: application === "membership" ? pathsByRole : pathsByRole.slice(0, 2),
    expected: {
      source: {
        primary: "ALLOW",
        "account-a": "ALLOW",
        "account-b": application === "membership" ? "DENY" : "ALLOW",
        anonymous: "DENY"
      },
      consent: { primary: "ALLOW", "account-a": "DENY", "account-b": "ALLOW", anonymous: "DENY" },
      operation: {
        primary: "ALLOW",
        "account-a": mode === "shared" ? "ALLOW" : "DENY",
        "account-b": mode === "shared" ? "ALLOW" : "DENY",
        anonymous: "DENY"
      }
    },
    heldOutFromProductionInference: true,
    evaluationSplit: reserved ? "RESERVED_AFTER_PRODUCT_SOURCE_FREEZE" : "DEVELOPMENT_SCENARIO",
    split: "PREDECLARED_SYNTHETIC_COUNTEREXAMPLE_MATRIX_NOT_INDEPENDENT_BENCHMARK"
  };
  const frozen = JSON.stringify(truth, null, 2);
  writeFileSync(join(root, "PREREGISTERED_HELD_OUT_TRUTH.json"), frozen, { flag: "wx" });
  writeFileSync(join(root, "TRUTH_SHA256.txt"), createHash("sha256").update(frozen).digest("hex"), { flag: "wx" });
  let tenantReassigned = false,
    fixed = false,
    actorStateDrift = false,
    stateDrift = false,
    reassigned = false,
    revoked = false;
  const server = createServer((req, res) => {
    const user = users.find((u) => req.headers.authorization === "Bearer numeric-" + u.slot),
      path = req.url ?? "/";
    let status = 200,
      body: unknown = { application };
    if (req.method !== "GET") {
      status = 405;
      body = {};
    } else if (path === "/whoami") {
      if (!user || revoked) {
        status = 401;
        body = {};
      } else
        body = {
          subject: user.subject,
          workspace: user.workspace,
          level: transition?.actorRoles?.[user.slot] ?? user.level
        };
    } else if (transition?.events.has(path)) {
      if (user?.slot !== "primary") {
        status = 403;
        body = {};
      } else body = transition.events.get(path);
    } else if (path !== "/") {
      if (!user) {
        status = 401;
        body = {};
      } else if (!pathsByRole.includes(path)) {
        status = 404;
        body = {};
      } else if (
        (application === "membership" &&
          ((path === pathsByRole[0] && user.slot === "account_b") ||
            (path === pathsByRole[1] && user.slot === "account_a"))) ||
        (path === pathsByRole[application === "membership" ? 2 : 1] &&
          user.slot !== "primary" &&
          fixed &&
          mode !== "shared")
      ) {
        status = 403;
        body = {};
      } else {
        const identity = reassigned
          ? application === "procurement"
            ? 99
            : "member-other"
          : mode === "wrong-object" && user.slot !== "primary"
            ? application === "procurement"
              ? 73
              : "member-other"
            : resource;
        body = {
          record: {
            number: identity,
            ...(transition ? { revision: transition.revision } : {}),
            workspace:
              transition?.resourceTenant ??
              (tenantReassigned && user.slot !== "primary" && path === pathsByRole[application === "membership" ? 2 : 1]
                ? "workspace-blue"
                : "workspace-red")
          },
          ...(application === "membership" && path === pathsByRole[1]
            ? {
                consent: {
                  state:
                    mode === "missing-state"
                      ? null
                      : (transition?.actorValues?.[user.slot]?.["consent.state"] ??
                        transition?.values["consent.state"] ??
                        "ENDORSED")
                }
              }
            : application === "membership" && path === pathsByRole[2]
              ? {
                  grant: {
                    stage:
                      mode === "missing-state"
                        ? null
                        : (transition?.actorValues?.[user.slot]?.["grant.stage"] ??
                          transition?.values["grant.stage"] ??
                          "READY")
                  }
                }
              : {
                  business: {
                    phase:
                      mode === "missing-state"
                        ? null
                        : (stateDrift || (actorStateDrift && user.slot === "account_a")) && path === pathsByRole[0]
                          ? "REVOKED"
                          : (transition?.actorValues?.[user.slot]?.["business.phase"] ??
                            transition?.values["business.phase"] ??
                            initialState)
                  }
                })
        };
      }
    }
    wire.push({ method: req.method ?? "", path, actor: user?.slot ?? "anonymous", status });
    res.writeHead(status, { "content-type": "application/json" });
    const delay = transition?.delayBusinessResponseMs ?? 0;
    if (delay && !path.includes("whoami")) {
      if (!Number.isInteger(delay) || delay < 0 || delay > 1000) throw Error("BOUNDED_FIXTURE_DELAY_REQUIRED");
      setTimeout(() => res.end(JSON.stringify(body)), delay);
    } else res.end(JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + (server.address() as AddressInfo).port,
    paths = resolveDashboardPaths(root),
    database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  const org = new OrganizationService(database).defaultOrganizationId();
  const targetId = new TargetRepository(database).create({
    displayName: "Generated role/state differential application",
    baseOrigin: origin,
    tags: ["disposable", "schema-application-2"],
    classification: "LOCAL",
    authorizationType: "OWNED",
    authorizationSummary: "Owned synthetic non-mutating native schema assessment",
    approvedScope: {
      ...exampleScope,
      program: "roleflow-owned",
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

  const execution = new ScanExecutionService(database, paths, vault),
    mapping = new ApplicationMappingService(database, vault, execution),
    service = new AuthorizationWorkbenchService(database, vault, execution),
    hypotheses = new ApplicationHypothesisService(database, vault, execution);
  const mappingInput: ApplicationMappingInput = {
    targetId,
    credentials,
    identityContextConfirmed: true,
    readOnlyRoutesConfirmed: true,
    routes: pathsByRole.map((path, i) => ({
      id: (application === "membership" ? ["source", "consent", "operation"] : ["source", "operation", "shared"])[i]!,
      url: origin + path,
      pathTemplate: path,
      kind: i === (application === "membership" ? 2 : 1) ? "FUNCTION" : "OBJECT",
      method: "GET",
      identityPath: "record.number",
      tenantPath: "record.workspace",
      statePaths: [
        application === "membership" && i === 1
          ? "consent.state"
          : application === "membership" && i === 2
            ? "grant.stage"
            : "business.phase",
        ...(transition ? ["record.revision"] : [])
      ]
    }))
  };
  const workflow = {
    name: application === "procurement" ? "Request to reviewed approval preview" : "Membership to entitlement preview",
    routeIds: application === "membership" ? ["source", "consent", "operation"] : ["source", "operation"]
  };
  const reviewFor = (p: { digest: string; flow?: { flowId: string } }) => ({
    action: "REVIEW_FLOW" as const,
    digest: p.digest,
    candidateId: p.flow!.flowId,
    policyConfirmed: true,
    ownershipConfirmed: true,
    relationshipExplanation:
      "Owner declares these exact routes describe the same disposable resource and read-only prerequisite state.",
    expectations: mappingInput.routes
      .filter((r) => workflow.routeIds.includes(r.id))
      .map((r, i) => ({
        routeId: r.id,
        url: r.url,
        kind: r.kind === "FUNCTION" ? "FUNCTION_AUTHORIZATION" : "TENANT_ISOLATION",
        explanation: "Owner declares the exact role and state access policy for this disposable resource.",
        decisions:
          r.id === "operation"
            ? truth.expected.operation
            : r.id === "consent"
              ? truth.expected.consent
              : truth.expected.source,
        identity: { path: "record.number", expectedValue: resource },
        tenant: { path: "record.workspace", expectedValue: "workspace-red" },
        states: [
          ...(transition ? [{ path: "record.revision", expectedValue: transition.revision }] : []),
          {
            path: r.statePaths![0]!,
            expectedValue:
              r.id === "consent"
                ? (transition?.values["consent.state"] ?? "ENDORSED")
                : application === "membership" && r.id === "operation"
                  ? (transition?.values["grant.stage"] ?? "READY")
                  : (transition?.values["business.phase"] ?? initialState)
          }
        ],
        dependsOn: i ? [workflow.routeIds[i - 1]!] : []
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

  const acquire = async () => {
    const revision = await mapping.create(org, mappingInput, "operator"),
      run = await mapping.execute(org, revision.revisionId, revision.digest, "operator");
    await wait(run.scanId!);
    return { revision, run, result: mapping.result(org, revision.revisionId) };
  };
  const capture = (label: string) =>
    writeFileSync(
      join(root, label + ".json"),
      JSON.stringify(
        {
          truthSha256: createHash("sha256").update(frozen).digest("hex"),
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
          proposals: database.db.prepare("SELECT * FROM application_hypothesis_proposals").all(),
          decisions: database.db.prepare("SELECT * FROM application_hypothesis_decisions").all(),
          dispatch: database.db.prepare("SELECT * FROM authorization_workbench_dispatches").all(),
          ack: database.db.prepare("SELECT * FROM authorization_workbench_acknowledgements").all()
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
    service,
    hypotheses,
    org,
    targetId,
    credentials,
    mappingInput,
    workflow,
    reviewFor,
    wait,
    acquire,
    capture,
    setTenantReassigned() {
      tenantReassigned = true;
    },
    setFixed() {
      fixed = true;
    },
    setAccessRegression() {
      fixed = false;
    },
    setStateDrift() {
      stateDrift = true;
    },
    setActorStateDrift() {
      actorStateDrift = true;
    },
    setReassigned() {
      reassigned = true;
    },
    setRevoked() {
      revoked = true;
    },
    async close() {
      try {
        await execution.shutdown();
        capture("NATIVE_ROLEFLOW_SQLITE_HTTP_RECEIPT");
      } finally {
        database.close();
        server.closeAllConnections();
        await new Promise<void>((r) => server.close(() => r()));
        retainOwnedTestDirectory(root);
      }
    }
  };
}
