import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { join } from "node:path";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { scopeSchema } from "../../src/config/ConfigSchema.js";
import { testPlan } from "./plan.js";
import { MutationRecoveryVault } from "../../src/core/offensive/MutationRecoveryVault.js";
import { type RecoverableWorkflow, type WorkflowCheckpoint } from "../../src/core/offensive/WorkflowMutationCoordinator.js";
import type { ResolvedScanPlan } from "../../src/core/planning/ScanPlan.js";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";

const servers: ReturnType<typeof createServer>[] = [];
export async function closeRecoveryFixtures() { for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done())); } }

export async function workflowRecoveryFixture(workflow: RecoverableWorkflow, options: { authProfile?: AuthProfile; requiredAuthorization?: string; caseId?: string } = {}) {
  const received: string[] = []; let restored = false;
  const server = createServer(async (request, response) => {
    received.push(`${request.method} ${request.url}`);
    if (options.requiredAuthorization && request.headers.authorization !== options.requiredAuthorization) return response.writeHead(401).end();
    if (request.url === "/fixture/cleanup" && request.method === "POST") {
      let body = ""; for await (const chunk of request) body += String(chunk);
      if (JSON.parse(body).restore !== "captured-restoration-sentinel") return response.writeHead(400).end();
      restored = true; return response.writeHead(204).end();
    }
    if (request.url === "/state") return response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ restored }));
    return response.writeHead(500).end();
  });
  servers.push(server); await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const scope = scopeSchema.parse({ ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "POST"], rateLimitPerSecond: 50 });
  const actor = { id: "public", safeAlias: "disposable-public", authSlot: options.authProfile ? "primary" : "anonymous", requestAuthentication: options.authProfile ? "PROFILE" : "NONE", sendAuthentication: Boolean(options.authProfile), relationship: "PUBLIC", declaredState: "ACTIVE" };
  const authorization = { mode: "CONTROLLED_LIFECYCLE", environment: "LOCAL", authorizationIdentityConfirmed: true, changeTicketConfirmed: true, confirmationAccepted: true, authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableAccounts: true, disposableEntities: true, disposableFixtures: true, productionAcknowledged: false };
  const cleanupRequest = { method: "POST", url: `${origin}/fixture/cleanup`, urlTemplate: `${origin}/fixture/cleanup`, headers: {}, stateChanging: true, secretSource: "anonymous", fields: { restore: "{{CAPTURE:restore}}" }, bodyFormat: "JSON" };
  const readRequest = { method: "GET", url: `${origin}/state`, urlTemplate: `${origin}/state`, headers: {}, stateChanging: false, secretSource: "anonymous" };
  const execution = { mode: "ONCE", attempts: 1, maxDispatchSkewMs: 100 };
  const steps = [
    { id: "never-replay", phase: "ACTION", actorId: "public", endpointId: "fixture", resourceId: "fixture", operation: "RESET_FIXTURE", request: { ...cleanupRequest, url: `${origin}/attack`, urlTemplate: `${origin}/attack` }, execution, captures: [], assertions: [{ kind: "STATUS_IN", values: [200] }], waitBeforeMs: 0 },
    { id: "restore", phase: "CLEANUP", actorId: "public", endpointId: "fixture", resourceId: "fixture", operation: "RESET_FIXTURE", request: cleanupRequest, execution, captures: [], assertions: [{ kind: "STATUS_IN", values: [204] }], waitBeforeMs: 0 },
    { id: "verify", phase: "CLEANUP", actorId: "public", endpointId: "fixture", resourceId: "fixture", operation: "OBSERVE", request: readRequest, execution, captures: [{ name: "restored", source: "JSON", path: "restored" }], assertions: workflow === "authenticationLifecycle" ? [{ kind: "JSON_EQUALS", path: "restored", expected: true }] : [{ kind: "BODY_FINGERPRINT", expectedSha256: createHash("sha256").update('{"restored":true}').digest("hex") }], waitBeforeMs: 0 }
  ];
  const testCase = { id: options.caseId ?? "disposable-case", label: "Disposable recovery case", category: "CUSTOM", actors: [actor], authorization, cleanupRequired: true, comparisonFingerprint: "a".repeat(64), steps,
    target: { type: "fixture", identityFingerprint: "b".repeat(64) }, preState: [{ id: "before", actorId: "public", request: readRequest, captures: [] }], actions: [{ request: cleanupRequest, execution }], groups: [], postState: [], invariants: [],
    cleanup: [{ id: "restore", actorId: "public", request: cleanupRequest, successStatusCodes: [204] }],
    cleanupVerification: [{ id: "verify", actorId: "public", request: readRequest, captures: [{ name: "restored", source: "JSON", path: "restored" }] }],
    cleanupInvariants: [{ id: "restored", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "restored" }, operator: "EQ", right: { source: "LITERAL", value: true } }],
    assertions: [{ id: "restored", scope: "CLEANUP", kind: "VALUE_EQUALS_LITERAL", dimension: "ENTITLEMENT", capture: "restored", expected: true }]
  };
  const endpoint = { id: "fixture", safeAlias: "fixture", kind: "FIXTURE_CONTROL", pathTemplate: "/fixture", allowedOrigins: [origin] };
  const protocolCase = {
    id: testCase.id,
    label: testCase.label,
    kind: "GRAPHQL_MUTATION",
    actorId: actor.id,
    requireVerifiedIdentity: false,
    url: `${origin}/attack`,
    headers: {},
    operationName: "NeverReplay",
    document: "mutation NeverReplay { neverReplay }",
    variables: { attack: "{{SECRET:missing-attack-secret}}" },
    expectation: { decision: "ALLOW", allowedStatuses: [200], deniedStatuses: [400, 401, 403], minMessages: 0 },
    authorization: { environment: "LOCAL", operator: "recovery-test", ticket: "recovery-test", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-01-02T00:00:00.000Z", confirmation: "I_AUTHORIZE_PROTOCOL_STATE_CHANGES", disposableResources: true },
    cleanup: { url: `${origin}/fixture/cleanup`, method: "POST", headers: {}, body: { restore: "captured-restoration-sentinel" }, statusIn: [204] },
    comparisonFingerprint: testCase.comparisonFingerprint
  };
  const selectedCase = workflow === "protocolSecurity" ? protocolCase : testCase;
  const modulePlan = { schemaVersion: 1, enabled: true, targetOrigin: origin, maxRequests: 20, maxRequestBytes: 8192, maxResponseBytes: 8192, maxDurationMs: 5000, maxConcurrency: 2, maxCases: 5, maxStepsPerCase: 10, actors: [actor], resources: [endpoint], endpoints: [endpoint], cases: [selectedCase], notes: [], provider: { kind: "CUSTOM_SYNTHETIC", mode: "LOCAL_EMULATOR", fixturePathPrefix: "/fixture", realPaymentExecution: "FORBIDDEN" } };
  const plan = { ...testPlan("quick", { scope }), [workflow]: modulePlan } as unknown as ResolvedScanPlan;
  const context = new ScanContext({ target: origin, scope, config: defaultConfig, plan, outputDir: join(process.env.ROUTECAIRN_MUTATION_DIR!, "scan-one"), ...(options.authProfile ? { authProfile: options.authProfile } : {}) });
  const prefix = { authenticationLifecycle: "auth-lifecycle", businessInvariant: "business-invariant", controlledRace: "controlled-race", protocolSecurity: "protocol-security", linkPortalSecurity: "link-portal", operationalEndpointSecurity: "operational", billingEntitlement: "billing-entitlement" }[workflow];
  const caseId = `${prefix}-${selectedCase.id}`;
  const captures = new Map<string, unknown>([["restore", "captured-restoration-sentinel"]]);
  context.mutations.register(workflow, caseId, selectedCase, workflow === "protocolSecurity" ? { state: captures } : { captures });
  const lock = context.mutations.lock(); await lock.acquire(caseId);
  await context.mutations.journal.append({ caseId, stage: "MUTATION_ARMED", targetOrigin: origin, mode: "CONTROLLED_MUTATION", requestUrl: `${origin}/one-time/captured-restoration-sentinel` });
  await lock.release(); // Simulate a terminated process: no in-memory captures survive.
  captures.clear();
  const path = join(context.mutations.directory, `${caseId}.recovery.enc`);
  const checkpoint = await new MutationRecoveryVault(context.mutations.directory).open<WorkflowCheckpoint>(path, caseId);
  return { context, checkpoint, path, received, origin, scope };
}
