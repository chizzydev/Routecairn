import { randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { RouteCairnEngine } from "../../src/core/engine/RouteCairnEngine.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { businessInvariantInputSchema, planBusinessInvariant } from "../../src/modules/businessInvariant/BusinessInvariantPlanner.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { recordWorkflowCaseExecutions } from "../../src/dashboard/comparisons/WorkflowCaseExecutionRecorder.js";
import { AdaptiveSecurityService } from "../../src/dashboard/execution/AdaptiveSecurityService.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import type { DashboardScanCreateRequest } from "../../src/dashboard/types/DashboardTypes.js";

let server: Server | undefined;
let database: DashboardDatabase | undefined;
let directory: string | undefined;
afterEach(async () => {
  database?.close(); database = undefined;
  if (server) { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve())); server = undefined; }
  if (directory) { await rm(directory, { recursive: true, force: true }); directory = undefined; }
});

describe("attack-state graph runtime lifecycle", () => {
  it("executes an approved exact graph contract over HTTP, restores state and verifies persisted case evidence", async () => {
    let balance = 100; let mutations = 0; let cleanups = 0;
    const trace: Array<{ method: string; path: string }> = [];
    server = createServer(async (request, response) => {
      trace.push({ method: request.method ?? "UNKNOWN", path: request.url ?? "/" });
      if (request.url === "/" || request.url === "/wallet") return void response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ balance }));
      if (request.url === "/withdraw" && request.method === "POST") { for await (const _chunk of request) { /* bounded fixture body is discarded */ } mutations++; balance -= 10; return void response.writeHead(200, { "content-type": "application/json" }).end('{"accepted":true}'); }
      if (request.url === "/restore" && request.method === "POST") {
        let body = ""; for await (const chunk of request) { body += String(chunk); if (body.length > 4096) return void response.writeHead(413).end(); }
        const restored = Number(JSON.parse(body).balance);
        if (!Number.isFinite(restored) || restored < 0 || restored > 100) return void response.writeHead(422).end();
        balance = restored; cleanups++; return void response.writeHead(204).end();
      }
      response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    directory = await mkdtemp(join(tmpdir(), "routecairn-attack-graph-"));
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const, rateLimitPerSecond: 100, concurrency: 1 };
    const dbPath = join(directory, "dashboard.sqlite");
    database = new DashboardDatabase(dbPath); database.migrate();
    const targetId = new TargetRepository(database).create({ displayName: "Owned disposable graph fixture", baseOrigin: origin, tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned loopback state transition fixture", productionEnabled: false, approvedScope: scope });
    const execute = async (input: unknown, label: string) => {
      const businessInvariant = planBusinessInvariant(businessInvariantInputSchema.parse(input), { target: `${origin}/`, scope });
      const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, businessInvariant, overrides: { includeModules: ["business-invariant"] } });
      const output = await new RouteCairnEngine().scan({ target: `${origin}/`, scope, config: defaultConfig, plan, outputDir: join(directory!, label) });
      return JSON.parse(await readFile(output.reportPath, "utf8")) as RouteCairnReport;
    };
    const source = await execute({ schemaVersion: 1, maxRequests: 10, cases: [walletCase(origin)] }, "source");
    const sourceCase = source.businessInvariant!.observations[0]!;
    expect(sourceCase).toMatchObject({ outcome: "PASS", cleanupOutcome: "ROLLBACK_VERIFIED", preStateVerified: true, postStateVerified: true });
    expect(balance).toBe(100);
    const register = (report: RouteCairnReport, binding?: unknown) => {
      const scanId = randomUUID();
      new ScanRepository(database!).create({ id: scanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: origin, safeTargetLabel: "Owned graph fixture", profile: "quick", evidenceLevel: "strong", safeConfigurationSummary: binding ? { adaptiveExecutionBinding: binding } : {}, targetId });
      database!.db.prepare("INSERT INTO scan_module_executions (id,scan_id,module_id,module_label,planned_order,status,executed_request_count) VALUES (?,?,?,'Business invariant',1,'COMPLETED',?)").run(randomUUID(), scanId, "business-invariant", report.requestAudit.length);
      recordWorkflowCaseExecutions(database!.db, scanId, report);
      return scanId;
    };
    const service = new AdaptiveSecurityService(database);
    const snapshot = service.observeCompletedScan(register(source), source, targetId) as any;
    const recommendation = snapshot.state.recommendations.find((item: any) => item.category === "EXACT_CONTRACT_REPLAY_BUSINESS_INVARIANT");
    expect(recommendation).toMatchObject({ operatorApprovalRequired: true, draft: { automation: { state: "READY_APPROVAL_GATED" }, attackGraphBinding: { graphFingerprint: snapshot.inventory.attackGraph.graphFingerprint } } });
    const workflowPath = snapshot.inventory.attackGraph.paths.find((path: any) => path.sourceCaseFingerprints.includes(sourceCase.comparisonFingerprint));
    expect(workflowPath).toMatchObject({ mutability: "STATE_CHANGING", contractReadiness: "COMPLETE" });
    expect(snapshot.inventory.attackGraph.edges.some((edge: any) => edge.kind === "CONSUMES")).toBe(true);
    const beforeApprovalMutations = mutations;
    expect(() => service.materializeRecommendation(recommendation.id)).toThrow("MUTATION_APPROVAL_REQUIRED");
    expect(() => service.decideRecommendation(recommendation.id, "APPROVED", "ok", "fixture-owner")).toThrow("EXPLICIT_REVIEW_REQUIRED");
    expect(mutations).toBe(beforeApprovalMutations);
    service.decideRecommendation(recommendation.id, "APPROVED", "Approve owned disposable wallet replay and verified restoration", "fixture-owner");
    database.db.prepare("UPDATE adaptive_security_recommendations SET reviewed_at=? WHERE id=?").run(new Date(Date.now() - 5 * 3600_000).toISOString(), recommendation.id);
    expect(() => service.materializeRecommendation(recommendation.id)).toThrow("APPROVAL_EXPIRED");
    service.decideRecommendation(recommendation.id, "APPROVED", "Fresh approval for owned disposable wallet replay and restoration", "fixture-owner");
    const materialized = service.materializeRecommendation(recommendation.id) as any;
    const request = { target: `${origin}/`, targetId, profile: "quick", maxRequests: materialized.limits.maxRequests, cleanupReservedRequests: materialized.limits.cleanupReservedRequests, includeModules: ["business-invariant"], businessInvariant: materialized.engineConfiguration, adaptiveExecutionBinding: materialized.binding, studio: { authentication: materialized.authentication } } as DashboardScanCreateRequest;
    expect(() => service.assertExecutionBinding(request)).not.toThrow();
    const changed = structuredClone(request); (changed.businessInvariant as any).cases[0].actions[0].request.url = `${origin}/unreviewed`;
    expect(() => service.assertExecutionBinding(changed)).toThrow("CONFIGURATION_CHANGED");
    const replay = await execute(materialized.engineConfiguration, "replay");
    const replayCase = replay.businessInvariant!.observations[0]!;
    expect(replayCase).toMatchObject({ outcome: "PASS", cleanupOutcome: "ROLLBACK_VERIFIED" });
    const unbound = register(replay);
    expect(() => service.linkRecommendation(recommendation.id, unbound, replayCase.comparisonFingerprint, "fixture-owner")).toThrow("LINKED_EXECUTION_BINDING_MISMATCH");
    const replayId = register(replay, materialized.binding);
    const linked = service.linkRecommendation(recommendation.id, replayId, replayCase.comparisonFingerprint, "fixture-owner") as any;
    expect(linked.recommendations.find((item: any) => item.id === recommendation.id)).toMatchObject({ status: "VERIFIED", executionOutcome: "VERIFIED", linkedScanId: replayId });
    expect(balance).toBe(100); expect(mutations).toBe(2); expect(cleanups).toBe(2);
    const graphFingerprint = snapshot.inventory.attackGraph.graphFingerprint;
    database.close(); database = new DashboardDatabase(dbPath); database.migrate();
    const persisted = new AdaptiveSecurityService(database).state(targetId) as any;
    expect(persisted.attackGraph.graphFingerprint).toBe(graphFingerprint);
    expect(persisted.recommendations.find((item: any) => item.id === recommendation.id).status).toBe("VERIFIED");
    expect(JSON.stringify(persisted)).not.toContain("Bearer ");
    const changedReport = structuredClone(source);
    (changedReport as any).apiMapper = { endpoints: [{ method: "POST", endpoint: `${origin}/new-transition` }], graphQlEndpoints: [] };
    const freshService = new AdaptiveSecurityService(database);
    freshService.observeCompletedScan(register(changedReport), changedReport, targetId);
    expect(() => freshService.materializeRecommendation(recommendation.id)).toThrow("MODEL_STALE");
    if (process.env.ROUTECAIRN_ATTACK_GRAPH_LAB_OUTPUT) await writeFile(join(process.env.ROUTECAIRN_ATTACK_GRAPH_LAB_OUTPUT, "runtime-proof.json"), `${JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), provenance: "SELF_MAINTAINED_LOOPBACK", externalTargetsTested: false, independentlyOperated: false, graphFingerprint, coverage: snapshot.inventory.attackGraph.coverage, sourceCaseFingerprint: sourceCase.comparisonFingerprint, replayCaseFingerprint: replayCase.comparisonFingerprint, executionOutcome: "VERIFIED", cleanup: "CONFIRMED", checks: ["REAL_HTTP_SOURCE_EXECUTION", "EXACT_CONTRACT_GRAPH_BINDING", "PRODUCER_CONSUMER_DEPENDENCY", "NO_MUTATION_BEFORE_APPROVAL", "EXPLICIT_REVIEW_REQUIRED", "EXPIRED_APPROVAL_REJECTED", "CHANGED_CONFIGURATION_REJECTED", "REAL_HTTP_APPROVED_REPLAY", "UNBOUND_EXECUTION_REJECTED", "VERIFIED_RESTORATION", "DATABASE_REOPEN_PERSISTENCE", "CHANGED_MODEL_REQUIRES_FRESH_REVIEW"], trace }, null, 2)}\n`, { flag: "wx" });
  });
});

function walletCase(origin: string) {
  const read = (id: string, name: string) => ({ id, actorId: "fixture", request: { method: "GET", url: `${origin}/wallet`, stateChanging: false }, captures: [{ name, source: "JSON", path: "balance" }] });
  return { id: "owned-wallet", label: "Disposable wallet transition", category: "FINANCIAL_LIMIT", actors: [{ id: "fixture", safeAlias: "Owned disposable actor", authSlot: "anonymous", requestAuthentication: "NONE", relationship: "SELF", declaredState: "FIXTURE" }], authorization: { mode: "CONTROLLED_INVARIANT", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING", authorizedBy: "fixture-owner", changeTicket: "owned-fixture-seed", authorizedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString(), disposableEntities: true }, preState: [read("before", "balance_before")], actions: [{ id: "withdraw", actorId: "fixture", request: { method: "POST", url: `${origin}/withdraw`, stateChanging: true, bodyFormat: "JSON", fields: { amount: 10 } }, execution: { mode: "ONCE", attempts: 1, maxConcurrency: 1 }, expectation: { authorization: "ALLOW", businessRule: "NOT_EVALUATED" } }], postState: [read("after", "balance_after")], invariants: [{ id: "delta", kind: "NUMERIC_DELTA", before: "balance_before", after: "balance_after", operator: "EQ", expected: -10 }], cleanupRequired: true, cleanup: [{ id: "restore", actorId: "fixture", request: { method: "POST", url: `${origin}/restore`, stateChanging: true, bodyFormat: "JSON", fields: { balance: "{{CAPTURE:balance_before}}" } }, successStatusCodes: [204] }], cleanupVerification: [read("restored", "balance_restored")], cleanupInvariants: [{ id: "restore-equality", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "balance_before" }, operator: "EQ", right: { source: "CAPTURE", ref: "balance_restored" } }] };
}
