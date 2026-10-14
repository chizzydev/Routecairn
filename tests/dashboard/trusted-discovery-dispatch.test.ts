import { createServer, type Server } from "node:http";
import { randomUUID, createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { channel } from "node:diagnostics_channel";
import { describe, it, expect, vi } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import {
  ScanRepository,
  TargetRepository,
  ProjectRepository,
  ArtifactRepository
} from "../../src/dashboard/db/DashboardRepositories.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { RequestSafetyBroker } from "../../src/core/http/RequestSafetyBroker.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { planAdaptiveDiscoveryCandidates } from "../../src/dashboard/execution/AdaptiveDiscoveryCandidatePlanner.js";
import { discoveryCandidateId } from "../../src/dashboard/execution/AdaptiveDiscoveryCandidateIR.js";
const pause = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const sha = (bytes: string | Buffer) => createHash("sha256").update(bytes).digest("hex");
function retainWitness(name: string, facts: object) {
  const directory = process.env.ROUTECAIRN_TRUSTED_DISCOVERY_WITNESS_DIR;
  if (directory)
    writeFileSync(
      join(directory, name + ".json"),
      JSON.stringify(
        {
          schemaVersion: 1,
          provenance: "SELF_MAINTAINED_LOOPBACK",
          externalTargetsTested: false,
          independentlyOperated: false,
          ...facts
        },
        null,
        2
      ) + "\n",
      { flag: "wx" }
    );
}
async function fixture(opts: { dnsDelay?: number; responseDelay?: number; responseStatus?: number } = {}) {
  const server: Server = createServer((q, r) => {
    receipts++;
    wire.push({
      method: q.method,
      body: false,
      cookie: !!q.headers.cookie,
      auth: !!q.headers.authorization,
      path: q.url
    });
    q.on("data", () => {
      wire[wire.length - 1]!.body = true;
    });
    setTimeout(
      () =>
        r
          .writeHead(opts.responseStatus ?? 200, opts.responseStatus === 302 ? { location: "/never-follow" } : {})
          .end("owned fixture"),
      opts.responseDelay ?? 0
    );
  });
  let receipts = 0,
    initiations = 0;
  const wire: any[] = [];
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const address = server.address();
  if (!address || typeof address === "string") throw Error("FIXTURE_FAILED");
  const origin = "http://localhost:" + address.port,
    root = process.env.ROUTECAIRN_MUTATION_DIR!,
    store = join(root, "reports");
  mkdirSync(store);
  const file = join(store, "source.json"),
    db = new DashboardDatabase(join(root, "fixture.sqlite"));
  db.migrate();
  const org = (db.db.prepare("SELECT id FROM organizations LIMIT 1").get() as any).id,
    user = randomUUID(),
    stamp = new Date().toISOString();
  db.db
    .prepare(
      "INSERT INTO dashboard_users (id,login,normalized_login,password_hash,role,enabled,created_at,updated_at,password_changed_at) VALUES (?,?,?,'FIXTURE_ONLY','OWNER',1,?,?,?)"
    )
    .run(user, "fixture", "fixture", stamp, stamp, stamp);
  db.db
    .prepare(
      "INSERT INTO organization_memberships (organization_id,user_id,role,created_by,created_at,updated_at) VALUES (?,?,'OWNER','FIXTURE',?,?)"
    )
    .run(org, user, stamp, stamp);
  const scope = {
    ...exampleScope,
    allowedDomains: ["localhost"],
    allowedMethods: ["GET"] as const,
    disallowedPaths: [],
    rateLimitPerSecond: 1,
    concurrency: 1,
    maxDepth: 0,
    sameOriginOnly: true,
    includeSubdomains: false
  };
  const project = new ProjectRepository(db).create({
      organizationId: org,
      name: "Owned fixture",
      tags: [],
      defaultScope: scope
    }),
    target = new TargetRepository(db).create({
      organizationId: org,
      projectId: project,
      displayName: "Owned fixture",
      baseOrigin: origin,
      tags: [],
      classification: "LOCAL",
      authorizationType: "CONTROLLED_LAB",
      authorizationSummary: "Owner authorizes this disposable loopback fixture",
      approvedScope: scope
    }),
    scan = randomUUID();
  new ScanRepository(db).create({
    id: scan,
    organizationId: org,
    projectId: project,
    targetId: target,
    source: "DASHBOARD",
    status: "COMPLETED",
    targetOrigin: origin,
    safeTargetLabel: "fixture",
    profile: "quick",
    evidenceLevel: "minimal",
    safeConfigurationSummary: {}
  });
  const report: any = {
    routeCairnVersion: "0.1.0",
    target: origin,
    mode: "quick",
    execution: { status: "COMPLETED", partial: false, cleanup: { state: "CLEAR", cases: [] } },
    requestAudit: [],
    responses: [],
    apiMapper: {
      endpoints: [
        { endpoint: origin + "/api/health", method: "GET", hasObjectId: false, authRelevance: "low", riskTags: [] }
      ],
      graphQlEndpoints: [],
      notes: []
    }
  };
  writeFileSync(file, JSON.stringify(report));
  const artifact = new ArtifactRepository(db).create({
    organizationId: org,
    scanId: scan,
    type: "JSON_REPORT",
    name: "Owned fixture",
    path: file,
    size: readFileSync(file).length,
    contentType: "application/json",
    hash: "scoped-not-a-full-file-digest",
    retentionState: "RETAIN"
  });
  new ScanRepository(db).attachArtifacts(scan, { json: artifact });
  const auth = {
      schemaVersion: 1 as const,
      mode: "INTERNAL_STAGING" as const,
      targetOrigin: origin,
      proof: { reference: "Separate owned fixture operator authorization", sha256: sha("fixture-authorization") }
    },
    config = { ...defaultConfig, requestTimeoutMs: 4000, bodyPreviewBytes: 1024 },
    plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({
      requestedProfile: "quick",
      scope,
      config,
      targetAuthorization: auth,
      overrides: { maxRequests: 3, cleanupReservedRequests: 1, evidenceLevel: "minimal" }
    });
  const controller = new AbortController(),
    context = new ScanContext({ target: origin, scope, config, plan, outputDir: root, abortSignal: controller.signal });
  const peer =
    opts.dnsDelay !== undefined
      ? new RequestSafetyBroker(
          {
            userAgent: scope.userAgent,
            timeoutMs: 4000,
            bodyPreviewBytes: 1024,
            maxResponseBytes: 4096,
            rateLimitPerSecond: 1,
            concurrency: 1,
            maxRequests: 3,
            retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1, retryStatusCodes: [] },
            abortSignal: controller.signal,
            dnsResolver: async () => {
              dnsEntered = true;
              await pause(opts.dnsDelay!);
              return ["127.0.0.1"];
            }
          },
          context.scopeMatcher,
          (e) => context.state.recordRequestAudit(e),
          { ledger: context.requestLedger, lane: "SCAN" }
        )
      : undefined;
  let dnsEntered = false,
    revoked = false,
    effect = true,
    clock: number | undefined,
    consentDeadline = Date.now() + 60000;
  const actorReceipt = Object.freeze({}),
    consentReceipt = Object.freeze({});
  const host = {
    verifyActor: (receipt: unknown) => (receipt === actorReceipt ? { organizationId: org, userId: user } : undefined),
    verifyConsent: (receipt: unknown, facts: any) =>
      receipt === consentReceipt && !revoked
        ? {
            organizationId: org,
            userId: user,
            targetId: target,
            route: origin + "/api/health",
            effect: effect ? "NON_MUTATING" : "UNKNOWN",
            sourceDigest: sha(readFileSync(file)),
            targetGeneration: facts.targetGeneration,
            expiresAt: consentDeadline
          }
        : undefined
  };
  const module = await import("../../src/dashboard/execution/TrustedDiscoveryDispatcher.js").catch(() => undefined);
  if (!module?.TrustedDiscoveryDispatcher) {
    await peer?.close();
    await context.dispose();
    db.close();
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
  expect(
    module?.TrustedDiscoveryDispatcher,
    "production source-bound dispatcher must exist; no report/manual-send fallback"
  ).toBeTypeOf("function");
  const create = (boundary?: any, ctx = context, broker = peer) =>
    new module!.TrustedDiscoveryDispatcher({
      database: db,
      reportRoot: store,
      context: ctx,
      host: boundary,
      broker,
      clock: () => clock ?? Date.now()
    });
  const service = create(host),
    observe = (e: any) => {
      if (e.socket.remotePort === address.port) initiations++;
    };
  const c = channel("undici:client:sendHeaders");
  c.subscribe(observe);
  const select = () => ({
    scanId: scan,
    candidateId: planAdaptiveDiscoveryCandidates(report).candidates[0]!.candidateId
  });
  const review = () => service.review(select(), actorReceipt),
    approve = (r = review()) => service.consent(r.review, consentReceipt);
  return {
    db,
    org,
    user,
    project,
    target,
    scan,
    artifact,
    origin,
    file,
    store,
    root,
    report,
    context,
    peer,
    controller,
    service,
    host,
    actorReceipt,
    consentReceipt,
    create,
    select,
    review,
    approve,
    get receipts() {
      return receipts;
    },
    get initiations() {
      return initiations;
    },
    get wire() {
      return wire;
    },
    get dnsEntered() {
      return dnsEntered;
    },
    revoke: () => {
      revoked = true;
    },
    setEffect: (v: boolean) => {
      effect = v;
    },
    setDeadline: (v: number) => {
      consentDeadline = v;
    },
    setClock: (v: number) => {
      clock = v;
    },
    save: () => {
      writeFileSync(file, JSON.stringify(report));
      db.db.prepare("UPDATE artifacts SET size=? WHERE id=?").run(readFileSync(file).length, artifact);
    },
    stopServer: async () => {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    },
    close: async () => {
      c.unsubscribe(observe);
      await peer?.close();
      await context.dispose();
      db.close();
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
  };
}
async function assertNoWire(f: Awaited<ReturnType<typeof fixture>>, value: any) {
  expect(value.code).toMatch(/^DENIED_/);
  expect(f.receipts).toBe(0);
  expect(f.initiations).toBe(0);
  expect(f.context.requestLedger.snapshot()).toMatchObject({
    scanTransmitted: 0,
    cleanupTransmitted: 0,
    cleanupRemaining: 1,
    inFlight: 0,
    queued: 0
  });
  expect(JSON.stringify(value)).not.toContain(f.origin);
  expect(JSON.stringify(value)).not.toContain(f.target);
  expect(JSON.stringify(value)).not.toContain("api/health");
}
describe("NG5B1 trusted source-bound dispatch", () => {
  async function duplicateWitness(f: Awaited<ReturnType<typeof fixture>>, result: any, name: string, prior = 1) {
    retainWitness(name, {
      result,
      clientInitiations: f.initiations,
      serverReceipts: f.receipts,
      ordinaryInitiations: f.initiations - result.initiated,
      expectedOrdinaryInitiations: prior,
      ledger: f.context.requestLedger.snapshot()
    });
    expect(result.code).toBe("DENIED_DUPLICATE");
    expect(result.initiated).toBe(0);
    expect(result.scanReserved).toBe(0);
    expect(f.receipts).toBe(prior);
    expect(f.initiations).toBe(prior);
    expect(f.context.requestLedger.snapshot()).toMatchObject({
      scanTransmitted: prior,
      cleanupTransmitted: 0,
      cleanupRemaining: 1,
      inFlight: 0,
      queued: 0
    });
    expect(JSON.stringify(result)).not.toMatch(/localhost|api\/health|sourceDigest|duplicate-canary-only|requestId/);
  }
  it("D1/D7 completed original-context ordinary GET blocks same-route discovery without cleanup loss", async () => {
    const f = await fixture();
    try {
      await f.context.httpClient.send({ url: f.origin + "/api/health", method: "GET", disableRetries: true });
      expect(f.context.state.getRequestAudit().some((a) => a.method === "GET" && a.outcome === "sent")).toBe(true);
      const r = f.review();
      await duplicateWitness(f, r.result, "D1");
      expect(r.review).toBeUndefined();
    } finally {
      await f.close();
    }
  });
  it("D2 in-flight original-context ordinary GET blocks discovery before completion audit", async () => {
    const f = await fixture({ responseDelay: 700 });
    let pending: Promise<unknown> | undefined;
    try {
      pending = f.context.httpClient.send({ url: f.origin + "/api/health", method: "GET", disableRetries: true });
      await vi.waitFor(() => expect(f.receipts).toBe(1));
      expect(f.context.state.getRequestAudit()).toHaveLength(0);
      const r = f.review();
      await pending;
      await duplicateWitness(f, r.result, "D2");
      expect(r.review).toBeUndefined();
    } finally {
      await pending;
      await f.close();
    }
  });
  it("D3 same-route ordinary GET after consent invalidates final private operation", async () => {
    const f = await fixture();
    try {
      const a = f.approve();
      expect(a.operation).toBeDefined();
      await f.context.httpClient.send({ url: f.origin + "/api/health", method: "GET", disableRetries: true });
      await duplicateWitness(f, await f.service.execute(a.operation), "D3");
    } finally {
      await f.close();
    }
  });
  it("D3 ordinary same-route GET between review and consent invalidates consent", async () => {
    const f = await fixture();
    try {
      const r = f.review();
      expect(r.review).toBeDefined();
      await f.context.httpClient.send({ url: f.origin + "/api/health", method: "GET", disableRetries: true });
      const a = f.service.consent(r.review, f.consentReceipt);
      await duplicateWitness(f, a.result, "D3-consent");
      expect(a.operation).toBeUndefined();
    } finally {
      await f.close();
    }
  });
  it("D6 failed original-context connection still records intent without claiming wire or budget", async () => {
    const f = await fixture();
    try {
      await f.stopServer();
      const failed = await f.context.httpClient.send({
        url: f.origin + "/api/health",
        method: "GET",
        disableRetries: true
      });
      expect(failed.error).toBeDefined();
      await duplicateWitness(f, f.review().result, "D6-connect-error", 0);
    } finally {
      await f.close();
    }
  });
  it("D3 queue-time ordinary same-route intent denies feature before final initiation", async () => {
    const f = await fixture({ dnsDelay: 0, responseDelay: 350 });
    let ordinary: Promise<unknown> | undefined;
    try {
      const a = f.approve();
      const warm = f.context.httpClient.send({ url: f.origin + "/warm", method: "GET", disableRetries: true });
      await vi.waitFor(() => expect(f.receipts).toBe(1));
      const discovery = f.service.execute(a.operation);
      ordinary = f.context.httpClient.send({ url: f.origin + "/api/health", method: "GET", disableRetries: true });
      await warm;
      const result = await discovery;
      await ordinary;
      await duplicateWitness(f, result, "D3-queue", 2);
    } finally {
      await ordinary;
      await f.close();
    }
  });
  it("D4 two actual native peers share the original SCAN-ledger GET identity barrier", async () => {
    const f = await fixture({ dnsDelay: 0 });
    try {
      await f.peer!.send({ url: f.origin + "/api/health", method: "GET", disableRetries: true });
      const original = f.create(f.host, f.context, f.context.httpClient);
      await duplicateWitness(f, original.review(f.select(), f.actorReceipt).result, "D4");
    } finally {
      await f.close();
    }
  });
  it("D5 unrelated original-context GET still permits exactly one selected discovery GET", async () => {
    const f = await fixture();
    try {
      await f.context.httpClient.send({ url: f.origin + "/warm", method: "GET", disableRetries: true });
      const result = await f.service.execute(f.approve().operation);
      expect(result.code).toBe("RESPONSE_OBSERVED");
      expect(result.initiated).toBe(1);
      expect(f.receipts).toBe(2);
      expect(f.initiations).toBe(2);
      expect(f.context.requestLedger.snapshot()).toMatchObject({
        scanTransmitted: 2,
        cleanupTransmitted: 0,
        cleanupRemaining: 1,
        inFlight: 0,
        queued: 0
      });
      retainWitness("D5", {
        result,
        clientInitiations: f.initiations,
        serverReceipts: f.receipts,
        priorOrdinaryInitiations: 1,
        ledger: f.context.requestLedger.snapshot()
      });
    } finally {
      await f.close();
    }
  });
  it.each(["canonical", "cache", "error"])(
    "D6 exact GET history conservatively handles %s without private public facts",
    async (kind) => {
      const f = await fixture({ responseStatus: kind === "error" ? 500 : 200 });
      try {
        const url =
          kind === "canonical"
            ? f.origin.replace("localhost", "LOCALHOST") + "/api/../api//health#ignored"
            : f.origin + "/api/health";
        const first = await f.context.httpClient.send({
          url,
          method: "GET",
          disableRetries: true,
          headers: { "x-fixture-proof": "duplicate-canary-only" }
        });
        expect(first.statusCode).toBe(kind === "error" ? 500 : 200);
        if (kind === "cache")
          await f.context.httpClient.send({
            url,
            method: "GET",
            disableRetries: true,
            headers: { "x-fixture-proof": "duplicate-canary-only" }
          });
        await duplicateWitness(f, f.review().result, "D6-" + kind);
      } finally {
        await f.close();
      }
    }
  );
  it("a valid different source candidate cannot replace the selected full identity", async () => {
    const f = await fixture();
    try {
      f.report.apiMapper.endpoints.push({
        endpoint: f.origin + "/api/status",
        method: "GET",
        hasObjectId: false,
        authRelevance: "low",
        riskTags: []
      });
      f.save();
      const candidates = planAdaptiveDiscoveryCandidates(f.report).candidates;
      expect(candidates).toHaveLength(2);
      await assertNoWire(
        f,
        f.service.review(
          { scanId: f.scan, candidateId: candidates[0]!.candidateId, candidate: candidates[1] },
          f.actorReceipt
        ).result
      );
    } finally {
      await f.close();
    }
  });
  it("two dispatcher instances share the same execution duplicate barrier", async () => {
    const f = await fixture();
    try {
      const first = f.review();
      expect(first.result.code).toBe("SELECTED_FOR_REVIEW");
      expect(f.create(f.host).review(f.select(), f.actorReceipt).result.code).toBe("DENIED_DUPLICATE");
      expect(f.receipts).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("a consumed native consent receipt cannot mint a second operation", async () => {
    const f = await fixture();
    let other: ScanContext | undefined;
    try {
      const a = f.approve();
      expect(a.operation).toBeDefined();
      other = new ScanContext({ ...f.context.options });
      const second = f.create(f.host, other, other.httpClient);
      const r = second.review(f.select(), f.actorReceipt);
      expect(r.result.code).toBe("SELECTED_FOR_REVIEW");
      expect(second.consent(r.review, f.consentReceipt).result.code).toBe("DENIED_OPERATOR_BINDING");
      expect(f.receipts).toBe(0);
    } finally {
      await other?.dispose();
      await f.close();
    }
  });
  it("proxy selection traps are rejected without evaluating hostile code", async () => {
    const f = await fixture();
    let traps = 0;
    try {
      const value = new Proxy(
        {},
        {
          getPrototypeOf() {
            traps++;
            throw Error("private");
          },
          ownKeys() {
            traps++;
            throw Error("private");
          }
        }
      );
      await assertNoWire(f, f.service.review(value, f.actorReceipt).result);
      expect(traps).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("native consent verification cannot change the source after its freshness check", async () => {
    const f = await fixture({ dnsDelay: 100 });
    let calls = 0;
    try {
      const host = {
        ...f.host,
        verifyConsent: (receipt: unknown, facts: any) => {
          const value = f.host.verifyConsent(receipt, facts);
          if (++calls === 3) f.db.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.target);
          return value;
        }
      };
      const s = f.create(host);
      const r = s.review(f.select(), f.actorReceipt),
        a = s.consent(r.review, f.consentReceipt);
      await assertNoWire(f, await s.execute(a.operation));
    } finally {
      await f.close();
    }
  });
  it("01-04 trusted registered source rederives exact candidate and sends one real GET", async () => {
    const f = await fixture();
    try {
      const r = f.review();
      expect(r.result.code).toBe("SELECTED_FOR_REVIEW");
      const a = f.approve(r);
      const result = await f.service.execute(a.operation);
      expect(result).toMatchObject({
        code: "RESPONSE_OBSERVED",
        attempted: 1,
        initiated: 1,
        responseObserved: 1,
        assessment: "NOT_ASSESSED"
      });
      expect(f.receipts).toBe(1);
      expect(f.initiations).toBe(1);
      expect(f.wire).toEqual([{ method: "GET", body: false, cookie: false, auth: false, path: "/api/health" }]);
      expect(f.context.requestLedger.snapshot()).toMatchObject({
        scanTransmitted: 1,
        cleanupRemaining: 1,
        cleanupTransmitted: 0,
        inFlight: 0,
        queued: 0
      });
      expect(JSON.stringify(result)).not.toMatch(/localhost|api\/health|requestId|sourceDigest|Bearer/);
      retainWitness("one-get", {
        result,
        clientInitiations: f.initiations,
        serverReceipts: f.receipts,
        ledger: f.context.requestLedger.snapshot(),
        anonymousGet: true,
        sourceFullBytesBound: true
      });
    } finally {
      await f.close();
    }
  });
  const rowCases = [
    ["empty source", "UPDATE scans SET json_report_artifact_id=NULL WHERE id=?", "scan"],
    ["imported source", "UPDATE scans SET status='IMPORTED' WHERE id=?", "scan"],
    ["failed source", "UPDATE scans SET status='FAILED' WHERE id=?", "scan"],
    ["interrupted source", "UPDATE scans SET status='INTERRUPTED' WHERE id=?", "scan"],
    ["imported source type", "UPDATE scans SET source='REPORT_IMPORTED' WHERE id=?", "scan"],
    ["missing target registration", "UPDATE scans SET target_id=NULL WHERE id=?", "scan"],
    ["archived target", "UPDATE targets SET archived_at='fixture' WHERE id=?", "target"],
    ["deleted source", "UPDATE scans SET deleted_at='fixture' WHERE id=?", "scan"],
    ["archived source", "UPDATE scans SET archived_at='fixture' WHERE id=?", "scan"],
    ["wrong target origin", "UPDATE scans SET target_origin='http://localhost:1' WHERE id=?", "scan"],
    ["artifact scan mismatch", "UPDATE artifacts SET scan_id=NULL WHERE id=?", "artifact"],
    ["artifact organization mismatch", "UPDATE artifacts SET organization_id=NULL WHERE id=?", "artifact"],
    ["unretained artifact", "UPDATE artifacts SET retention_state='DELETE' WHERE id=?", "artifact"],
    ["missing artifact flag", "UPDATE artifacts SET missing_file_flag=1 WHERE id=?", "artifact"],
    ["archived project", "UPDATE projects SET archived_at='fixture' WHERE id=?", "project"],
    ["wrong project", "UPDATE scans SET project_id=NULL WHERE id=?", "scan"],
    ["unknown classification", "UPDATE targets SET classification='UNKNOWN' WHERE id=?", "target"],
    ["production classification", "UPDATE targets SET classification='PRODUCTION' WHERE id=?", "target"],
    ["external authorization", "UPDATE targets SET authorization_type='BUG_BOUNTY' WHERE id=?", "target"],
    ["disabled owner", "UPDATE dashboard_users SET enabled=0 WHERE id=?", "user"]
  ] as const;
  for (const [label, sql, id] of rowCases)
    it("rejects " + label + " from actual authoritative SQLite rows", async () => {
      const f = await fixture();
      try {
        f.db.db.prepare(sql).run(f[id]);
        await assertNoWire(f, f.review().result);
      } finally {
        await f.close();
      }
    });
  const reportCases = [
    [
      "partial source",
      (f: any) => {
        f.report.execution.partial = true;
      }
    ],
    [
      "wrong report target",
      (f: any) => {
        f.report.target = "http://localhost:1";
      }
    ],
    [
      "unknown method",
      (f: any) => {
        f.report.apiMapper.endpoints[0].method = "BANANA";
      }
    ],
    [
      "non GET method",
      (f: any) => {
        f.report.apiMapper.endpoints[0].method = "POST";
      }
    ],
    [
      "second origin",
      (f: any) => {
        f.report.apiMapper.endpoints[0].endpoint = "http://localhost:1/api/health";
      }
    ],
    [
      "query",
      (f: any) => {
        f.report.apiMapper.endpoints[0].endpoint += "?token=fixture-private";
      }
    ],
    [
      "fragment",
      (f: any) => {
        f.report.apiMapper.endpoints[0].endpoint += "#fixture";
      }
    ],
    [
      "encoded separator",
      (f: any) => {
        f.report.apiMapper.endpoints[0].endpoint += "/%2fread";
      }
    ],
    [
      "double encoding",
      (f: any) => {
        f.report.apiMapper.endpoints[0].endpoint += "/%252fread";
      }
    ],
    [
      "credential URL",
      (f: any) => {
        f.report.apiMapper.endpoints[0].endpoint =
          f.origin.replace("http://", "http://fixture:private@") + "/api/health";
      }
    ],
    [
      "stateful GET",
      (f: any) => {
        f.report.apiMapper.endpoints[0].endpoint = f.origin + "/api/reset";
      }
    ],
    [
      "capability identifier",
      (f: any) => {
        f.report.apiMapper.endpoints[0].endpoint += "/abcdefghijklmnopqrstuvwxyzABCDEF123456";
      }
    ],
    [
      "duplicate mapper identity",
      (f: any) => {
        f.report.apiMapper.endpoints.push({ ...f.report.apiMapper.endpoints[0] });
      }
    ],
    [
      "upstream invalid",
      (f: any) => {
        f.report.requestAudit = [{ method: "GET", requestedUrl: f.origin + "/api/health", outcome: "mystery" }];
      }
    ],
    [
      "sent unpaired",
      (f: any) => {
        f.report.requestAudit = [
          {
            method: "GET",
            requestedUrl: f.origin + "/api/health",
            finalUrl: f.origin + "/api/health",
            outcome: "sent",
            redirectChain: [],
            requestHeaders: {}
          }
        ];
      }
    ],
    [
      "browser transmitted only",
      (f: any) => {
        f.report.browserCrawl = {
          networkRequests: [{ url: f.origin + "/api/health", method: "GET", decision: "allowed", transmitted: true }]
        };
      }
    ],
    [
      "API probe already sent",
      (f: any) => {
        f.report.apiProbe = {
          endpointsReviewed: [
            { endpoint: f.origin + "/api/health", methodsTested: ["GET"], statusByMethod: { GET: 200 } }
          ]
        };
      }
    ],
    [
      "completed response without audit",
      (f: any) => {
        f.report.responses = [
          {
            method: "GET",
            requestedUrl: f.origin + "/api/health",
            finalUrl: f.origin + "/api/health",
            statusCode: 200,
            redirectChain: [],
            headers: {},
            responseTimeMs: 1
          }
        ];
      }
    ],
    [
      "source reference overflow",
      (f: any) => {
        f.report.apiMapper.endpoints = Array.from({ length: 65 }, () => ({ ...f.report.apiMapper.endpoints[0] }));
      }
    ],
    [
      "contradictory browser",
      (f: any) => {
        f.report.browserCrawl = {
          networkRequests: [{ url: f.origin + "/api/health", method: "GET", decision: "blocked", transmitted: true }]
        };
      }
    ]
  ] as const;
  for (const [label, edit] of reportCases)
    it("rejects " + label + " from exact canonical source bytes", async () => {
      const f = await fixture();
      try {
        edit(f);
        f.save();
        const candidates = planAdaptiveDiscoveryCandidates(f.report).candidates;
        const result = f.service.review(
          { scanId: f.scan, candidateId: candidates[0]?.candidateId ?? "a".repeat(64) },
          f.actorReceipt
        ).result;
        await assertNoWire(f, result);
      } finally {
        await f.close();
      }
    });
  it("wrong organization cannot authenticate by ID or owner boolean", async () => {
    const f = await fixture();
    try {
      await assertNoWire(
        f,
        f.service.review(f.select(), { organizationId: f.org, userId: f.user, owner: true }).result
      );
      const other = randomUUID(),
        stamp = new Date().toISOString();
      f.db.db
        .prepare(
          "INSERT INTO organizations(id,slug,name,status,created_by,created_at,updated_at) VALUES (?,?,'fixture','ACTIVE','FIXTURE',?,?)"
        )
        .run(other, other, stamp, stamp);
      f.db.db
        .prepare(
          "INSERT INTO organization_memberships(organization_id,user_id,role,created_by,created_at,updated_at) VALUES (?,?,'OWNER','FIXTURE',?,?)"
        )
        .run(other, f.user, stamp, stamp);
      const otherHost = {
        ...f.host,
        verifyActor: (receipt: unknown) =>
          receipt === f.actorReceipt ? { organizationId: other, userId: f.user } : undefined
      };
      await assertNoWire(f, f.create(otherHost).review(f.select(), f.actorReceipt).result);
    } finally {
      await f.close();
    }
  });
  it("hostile getters and caller reports are never evaluated", async () => {
    const f = await fixture();
    let evaluated = 0;
    try {
      const input = Object.defineProperty({}, "scanId", {
        get() {
          evaluated++;
          throw Error("private getter");
        }
      });
      await assertNoWire(f, f.service.review(input, f.actorReceipt).result);
      await assertNoWire(f, f.service.review({ ...f.select(), report: f.report }, f.actorReceipt).result);
      const cycle: any = {};
      cycle.cycle = cycle;
      await assertNoWire(f, f.service.review(cycle, f.actorReceipt).result);
      expect(evaluated).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("default OFF never grants authority without native host boundary", async () => {
    const f = await fixture();
    try {
      await assertNoWire(f, f.create(undefined).review(f.select(), f.actorReceipt).result);
    } finally {
      await f.close();
    }
  });
  it.each(["candidate identity", "ordinal inversion", "source index swap"])(
    "rejects internally rehashed forged %s",
    async (kind) => {
      const f = await fixture();
      try {
        const candidate = structuredClone(planAdaptiveDiscoveryCandidates(f.report).candidates[0]!);
        if (kind === "source index swap") candidate.sourceReferences[0]!.sourceIndex = 1;
        else {
          candidate.routeOrdinal++;
          candidate.candidateId = discoveryCandidateId({
            targetOrigin: candidate.targetOrigin,
            originRelation: candidate.originRelation,
            routeOrdinal: candidate.routeOrdinal,
            method: candidate.method
          });
        }
        await assertNoWire(f, f.service.review({ ...f.select(), candidate }, f.actorReceipt).result);
      } finally {
        await f.close();
      }
    }
  );
  it("rejects unknown effect and forged JSON operation", async () => {
    const f = await fixture();
    try {
      f.setEffect(false);
      expect(f.approve().result.code).toBe("DENIED_EFFECT_UNKNOWN");
      await assertNoWire(f, await f.service.execute({ approved: true, operation: true }));
    } finally {
      await f.close();
    }
  });
  it("operation capability is not serializable or transferable to another context", async () => {
    const f = await fixture();
    try {
      const a = f.approve();
      expect(() => JSON.stringify(a.operation)).toThrow();
      await assertNoWire(f, await f.create(f.host).execute(a.operation));
    } finally {
      await f.close();
    }
  });
  it("current duplicate and parallel replay permits at most one operation", async () => {
    const f = await fixture();
    try {
      const a = f.approve();
      const values = await Promise.all([f.service.execute(a.operation), f.service.execute(a.operation)]);
      expect(values.filter((v) => v.initiated === 1)).toHaveLength(1);
      expect(f.receipts).toBe(1);
      expect(f.initiations).toBe(1);
      expect(f.review().result.code).toBe("DENIED_DUPLICATE");
    } finally {
      await f.close();
    }
  });
  const lateCases = [
    [
      "target version",
      (f: any) => f.db.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.target)
    ],
    [
      "target scope",
      (f: any) => f.db.db.prepare("UPDATE targets SET approved_scope_json='{}' WHERE id=?").run(f.target)
    ],
    ["source deleted", (f: any) => f.db.db.prepare("UPDATE scans SET deleted_at='late' WHERE id=?").run(f.scan)],
    ["source bytes", (f: any) => writeFileSync(f.file, readFileSync(f.file, "utf8").replace("low", "med"))],
    [
      "artifact pointer",
      (f: any) => f.db.db.prepare("UPDATE scans SET json_report_artifact_id=NULL WHERE id=?").run(f.scan)
    ],
    ["revoke consent", (f: any) => f.revoke()],
    ["expire consent", (f: any) => f.setDeadline(Date.now() - 1)]
  ] as const;
  for (const [label, edit] of lateCases)
    it("final actual DNS boundary denies " + label + " changed after review", async () => {
      const f = await fixture({ dnsDelay: 300 });
      try {
        const a = f.approve();
        const pending = f.service.execute(a.operation);
        await vi.waitFor(() => expect(f.dnsEntered).toBe(true), { timeout: 2000 });
        edit(f);
        const result = await pending;
        await assertNoWire(f, result);
        retainWitness("late-dns-" + label.replaceAll(" ", "-"), {
          result,
          clientInitiations: f.initiations,
          serverReceipts: f.receipts,
          ledger: f.context.requestLedger.snapshot()
        });
      } finally {
        await f.close();
      }
    });
  it("natural DNS expiry has zero initiation and receipt", async () => {
    const f = await fixture({ dnsDelay: 400 });
    try {
      f.setDeadline(Date.now() + 150);
      await assertNoWire(f, await f.service.execute(f.approve().operation));
    } finally {
      await f.close();
    }
  });
  it("natural shared queue expiry spends no discovery SCAN reservation", async () => {
    const f = await fixture();
    let release!: () => void;
    try {
      const held = f.context.requestLedger.transmit(
        "SCAN",
        undefined,
        () =>
          new Promise<void>((r) => {
            release = r;
          })
      );
      while (!release) await pause(1);
      f.setDeadline(Date.now() + 100);
      const a = f.approve(),
        pending = f.service.execute(a.operation);
      await pause(160);
      release();
      await held;
      const r = await pending;
      expect(r.initiated).toBe(0);
      expect(f.receipts).toBe(0);
      expect(f.initiations).toBe(0);
      expect(f.context.requestLedger.snapshot()).toMatchObject({
        scanTransmitted: 1,
        cleanupRemaining: 1,
        inFlight: 0,
        queued: 0
      });
      retainWitness("late-queue-expiry", {
        result: r,
        clientInitiations: f.initiations,
        serverReceipts: f.receipts,
        ledger: f.context.requestLedger.snapshot(),
        priorScanReservation: 1
      });
    } finally {
      release?.();
      await f.close();
    }
  });
  it.each([-1, 0, 1])("exact consent deadline offset %s uses injected guard clock only", async (offset) => {
    const f = await fixture({ dnsDelay: 80 });
    try {
      const deadline = Date.now() + 60000;
      f.setDeadline(deadline);
      const pending = f.service.execute(f.approve().operation);
      await vi.waitFor(() => expect(f.dnsEntered).toBe(true), { timeout: 2000 });
      f.setClock(deadline + offset);
      const result = await pending;
      expect(result.initiated).toBe(offset < 0 ? 1 : 0);
      expect(f.receipts).toBe(offset < 0 ? 1 : 0);
    } finally {
      await f.close();
    }
  });
  it("valid in-window initiation may observe a later response", async () => {
    const f = await fixture({ responseDelay: 350 });
    try {
      f.setDeadline(Date.now() + 150);
      const result = await f.service.execute(f.approve().operation);
      expect(result.responseObserved).toBe(1);
      expect(f.receipts).toBe(1);
      expect(f.initiations).toBe(1);
    } finally {
      await f.close();
    }
  });
  it.each([302, 500])("never redirects or retries response %s", async (status) => {
    const f = await fixture({ responseStatus: status });
    try {
      await f.service.execute(f.approve().operation);
      expect(f.receipts).toBe(1);
      expect(f.initiations).toBe(1);
    } finally {
      await f.close();
    }
  });
  it("abort during actual DNS leaves no initialization and no stuck ledger", async () => {
    const f = await fixture({ dnsDelay: 200 });
    try {
      const pending = f.service.execute(f.approve().operation);
      await vi.waitFor(() => expect(f.dnsEntered).toBe(true), { timeout: 2000 });
      f.controller.abort();
      const result = await pending;
      expect(result.code).toBe("DENIED_CANCELLED");
      expect(f.receipts).toBe(0);
      expect(f.context.requestLedger.snapshot()).toMatchObject({
        inFlight: 0,
        queued: 0,
        scanTransmitted: 0,
        cleanupRemaining: 1
      });
    } finally {
      await f.close();
    }
  });
  it("registered scope intersection remains mandatory", async () => {
    const f = await fixture();
    try {
      f.db.db
        .prepare("UPDATE targets SET approved_scope_json=? WHERE id=?")
        .run(JSON.stringify({ ...f.context.options.scope, disallowedPaths: ["/api"] }), f.target);
      await assertNoWire(f, f.review().result);
    } finally {
      await f.close();
    }
  });
  it.each(["malformed", "oversize", "traversal", "symlink"])("rejects unsafe canonical artifact %s", async (kind) => {
    const f = await fixture();
    try {
      if (kind === "malformed") writeFileSync(f.file, "{invalid");
      else if (kind === "oversize") writeFileSync(f.file, " ".repeat(2097153));
      else if (kind === "traversal")
        f.db.db
          .prepare("UPDATE artifacts SET canonical_path=? WHERE id=?")
          .run(join(f.store, "..", "escape.json"), f.artifact);
      else {
        const link = join(f.store, "linked");
        const outside = join(f.root, "outside");
        mkdirSync(outside);
        writeFileSync(join(outside, "source.json"), readFileSync(f.file));
        symlinkSync(outside, link, "junction");
        f.db.db.prepare("UPDATE artifacts SET canonical_path=? WHERE id=?").run(join(link, "source.json"), f.artifact);
      }
      await assertNoWire(f, f.review().result);
    } finally {
      await f.close();
    }
  });
  it("arbitrary private host error never appears in public data", async () => {
    const f = await fixture();
    try {
      const host = {
        ...f.host,
        verifyActor: () => {
          throw Error("Bearer private-value path /private-data");
        }
      };
      const result = f.create(host).review(f.select(), f.actorReceipt).result;
      await assertNoWire(f, result);
      expect(JSON.stringify(result)).not.toContain("private");
    } finally {
      await f.close();
    }
  });
  it("reused native connection still revalidates source before feature initiation", async () => {
    const f = await fixture({ dnsDelay: 0 });
    try {
      expect((await f.peer!.send({ url: f.origin + "/warm", method: "GET", skipCache: true })).statusCode).toBe(200);
      const a = f.approve();
      const pending = f.service.execute(a.operation);
      await pause(20);
      f.revoke();
      const result = await pending;
      expect(result.initiated).toBe(0);
      expect(f.receipts).toBe(1);
      expect(f.initiations).toBe(1);
      expect(f.context.requestLedger.snapshot().cleanupRemaining).toBe(1);
    } finally {
      await f.close();
    }
  });
});
