import { describe, it, expect, vi } from "vitest";
import { fork } from "node:child_process";
import SqliteDatabase from "better-sqlite3";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, appendFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { IncomingMessage, createServer } from "node:http";
import { Socket } from "node:net";
import { stageAFixture, consentFor } from "./trusted-discovery-stage-a.fixture.js";
import { TrustedDiscoveryOperatorService } from "../../src/dashboard/execution/TrustedDiscoveryOperatorService.js";
import { TrustedDiscoveryReviewStore } from "../../src/dashboard/execution/TrustedDiscoveryReviewStore.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { BackupRestoreService } from "../../src/dashboard/operations/BackupRestoreService.js";
import { TrustedDiscoveryWitness } from "../../src/dashboard/execution/TrustedDiscoveryWitness.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { RequestSafetyBroker } from "../../src/core/http/RequestSafetyBroker.js";
import { HttpClient } from "../../src/core/http/HttpClient.js";
import type { TrustedDiscoveryFacts } from "../../src/dashboard/execution/TrustedDiscoveryBinding.js";
import type { DnsResolver } from "../../src/core/http/HttpTypes.js";
import { provisionFixtureWitness } from "./trusted-discovery-stage-b.fixture.js";
import { PinnedOriginPool } from "../../src/core/http/PinnedOriginPool.js";
import { TrustedDiscoveryPrivateRoot } from "../../src/dashboard/execution/TrustedDiscoveryPrivateRoot.js";

function observeNativeContext(resolver?: DnsResolver) {
  const contexts: ScanContext[] = [],
    original = ScanContext.prototype.createHttpClient;
  const spy = vi.spyOn(ScanContext.prototype, "createHttpClient").mockImplementation(function () {
    contexts.push(this);
    if (!resolver) return original.call(this);
    const limits = this.options.plan.limits;
    return new RequestSafetyBroker(
      {
        userAgent: this.options.scope.userAgent,
        timeoutMs: limits.requestTimeoutMs,
        rateLimitPerSecond: limits.rateLimitPerSecond,
        concurrency: limits.concurrency,
        bodyPreviewBytes: limits.bodyPreviewBytes,
        maxResponseBytes: limits.maxResponseBytes,
        retry: limits.retry,
        maxRequests: limits.maxRequests,
        abortSignal: this.options.abortSignal,
        transport: this.options.config.transport,
        dnsResolver: resolver
      },
      this.scopeMatcher,
      (entry) => this.state.recordRequestAudit(entry),
      { ledger: this.requestLedger, lane: "SCAN" }
    );
  });
  return { contexts, spy };
}

async function fixture(
  host: "127.0.0.1" | "::1" | "localhost" = "127.0.0.1",
  response?: { delay?: number; status?: number; bodyBytes?: number }
) {
  const f = await stageAFixture({ targetHost: host === "localhost" ? "127.0.0.1" : host });
  let origin = f.targetOrigin,
    initial = f.initial;
  let customWire = 0;
  const custom = response
    ? createServer((_request, reply) => {
        customWire++;
        const finish = () => {
          if (reply.destroyed) return;
          reply.statusCode = response.status ?? 200;
          if (reply.statusCode === 302) reply.setHeader("location", "/api/redirected");
          reply.end("x".repeat(response.bodyBytes ?? 10));
        };
        if (response.delay) setTimeout(finish, response.delay);
        else finish();
      })
    : undefined;
  if (custom) {
    await new Promise<void>((done) => custom.listen(0, "127.0.0.1", done));
    const address = custom.address();
    if (!address || typeof address === "string") throw Error("FIXTURE_LISTEN");
    origin = `http://127.0.0.1:${address.port}`;
  }
  if (host === "localhost") origin = origin.replace("127.0.0.1", "localhost");
  if (origin !== f.targetOrigin) {
    const scope = { ...f.scope, allowedDomains: [new URL(origin).hostname] };
    f.db.db
      .prepare("UPDATE targets SET base_origin=?,approved_scope_json=? WHERE id=?")
      .run(origin, JSON.stringify(scope), f.target);
    f.db.db.prepare("UPDATE scans SET target_origin=? WHERE id=?").run(origin, f.initial.scanId);
    const bytes = f.initial.bytes.replaceAll(f.targetOrigin, origin);
    writeFileSync(f.initial.file, bytes);
    const report = JSON.parse(bytes);
    const { planAdaptiveDiscoveryCandidates } =
      await import("../../src/dashboard/execution/AdaptiveDiscoveryCandidatePlanner.js");
    initial = {
      ...initial,
      bytes,
      report,
      candidateId: planAdaptiveDiscoveryCandidates(report).candidates[0]!.candidateId
    };
  }
  const witnessRoot = mkdtempSync(join(tmpdir(), "rcb-witness-"));
  const store = new TrustedDiscoveryReviewStore(f.db, join(f.root, "keys", "trusted-discovery-review.key"));
  const module = await import("../../src/dashboard/execution/TrustedDiscoveryWitness.js");
  const witness = provisionFixtureWitness(f.db, store, witnessRoot, origin);
  const service = new TrustedDiscoveryOperatorService(f.db, resolveDashboardPaths(f.root), f.sessions, witness);
  function authority(identity = f.auth) {
    const request = new IncomingMessage(new Socket());
    request.headers = {
      cookie: identity.cookie,
      origin: f.security.publicOrigin,
      "x-forwarded-proto": "https",
      "content-type": "application/json"
    };
    return f.sessions.captureTrustedDiscoverySession(request, identity.csrf);
  }
  const review = () => service.review({ scanId: initial.scanId, candidateId: initial.candidateId }, authority(), f.org);
  async function close() {
    await service.shutdown();
    store.dispose();
    witness.close();
    const evidence = process.env.ROUTECAIRN_STAGE_B_WIRE_EVIDENCE;
    if (evidence)
      appendFileSync(
        evidence,
        JSON.stringify({
          fixture: witnessRoot.split(/[\\/]/).at(-1),
          wireReceipts: f.wire() + customWire,
          externalTargetsTested: false
        }) + "\n"
      );
    if (custom) {
      custom.closeAllConnections();
      await new Promise<void>((done) => custom.close(() => done()));
    }
    await f.close();
    // Both roots were freshly generated in this fixture, never owner data.
    if (!witnessRoot.startsWith(join(tmpdir(), "rcb-witness-"))) throw Error("FIXTURE_SCOPE");
    rmSync(witnessRoot, { recursive: true, force: true });
  }
  return {
    ...f,
    initial,
    targetOrigin: origin,
    witnessRoot,
    store,
    witness,
    service,
    authority,
    review,
    close,
    wire: () => f.wire() + customWire
  };
}

describe("NG5B2 Stage B native owned fixture only, public execution absent", () => {
  it("S-B08 product witness provisioning is absent so rollback cannot choose a new anchor", () => {
    expect(Object.hasOwn(TrustedDiscoveryWitness, "provisionFixture")).toBe(false);
  });
  it("S-B04 localhost resolving outside loopback is denied BEFORE pool acquisition", async () => {
    const f = await fixture("localhost");
    const context = observeNativeContext(async () => [{ address: "8.8.8.8", family: 4 }]);
    let externalPools = 0;
    const original = PinnedOriginPool.prototype.acquire;
    const spy = vi.spyOn(PinnedOriginPool.prototype, "acquire").mockImplementation(function (pin) {
      if (!["127.0.0.1", "::1"].includes(pin.address.address)) {
        externalPools++;
        throw Error("FALSIFICATION_STOP_BEFORE_ANY_SOCKET");
      }
      return original.call(this, pin);
    });
    try {
      const { review } = await f.review();
      const result = await f.service.executeFresh(consentFor(review), f.authority(), f.org);
      expect(result.initiated).toBe(0);
      expect(f.wire()).toBe(0);
      expect(externalPools).toBe(0);
    } finally {
      spy.mockRestore();
      context.spy.mockRestore();
      await f.close();
    }
  });
  it("S-B01 public execute remains404 and disabled service cannot execute", async () => {
    const f = await stageAFixture();
    const service = new TrustedDiscoveryOperatorService(f.db, resolveDashboardPaths(f.root), f.sessions);
    try {
      expect((await f.post("/api/trusted-discovery/execute", {})).status).toBe(404);
      expect(await service.executeFresh({}, {}, f.org)).toMatchObject({ code: "DISABLED", attempted: 0, initiated: 0 });
      expect(existsSync(join(f.root, "trusted-discovery-witness"))).toBe(false);
      expect(f.wire()).toBe(0);
    } finally {
      await service.shutdown();
      await f.close();
    }
  });
  it.each(["127.0.0.1", "::1", "localhost"] as const)(
    "S-B03 exact %s fixture records one realGET and no body",
    async (host) => {
      const f = await fixture(host);
      try {
        const reviewed = await f.review();
        const result = await f.service.executeFresh(consentFor(reviewed.review), f.authority(), f.org);
        expect(result).toMatchObject({
          code: "RESPONSE_OBSERVED",
          attempted: 1,
          initiated: 1,
          responseObserved: 1,
          assessment: "NOT_ASSESSED"
        });
        expect(f.wire()).toBe(1);
        expect(readdirSync(join(f.root, "trusted-discovery-private"))).toEqual([]);
        expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 1 });
        expect(JSON.stringify(result)).not.toContain(f.targetOrigin);
        expect(JSON.stringify(result)).not.toContain("owned disposable loopback");
        const replay = await f.service.executeFresh(consentFor(reviewed.review), f.authority(), f.org);
        expect(replay.initiated).toBe(0);
        expect(f.wire()).toBe(1);
      } finally {
        await f.close();
      }
    }
  );
  it.each(["confirmation", "digest", "session", "org", "forged"])("S-B02/B04 %s cannot authorize", async (kind) => {
    const f = await fixture();
    try {
      const { review } = await f.review();
      const input = {
        ...consentFor(review),
        ...(kind === "confirmation" ? { confirmation: "yes" } : {}),
        ...(kind === "digest" ? { reviewDigest: "0".repeat(64) } : {})
      };
      const other = kind === "session" ? await f.login() : f.auth;
      const result = await f.service.executeFresh(
        input,
        kind === "forged" ? {} : f.authority(other),
        kind === "org" ? f.otherOrg : f.org
      );
      expect(result.initiated).toBe(0);
      expect(result.attempted).toBe(0);
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it.each(["revoke", "role", "lock", "password", "membership", "artifact", "lease", "target"])(
    "S-B05 freshness %s denies before debit",
    async (kind) => {
      const f = await fixture();
      try {
        const { review } = await f.review();
        const authority = f.authority();
        if (kind === "revoke") f.sessions.revokeUserSessions(f.owner);
        if (kind === "role") f.db.db.prepare("UPDATE dashboard_users SET role='VIEWER' WHERE id=?").run(f.owner);
        if (kind === "lock")
          f.db.db
            .prepare("UPDATE dashboard_users SET locked_until=? WHERE id=?")
            .run(new Date(Date.now() + 10000).toISOString(), f.owner);
        if (kind === "password")
          f.db.db
            .prepare("UPDATE dashboard_users SET password_changed_at=? WHERE id=?")
            .run(new Date(Date.now() + 1).toISOString(), f.owner);
        if (kind === "membership")
          f.db.db.prepare("UPDATE organization_memberships SET role='VIEWER' WHERE user_id=?").run(f.owner);
        if (kind === "artifact") writeFileSync(f.initial.file, f.initial.bytes + " ");
        if (kind === "lease")
          f.db.db.prepare("UPDATE scan_job_leases SET release_category='CHANGED' WHERE job_id=?").run(f.initial.scanId);
        if (kind === "target")
          f.db.db.prepare("UPDATE targets SET authorization_summary='changed' WHERE id=?").run(f.target);
        const result = await f.service.executeFresh(consentFor(review), authority, f.org);
        expect(result.attempted).toBe(0);
        expect(f.wire()).toBe(0);
      } finally {
        await f.close();
      }
    }
  );
  it("S-B04 StageA historical preconsent and restart cannot resurrect permission", async () => {
    const f = await fixture();
    try {
      const { review } = await f.review();
      await f.service.preconsent(consentFor(review), f.authority(), f.org);
      expect((await f.service.executeFresh(consentFor(review), f.authority(), f.org)).attempted).toBe(0);
      const module = await import("../../src/dashboard/execution/TrustedDiscoveryWitness.js");
      const newWitness = module.TrustedDiscoveryWitness.openFixture(f.db, f.store, f.witnessRoot, f.targetOrigin);
      const restarted = new TrustedDiscoveryOperatorService(
        f.db,
        resolveDashboardPaths(f.root),
        f.sessions,
        newWitness
      );
      try {
        expect((await restarted.executeFresh(consentFor(review), f.authority(), f.org)).initiated).toBe(0);
      } finally {
        await restarted.shutdown();
      }
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("S-B08 actual older staged backup restore loses DB attempt but independent witness blocks", async () => {
    const f = await fixture();
    let reopened: DashboardDatabase | undefined;
    try {
      const paths = resolveDashboardPaths(f.root);
      const backups = new BackupRestoreService(f.db, paths, undefined);
      const older = await backups.create(false, "owned-fixture");
      const { review } = await f.review();
      expect((await f.service.executeFresh(consentFor(review), f.authority(), f.org)).initiated).toBe(1);
      backups.stageRestore(older);
      await f.service.shutdown();
      await f.stop();
      f.db.close();
      expect(BackupRestoreService.applyStagedRestore(paths, undefined)).toBe(true);
      reopened = new DashboardDatabase(paths.databasePath);
      reopened.migrate();
      expect(reopened.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 0 });
      const restoredStore = new TrustedDiscoveryReviewStore(
        reopened,
        join(f.root, "keys", "trusted-discovery-review.key")
      );
      const module = await import("../../src/dashboard/execution/TrustedDiscoveryWitness.js");
      try {
        expect(() =>
          module.TrustedDiscoveryWitness.openFixture(reopened!, restoredStore, f.witnessRoot, f.targetOrigin)
        ).toThrow(/WITNESS/);
      } finally {
        restoredStore.dispose();
      }
      expect(f.wire()).toBe(1);
    } finally {
      reopened?.close();
      await f.close();
    }
  });
  it.each(["key", "missing-key", "missing-namespace", "witness"])("S-B07 corrupt %s fails closed", async (kind) => {
    const f = await fixture();
    try {
      if (kind === "key") writeFileSync(join(f.witnessRoot, "witness.key"), "0".repeat(64));
      if (kind === "missing-key") rmSync(join(f.witnessRoot, "witness.key"));
      if (kind === "missing-namespace")
        f.db.db.prepare("DELETE FROM dashboard_meta WHERE key='trusted_discovery_stage_b_witness_v1'").run();
      if (kind === "witness") writeFileSync(join(f.witnessRoot, "witness.sqlite"), "corrupt");
      await expect(f.review()).rejects.toThrow();
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("S-B08 full-disk rollback profile is refused without an external monotonic anchor", async () => {
    const f = await fixture();
    try {
      expect(f.witness.protection).toBe("DB_AND_DATA_DIRECTORY_ROLLBACK_ONLY");
      expect(() => f.witness.requireProtection("ALL_DISKS_ROLLBACK")).toThrow(/EXTERNAL_ANCHOR_REQUIRED/);
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("S-B09 isolated generated context root cannot touch shared journal", async () => {
    const f = await fixture();
    try {
      const shared = join(resolveDashboardPaths(f.root).mutationJournalDir, "owner-sentinel.txt");
      writeFileSync(shared, "owner-existing");
      const { review } = await f.review();
      expect((await f.service.executeFresh(consentFor(review), f.authority(), f.org)).initiated).toBe(1);
      expect(readFileSync(shared, "utf8")).toBe("owner-existing");
    } finally {
      await f.close();
    }
  });
  it("S-B06/B13 TWO independent processes observe at most one actual fixtureGET", async () => {
    const f = await fixture();
    const children: ReturnType<typeof fork>[] = [];
    try {
      const input = {
        root: f.root,
        witnessRoot: f.witnessRoot,
        origin: f.targetOrigin,
        organization: f.org,
        scanId: f.initial.scanId,
        candidateId: f.initial.candidateId,
        security: f.security,
        cookie: f.auth.cookie,
        csrf: f.auth.csrf
      };
      const launch = () => {
        const child = fork(join(process.cwd(), "tests/dashboard/trusted-discovery-stage-b.worker.ts"), [], {
          execArgv: ["--import", "tsx"],
          silent: true,
          windowsHide: true
        });
        children.push(child);
        let ready: () => void, readyFail: (error: Error) => void;
        const readiness = new Promise<void>((done, fail) => {
          ready = done;
          readyFail = fail;
        });
        let result: TrustedDiscoveryFacts | undefined;
        let failure = "FIXTURE_PROCESS_FAILED";
        const completion = new Promise<TrustedDiscoveryFacts>((done, fail) => {
          child.on("message", (message: { ready?: boolean; result?: TrustedDiscoveryFacts; failure?: string }) => {
            if (message.ready) ready();
            if (message.result) result = message.result;
            if (message.failure) failure = message.failure;
          });
          child.once("error", (error) => {
            readyFail(error);
            fail(error);
          });
          child.once("exit", (code) => {
            if (code === 0 && result) done(result);
            else {
              const error = Error(failure);
              readyFail(error);
              fail(error);
            }
          });
        });
        // Observe early startup rejection; readiness still rejects the test and
        // the exact result is awaited below. No process failure becomes success.
        void completion.catch(() => undefined);
        child.send(input);
        return { child, readiness, completion };
      };
      const a = launch();
      await a.readiness;
      const b = launch();
      await b.readiness;
      a.child.send("CONFIRMED");
      b.child.send("CONFIRMED");
      const results = await Promise.all([a.completion, b.completion]);
      expect(a.child.pid).not.toBe(b.child.pid);
      expect(results.reduce((n, value) => n + value.initiated, 0)).toBe(1);
      expect(f.wire()).toBe(1);
      expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 1 });
      f.witness.assertConsistent(f.db, f.store);
    } finally {
      for (const child of children) if (child.exitCode === null) child.kill();
      await f.close();
    }
  }, 30000);
  it("S-B07 partial witness commit before DB rollback is permanently blocked", async () => {
    const f = await fixture();
    try {
      const { review } = await f.review();
      await f.service.preconsent(consentFor(review), f.authority(), f.org);
      const row = f.db.db.prepare("SELECT id FROM trusted_discovery_reviews").get() as { id: string };
      expect(() =>
        f.db.db
          .transaction(() => {
            f.witness.spend(f.db, f.store, f.store.attemptDescriptor(row.id));
            throw Error("SIMULATED_PROCESS_CRASH_BEFORE_MAIN_COMMIT");
          })
          .immediate()
      ).toThrow(/SIMULATED/);
      expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 0 });
      expect(() => f.witness.assertConsistent(f.db, f.store)).toThrow(/WITNESS/);
      expect(() => TrustedDiscoveryWitness.openFixture(f.db, f.store, f.witnessRoot, f.targetOrigin)).toThrow(
        /WITNESS/
      );
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("S-B07 bounded busy DB never falls back to ephemeral permission", async () => {
    const f = await fixture();
    const other = new DashboardDatabase(f.dbPath);
    try {
      const { review } = await f.review(),
        authority = f.authority();
      other.db.exec("BEGIN IMMEDIATE");
      const begin = performance.now();
      const result = await f.service.executeFresh(consentFor(review), authority, f.org);
      expect(performance.now() - begin).toBeLessThan(1000);
      expect(result.initiated).toBe(0);
      expect(f.wire()).toBe(0);
    } finally {
      other.db.exec("ROLLBACK");
      other.close();
      await f.close();
    }
  });
  it("S-B08 copiedDB binding and attempted namespace reprovision are denied", async () => {
    const f = await fixture();
    let copied: DashboardDatabase | undefined;
    try {
      await f.db.db.backup(join(f.root, "copy.sqlite"));
      copied = new DashboardDatabase(join(f.root, "copy.sqlite"));
      expect(() => f.witness.assertConsistent(copied!, f.store)).toThrow(/WITNESS/);
      expect(() => provisionFixtureWitness(f.db, f.store, f.witnessRoot, f.targetOrigin)).toThrow(/WITNESS/);
      expect(f.wire()).toBe(0);
    } finally {
      copied?.close();
      await f.close();
    }
  });
  it("S-B09 spent socket failure cannot become retry; immutable audit retained", async () => {
    const f = await fixture();
    try {
      const { review } = await f.review();
      // A native send observer records an actual returned transport error. It
      // never manufactures initiation or a server receipt.
      const original = HttpClient.prototype.send;
      let errors = 0;
      const spy = vi.spyOn(HttpClient.prototype, "send").mockImplementation(async function (...args) {
        const response = await original.apply(this, args);
        if (response.error) errors++;
        return response;
      });
      // Destroying the real pool before dispatch is an uninitiated connection
      // failure; a permanent witness must still prohibit another workflow.
      const contexts: ScanContext[] = [];
      const contextOriginal = ScanContext.prototype.createHttpClient;
      const contextSpy = vi.spyOn(ScanContext.prototype, "createHttpClient").mockImplementation(function () {
        contexts.push(this);
        return contextOriginal.call(this);
      });
      const nextSource = f.source("/api/status");
      const selector = { scanId: nextSource.scanId, candidateId: nextSource.candidateId };
      const next = await f.service.review(selector, f.authority(), f.org);
      await contexts[0]!.httpClient.close();
      // ScanContext uses its own native shared pool; dispose it to close the
      // physical pool, without replacing transport with a simulated success.
      await contexts[0]!.dispose();
      const result = await f.service.executeFresh(consentFor(next.review), f.authority(), f.org);
      expect(result).toMatchObject({ attempted: 1, initiated: 0, status: "ATTEMPTED_NO_WIRE" });
      expect(errors).toBe(1);
      expect(f.wire()).toBe(0);
      await expect(f.service.review(selector, f.authority(), f.org)).rejects.toThrow();
      spy.mockRestore();
      contextSpy.mockRestore();
      // The unrelated first review is still fresh but cannot reuse a disposed
      // operation or reinterpret the failed request as a successful response.
      expect(review.method).toBe("GET");
    } finally {
      vi.restoreAllMocks();
      await f.close();
    }
  });
  it("S-B10 hostile getter/proxy does not evaluate; missing native witness cannot mint", async () => {
    const f = await fixture();
    try {
      let calls = 0;
      const getter = {
        get reviewId() {
          calls++;
          return "fake";
        }
      };
      const proxy = new Proxy(
        {},
        {
          getPrototypeOf() {
            calls++;
            throw Error("HOSTILE");
          }
        }
      );
      expect((await f.service.executeFresh(getter, f.authority(), f.org)).initiated).toBe(0);
      expect((await f.service.executeFresh(proxy, f.authority(), f.org)).initiated).toBe(0);
      expect(calls).toBe(0);
      expect(TrustedDiscoveryWitness.isNative({ protection: f.witness.protection })).toBe(false);
      expect(() =>
        Reflect.apply(TrustedDiscoveryWitness.openFixture, TrustedDiscoveryWitness, [
          proxy,
          {},
          "unused",
          f.targetOrigin
        ])
      ).toThrow(/WITNESS/);
      expect(calls).toBe(0);
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("S-B11 retained witness outcome is immutable, bounded and secret-free", async () => {
    const f = await fixture();
    try {
      const { review } = await f.review();
      await f.service.executeFresh(consentFor(review), f.authority(), f.org);
      const witnessDB = new SqliteDatabase(join(f.witnessRoot, "witness.sqlite"));
      try {
        expect(witnessDB.prepare("SELECT initiated,observed FROM outcomes").get()).toEqual({
          initiated: 1,
          observed: 1
        });
        expect(() => witnessDB.exec("DELETE FROM attempts")).toThrow(/IMMUTABLE/);
        expect(() => witnessDB.exec("UPDATE outcomes SET initiated=0")).toThrow(/IMMUTABLE/);
        const text = JSON.stringify(witnessDB.prepare("SELECT * FROM attempts").all());
        expect(text).not.toContain(f.targetOrigin);
        expect(text).not.toContain(f.auth.cookie);
      } finally {
        witnessDB.close();
      }
    } finally {
      await f.close();
    }
  });
  it.each([302, 500])("S-B03 real response%s is observed once without retry or redirect", async (status) => {
    const f = await fixture("127.0.0.1", { status });
    try {
      const { review } = await f.review();
      const result = await f.service.executeFresh(consentFor(review), f.authority(), f.org);
      expect(result).toMatchObject({ initiated: 1, responseObserved: 1, assessment: "NOT_ASSESSED" });
      expect(f.wire()).toBe(1);
    } finally {
      await f.close();
    }
  });
  it("S-B03 native stream ceiling stays4096 with no body retained", async () => {
    const f = await fixture("127.0.0.1", { bodyBytes: 64000 });
    const original = HttpClient.prototype.send;
    let bytes = 0,
      body = false;
    const spy = vi.spyOn(HttpClient.prototype, "send").mockImplementation(async function (...args) {
      const response = await original.apply(this, args);
      bytes = response.bytesRead ?? 0;
      body = response.bodyPreview !== undefined;
      return response;
    });
    try {
      const { review } = await f.review();
      const result = await f.service.executeFresh(consentFor(review), f.authority(), f.org);
      expect(result.initiated).toBe(1);
      expect(f.wire()).toBe(1);
      expect(bytes).toBeLessThanOrEqual(4096);
      expect(body).toBe(false);
    } finally {
      spy.mockRestore();
      await f.close();
    }
  });
  it.each(["session", "artifact", "lease"])(
    "S-B05 actual asynchronous DNS wait rechecks%s before wire",
    async (kind) => {
      const f = await fixture("localhost");
      let entered = false,
        release!: () => void;
      const gate = new Promise<void>((done) => {
        release = done;
      });
      const observed = observeNativeContext(async () => {
        entered = true;
        await gate;
        return [{ address: "127.0.0.1", family: 4 }];
      });
      try {
        const { review } = await f.review();
        const pending = f.service.executeFresh(consentFor(review), f.authority(), f.org);
        await vi.waitFor(() => expect(entered).toBe(true));
        if (kind === "session") f.sessions.revokeUserSessions(f.owner);
        if (kind === "artifact") writeFileSync(f.initial.file, f.initial.bytes + " ");
        if (kind === "lease")
          f.db.db.prepare("UPDATE scan_job_leases SET release_category='CHANGED' WHERE job_id=?").run(f.initial.scanId);
        release();
        const result = await pending;
        expect(result).toMatchObject({ attempted: 1, initiated: 0, responseObserved: 0, status: "ATTEMPTED_NO_WIRE" });
        expect(f.wire()).toBe(0);
        expect(observed.contexts[0]!.requestLedger.snapshot().scanTransmitted).toBe(0);
      } finally {
        release();
        observed.spy.mockRestore();
        await f.close();
      }
    }
  );
  it("S-B05 actual original SCAN ledger queue wait rechecks revoked owner", async () => {
    const f = await fixture();
    const observed = observeNativeContext();
    let release!: () => void;
    const gate = new Promise<void>((done) => {
      release = done;
    });
    try {
      const { review } = await f.review(),
        context = observed.contexts[0]!;
      const occupied = context.requestLedger.transmit(
        "SCAN",
        undefined,
        async () => {
          await gate;
          return true;
        },
        { reserveAtInitiation: true }
      );
      await vi.waitFor(() => expect(context.requestLedger.snapshot().inFlight).toBe(1));
      const pending = f.service.executeFresh(consentFor(review), f.authority(), f.org);
      await vi.waitFor(() => expect(context.requestLedger.snapshot().queued).toBe(1));
      f.sessions.revokeUserSessions(f.owner);
      release();
      await occupied;
      expect((await pending).initiated).toBe(0);
      expect(f.wire()).toBe(0);
    } finally {
      release();
      observed.spy.mockRestore();
      await f.close();
    }
  });
  it("S-B05 exact synchronous onRequestStart mutation is denied after durable spend", async () => {
    const f = await fixture();
    const original = HttpClient.prototype.send;
    const spy = vi.spyOn(HttpClient.prototype, "send").mockImplementation(function (request, url, redirects, control) {
      return original.call(
        this,
        request,
        url,
        redirects,
        control
          ? {
              ...control,
              begin: () => {
                f.sessions.revokeUserSessions(f.owner);
                control.begin();
              }
            }
          : undefined
      );
    });
    try {
      const { review } = await f.review();
      const result = await f.service.executeFresh(consentFor(review), f.authority(), f.org);
      expect(result).toMatchObject({ attempted: 1, initiated: 0, status: "ATTEMPTED_NO_WIRE" });
      expect(f.wire()).toBe(0);
    } finally {
      spy.mockRestore();
      await f.close();
    }
  });
  it("S-B04 expired60second review and native session cannot dispatch", async () => {
    const f = await fixture();
    try {
      const { review } = await f.review(),
        authority = f.authority();
      const now = Date.now(),
        clock = vi.spyOn(Date, "now").mockReturnValue(now + 60001);
      try {
        expect((await f.service.executeFresh(consentFor(review), authority, f.org)).attempted).toBe(0);
      } finally {
        clock.mockRestore();
      }
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("S-B09 shutdown aborts during DNS, permanently spends attempt and removes private root", async () => {
    const f = await fixture("localhost");
    let entered = false,
      release!: () => void;
    const gate = new Promise<void>((done) => {
      release = done;
    });
    const observed = observeNativeContext(async () => {
      entered = true;
      await gate;
      return [{ address: "127.0.0.1", family: 4 }];
    });
    try {
      const { review } = await f.review();
      const pending = f.service.executeFresh(consentFor(review), f.authority(), f.org);
      await vi.waitFor(() => expect(entered).toBe(true));
      const stopped = f.service.shutdown();
      release();
      expect((await pending).initiated).toBe(0);
      await stopped;
      expect(f.wire()).toBe(0);
      expect(readdirSync(join(f.root, "trusted-discovery-private"))).toEqual([]);
      expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 1 });
    } finally {
      release();
      observed.spy.mockRestore();
      await f.close();
    }
  });
  it("S-B09 concurrent exact execute consumes one native operation and sees one late response", async () => {
    const f = await fixture("127.0.0.1", { delay: 300 });
    try {
      const { review } = await f.review();
      const results = await Promise.all([
        f.service.executeFresh(consentFor(review), f.authority(), f.org),
        f.service.executeFresh(consentFor(review), f.authority(), f.org)
      ]);
      expect(results.reduce((n, value) => n + value.initiated, 0)).toBe(1);
      expect(f.wire()).toBe(1);
    } finally {
      await f.close();
    }
  });
  it("S-B07 actual process death after witness commit cannot revive authority", async () => {
    const f = await fixture();
    const child = fork(join(process.cwd(), "tests/dashboard/trusted-discovery-stage-b.worker.ts"), [], {
      execArgv: ["--import", "tsx"],
      silent: true,
      windowsHide: true
    });
    try {
      const exited = new Promise<number | null>((done, fail) => {
        child.once("exit", done);
        child.once("error", fail);
      });
      child.on("message", (message: { ready?: boolean }) => {
        if (message.ready) child.send("CONFIRMED");
      });
      child.send({
        root: f.root,
        witnessRoot: f.witnessRoot,
        origin: f.targetOrigin,
        organization: f.org,
        scanId: f.initial.scanId,
        candidateId: f.initial.candidateId,
        security: f.security,
        cookie: f.auth.cookie,
        csrf: f.auth.csrf,
        crashAfterWitness: true
      });
      expect(await exited).toBe(86);
      expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 0 });
      expect(() => TrustedDiscoveryWitness.openFixture(f.db, f.store, f.witnessRoot, f.targetOrigin)).toThrow(
        /WITNESS/
      );
      expect(f.wire()).toBe(0);
    } finally {
      if (child.exitCode === null) child.kill();
      await f.close();
    }
  });
  it.each(["missing", "rotated", "namespace"])(
    "S-B07 original protected reviewkey%s is rechecked after DNS",
    async (kind) => {
      const f = await fixture("localhost");
      let entered = false,
        release!: () => void;
      const gate = new Promise<void>((done) => {
        release = done;
      });
      const observed = observeNativeContext(async () => {
        entered = true;
        await gate;
        return [{ address: "127.0.0.1", family: 4 }];
      });
      const keyPath = join(f.root, "keys", "trusted-discovery-review.key");
      const saved = readFileSync(keyPath);
      try {
        const { review } = await f.review();
        const pending = f.service.executeFresh(consentFor(review), f.authority(), f.org);
        await vi.waitFor(() => expect(entered).toBe(true));
        if (kind === "missing") rmSync(keyPath);
        if (kind === "rotated") writeFileSync(keyPath, "0".repeat(64));
        if (kind === "namespace")
          f.db.db.prepare("DELETE FROM dashboard_meta WHERE key='trusted_discovery_namespace_v1'").run();
        release();
        expect((await pending).initiated).toBe(0);
        expect(f.wire()).toBe(0);
      } finally {
        release();
        writeFileSync(keyPath, saved, { mode: 0o600 });
        observed.spy.mockRestore();
        await f.close();
      }
    }
  );
  it("S-B08 current actual backup remains compatible with authenticated witness", async () => {
    const f = await fixture();
    let reopened: DashboardDatabase | undefined;
    try {
      const { review } = await f.review();
      await f.service.executeFresh(consentFor(review), f.authority(), f.org);
      const paths = resolveDashboardPaths(f.root),
        backups = new BackupRestoreService(f.db, paths, undefined);
      const current = await backups.create(false, "owned-fixture");
      backups.stageRestore(current);
      await f.service.shutdown();
      await f.stop();
      f.db.close();
      expect(BackupRestoreService.applyStagedRestore(paths, undefined)).toBe(true);
      reopened = new DashboardDatabase(paths.databasePath);
      reopened.migrate();
      const store = new TrustedDiscoveryReviewStore(reopened, join(f.root, "keys", "trusted-discovery-review.key"));
      try {
        const witness = TrustedDiscoveryWitness.openFixture(reopened, store, f.witnessRoot, f.targetOrigin);
        witness.assertConsistent(reopened, store);
        witness.close();
      } finally {
        store.dispose();
      }
      expect(f.wire()).toBe(1);
    } finally {
      reopened?.close();
      await f.close();
    }
  });
  it.each(["routeLabel", "targetId", "scanId", "candidateId", "expiresAt", "effect", "method", "extra"])(
    "S-B04 exact selection mismatch%s cannot acquire permission",
    async (field) => {
      const f = await fixture();
      try {
        const { review } = await f.review();
        const input = {
          ...consentFor(review),
          [field]:
            field === "routeLabel"
              ? "/api/different"
              : field === "expiresAt"
                ? new Date(Date.now() + 5000).toISOString()
                : "forged"
        };
        expect((await f.service.executeFresh(input, f.authority(), f.org)).attempted).toBe(0);
        expect(f.wire()).toBe(0);
      } finally {
        await f.close();
      }
    }
  );
  it("S-B08 root inside ordinary dataDir cannot masquerade as independent custody", async () => {
    const f = await fixture();
    try {
      expect(() => TrustedDiscoveryWitness.openFixture(f.db, f.store, f.root, f.targetOrigin)).toThrow(/WITNESS/);
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("S-B08 partial signed witness update cannot be interpreted as a clean empty ledger", async () => {
    const f = await fixture();
    try {
      const { review } = await f.review();
      await f.service.executeFresh(consentFor(review), f.authority(), f.org);
      const witnessDB = new SqliteDatabase(join(f.witnessRoot, "witness.sqlite"));
      try {
        witnessDB.exec("DROP TRIGGER witness_no_update; UPDATE attempts SET seal='partial'");
      } finally {
        witnessDB.close();
      }
      expect(() => TrustedDiscoveryWitness.openFixture(f.db, f.store, f.witnessRoot, f.targetOrigin)).toThrow(
        /WITNESS/
      );
      expect(f.wire()).toBe(1);
    } finally {
      await f.close();
    }
  });
  it("S-B09 cleanup failure preserves real counters and blocks fresh authority", async () => {
    const f = await fixture();
    const original = TrustedDiscoveryPrivateRoot.prototype.dispose;
    const roots: TrustedDiscoveryPrivateRoot[] = [];
    const spy = vi.spyOn(TrustedDiscoveryPrivateRoot.prototype, "dispose").mockImplementation(function () {
      roots.push(this);
      throw Error("OWNED_FIXTURE_CLEANUP_FAILURE");
    });
    try {
      const { review } = await f.review();
      const result = await f.service.executeFresh(consentFor(review), f.authority(), f.org);
      expect(result).toMatchObject({
        initiated: 1,
        responseObserved: 1,
        cleanup: "FAILED",
        status: "INITIATED_INCONCLUSIVE"
      });
      expect(f.wire()).toBe(1);
      await expect(f.review()).rejects.toThrow();
      await expect(f.service.shutdown()).rejects.toThrow(/DISPOSAL_FAILED/);
    } finally {
      spy.mockRestore();
      for (const root of roots) original.call(root);
      await f.close();
    }
  });
  it("S-B10 shutdown deadline covers pending disposal as well as transport", async () => {
    const f = await fixture();
    let release!: () => void;
    const gate = new Promise<void>((done) => {
      release = done;
    });
    const original = ScanContext.prototype.dispose;
    const spy = vi.spyOn(ScanContext.prototype, "dispose").mockImplementation(async function () {
      await gate;
      await original.call(this);
    });
    let outcome: Promise<string> | undefined;
    try {
      await f.review();
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      outcome = f.service.shutdown().then(
        () => "RESOLVED",
        (error) => (error instanceof Error ? error.message : "FAILED")
      );
      await vi.advanceTimersByTimeAsync(6001);
      expect(await Promise.race([outcome, Promise.resolve("PENDING")])).toBe("TRUSTED_DISCOVERY_SHUTDOWN_TIMEOUT");
      expect(f.wire()).toBe(0);
    } finally {
      release();
      vi.useRealTimers();
      await outcome;
      spy.mockRestore();
      await f.close();
    }
  });
});
