import { randomUUID } from "node:crypto";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { ProjectRepository, TargetRepository, ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { dashboardMigrations } from "../../src/dashboard/db/Migrations.js";
import { describe, it, expect } from "vitest";
import { Worker } from "node:worker_threads";
import { join } from "node:path";
import { writeFileSync, readFileSync, unlinkSync } from "node:fs";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { stageAFixture, consentFor } from "./trusted-discovery-stage-a.fixture.js";

async function seed() {
  const f = await stageAFixture({ preview: true });
  try {
    const response = await f.post("/api/trusted-discovery/review", {
      scanId: f.initial.scanId,
      candidateId: f.initial.candidateId,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as any;
    expect((await f.post("/api/trusted-discovery/pre-consent", consentFor(body.review))).status).toBe(200);
    return f;
  } catch (error) {
    await f.close();
    throw error;
  }
}
async function store(f: Awaited<ReturnType<typeof seed>>) {
  const { TrustedDiscoveryReviewStore } = await import("../../src/dashboard/execution/TrustedDiscoveryReviewStore.js");
  return new TrustedDiscoveryReviewStore(f.db, join(f.root, "keys", "trusted-discovery-review.key"));
}
function workerReservation(path: string, id: string, start: SharedArrayBuffer) {
  return new Promise<string>((done, fail) => {
    let outcome: string | undefined;
    const worker = new Worker(
      `require('tsx/cjs');const {parentPort,workerData}=require('node:worker_threads');const {DashboardDatabase}=require(workerData.databaseModule);const {TrustedDiscoveryReviewStore}=require(workerData.storeModule);const db=new DashboardDatabase(workerData.path);const store=new TrustedDiscoveryReviewStore(db,workerData.keyPath);parentPort.postMessage('READY');const ready=Atomics.wait(new Int32Array(workerData.start),0,0,5000);try{if(ready==='timed-out')throw Error('BARRIER_TIMEOUT');parentPort.postMessage(store.reserveFutureAttempt(workerData.id)?'RESERVED':'DENIED');}finally{store.dispose();db.close();}`,
      {
        eval: true,
        workerData: {
          path,
          id,
          start,
          keyPath: join(path, "..", "keys", "trusted-discovery-review.key"),
          databaseModule: join(process.cwd(), "src", "dashboard", "db", "DashboardDatabase.ts"),
          storeModule: join(process.cwd(), "src", "dashboard", "execution", "TrustedDiscoveryReviewStore.ts"),
        },
      },
    );
    worker.on("message", (value) => {
      if (value === "READY") {
        Atomics.add(new Int32Array(start), 1, 1);
        if (Atomics.load(new Int32Array(start), 1) === 2) {
          Atomics.store(new Int32Array(start), 0, 1);
          Atomics.notify(new Int32Array(start), 0);
        }
      } else outcome = value;
    });
    worker.on("error", fail);
    worker.on("exit", (code) => {
      if (code === 0 && outcome) done(outcome);
      else fail(Error("RESERVATION_WORKER_FAILED"));
    });
  });
}
describe("NG5B2 Stage A durable pure-DB foundation (never transport)", () => {
  it("S09 real schema44 upgrades additively to45 and reopens with retained resources", async () => {
    const f = await stageAFixture();
    let legacy = new DashboardDatabase(join(f.root, "legacy44.sqlite"));
    try {
      legacy.db.exec("CREATE TABLE dashboard_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL)");
      for (const migration of dashboardMigrations.filter((value) => value.version <= 44)) {
        if (migration.requiresForeignKeysDisabled) {
          legacy.db.pragma("foreign_keys=OFF");
          legacy.db.pragma("legacy_alter_table=ON");
        }
        try {
          legacy.db.transaction(() => {
            legacy.db.exec(migration.sql);
            legacy.db
              .prepare("INSERT INTO dashboard_migrations(version,applied_at) VALUES(?,?)")
              .run(migration.version, new Date().toISOString());
          })();
        } finally {
          legacy.db.pragma("legacy_alter_table=OFF");
          legacy.db.pragma("foreign_keys=ON");
        }
      }
      legacy.db
        .prepare("INSERT INTO dashboard_meta(key,value,updated_at) VALUES('schema_version','44',?)")
        .run(new Date().toISOString());
      const legacyOrg = new OrganizationService(legacy).create(
        { name: "Legacy tenant", slug: "legacy-tenant" },
        "local-operator",
      );
      const projectId = new ProjectRepository(legacy).create({
        organizationId: legacyOrg,
        name: "Retained legacy project",
        tags: [],
        defaultScope: f.scope,
      });
      const targetId = new TargetRepository(legacy).create({
        organizationId: legacyOrg,
        projectId,
        displayName: "Retained",
        baseOrigin: f.targetOrigin,
        tags: [],
        classification: "LOCAL",
        authorizationType: "CONTROLLED_LAB",
        authorizationSummary: "Disposable owned fixture",
        approvedScope: f.scope,
      });
      const scanId = randomUUID();
      new ScanRepository(legacy).create({
        id: scanId,
        organizationId: legacyOrg,
        projectId,
        targetId,
        source: "DASHBOARD",
        status: "COMPLETED",
        targetOrigin: f.targetOrigin,
        safeTargetLabel: "fixture",
        profile: "quick",
        evidenceLevel: "minimal",
        safeConfigurationSummary: {},
      });
      const before = legacy.db.prepare("SELECT count(*) AS n FROM dashboard_migrations").get();
      expect(before).toEqual({ n: 44 });
      legacy.migrate();
      expect(legacy.db.prepare("SELECT value FROM dashboard_meta WHERE key='schema_version'").get()).toEqual({
        value: "45",
      });
      expect(legacy.db.pragma("foreign_key_check")).toEqual([]);
      expect(legacy.db.prepare("SELECT count(*) AS n FROM trusted_discovery_reviews").get()).toEqual({ n: 0 });
      legacy.migrate();
      expect(legacy.db.prepare("SELECT count(*) AS n FROM dashboard_migrations").get()).toEqual({ n: 45 });
      legacy.close();
      legacy = new DashboardDatabase(join(f.root, "legacy44.sqlite"));
      legacy.migrate();
      expect(legacy.db.prepare("SELECT organization_id,target_id,status FROM scans WHERE id=?").get(scanId)).toEqual({
        organization_id: legacyOrg,
        target_id: targetId,
        status: "COMPLETED",
      });
      expect(f.wire()).toBe(0);
    } finally {
      legacy.close();
      await f.close();
    }
  });
  it("S09 real concurrent SQLite transactions reserve one conservative route tombstone", async () => {
    const f = await seed();
    try {
      const s = await store(f);
      const id = (f.db.db.prepare("SELECT id FROM trusted_discovery_reviews").get() as any).id;
      const gate = new SharedArrayBuffer(8);
      const outcomes = await Promise.all([
        workerReservation(f.dbPath, id, gate),
        workerReservation(f.dbPath, id, gate),
      ]);
      expect(outcomes.filter((v) => v === "RESERVED")).toHaveLength(1);
      expect(outcomes.filter((v) => v === "DENIED")).toHaveLength(1);
      expect(() => f.db.db.prepare("DELETE FROM trusted_discovery_attempts").run()).toThrow(/IMMUTABLE/);
      expect(() => f.db.db.prepare("UPDATE trusted_discovery_attempts SET route_key='changed'").run()).toThrow(
        /IMMUTABLE/,
      );
      expect(s.reserveFutureAttempt(id)).toBe(false);
      const other = f.source();
      const r = await f.post("/api/trusted-discovery/review", { scanId: other.scanId, candidateId: other.candidateId });
      expect(r.status).toBe(409);
      const reopened = new DashboardDatabase(f.dbPath);
      try {
        reopened.migrate();
        expect(reopened.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 1 });
      } finally {
        reopened.close();
      }
      expect(f.wire()).toBe(0);
      s.dispose();
    } finally {
      await f.close();
    }
  });
  it("S09 internal reservation API fails closed when another instance holds a write lock", async () => {
    const f = await seed();
    try {
      const s = await store(f);
      const id = (f.db.db.prepare("SELECT id FROM trusted_discovery_reviews").get() as any).id;
      const other = new DashboardDatabase(f.dbPath);
      f.db.db.pragma("busy_timeout=0");
      other.db.exec("BEGIN IMMEDIATE");
      try {
        expect(() => s.reserveFutureAttempt(id)).toThrow();
        expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 0 });
      } finally {
        other.db.exec("ROLLBACK");
        other.close();
      }
      expect(s.reserveFutureAttempt(id)).toBe(true);
      expect(s.reserveFutureAttempt(id)).toBe(false);
      expect(f.wire()).toBe(0);
      s.dispose();
    } finally {
      await f.close();
    }
  });
  it("S09 preserved namespace fails closed on missing or rotated key", async () => {
    const f = await seed();
    try {
      const keyPath = join(f.root, "keys", "trusted-discovery-review.key");
      const original = readFileSync(keyPath);
      const { TrustedDiscoveryReviewStore } =
        await import("../../src/dashboard/execution/TrustedDiscoveryReviewStore.js");
      writeFileSync(keyPath, "0".repeat(64));
      expect(() => new TrustedDiscoveryReviewStore(f.db, keyPath)).toThrow(/KEY/);
      unlinkSync(keyPath);
      expect(() => new TrustedDiscoveryReviewStore(f.db, keyPath)).toThrow(/KEY/);
      writeFileSync(keyPath, original, { mode: 0o600 });
      const s = new TrustedDiscoveryReviewStore(f.db, keyPath);
      s.dispose();
      expect(() => s.reserveFutureAttempt("closed")).toThrow(/CLOSED/);
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
});
