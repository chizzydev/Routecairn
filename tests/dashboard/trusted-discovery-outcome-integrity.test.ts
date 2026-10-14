import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { IncomingMessage } from "node:http";
import { Socket } from "node:net";
import SqliteDatabase from "better-sqlite3";
import { createHash } from "node:crypto";
import { fork } from "node:child_process";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { BackupRestoreService } from "../../src/dashboard/operations/BackupRestoreService.js";
import { stageAFixture, consentFor } from "./trusted-discovery-stage-a.fixture.js";
import { provisionFixtureWitness } from "./trusted-discovery-stage-b.fixture.js";
import { TrustedDiscoveryWitness } from "../../src/dashboard/execution/TrustedDiscoveryWitness.js";
import { TrustedDiscoveryReviewStore } from "../../src/dashboard/execution/TrustedDiscoveryReviewStore.js";
import { TrustedDiscoveryOperatorService } from "../../src/dashboard/execution/TrustedDiscoveryOperatorService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

async function fixture() {
  const f = await stageAFixture();
  const witnessRoot = mkdtempSync(join(tmpdir(), "rco-witness-"));
  const store = new TrustedDiscoveryReviewStore(f.db, join(f.root, "keys", "trusted-discovery-review.key"));
  const witness = provisionFixtureWitness(f.db, store, witnessRoot, f.targetOrigin);
  const service = new TrustedDiscoveryOperatorService(f.db, resolveDashboardPaths(f.root), f.sessions, witness);
  const authority = () => {
    const request = new IncomingMessage(new Socket());
    request.headers = {
      cookie: f.auth.cookie,
      origin: f.security.publicOrigin,
      "x-forwarded-proto": "https",
      "content-type": "application/json"
    };
    return f.sessions.captureTrustedDiscoverySession(request, f.auth.csrf);
  };
  const open = () => TrustedDiscoveryWitness.openFixture(f.db, store, witnessRoot, f.targetOrigin);
  async function execute(source = f.initial) {
    const selected = await service.review(
      { scanId: source.scanId, candidateId: source.candidateId },
      authority(),
      f.org
    );
    return service.executeFresh(consentFor(selected.review), authority(), f.org);
  }
  async function close() {
    await service.shutdown();
    store.dispose();
    witness.close();
    if (process.env.ROUTECAIRN_OUTCOME_WIRE_EVIDENCE)
      appendFileSync(
        process.env.ROUTECAIRN_OUTCOME_WIRE_EVIDENCE,
        JSON.stringify({
          fixture: witnessRoot.split(/[\\/]/).at(-1),
          wireReceipts: f.wire(),
          externalTargetsTested: false
        }) + "\n"
      );
    await f.close();
    if (!witnessRoot.startsWith(join(tmpdir(), "rco-witness-"))) throw Error("FIXTURE_SCOPE");
    rmSync(witnessRoot, { recursive: true, force: true });
  }
  return { ...f, witnessRoot, store, witness, service, authority, open, execute, close };
}

describe("Stage B outcome authenticated custody repair", () => {
  it("O01 recorded outcome deletion after trigger removal refuses fresh native custody", async () => {
    const f = await fixture();
    try {
      expect(await f.execute()).toMatchObject({ initiated: 1, responseObserved: 1, status: "RESPONSE_OBSERVED" });
      expect(f.wire()).toBe(1);
      await f.service.shutdown();
      const tamper = new SqliteDatabase(join(f.witnessRoot, "witness.sqlite"));
      try {
        expect(tamper.prepare("SELECT count(*) AS n FROM outcomes").get()).toEqual({ n: 1 });
        tamper.exec("DROP TRIGGER outcomes_no_delete; DELETE FROM outcomes");
        expect(tamper.prepare("SELECT count(*) AS n FROM outcomes").get()).toEqual({ n: 0 });
      } finally {
        tamper.close();
      }
      expect(() => {
        const reopened = f.open();
        reopened.close();
      }).toThrow(/WITNESS/);
      expect(f.wire()).toBe(1);
    } finally {
      await f.close();
    }
  });
  it.each(["deletion-with-restored-trigger", "changed-fact", "truncated", "reordered", "missing-trigger"])(
    "O02 signed set/count/order refuses%s",
    async (kind) => {
      const f = await fixture();
      try {
        await f.execute();
        if (kind === "truncated" || kind === "reordered") await f.execute(f.source("/api/status"));
        const before = f.wire();
        await f.service.shutdown();
        const tamper = new SqliteDatabase(join(f.witnessRoot, "witness.sqlite"));
        try {
          const guards = tamper
            .prepare("SELECT name,sql FROM sqlite_master WHERE name IN ('outcomes_no_delete','outcomes_no_update')")
            .all() as { name: string; sql: string }[];
          tamper.exec("DROP TRIGGER outcomes_no_delete; DROP TRIGGER outcomes_no_update");
          if (kind === "deletion-with-restored-trigger") tamper.exec("DELETE FROM outcomes");
          if (kind === "truncated") tamper.exec("DELETE FROM outcomes WHERE seq=2");
          if (kind === "reordered")
            tamper.exec("UPDATE outcomes SET seq=seq+10; UPDATE outcomes SET seq=CASE seq WHEN 11 THEN 2 ELSE 1 END");
          if (kind === "changed-fact") {
            const digest = createHash("sha256").update("unkeyed fabricated facts").digest("hex");
            tamper.prepare("UPDATE outcomes SET observed=0,seal=?").run(digest);
          }
          if (kind !== "missing-trigger") for (const guard of guards) tamper.exec(guard.sql);
        } finally {
          tamper.close();
        }
        expect(() => {
          const reopened = f.open();
          reopened.close();
        }).toThrow(/WITNESS/);
        expect(f.wire()).toBe(before);
      } finally {
        await f.close();
      }
    }
  );
  it.each(["deleted", "unkeyed-forgery", "authenticated-old-prefix"])(
    "O03 separate main outcome checkpoint%s is not silently repaired",
    async (kind) => {
      const f = await fixture();
      try {
        const key = "trusted_discovery_outcome_checkpoint_v2";
        const original = (f.db.db.prepare("SELECT value FROM dashboard_meta WHERE key=?").get(key) as { value: string })
          .value;
        await f.execute();
        await f.service.shutdown();
        if (kind === "deleted") f.db.db.prepare("DELETE FROM dashboard_meta WHERE key=?").run(key);
        else
          f.db.db.prepare("UPDATE dashboard_meta SET value=? WHERE key=?").run(
            kind === "authenticated-old-prefix"
              ? original
              : JSON.stringify({
                  ...JSON.parse(original),
                  seal: createHash("sha256").update(original).digest("hex")
                }),
            key
          );
        expect(() => {
          const reopened = f.open();
          reopened.close();
        }).toThrow(/WITNESS/);
        expect(f.wire()).toBe(1);
      } finally {
        await f.close();
      }
    }
  );
  it.each(["BEFORE_WRITE", "AFTER_WITNESS_COMMIT"] as const)(
    "O04 actual process death%s preserves irreversible attempt",
    async (point) => {
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
          outcomeCrash: point
        });
        expect(await exited).toBe(point === "BEFORE_WRITE" ? 87 : 88);
        expect(f.wire()).toBe(1);
        expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 1 });
        const check = new SqliteDatabase(join(f.witnessRoot, "witness.sqlite"));
        try {
          expect(check.prepare("SELECT count(*) AS n FROM outcomes").get()).toEqual({
            n: point === "BEFORE_WRITE" ? 0 : 1
          });
        } finally {
          check.close();
        }
        if (point === "AFTER_WITNESS_COMMIT")
          expect(() => {
            const reopened = f.open();
            reopened.close();
          }).toThrow(/WITNESS/);
        else {
          const reopened = f.open();
          const service = new TrustedDiscoveryOperatorService(
            f.db,
            resolveDashboardPaths(f.root),
            f.sessions,
            reopened
          );
          try {
            await expect(
              service.review({ scanId: f.initial.scanId, candidateId: f.initial.candidateId }, f.authority(), f.org)
            ).rejects.toThrow(/DUPLICATE/);
          } finally {
            await service.shutdown();
          }
        }
        expect(f.wire()).toBe(1);
      } finally {
        if (child.exitCode === null) child.kill();
        await f.close();
      }
    }
  );
  it.each(["WITNESS_INSERT", "MAIN_CHECKPOINT"] as const)(
    "O05 actual response plus persistence failure%s keeps native counters",
    async (point) => {
      const f = await fixture();
      try {
        if (point === "MAIN_CHECKPOINT")
          f.db.db.exec(
            "CREATE TEMP TRIGGER fixture_outcome_abort BEFORE UPDATE ON dashboard_meta WHEN NEW.key='trusted_discovery_outcome_checkpoint_v2' BEGIN SELECT RAISE(ABORT,'FIXTURE_OUTCOME_CHECKPOINT_FAIL'); END"
          );
        else {
          const inject = new SqliteDatabase(join(f.witnessRoot, "witness.sqlite"));
          try {
            inject.exec(
              "CREATE TRIGGER fixture_outcome_abort BEFORE INSERT ON outcomes BEGIN SELECT RAISE(ABORT,'FIXTURE_OUTCOME_INSERT_FAIL'); END"
            );
          } finally {
            inject.close();
          }
        }
        expect(await f.execute()).toMatchObject({
          attempted: 1,
          initiated: 1,
          responseObserved: 1,
          code: "INCONCLUSIVE",
          status: "INITIATED_INCONCLUSIVE"
        });
        expect(f.wire()).toBe(1);
        await expect(
          f.service.review({ scanId: f.initial.scanId, candidateId: f.initial.candidateId }, f.authority(), f.org)
        ).rejects.toThrow();
        await expect(f.service.shutdown()).rejects.toThrow(/OUTCOME_COMMIT_FAILED/);
        if (point === "MAIN_CHECKPOINT")
          expect(() => {
            const reopened = f.open();
            reopened.close();
          }).toThrow(/WITNESS/);
        else {
          const reopened = f.open();
          reopened.assertConsistent(f.db, f.store);
          reopened.close();
        }
        expect(f.wire()).toBe(1);
      } finally {
        await f.close();
      }
    }
  );
  it.each(["OLD_BEFORE_OUTCOME", "CURRENT_AFTER_OUTCOME"] as const)(
    "O06 actual backup restore%s respects outcome custody",
    async (when) => {
      const f = await fixture();
      let restored: DashboardDatabase | undefined;
      try {
        const paths = resolveDashboardPaths(f.root),
          backups = new BackupRestoreService(f.db, paths, undefined);
        const old = when === "OLD_BEFORE_OUTCOME" ? await backups.create(false, "owned-fixture") : undefined;
        await f.execute();
        const id = old ?? (await backups.create(false, "owned-fixture"));
        backups.stageRestore(id);
        await f.service.shutdown();
        await f.stop();
        f.db.close();
        expect(BackupRestoreService.applyStagedRestore(paths, undefined)).toBe(true);
        restored = new DashboardDatabase(paths.databasePath);
        restored.migrate();
        const store = new TrustedDiscoveryReviewStore(restored, join(f.root, "keys", "trusted-discovery-review.key"));
        try {
          const open = () => TrustedDiscoveryWitness.openFixture(restored!, store, f.witnessRoot, f.targetOrigin);
          if (old)
            expect(() => {
              const witness = open();
              witness.close();
            }).toThrow(/WITNESS/);
          else {
            const witness = open();
            witness.assertConsistent(restored, store);
            witness.close();
          }
        } finally {
          store.dispose();
        }
        expect(f.wire()).toBe(1);
      } finally {
        restored?.close();
        await f.close();
      }
    }
  );
  it("O07 even empty custody without its signed outcome checkpoint refuses startup", async () => {
    const f = await fixture();
    try {
      expect(
        (
          f.db.db
            .prepare("SELECT value FROM dashboard_meta WHERE key='trusted_discovery_outcome_checkpoint_v2'")
            .get() as { value: string }
        ).value
      ).toContain('"seq":0');
      await f.service.shutdown();
      f.db.db.prepare("DELETE FROM dashboard_meta WHERE key='trusted_discovery_outcome_checkpoint_v2'").run();
      expect(() => {
        const reopened = f.open();
        reopened.close();
      }).toThrow(/WITNESS/);
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("O08 restored old outcome checkpoint denies even when attempt chains still match", async () => {
    const f = await fixture();
    let restored: DashboardDatabase | undefined;
    try {
      const key = "trusted_discovery_outcome_checkpoint_v2";
      const before = (f.db.db.prepare("SELECT value FROM dashboard_meta WHERE key=?").get(key) as { value: string })
        .value;
      await f.execute();
      await f.service.shutdown();
      const after = (f.db.db.prepare("SELECT value FROM dashboard_meta WHERE key=?").get(key) as { value: string })
        .value;
      // Capture the authentic pre-outcome commitment in a disposable snapshot,
      // preserving the already-spent attempt to isolate outcome rollback.
      f.db.db.prepare("UPDATE dashboard_meta SET value=? WHERE key=?").run(before, key);
      const paths = resolveDashboardPaths(f.root),
        backups = new BackupRestoreService(f.db, paths, undefined);
      const id = await backups.create(false, "owned-fixture-outcome-rollback");
      f.db.db.prepare("UPDATE dashboard_meta SET value=? WHERE key=?").run(after, key);
      backups.stageRestore(id);
      await f.stop();
      f.db.close();
      expect(BackupRestoreService.applyStagedRestore(paths, undefined)).toBe(true);
      restored = new DashboardDatabase(paths.databasePath);
      restored.migrate();
      expect(restored.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 1 });
      const store = new TrustedDiscoveryReviewStore(restored, join(f.root, "keys", "trusted-discovery-review.key"));
      try {
        expect(() => {
          const opened = TrustedDiscoveryWitness.openFixture(restored!, store, f.witnessRoot, f.targetOrigin);
          opened.close();
        }).toThrow(/WITNESS/);
      } finally {
        store.dispose();
      }
      expect(f.wire()).toBe(1);
    } finally {
      restored?.close();
      await f.close();
    }
  });
});
