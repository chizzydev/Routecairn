import { describe, expect, it } from "vitest";
import { appendFileSync, lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, unlinkSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { tmpdir, release } from "node:os";
import { fork } from "node:child_process";
import SqliteDatabase from "better-sqlite3";
import { stageAFixture } from "./trusted-discovery-stage-a.fixture.js";
import { provisionFixtureWitness } from "./trusted-discovery-stage-b.fixture.js";
import { TrustedDiscoveryReviewStore } from "../../src/dashboard/execution/TrustedDiscoveryReviewStore.js";
import { TrustedDiscoveryWitness } from "../../src/dashboard/execution/TrustedDiscoveryWitness.js";
import { TrustedDiscoveryPrivateRoot } from "../../src/dashboard/execution/TrustedDiscoveryPrivateRoot.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { BackupRestoreService } from "../../src/dashboard/operations/BackupRestoreService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

type Fixture = Awaited<ReturnType<typeof stageAFixture>>;
function proof(data: Record<string, unknown>) { if (process.env.ROUTECAIRN_D0_PROOF) appendFileSync(process.env.ROUTECAIRN_D0_PROOF, JSON.stringify({ schemaVersion: 1, platform: process.platform, release: release(), ...data }) + "\n"); }
async function custody() {
  const f = await stageAFixture({ preview: false }); const witnessRoot = realpathSync(mkdtempSync(join(tmpdir(), "rcd-witness-")));
  const store = new TrustedDiscoveryReviewStore(f.db, join(f.root, "keys", "trusted-discovery-review.key"));
  const witness = provisionFixtureWitness(f.db, store, witnessRoot, f.targetOrigin); witness.close(); store.dispose();
  return { f, witnessRoot };
}
function removeOwnWitness(path: string) { const absolute = resolve(path), rel = relative(resolve(tmpdir()), absolute); if (!rel.startsWith("rcd-witness-") || rel.startsWith(".." + sep) || !lstatSync(absolute).isDirectory() || lstatSync(absolute).isSymbolicLink()) throw Error("D0_WITNESS_CLEANUP_SCOPE"); rmSync(absolute, { recursive: true, force: false }); }
async function processAttempt(f: Fixture, witnessRoot: string) {
  const child = fork(resolve("tests/acceptance/trusted-discovery-d0-process.ts"), { execArgv: ["--import", "tsx"], stdio: ["ignore", "inherit", "inherit", "ipc"] });
  let result: { attempted?: number; initiated?: number; responseObserved?: number } | undefined, failure: string | undefined;
  const exited = new Promise<number | null>((done, reject) => { child.once("error", reject); child.once("exit", done); });
  child.on("message", (message: { ready?: boolean; result?: typeof result; failure?: string }) => { if (message.ready) child.send("go"); if (message.result) result = message.result; if (message.failure) failure = message.failure; });
  child.send({ root: f.root, witnessRoot, origin: f.targetOrigin, organization: f.org, scanId: f.initial.scanId, candidateId: f.initial.candidateId, security: f.security, cookie: f.auth.cookie, csrf: f.auth.csrf });
  try { return { exit: await exited, result, failure }; } finally { if (child.exitCode === null && child.signalCode === null) child.kill(); }
}
describe("D0 actual native host/process custody acceptance", () => {
  it("P01 records actual canonical inode/SQLite/permissions and fail-closed disposable link behavior", async () => {
    const { f, witnessRoot } = await custody(); let privateRoot: TrustedDiscoveryPrivateRoot | undefined;
    try {
      const key = lstatSync(join(witnessRoot, "witness.key")), db = new SqliteDatabase(join(witnessRoot, "witness.sqlite"));
      try { expect(db.pragma("synchronous", { simple: true })).toBe(2); } finally { db.close(); }
      const a = lstatSync(witnessRoot), b = lstatSync(realpathSync(witnessRoot)); expect([a.dev, a.ino]).toEqual([b.dev, b.ino]);
      const store = new TrustedDiscoveryReviewStore(f.db, join(f.root, "keys", "trusted-discovery-review.key"));
      try { expect(() => TrustedDiscoveryWitness.openFixture(f.db, store, "\\\\d0-never-connected.invalid\\custody", f.targetOrigin)).toThrow(); }
      finally { store.dispose(); }
      if (process.platform === "linux") { expect(key.mode & 0o777).toBe(0o600); expect(a.mode & 0o777).toBe(0o700); }
      privateRoot = new TrustedDiscoveryPrivateRoot(f.root); const link = join(privateRoot.path, "mutations", "hostile-link"), destination = join(f.root, "disposable-link-destination"); mkdirSync(destination);
      let linkStatus = "BLOCKED";
      try { symlinkSync(destination, link, process.platform === "win32" ? "junction" : "dir"); linkStatus = "PASS"; expect(() => privateRoot!.dispose()).toThrow(/ROOT_INVALID/); unlinkSync(link); }
      catch (error) { if (linkStatus === "PASS" || !["EPERM", "EACCES", "ENOSYS"].includes(String((error as NodeJS.ErrnoException).code))) throw error; }
      privateRoot.dispose(); privateRoot = undefined;
      proof({ case: "P01", inodeIdentity: "PASS", sqliteFull: "PASS", symbolicLink: linkStatus, networkPath: "DENIED_BEFORE_IO", posixModes: process.platform === "linux" ? "PASS" : "NOT_APPLICABLE", windowsOperationalAcl: "NOT_VERIFIED", mountBoundary: "NOT_VERIFIED", targetReceipts: f.wire() }); expect(f.wire()).toBe(0);
    } finally { privateRoot?.dispose(); await f.close(); removeOwnWitness(witnessRoot); }
  });
  it("P02 new actual OS process cannot retry a route committed by an exited peer", async () => {
    const { f, witnessRoot } = await custody();
    try { const first = await processAttempt(f, witnessRoot); expect(first.exit).toBe(0); expect(first.result).toMatchObject({ attempted: 1, initiated: 1, responseObserved: 1 }); expect(f.wire()).toBe(1);
      const restarted = await processAttempt(f, witnessRoot); expect(restarted.exit).toBe(1); expect(restarted.failure).toMatch(/DUPLICATE/); expect(f.wire()).toBe(1); proof({ case: "P02", processRestart: "PASS", replay: "DENIED", targetReceipts: f.wire(), firstCounters: first.result });
    } finally { await f.close(); removeOwnWitness(witnessRoot); }
  });
  it.each(["CURRENT", "OLD"] as const)("P03/P04 actual restore%s then fresh native process never sends a second GET", async (kind) => {
    const { f, witnessRoot } = await custody(); let restored: DashboardDatabase | undefined;
    try {
      const paths = resolveDashboardPaths(f.root), backups = new BackupRestoreService(f.db, paths, undefined);
      const old = kind === "OLD" ? await backups.create(false, "d0-owned-fixture") : undefined;
      expect((await processAttempt(f, witnessRoot)).exit).toBe(0); expect(f.wire()).toBe(1);
      backups.stageRestore(old ?? await backups.create(false, "d0-owned-fixture")); await f.stop(); f.db.close(); expect(BackupRestoreService.applyStagedRestore(paths, undefined)).toBe(true);
      restored = new DashboardDatabase(paths.databasePath); const store = new TrustedDiscoveryReviewStore(restored, join(f.root, "keys", "trusted-discovery-review.key"));
      try {
        if (kind === "CURRENT") { const witness = TrustedDiscoveryWitness.openFixture(restored, store, witnessRoot, f.targetOrigin); witness.assertConsistent(restored, store); witness.close(); }
        else expect(() => TrustedDiscoveryWitness.openFixture(restored!, store, witnessRoot, f.targetOrigin)).toThrow(/WITNESS/);
      } finally { store.dispose(); restored.close(); restored = undefined; }
      const peer = await processAttempt(f, witnessRoot); expect(peer.exit).toBe(1); expect(peer.failure).toMatch(kind === "CURRENT" ? /DUPLICATE/ : /WITNESS/); expect(f.wire()).toBe(1);
      proof({ case: kind === "CURRENT" ? "P03" : "P04", restore: kind, processRestart: "PASS", result: "DENIED_NO_RETRY", targetReceipts: f.wire(), sharedJournalChanged: false });
    } finally { restored?.close(); await f.close(); removeOwnWitness(witnessRoot); }
  });
});
