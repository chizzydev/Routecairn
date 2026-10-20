import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

describe("worker exit resource ownership boundary", () => {
  it("never removes or adopts an unregistered path on child exit", async () => {
    const parent = process.env.ROUTECAIRN_WORKER_LAB ?? process.env.ROUTECAIRN_TEST_RESOURCE_ROOT;
    if (!parent) throw Error("Explicit disposable lab required");
    const root = join(parent, "retention-" + randomUUID()); mkdirSync(root);
    const paths = resolveDashboardPaths(root), db = new DashboardDatabase(paths.databasePath); db.migrate();
    const manager = new ScanWorkerManager(db, paths);
    const temp = join(paths.workersDir, randomUUID(), "tmp"); mkdirSync(temp, { recursive: true });
    const canary = join(temp, "SYNTHETIC_DISPOSABLE_CANARY.txt"); writeFileSync(canary, "SYNTHETIC_NOT_OWNER_DATA\n", { flag: "wx" });
    const child = spawn(process.execPath, ["-e", "setTimeout(()=>process.exit(0),50)"], { windowsHide: true, stdio: "ignore" });
    const closed = new Promise<void>(resolve => child.once("close", () => resolve()));
    let refused: string | undefined;
    try {
      try { (manager as unknown as { scheduleTempCleanup(child: ChildProcess, path: string): void }).scheduleTempCleanup(child, temp); }
      catch (error) { refused = error instanceof Error ? error.message : String(error); }
      await closed; await manager.drainCompletedWorkers();
      const evidence = { root, candidate: temp, canaryRetained: existsSync(canary), refused, kind: "SACRIFICIAL_GENERATED_FIXTURE_ONLY", ownerDataUsed: false };
      writeFileSync(join(root, "RETENTION_RECEIPT.json"), JSON.stringify(evidence, null, 2), { flag: "wx" });
      expect(evidence.canaryRetained, JSON.stringify(evidence)).toBe(true);
      expect(refused).toContain("UNOWNED");
    } finally { if (child.exitCode === null) child.kill(); await closed; db.close(); }
  });
});
