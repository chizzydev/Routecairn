import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { WorkerProcessCustody } from "../../src/dashboard/worker/WorkerProcessCustody.js";
import { windowsProcessBirth } from "../../src/dashboard/worker/WindowsProcessIdentity.js";
import { terminateProcessTree } from "../../src/dashboard/worker/WorkerProcessTree.js";

describe.skipIf(process.platform !== "win32")("native Windows worker process custody", () => {
  it("refuses bare PID termination", async () => { await expect(terminateProcessTree(process.pid, true, "win32")).rejects.toThrow("CUSTODY_REQUIRED"); });
  it("uses a new kernel job to terminate only its owned root and descendants", async () => {
    const parent = process.env.ROUTECAIRN_WORKER_LAB ?? process.env.ROUTECAIRN_TEST_RESOURCE_ROOT; if (!parent || process.platform !== "win32") throw Error("Windows owned lab required");
    const temp = join(parent, "custody-" + randomUUID()); mkdirSync(temp);
    const child = spawn(process.execPath, ["-e", "process.stdin.once('data',()=>{const c=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore',windowsHide:true});console.log(c.pid)});setInterval(()=>{},1000)"], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    const sentinel = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { windowsHide: true, stdio: "ignore" });
    const sentinelClosed = new Promise<void>(r => sentinel.once("close", () => r()));
    const custody = new WorkerProcessCustody(child, temp);
    try {
      const birth = await windowsProcessBirth(child.pid!, temp); expect(birth).toBeTruthy(); await custody.bind(birth!);
      const descendant = new Promise<number>(r => child.stdout.once("data", b => r(Number(String(b).trim())))); child.stdin.write("GO\n"); const pid = await descendant;
      const descendantBirth = await windowsProcessBirth(pid, temp); expect(descendantBirth).toBeTruthy();
      await custody.terminate(); await custody.drain();
      expect(custody.closed).toBe(true); expect(await windowsProcessBirth(pid, temp)).not.toBe(descendantBirth);
      expect(sentinel.exitCode).toBeNull(); expect(sentinel.signalCode).toBeNull();
      const receipt = custody.receipt(); writeFileSync(join(temp, "CUSTODY_RECEIPT.json"), JSON.stringify({ ...receipt, descendant: { pid, birth: descendantBirth }, unrelatedSentinelSurvived: true }, null, 2), { flag: "wx" });
      expect(receipt).toMatchObject({ issues: [], job: { drained: true, completeDescendantContainment: true } });
    } finally { await custody.terminate(); await custody.drain(); sentinel.kill("SIGKILL"); await sentinelClosed; }
  });
  it("rejects a wrong birth without acquiring or killing that process", async () => {
    const parent = process.env.ROUTECAIRN_WORKER_LAB ?? process.env.ROUTECAIRN_TEST_RESOURCE_ROOT; if (!parent) throw Error("Owned lab required"); const temp = join(parent, "wrong-birth-" + randomUUID()); mkdirSync(temp);
    const child = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { windowsHide: true, stdio: "ignore" }); const custody = new WorkerProcessCustody(child, temp);
    try { await expect(custody.bind("111111111111111111")).rejects.toThrow("ATTACH_FAILED"); expect(child.exitCode).toBeNull(); expect(child.signalCode).toBeNull(); }
    finally { child.kill("SIGKILL"); await custody.drain(); }
  });
});
