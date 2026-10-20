import type { ChildProcess } from "node:child_process";
import { WindowsWorkerJob } from "./WindowsWorkerJob.js";
import type { WindowsProcessIdentity } from "./WindowsProcessIdentity.js";
import { terminateProcessTree } from "./WorkerProcessTree.js";

/** Root process handle plus a birth-verified, unnamed Windows kernel job. */
export class WorkerProcessCustody {
  public readonly exited: Promise<void>;
  public closed = false;
  private root: WindowsProcessIdentity | undefined;
  private job: WindowsWorkerJob | undefined;
  private attaching: Promise<void> | undefined;
  private rootOnlyFallback = false;
  private readonly issues = new Set<string>();
  public constructor(public readonly child: ChildProcess, private readonly temp: string, private readonly onFailure: () => void = () => {}) {
    this.exited = new Promise(resolve => {
      const close = () => { this.closed = true; resolve(); };
      if (child.exitCode !== null || child.signalCode !== null) close();
      else {
        // Native exit is authoritative for the root. `close` also waits for
        // inherited pipe handles and can be delayed by descendants on Windows.
        child.once("exit", () => { close(); if (child.connected) child.disconnect(); });
        child.once("error", () => { if (!child.pid) close(); });
        child.once("close", () => { if (!child.pid || child.exitCode !== null || child.signalCode !== null) close(); });
      }
    });
  }
  public async bind(birth: string | undefined): Promise<void> {
    if (this.root || this.closed || !this.child.pid) throw Error("WORKER_PROCESS_BINDING_REFUSED");
    if (process.platform === "win32" && (!birth || !/^\d{16,20}$/.test(birth))) throw Error("WORKER_PROCESS_BIRTH_REQUIRED");
    this.root = { pid: this.child.pid, parentPid: process.pid, birth: birth ?? "0" };
    if (process.platform === "win32") {
      this.job = new WindowsWorkerJob(this.child.pid, birth!, this.temp, () => { this.issues.add("JOB_CUSTODY_LOST"); this.onFailure(); });
      this.attaching = this.job.attached();
      try { await this.attaching; } catch (error) { this.issues.add("JOB_ATTACH_FAILED"); throw error; }
    }
  }
  public identity(): WindowsProcessIdentity | undefined { return this.root && { ...this.root }; }
  public async sample(): Promise<void> { /* Kernel membership replaces inferred PID trees on Windows. */ }
  public async terminate(): Promise<void> {
    if (this.job) {
      try { await this.job.terminate(); return; } catch { this.issues.add("JOB_TERMINATION_UNKNOWN"); }
    }
    if (!this.closed && this.child.exitCode === null && this.child.signalCode === null) {
      if (process.platform === "win32") { this.rootOnlyFallback = true; this.child.kill("SIGKILL"); }
      else if (this.child.pid) await terminateProcessTree(this.child.pid, true);
    }
  }
  public async drain(voluntaryExit = false): Promise<void> {
    await this.exited;
    if (this.attaching) await this.attaching.catch(() => {});
    if (this.job) { try { await this.job.drain(voluntaryExit); } catch { this.issues.add("JOB_DRAIN_UNKNOWN"); } }
  }
  public receipt(): Record<string, unknown> { return { root: this.root, rootOnlyFallback: this.rootOnlyFallback, terminationOutcome: this.issues.size ? "UNKNOWN" : (this.job?.receipt().terminationAcknowledged ? "ACKNOWLEDGED_ZERO" : "NOT_ACKNOWLEDGED"), rootClosed: this.closed, rootExitCode: this.child.exitCode, rootExitSignal: this.child.signalCode, issues: [...this.issues], ...(this.job ? { job: this.job.receipt() } : { completeDescendantContainment: false }) }; }
}
