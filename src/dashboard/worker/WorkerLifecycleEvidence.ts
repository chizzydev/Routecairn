import { createHash, createHmac, timingSafeEqual, randomUUID } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, openSync, writeFileSync, fsyncSync, closeSync, fstatSync, opendirSync } from "node:fs";
import type { OwnedTemporaryResource } from "../../core/storage/OwnedTemporaryResource.js";
import { dirname, join, resolve } from "node:path";

export interface WorkerResourceProof { resourceId: string; markerSha256: string; rootDev: string; rootIno: string; tempDev: string; tempIno: string; }
/** A fresh manager's private IPC handoff, not an API for adopting old resources. */
export class WorkerLifecycleEvidence {
  private readonly diagnostic: number;
  private uncertain = false;
  public constructor(private readonly temp: string, private readonly proof: WorkerResourceProof, private readonly binding: { workerId: string; generation: string; jobId: string }, private readonly secret: string) {
    this.assertBound();
    this.diagnostic = openSync(join(temp, "lifecycle-diagnostic-" + randomUUID() + ".jsonl"), "wx", 0o600);
  }
  private assertBound(): void {
    if (this.uncertain) throw Error("WORKER_RESOURCE_PERMANENT_REFUSAL");
    const root = dirname(this.temp), a = lstatSync(root, { bigint: true }), b = lstatSync(this.temp, { bigint: true }), marker = join(root, "OWNERSHIP.json"), m = lstatSync(marker, { bigint: true });
    if (!a.isDirectory() || !b.isDirectory() || a.isSymbolicLink() || b.isSymbolicLink() || !m.isFile() || m.isSymbolicLink() || m.nlink !== 1n || String(a.dev) !== this.proof.rootDev || String(a.ino) !== this.proof.rootIno || String(b.dev) !== this.proof.tempDev || String(b.ino) !== this.proof.tempIno || resolve(realpathSync.native(this.temp)).toLowerCase() !== resolve(this.temp).toLowerCase()) throw Error("WORKER_RESOURCE_IDENTITY_CHANGED");
    if (m.size > 8192n) throw Error("WORKER_RESOURCE_MARKER_CHANGED");
    const bytes = readFileSync(marker); if (bytes.length > 8192 || createHash("sha256").update(bytes).digest("hex") !== this.proof.markerSha256) throw Error("WORKER_RESOURCE_MARKER_CHANGED");
    const value = JSON.parse(bytes.toString()) as { id: string; binding: { workerId: string; generation: string; jobId: string } };
    if (value.id !== this.proof.resourceId || value.binding.workerId !== this.binding.workerId || value.binding.jobId !== this.binding.jobId || value.binding.generation !== this.binding.generation) throw Error("WORKER_RESOURCE_BINDING_INVALID");
  }
  public record(event: "INITIALIZED" | "EXECUTION_REQUESTED" | "SHUTDOWN_REQUESTED" | "PROCESS_EXIT_READY" | "PROCESS_EXIT" | "UNCAUGHT_FAILURE", cleanupState: string, exitCode?: number): void {
    try { this.recordBound(event, cleanupState, exitCode); }
    catch (error) {
      this.uncertain = true;
      // This already-open, exclusively created inode is diagnostic custody. No
      // pathname is reopened after an identity failure and no arbitrary message
      // (potentially containing credentials) is written.
      const stat = fstatSync(this.diagnostic);
      if (stat.isFile() && stat.nlink === 1) { writeFileSync(this.diagnostic, JSON.stringify({ event, refused: true, code: error instanceof Error && /^[A-Z_]+$/.test(error.message) ? error.message : "RESOURCE_IO_FAILURE" }) + "\n"); fsyncSync(this.diagnostic); }
      throw error;
    }
  }
  private recordBound(event: string, cleanupState: string, exitCode?: number): void {
    this.assertBound();
    const file = openSync(join(this.temp, "lifecycle-" + randomUUID() + ".json"), "wx", 0o600);
    const body = { version: 1, ...this.binding, resourceId: this.proof.resourceId, event, cleanupState, ...(exitCode === undefined ? {} : { exitCode }), at: new Date().toISOString(), coverageClaim: "NONE", deletionAuthorized: false };
    try { writeFileSync(file, JSON.stringify({ body, hmac: createHmac("sha256", this.secret).update(JSON.stringify(body)).digest("hex") }) + "\n"); fsyncSync(file); }
    finally { closeSync(file); }
    this.assertBound();
  }
}

/** Only a current in-memory capability and its attempt secret can confirm that
 * the root awaited its job before voluntary exit. Historical receipts cannot. */
export function verifiedWorkerExit(resource: OwnedTemporaryResource, secret: string): boolean {
  try {
    resource.assertOwned(); const directory = opendirSync(resource.directory("tmp"));
    let exitReady = false, cleanExit = false, count = 0;
    try { for (let entry = directory.readSync(); entry; entry = directory.readSync()) {
      if (++count > 4096) return false;
      if (!/^lifecycle-[a-f0-9-]{36}\.json$/.test(entry.name)) continue;
      const path = join(directory.path, entry.name), stat = lstatSync(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4096) return false;
      const value = JSON.parse(readFileSync(path, "utf8")) as { body: Record<string, unknown>; hmac: string };
      if (!/^[a-f0-9]{64}$/.test(value.hmac)) return false;
      const expected = createHmac("sha256", secret).update(JSON.stringify(value.body)).digest();
      if (!timingSafeEqual(expected, Buffer.from(value.hmac, "hex"))) return false;
      const body = value.body;
      if (body.resourceId !== resource.id || body.workerId !== resource.binding.workerId || body.jobId !== resource.binding.jobId || body.generation !== resource.binding.generation) return false;
      if (body.event === "PROCESS_EXIT_READY") exitReady = true;
      if (body.event === "PROCESS_EXIT" && body.exitCode === 0) cleanExit = true;
    } } finally { directory.closeSync(); }
    resource.assertOwned(); return exitReady && cleanExit;
  } catch { return false; }
}
