import { createHmac, randomBytes } from "node:crypto";
import { mkdir, open, readFile, readdir, rename, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type { MutationJournalEntry } from "./ControlledMutationTypes.js";
import { MutationJournalRegistry, mutationRegistryPaths } from "./MutationJournalRegistry.js";
import { distributedMutationCoordinatorFromEnvironment, type DistributedMutationCoordinatorClient, type DistributedMutationLease, type DistributedMutationReleaseState } from "./DistributedMutationCoordinator.js";
import Database from "better-sqlite3";

export class MutationJournal {
  private readonly attestationKey = randomBytes(32);
  public constructor(public readonly path: string, private readonly beforeAppend?: (entry: Omit<MutationJournalEntry, "sequence" | "timestamp">) => Promise<void | Omit<MutationJournalEntry, "sequence" | "timestamp">>, private readonly afterAppend?: (entry: MutationJournalEntry) => Promise<void>) {}

  public async append(entry: Omit<MutationJournalEntry, "sequence" | "timestamp">): Promise<MutationJournalEntry> {
    const writer = new GlobalMutationLock(`${this.path}.append.lock`);
    for (let attempt = 0; ; attempt += 1) {
      try { await writer.acquire(entry.caseId, true); break; }
      catch (error) { if (!(error instanceof Error) || !error.message.startsWith("MUTATION_LOCK_HELD") || attempt >= 100) throw error; await new Promise((done) => setTimeout(done, 20)); }
    }
    try {
      const prepared = await this.beforeAppend?.(entry) ?? entry;
      const entries = await this.read();
      const sealed: MutationJournalEntry = { ...prepared, sequence: entries.length + 1, timestamp: new Date().toISOString() };
      await durableAtomicWrite(this.path, `${JSON.stringify([...entries, sealed], null, 2)}\n`);
      await this.afterAppend?.(sealed);
      return sealed;
    } finally { await writer.release(); }
  }

  public async read(): Promise<MutationJournalEntry[]> {
    try {
      const entries: unknown = JSON.parse(await readFile(this.path, "utf8"));
      if (!Array.isArray(entries) || entries.some((entry, index) => !entry || typeof entry !== "object" || entry.sequence !== index + 1 || typeof entry.caseId !== "string" || !/^[A-Za-z0-9._-]{1,200}$/.test(entry.caseId) || !journalStages.has(entry.stage) || typeof entry.timestamp !== "string" || !Number.isFinite(Date.parse(entry.timestamp)))) throw new Error("MUTATION_JOURNAL_INVALID");
      return entries as MutationJournalEntry[];
    }
    catch (error) { if (isMissing(error)) return []; throw error; }
  }

  public attestBody(body: string | undefined): string | undefined {
    return body ? createHmac("sha256", this.attestationKey).update(body).digest("hex") : undefined;
  }

  public async unresolvedCaseIds(): Promise<string[]> {
    const latest = new Map<string, MutationJournalEntry>();
    for (const entry of await this.read()) latest.set(entry.caseId, entry);
    return [...latest.values()].filter((entry) => cleanupObligationStages.has(entry.stage)).map((entry) => entry.caseId);
  }
}

const cleanupObligationStages = new Set<MutationJournalEntry["stage"]>(["MUTATION_ARMED", "MUTATION_SENT", "IMPACT_VERIFIED", "ROLLBACK_SENT", "CLEANUP_REQUIRED", "CLEANUP_FAILED"]);
const journalStages = new Set<string>(["AUTHORIZED", "ACTOR_IDENTITY_VERIFIED", "TARGET_IDENTITY_VERIFIED", "PRE_STATE_CAPTURED", ...cleanupObligationStages, "ROLLBACK_VERIFIED", "SEALED"]);

export class GlobalMutationLock {
  private handle: Awaited<ReturnType<typeof open>> | undefined;
  private lease: Database.Database | undefined;
  private distributedClient: DistributedMutationCoordinatorClient | undefined;
  private distributedLease: DistributedMutationLease | undefined;
  private distributedHolderId = randomBytes(24).toString("base64url");
  private renewalTimer: ReturnType<typeof setInterval> | undefined;
  public constructor(private readonly path: string, private readonly options: { distributed?: boolean; coordinator?: DistributedMutationCoordinatorClient } = {}) {}

  public async acquire(caseId: string, recovery = false): Promise<void> {
    if (this.lease) throw new Error("MUTATION_LOCK_HELD: global lock already held.");
    await mkdir(dirname(this.path), { recursive: true });
    // An OS-backed SQLite write lease survives asynchronous work but is released
    // automatically on process death, even before lock metadata was written.
    const lease = new Database(`${this.path}.coordination.sqlite`, { timeout: 0 });
    try {
      lease.exec("BEGIN IMMEDIATE");
    } catch (error) {
      lease.close();
      if (typeof error === "object" && error !== null && "code" in error && error.code === "SQLITE_BUSY") throw new Error("MUTATION_LOCK_HELD: global lock already held.");
      throw error;
    }
    this.lease = lease;
    try {
      // Preserve interoperability with a live owner of a pre-upgrade lock.
      // Dead or incomplete metadata can only be reaped while holding the lease.
      try {
        const contents = await readFile(this.path, "utf8");
        let record: { pid?: unknown } = {};
        try { record = JSON.parse(contents) as { pid?: unknown }; } catch { /* A crashed metadata write. */ }
        if (typeof record?.pid === "number" && processIsAlive(record.pid)) throw new Error("MUTATION_LOCK_HELD: global lock already held.");
        await unlink(this.path);
      } catch (error) { if (!isMissing(error)) throw error; }
      this.handle = await open(this.path, "wx", 0o600);
      await this.handle.writeFile(JSON.stringify({ caseId, pid: process.pid, acquiredAt: new Date().toISOString() }));
      await this.handle.sync();
      if (!recovery) {
        const root = dirname(this.path);
        const registered = (await Promise.all(mutationRegistryPaths(root).map((path) => new MutationJournalRegistry(path).directories()))).flat();
        for (const directory of new Set([root, ...registered])) {
          const entries = await new MutationJournal(join(directory, "mutation-journal.json")).read();
          const latest = new Map(entries.map((entry) => [entry.caseId, entry]));
          if ([...latest.values()].some((entry) => cleanupObligationStages.has(entry.stage))) throw new Error("UNRESOLVED_PRIOR_CLEANUP");
          const files = await readdir(directory).catch((error: unknown) => { if (isMissing(error)) return []; throw error; });
          if (files.some((file) => file.endsWith(".recovery.enc") && latest.get(file.slice(0, -13))?.stage !== "ROLLBACK_VERIFIED")) throw new Error("UNRESOLVED_RECOVERY_CHECKPOINT");
        }
      }
      const distributed = this.distributedCoordinator();
      if (distributed) {
        this.distributedClient = distributed;
        this.distributedLease = await distributed.acquire(caseId, this.distributedHolderId, recovery);
        this.startRenewal();
      }
    } catch (error) { await this.release(); throw error; }
  }

  public async release(): Promise<void> {
    let distributedError: unknown;
    try {
      this.stopRenewal();
      if (this.distributedClient && this.distributedLease) {
        const cleanup = await distributedReleaseState(dirname(this.path));
        try { await this.distributedClient.release(this.distributedLease, this.distributedHolderId, cleanup); }
        catch (error) { distributedError = error; }
      }
      this.distributedLease = undefined;
      this.distributedClient = undefined;
      if (this.handle) {
        await this.handle.close();
        this.handle = undefined;
        await unlink(this.path).catch((error: unknown) => { if (!isMissing(error)) throw error; });
      }
    } finally {
      if (this.lease) { this.lease.close(); this.lease = undefined; }
    }
    if (distributedError) throw distributedError;
  }

  private distributedCoordinator(): DistributedMutationCoordinatorClient | undefined {
    if (this.options.distributed === false || isAuxiliaryLock(this.path)) return undefined;
    return this.options.coordinator ?? distributedMutationCoordinatorFromEnvironment();
  }

  private startRenewal(): void {
    this.stopRenewal();
    this.renewalTimer = setInterval(() => {
      const client = this.distributedClient, lease = this.distributedLease;
      if (!client || !lease) return;
      void client.renew(lease, this.distributedHolderId).then((result) => { lease.expiresAt = result.expiresAt; }).catch(() => undefined);
    }, 30_000);
    this.renewalTimer.unref();
  }

  private stopRenewal(): void { if (this.renewalTimer) clearInterval(this.renewalTimer); this.renewalTimer = undefined; }
}

export function safeRequestUrl(rawUrl: string): string {
  const url = new URL(rawUrl);
  url.username = ""; url.password = ""; url.search = ""; url.hash = "";
  return url.toString();
}

export async function durableAtomicWrite(path: string, contents: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(contents, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, path);
  await syncDirectory(dirname(resolve(path)));
}

async function syncDirectory(path: string): Promise<void> {
  try {
    const directory = await open(path, "r");
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    if (process.platform !== "win32") throw error;
  }
}

function isMissing(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT"; }
function processIsAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return !(typeof error === "object" && error !== null && "code" in error && error.code === "ESRCH"); }
}

function isAuxiliaryLock(path: string): boolean { return /\.(?:append|registration|creation)\.lock$/i.test(path); }

async function distributedReleaseState(root: string): Promise<DistributedMutationReleaseState> {
  try {
    const registered = (await Promise.all(mutationRegistryPaths(root).map((path) => new MutationJournalRegistry(path).directories()))).flat();
    const obligations = new Map<string, string>();
    for (const directory of new Set([resolve(root), ...registered.map((value) => resolve(value))])) {
      const entries = await new MutationJournal(join(directory, "mutation-journal.json")).read();
      const latest = new Map(entries.map((entry) => [entry.caseId, entry]));
      for (const unresolved of [...latest.values()].filter((entry) => cleanupObligationStages.has(entry.stage))) obligations.set(unresolved.caseId, unresolved.stage);
      const files = await readdir(directory).catch((error: unknown) => { if (isMissing(error)) return []; throw error; });
      for (const file of files.filter((name) => name.endsWith(".recovery.enc") && latest.get(name.slice(0, -13))?.stage !== "ROLLBACK_VERIFIED")) obligations.set(file.slice(0, -13), "MUTATION_STATE_UNCERTAIN");
    }
    if (obligations.size) return { state: "UNRESOLVED", obligations: [...obligations].map(([caseId, stage]) => ({ caseId, stage })) };
    return { state: "CLEAN" };
  } catch { return { state: "UNKNOWN", stage: "MUTATION_STATE_UNCERTAIN" }; }
}
