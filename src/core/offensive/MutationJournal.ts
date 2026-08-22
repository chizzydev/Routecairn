import { createHmac, randomBytes } from "node:crypto";
import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { MutationJournalEntry } from "./ControlledMutationTypes.js";

export class MutationJournal {
  private readonly attestationKey = randomBytes(32);
  public constructor(public readonly path: string) {}

  public async append(entry: Omit<MutationJournalEntry, "sequence" | "timestamp">): Promise<MutationJournalEntry> {
    const entries = await this.read();
    const sealed: MutationJournalEntry = { ...entry, sequence: entries.length + 1, timestamp: new Date().toISOString() };
    await durableAtomicWrite(this.path, `${JSON.stringify([...entries, sealed], null, 2)}\n`);
    return sealed;
  }

  public async read(): Promise<MutationJournalEntry[]> {
    try { return JSON.parse(await readFile(this.path, "utf8")) as MutationJournalEntry[]; }
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

export class GlobalMutationLock {
  private handle: Awaited<ReturnType<typeof open>> | undefined;
  public constructor(private readonly path: string) {}

  public async acquire(caseId: string): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    try {
      this.handle = await open(this.path, "wx", 0o600);
      await this.handle.writeFile(JSON.stringify({ caseId, pid: process.pid, acquiredAt: new Date().toISOString() }));
    } catch (error) {
      if (isAlreadyExists(error) && await this.removeOrphanedLock()) {
        this.handle = await open(this.path, "wx", 0o600);
        await this.handle.writeFile(JSON.stringify({ caseId, pid: process.pid, acquiredAt: new Date().toISOString(), recoveredOrphanedLock: true }));
        return;
      }
      if (isAlreadyExists(error)) throw new Error(`Another controlled mutation holds the global lock at ${this.path}.`);
      throw error;
    }
  }

  public async release(): Promise<void> {
    await this.handle?.close();
    this.handle = undefined;
    await unlink(this.path).catch((error: unknown) => { if (!isMissing(error)) throw error; });
  }

  private async removeOrphanedLock(): Promise<boolean> {
    try {
      const record = JSON.parse(await readFile(this.path, "utf8")) as { pid?: unknown };
      if (typeof record.pid !== "number" || processIsAlive(record.pid)) return false;
      await unlink(this.path);
      return true;
    } catch { return false; }
  }
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
function isAlreadyExists(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && error.code === "EEXIST"; }
function processIsAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return !(typeof error === "object" && error !== null && "code" in error && error.code === "ESRCH"); }
}
