import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { durableAtomicWrite, GlobalMutationLock } from "./MutationJournal.js";

interface RegistryEntry { directory: string; registeredAt: string }
interface RegistryFile { version: 1; journals: RegistryEntry[] }

/** The canonical registry follows the coordination root, not a dashboard's
 * database directory. Keep the former dashboard location readable on upgrade. */
export function mutationRegistryPaths(directory: string, primaryRegistry?: string): string[] {
  return [...new Set([resolve(primaryRegistry ?? join(directory, "mutation-journals.json")), resolve(directory, "mutation-journals.json"), resolve(dirname(directory), "controlled-mutation-journals.json")])];
}

export class MutationJournalRegistry {
  public constructor(public readonly path: string) {}

  public async register(directory: string): Promise<void> {
    const writer = new GlobalMutationLock(`${this.path}.registration.lock`);
    for (let attempt = 0; ; attempt += 1) {
      try { await writer.acquire("journal-registration", true); break; }
      catch (error) {
        if (!(error instanceof Error) || !error.message.startsWith("MUTATION_LOCK_HELD") || attempt >= 500) throw error;
        await new Promise((done) => setTimeout(done, 20));
      }
    }
    try {
      const normalized = resolve(directory);
      const current = await this.read();
      const journals = current.filter((entry) => resolve(entry.directory) !== normalized);
      journals.push({ directory: normalized, registeredAt: new Date().toISOString() });
      await durableAtomicWrite(this.path, `${JSON.stringify({ version: 1, journals } satisfies RegistryFile, null, 2)}\n`);
    } finally { await writer.release(); }
  }

  public async directories(): Promise<string[]> {
    return (await this.read()).map((entry) => resolve(entry.directory));
  }

  private async read(): Promise<RegistryEntry[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path, "utf8")) as Partial<RegistryFile>;
      if (parsed.version !== 1 || !Array.isArray(parsed.journals) || parsed.journals.some((entry) => !entry || typeof entry.directory !== "string" || typeof entry.registeredAt !== "string")) throw new Error("MUTATION_REGISTRY_INVALID");
      return parsed.journals;
    } catch (error) {
      if (isMissing(error)) return [];
      throw error;
    }
  }
}

function isMissing(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT"; }
