import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { durableAtomicWrite } from "./MutationJournal.js";

interface RegistryEntry { directory: string; registeredAt: string }
interface RegistryFile { version: 1; journals: RegistryEntry[] }

export class MutationJournalRegistry {
  public constructor(public readonly path: string) {}

  public async register(directory: string): Promise<void> {
    const normalized = resolve(directory);
    const current = await this.read();
    const journals = current.filter((entry) => resolve(entry.directory) !== normalized);
    journals.push({ directory: normalized, registeredAt: new Date().toISOString() });
    await durableAtomicWrite(this.path, `${JSON.stringify({ version: 1, journals } satisfies RegistryFile, null, 2)}\n`);
  }

  public async directories(): Promise<string[]> {
    return (await this.read()).map((entry) => resolve(entry.directory));
  }

  private async read(): Promise<RegistryEntry[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path, "utf8")) as Partial<RegistryFile>;
      if (parsed.version !== 1 || !Array.isArray(parsed.journals)) return [];
      return parsed.journals.filter((entry): entry is RegistryEntry => Boolean(entry) && typeof entry.directory === "string" && typeof entry.registeredAt === "string");
    } catch (error) {
      if (isMissing(error)) return [];
      throw error;
    }
  }
}

function isMissing(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT"; }
