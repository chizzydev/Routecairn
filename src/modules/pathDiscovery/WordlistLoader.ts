import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { PathSource } from "./PathSources.js";
import type { PathCandidate } from "../../reports/ReportTypes.js";

export type WordlistEntry = PathCandidate & {
  source: PathSource | `tech:${string}` | `js:${string}`;
};

const sourceFiles: Record<PathSource, string> = {
  "wordlist:common": "common.txt",
  "wordlist:admin": "admin.txt",
  "wordlist:api": "api.txt"
};

export class WordlistLoader {
  public async load(sources: PathSource[]): Promise<WordlistEntry[]> {
    const entries = await Promise.all(sources.map((source) => this.loadSource(source)));
    return entries.flat();
  }

  private async loadSource(source: PathSource): Promise<WordlistEntry[]> {
    const filePath = resolve("data", "wordlists", sourceFiles[source]);
    const raw = await readFile(filePath, "utf8");

    return raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#"))
      .map((line) => ({
        path: line.startsWith("/") ? line : `/${line}`,
        source
      }));
  }
}
