import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Storage, StoredScanSummary } from "./Storage.js";

export class FileStorage<TScan = unknown> implements Storage<TScan> {
  public constructor(private readonly rootDir: string) {}

  public async saveScan(scanId: string, scan: TScan): Promise<string> {
    const scanDir = join(this.rootDir, scanId);
    const reportPath = join(scanDir, "report.json");

    await mkdir(scanDir, { recursive: true });
    await writeFile(reportPath, `${JSON.stringify(scan, null, 2)}\n`, "utf8");

    return reportPath;
  }

  public async loadScan(scanId: string): Promise<TScan> {
    const reportPath = join(this.rootDir, scanId, "report.json");
    return JSON.parse(await readFile(reportPath, "utf8")) as TScan;
  }

  public async listScans(): Promise<StoredScanSummary[]> {
    const entries = await readdir(this.rootDir, { withFileTypes: true }).catch(() => []);
    const summaries: StoredScanSummary[] = [];

    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }

      summaries.push({
        id: entry.name,
        target: "unknown",
        startedAt: "unknown",
        reportPath: join(this.rootDir, entry.name, "report.json")
      });
    }

    return summaries;
  }
}
