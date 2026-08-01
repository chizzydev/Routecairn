import { Command } from "commander";
import { resolve } from "node:path";
import { defaultConfig } from "../../config/defaults.js";
import { loadScanIndex, scanIndexPath, type ScanIndexEntry } from "../../storage/ScanIndex.js";

interface HistoryCommandOptions {
  reportsDir?: string;
  limit?: string;
  domain?: string;
}

export function registerHistoryCommand(program: Command): void {
  program
    .command("history")
    .description("Show RouteCairn scan history from the local scan index.")
    .option("--reports-dir <dir>", "Reports directory containing scan-index.json.", defaultConfig.reportsDir)
    .option("--limit <number>", "Maximum scans to show.", "20")
    .option("--domain <domain>", "Filter history by domain or target text.")
    .action(async (options: HistoryCommandOptions) => {
      console.log(await showHistory(options));
    });
}

export async function showHistory(options: HistoryCommandOptions = {}): Promise<string> {
  const reportsDir = resolve(options.reportsDir ?? defaultConfig.reportsDir);
  const index = await loadScanIndex(scanIndexPath(reportsDir));
  const limit = parseLimit(options.limit ?? "20");
  const scans = index.scans
    .filter((scan) => !options.domain || scan.domain.includes(options.domain.toLowerCase()) || scan.target.toLowerCase().includes(options.domain.toLowerCase()))
    .slice(0, limit);

  return [
    "RouteCairn Scan History",
    "",
    `Index: ${scanIndexPath(reportsDir)}`,
    `Scans: ${index.scans.length}`,
    "",
    ...historyLines(scans)
  ].join("\n");
}

function historyLines(scans: ScanIndexEntry[]): string[] {
  if (scans.length === 0) return ["- none"];
  return scans.map(
    (scan) =>
      `- ${scan.id} | ${scan.domain} | ${scan.completedAt} | ${scan.profile ?? scan.mode} | findings ${scan.counts.findings} | urls ${scan.counts.urls} | ${scan.reportPath}`
  );
}

function parseLimit(value: string): number {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 20;
}