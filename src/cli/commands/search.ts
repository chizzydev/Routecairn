import { Command } from "commander";
import { resolve } from "node:path";
import { defaultConfig } from "../../config/defaults.js";
import { loadScanIndex, scanIndexPath, searchScanIndex, type ScanIndexEntry, type ScanIndexSearchQuery } from "../../storage/ScanIndex.js";

interface SearchCommandOptions {
  reportsDir?: string;
  domain?: string;
  findingType?: string;
  technology?: string;
  endpoint?: string;
  target?: string;
  limit?: string;
}

export function registerSearchCommand(program: Command): void {
  program
    .command("search")
    .description("Search previous RouteCairn scans by domain, finding type, technology, or endpoint.")
    .option("--reports-dir <dir>", "Reports directory containing scan-index.json.", defaultConfig.reportsDir)
    .option("--domain <domain>", "Match scan domain or target.")
    .option("--finding-type <type>", "Match finding type.")
    .option("--technology <name>", "Match detected technology.")
    .option("--endpoint <text>", "Match API, JS, or auth endpoint.")
    .option("--target <text>", "Match target URL.")
    .option("--limit <number>", "Maximum matches to show.", "20")
    .action(async (options: SearchCommandOptions) => {
      console.log(await searchHistory(options));
    });
}

export async function searchHistory(options: SearchCommandOptions = {}): Promise<string> {
  const reportsDir = resolve(options.reportsDir ?? defaultConfig.reportsDir);
  const query: ScanIndexSearchQuery = {
    ...(options.domain ? { domain: options.domain } : {}),
    ...(options.findingType ? { findingType: options.findingType } : {}),
    ...(options.technology ? { technology: options.technology } : {}),
    ...(options.endpoint ? { endpoint: options.endpoint } : {}),
    ...(options.target ? { target: options.target } : {})
  };
  const index = await loadScanIndex(scanIndexPath(reportsDir));
  const matches = searchScanIndex(index, query).slice(0, parseLimit(options.limit ?? "20"));

  return [
    "RouteCairn Scan Search",
    "",
    `Matches: ${matches.length}`,
    "",
    ...searchLines(matches)
  ].join("\n");
}

function searchLines(scans: ScanIndexEntry[]): string[] {
  if (scans.length === 0) return ["- none"];
  return scans.map(
    (scan) =>
      `- ${scan.id} | ${scan.domain} | ${scan.profile ?? scan.mode} | tech ${inline(scan.technologies)} | types ${inline(scan.findingTypes)} | endpoints ${scan.endpoints.length}`
  );
}

function inline(values: string[]): string {
  return values.length > 0 ? values.slice(0, 5).join(", ") : "none";
}

function parseLimit(value: string): number {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 20;
}