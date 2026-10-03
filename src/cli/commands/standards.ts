import { readBoundedFile } from "../../core/files/BoundedFile.js";
import type { Command } from "commander";

import { durableAtomicWrite } from "../../core/offensive/MutationJournal.js";
import { officialCatalogEntries, standardsCatalogIdentity, wstgAreas } from "../../standards/StandardsCatalog.js";
import { validateBuiltInStandardsMappings } from "../../standards/StandardsMappingValidation.js";
import { validateStandardsCoverage } from "../../standards/StandardsCoverageValidation.js";
import { StandardsCoverageWriter } from "../../standards/StandardsCoverageWriter.js";

export function registerStandardsCommand(program: Command): void {
  const command = program.command("standards").description("Verify pinned official catalogs, mappings, and strict evidence accounting.");
  command.command("verify").option("--output <file>", "Retain verification summary").action(async (options: { output?: string }) => {
    const mappings = validateBuiltInStandardsMappings();
    const result = { schemaVersion: 1, status: "VERIFIED", catalog: standardsCatalogIdentity, builtInMappings: mappings.length, mappings };
    if (options.output) await durableAtomicWrite(options.output, `${JSON.stringify(result, null, 2)}\n`);
    process.stdout.write(`${JSON.stringify({ status: result.status, catalogSha256: result.catalog.sha256, counts: result.catalog.counts, builtInMappings: result.builtInMappings })}\n`);
  });
  command.command("catalog").requiredOption("--output <file>", "Export complete catalog and source provenance").action(async (options: { output: string }) => {
    await durableAtomicWrite(options.output, `${JSON.stringify({ schemaVersion: 1, catalog: standardsCatalogIdentity, areas: wstgAreas, entries: officialCatalogEntries }, null, 2)}\n`);
    process.stdout.write("Official catalog exported.\n");
  });
  command.command("validate-report").requiredOption("--input <file>", "Coverage JSON or RouteCairn report containing standardsCoverage").option("--output-dir <directory>", "Export verified coverage JSON and CSV").action(async (options: { input: string; outputDir?: string }) => {
    const bytes = await readBoundedFile(options.input, 16 * 1024 * 1024);
    const input = JSON.parse(bytes.toString("utf8")) as unknown;
    const coverage = input && typeof input === "object" && "standardsCoverage" in input ? input.standardsCoverage : input;
    validateStandardsCoverage(coverage);
    if (options.outputDir) await new StandardsCoverageWriter().write(options.outputDir, coverage);
    process.stdout.write(`${JSON.stringify({ status: "VERIFIED", schemaVersion: coverage.schemaVersion, catalogSha256: coverage.catalog.sha256, executedCases: coverage.accounting.executedCases, unmappedCases: coverage.accounting.unmappedCases })}\n`);
  });
}
