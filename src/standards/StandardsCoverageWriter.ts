import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { durableAtomicWrite } from "../core/offensive/MutationJournal.js";
import type { StandardsCoverageReport } from "./StandardsCoverageTypes.js";
import { validateStandardsCoverage } from "./StandardsCoverageValidation.js";

export interface StandardsCoveragePaths { jsonPath: string; csvPath: string }

export class StandardsCoverageWriter {
  public async write(outputDir: string, report: StandardsCoverageReport): Promise<StandardsCoveragePaths> {
    validateStandardsCoverage(report);
    await mkdir(outputDir, { recursive: true });
    const jsonPath = join(outputDir, "standards-coverage.json");
    const csvPath = join(outputDir, "standards-coverage.csv");
    await Promise.all([
      durableAtomicWrite(jsonPath, JSON.stringify(report, null, 2)),
      durableAtomicWrite(csvPath, renderCsv(report))
    ]);
    return { jsonPath, csvPath };
  }
}

function renderCsv(report: StandardsCoverageReport): string {
  const rows = [["module_id", "case_id", "label", "outcome", "request_transmitted", "framework", "reference_id", "reference_title", "mapping_strength", "reference_url", "finding_ids", "evidence_refs"]];
  for (const testCase of report.cases) {
    const references = testCase.references.length ? testCase.references : [{ framework: "", id: "", title: "", strength: "", url: "" }];
    for (const reference of references) rows.push([testCase.moduleId, testCase.caseId, testCase.label, testCase.outcome, testCase.requestTransmitted === undefined ? "" : String(testCase.requestTransmitted), reference.framework, reference.id, reference.title, reference.strength, reference.url, testCase.findingIds.join(";"), testCase.evidenceRefs.join(";")]);
  }
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
}

function csvCell(value: unknown): string {
  const text = String(value ?? "");
  // CSV quoting alone does not prevent formulas, including leading control whitespace.
  const safe = /^[\s\u0000-\u001f]*[=+\-@]/u.test(text) || /^[\t\r\n]/u.test(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
}
