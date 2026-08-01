import { Command } from "commander";
import { dirname, resolve } from "node:path";
import { readFile } from "node:fs/promises";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { HtmlReportWriter } from "../../reports/HtmlReportWriter.js";
import { AppError } from "../../core/errors/AppError.js";
import { createLogger } from "../../core/logging/Logger.js";
import { loadTriageState, markFinding, saveTriageState, triagePathForReport } from "../../triage/TriageStore.js";
import { triageStatusSchema, type TriageStatus } from "../../triage/TriageTypes.js";

const logger = createLogger();

interface TriageCommandOptions {
  status?: string;
  note?: string;
  by?: string;
}

export function registerTriageCommand(program: Command): void {
  program
    .command("triage")
    .description("Mark a finding in a separate triage.json file without changing raw scan evidence.")
    .argument("<report>", "Path to report.json.")
    .argument("<findingId>", "Finding ID to triage.")
    .requiredOption("--status <status>", "Triage status: reviewed, false-positive, confirmed, needs-retest.")
    .option("--note <text>", "Optional triage note.", "")
    .option("--by <name>", "Reviewer name stored in triage state.", "routecairn")
    .action(async (reportPath: string, findingId: string, options: TriageCommandOptions) => {
      const result = await triageFinding(reportPath, findingId, options);
      logger.success(`Triage saved to ${result.triagePath}`);
      logger.info(`HTML report refreshed at ${result.htmlReportPath}`);
    });
}

export async function triageFinding(reportPathInput: string, findingId: string, options: TriageCommandOptions): Promise<{ triagePath: string; htmlReportPath: string }> {
  const reportPath = resolve(reportPathInput);
  const report = await loadReport(reportPath);
  const finding = report.findings.find((item) => item.id === findingId);

  if (!finding) {
    throw new AppError(`Finding not found in report: ${findingId}`, "FINDING_NOT_FOUND");
  }

  const status = parseStatus(options.status);
  const triagePath = triagePathForReport(reportPath);
  const current = await loadTriageState(triagePath, report);
  const next = markFinding(current, findingId, status, options.note ?? "", options.by ?? "routecairn");
  await saveTriageState(triagePath, next);

  const htmlReportPath = await new HtmlReportWriter().write(dirname(reportPath), report);
  return { triagePath, htmlReportPath };
}

async function loadReport(reportPath: string): Promise<RouteCairnReport> {
  return JSON.parse(await readFile(reportPath, "utf8")) as RouteCairnReport;
}

function parseStatus(value: string | undefined): TriageStatus {
  const parsed = triageStatusSchema.safeParse(value);

  if (!parsed.success) {
    throw new AppError("Unsupported triage status. Use reviewed, false-positive, confirmed, or needs-retest.", "TRIAGE_STATUS_INVALID");
  }

  return parsed.data;
}