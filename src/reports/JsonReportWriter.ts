import { mkdir } from "node:fs/promises";
import { durableAtomicWrite } from "../core/offensive/MutationJournal.js";
import { join } from "node:path";
import type { RouteCairnReport } from "./ReportTypes.js";

export class JsonReportWriter {
  public async write(outputDir: string, report: RouteCairnReport): Promise<string> {
    await mkdir(outputDir, { recursive: true });
    const reportPath = join(outputDir, "report.json");
    await durableAtomicWrite(reportPath, `${JSON.stringify(report, null, 2)}\n`);
    return reportPath;
  }
}
