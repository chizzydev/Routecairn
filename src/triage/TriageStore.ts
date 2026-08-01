import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { RouteCairnReport } from "../reports/ReportTypes.js";
import { emptyTriageState, triageStateSchema, type TriageState, type TriageStatus } from "./TriageTypes.js";

export const triageFileName = "triage.json";

export function triagePathForReport(reportPath: string): string {
  return join(dirname(reportPath), triageFileName);
}

export async function loadTriageState(filePath: string, report?: RouteCairnReport): Promise<TriageState> {
  try {
    const raw = await readFile(filePath, "utf8");
    return triageStateSchema.parse(JSON.parse(raw));
  } catch (error) {
    if (isMissingFileError(error)) {
      return emptyTriageState(report?.target, report?.metadata.completedAt);
    }
    throw error;
  }
}

export async function saveTriageState(filePath: string, state: TriageState): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(triageStateSchema.parse(state), null, 2)}\n`, "utf8");
}

export function markFinding(state: TriageState, findingId: string, status: TriageStatus, note = "", updatedBy = "routecairn"): TriageState {
  return {
    ...state,
    entries: {
      ...state.entries,
      [findingId]: {
        findingId,
        status,
        note,
        updatedBy,
        updatedAt: new Date().toISOString()
      }
    }
  };
}

function isMissingFileError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}