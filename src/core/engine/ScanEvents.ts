import type { ModuleId } from "../planning/ScanPlan.js";

export type ScanExecutionEventType =
  | "PLAN_STARTED"
  | "PLAN_COMPLETED"
  | "SCAN_STARTED"
  | "BASELINE_STARTED"
  | "BASELINE_COMPLETED"
  | "MODULE_QUEUED"
  | "MODULE_STARTED"
  | "MODULE_COMPLETED"
  | "MODULE_BLOCKED"
  | "MODULE_FAILED"
  | "MODULE_CANCELLED"
  | "FINDING_RECORDED"
  | "OBSERVATION_RECORDED"
  | "BUDGET_UPDATED"
  | "CANCELLATION_REQUESTED"
  | "SCAN_CANCELLED"
  | "SCAN_COMPLETED"
  | "SCAN_FAILED"
  | "SCAN_INTERRUPTED"
  | "REPORT_WRITTEN";

export interface ScanExecutionEvent {
  type: ScanExecutionEventType;
  message: string;
  moduleId?: ModuleId;
  metadata?: Record<string, unknown>;
  timestamp?: string;
}

export interface ScanEventSink {
  emit(event: ScanExecutionEvent): void | Promise<void>;
}

export const noopScanEventSink: ScanEventSink = {
  emit: () => undefined
};

export class ScanCancelledError extends Error {
  public constructor(message = "Scan cancelled by operator.") {
    super(message);
    this.name = "ScanCancelledError";
  }
}

export function throwIfScanAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw new ScanCancelledError();
  }
}
