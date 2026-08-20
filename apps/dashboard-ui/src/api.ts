export interface ScanSummary {
  id: string;
  shortId: string;
  status: string;
  target: string;
  profile: string;
  evidenceLevel: string;
  createdAt: string;
  startedAt?: string;
  currentModule?: string;
  progressPercent: number;
  plannedModuleCount: number;
  completedModuleCount: number;
  failedModuleCount: number;
  findingCount: number;
  errorSummary?: string;
}

export interface FindingSummary {
  id: string;
  title: string;
  module: string;
  category: string;
  endpoint: string;
  severity: string;
  confidence: string;
  reviewStatus: string;
  remediationStatus: string;
  firstSeenAt: string;
  lastSeenAt: string;
  occurrenceCount: number;
  projectId?: string;
  projectName?: string;
  targetId?: string;
  targetName?: string;
  method: string;
  effectiveSeverity: string;
  assigneeUserId?: string;
  assigneeLabel?: string;
  reviewerUserId?: string;
  reviewerLabel?: string;
  reviewStartedAt?: string;
  retestStatus: string;
  proofReadiness: string;
  newOccurrenceKind?: string;
  rowVersion: number;
}

export interface FindingPage {
  findings: FindingSummary[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface FindingDetailData {
  finding: FindingSummary;
  description?: string;
  occurrences: Array<Record<string, unknown> & { id: string; scan_id: string; created_at: string; severity: string; confidence: string; evidence_summary: string }>;
  occurrenceDifferences: Array<Record<string, unknown>>;
  evidence: Array<Record<string, unknown> & { id: string; finding_occurrence_id: string; evidence_type: string; evidence_level: string; safe_summary: string; safe_structured_data_json: string; artifact_id?: string; missing_file_flag?: number }>;
  reviews: Array<Record<string, unknown> & { id: string; previous_review_status?: string; new_review_status: string; reason?: string; review_note?: string; actor_label?: string; local_reviewer_label?: string; created_at: string }>;
  remediationHistory: Array<Record<string, unknown>>;
  notes: Array<Record<string, unknown> & { id: string; safe_text: string; author_label?: string; created_at: string }>;
  retests: Array<Record<string, unknown>>;
  duplicates: Array<Record<string, unknown>>;
  related: Array<Record<string, unknown>>;
}

export interface PlanPreview {
  previewIdentity: string;
  profile: string;
  modules: Array<{ id: string; phase: string; settings: Record<string, unknown> }>;
  limits: Record<string, unknown>;
  evidence: Record<string, unknown>;
  skippedModules: Array<{ id: string; reason: string }>;
  controlledWorkflowRequests: Array<{
    workflowId: string;
    exactRequests: number;
  }>;
  planSnapshot: Record<string, unknown>;
  warnings: string[];
}

export interface ProjectSummary {
  id: string;
  name: string;
  description?: string;
  tags: string[];
  defaultProfile?: string;
  defaultScope: Record<string, unknown>;
  openFindingCount: number;
  archived: boolean;
  rowVersion: number;
  targetCount: number;
  scanCount: number;
}

export interface TargetSummary {
  id: string;
  projectId?: string;
  displayName: string;
  baseOrigin: string;
  authorizationType: string;
  authorizationSummary: string;
  classification: string;
  defaultProfile?: string;
  scanCount: number;
  openFindingCount: number;
  description?: string;
  tags: string[];
  approvedScope: Record<string, unknown>;
  defaultConfigurationId?: string;
  defaultCredentialProfileId?: string;
  defaultEvidenceLevel?: string;
  defaultAuthTemplate: Record<string, unknown>;
  archived: boolean;
  rowVersion: number;
}

export interface AuditEvent {
  id: string;
  actor_label: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  safe_summary: string;
  safe_metadata_json: string;
  created_at: string;
}

const csrfStorageKey = "routecairn.dashboard.csrf";
let csrfToken = readStoredCsrfToken();

export interface ApiDiagnostic {
  path: string[];
  message: string;
}

export class DashboardApiError extends Error {
  public constructor(
    message: string,
    public readonly code: string,
    public readonly diagnostics: readonly ApiDiagnostic[] = [],
    public readonly coreCode?: string
  ) {
    super(message);
    this.name = "DashboardApiError";
  }
}

export function setCsrfToken(value: string): void {
  csrfToken = value;
  if (value) window.sessionStorage.setItem(csrfStorageKey, value);
  else window.sessionStorage.removeItem(csrfStorageKey);
}

export async function bootstrap(): Promise<boolean> {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const token = params.get("bootstrap");
  const response = await fetch(token ? "/api/session/bootstrap" : "/api/auth/csrf", {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(token ? { token } : {})
  });
  if (!token && response.status === 401) return false;
  if (!response.ok) throw new Error("Dashboard bootstrap failed.");
  const body = (await response.json()) as { csrfToken: string };
  setCsrfToken(body.csrfToken);
  if (token) history.replaceState(null, "", window.location.pathname);
  return true;
}

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin" });
  if (response.status === 401) window.dispatchEvent(new Event("routecairn:session-expired"));
  if (!response.ok) throw await responseError(response);
  return (await response.json()) as T;
}

export async function apiMutation<T>(path: string, method: "POST" | "PATCH", body: unknown): Promise<T> {
  const effectiveCsrfToken = csrfToken || readStoredCsrfToken();
  const response = await fetch(path, {
    method,
    headers: { "content-type": "application/json", "x-csrf-token": effectiveCsrfToken },
    credentials: "same-origin",
    body: JSON.stringify(body)
  });
  if (response.status === 401) window.dispatchEvent(new Event("routecairn:session-expired"));
  if (!response.ok) throw await responseError(response);
  return (await response.json()) as T;
}

function readStoredCsrfToken(): string {
  try {
    return window.sessionStorage.getItem(csrfStorageKey) ?? "";
  } catch {
    return "";
  }
}

async function responseError(response: Response): Promise<DashboardApiError> {
  const body = await response.json().catch(() => ({})) as { error?: string; code?: string; coreCode?: string; diagnostics?: ApiDiagnostic[] };
  return new DashboardApiError(body.error ?? "API request failed.", body.code ?? "API_REQUEST_FAILED", body.diagnostics ?? [], body.coreCode);
}
