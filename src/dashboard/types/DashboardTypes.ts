import type { ScanProfileName } from "../../config/ScanProfiles.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import type { ScanStudioData } from "../contracts/ScanStudioSchemas.js";

export type DashboardScanSource = "DASHBOARD" | "CLI_IMPORTED" | "REPORT_IMPORTED";
export type DashboardScanStatus = "QUEUED" | "PLANNING" | "RUNNING" | "CANCEL_REQUESTED" | "CANCELLED" | "COMPLETED" | "FAILED" | "INTERRUPTED" | "IMPORTED";
export type ModuleExecutionStatus = "QUEUED" | "RUNNING" | "COMPLETED" | "BLOCKED" | "SKIPPED" | "FAILED" | "CANCELLED";
export type ReviewStatus = "UNREVIEWED" | "IN_REVIEW" | "CONFIRMED" | "FALSE_POSITIVE" | "ACCEPTED_RISK" | "DUPLICATE" | "RESOLVED" | "REOPENED";
export type RemediationStatus = "OPEN" | "ASSIGNED" | "FIX_IN_PROGRESS" | "FIXED_PENDING_RETEST" | "FIXED_VERIFIED" | "WONT_FIX";
export type RetestStatus = "NOT_RETESTED" | "RETEST_SCHEDULED" | "RETEST_RUNNING" | "RETEST_PASSED" | "RETEST_FAILED" | "RETEST_INCONCLUSIVE";
export type ProofReadinessStatus = "NOT_READY" | "MISSING_REVIEW" | "MISSING_EVIDENCE" | "READY" | "IN_PROOF_PACK";

export interface DashboardScanCreateRequest {
  target: string;
  recoveryScope?: import("../../config/ConfigSchema.js").RouteCairnScope | undefined;
  workflowRecoveryDigest?: string | undefined;
  scopeFile?: string | undefined;
  profile: ScanProfileName;
  projectId?: string | undefined;
  targetId?: string | undefined;
  authorizationDeclaration?: string | undefined;
  configFile?: string | undefined;
  authFile?: string | undefined;
  authAFile?: string | undefined;
  authBFile?: string | undefined;
  credentialProfileId?: string | undefined;
  credentialProfileAId?: string | undefined;
  credentialProfileBId?: string | undefined;
  rateLimitPerSecond?: number | undefined;
  concurrency?: number | undefined;
  maxRequests?: number | undefined;
  cleanupReservedRequests?: number | undefined;
  includeModules?: string[] | undefined;
  authenticationLifecycleFile?: string | undefined;
  authenticationLifecycleAutoFile?: string | undefined;
  businessInvariantFile?: string | undefined;
  controlledRaceFile?: string | undefined;
  apiGraphqlFile?: string | undefined;
  linkPortalSecurityFile?: string | undefined;
  operationalEndpointSecurityFile?: string | undefined;
  billingEntitlementFile?: string | undefined;
  assistedReviewFile?: string | undefined;
  preHandoverFile?: string | undefined;
  preHandover?: import("zod").input<typeof import("../../modules/preHandover/PreHandoverPlanner.js").preHandoverInputSchema> | undefined;
  targetAuthorizationFile?: string | undefined;
  targetAuthorization?: import("zod").input<typeof import("../../core/authorization/TargetAuthorization.js").targetAuthorizationSchema> | undefined;
  assistedReview?: import("zod").input<typeof import("../../modules/assistedReview/AssistedReviewPlanner.js").assistedReviewInputSchema> | undefined;
  studio?: ScanStudioData | undefined;
}

export interface PlanPreviewResponse {
  previewIdentity: string;
  profile: string;
  modules: Array<{ id: string; phase: string; settings: Record<string, unknown> }>;
  limits: Record<string, unknown>;
  evidence: Record<string, unknown>;
  skippedModules: Array<{ id: string; reason: string }>;
  controlledWorkflowRequests: Array<{ workflowId: string; exactRequests: number }>;
  planSnapshot: Record<string, unknown>;
  warnings: string[];
}

export interface DashboardScanSummary {
  id: string;
  shortId: string;
  source: DashboardScanSource;
  status: DashboardScanStatus;
  target: string;
  profile: string;
  evidenceLevel: string;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  currentModule?: string;
  progressPercent: number;
  plannedModuleCount: number;
  completedModuleCount: number;
  failedModuleCount: number;
  findingCount: number;
  errorSummary?: string;
}

export interface DashboardFindingSummary {
  id: string;
  title: string;
  module: string;
  category: string;
  endpoint: string;
  severity: string;
  confidence: string;
  reviewStatus: ReviewStatus;
  remediationStatus: RemediationStatus;
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
  retestStatus: RetestStatus;
  proofReadiness: ProofReadinessStatus;
  newOccurrenceKind?: string;
  rowVersion: number;
}

export interface FindingRetestContext {
  findingId: string;
  sourceOccurrenceId: string;
  sourceScanId: string;
  relevantModule: string;
  relevantWorkflow?: string | undefined;
  relevantCase?: string | undefined;
  purpose: string;
}

export interface ReviewTransitionRequest {
  newStatus: ReviewStatus;
  reason?: string | undefined;
  note?: string | undefined;
  duplicateTargetFindingId?: string | undefined;
  reviewerLabel?: string | undefined;
}

export type ComparisonClassification = "NEW" | "PERSISTING" | "CHANGED" | "RESOLVED" | "NOT_RETESTED" | "INCOMPARABLE";
export type RegressionFlag = "REGRESSION" | "RECURRENCE" | "SEVERITY_INCREASE" | "CONFIDENCE_INCREASE" | "EVIDENCE_STRENGTHENED" | "EVIDENCE_WEAKENED" | "AUTHORIZATION_BOUNDARY_WORSENED" | "AUTHORIZATION_BOUNDARY_IMPROVED";
export type ComparisonState = "PENDING" | "ANALYZING" | "COMPLETED" | "PARTIAL" | "FAILED" | "STALE";

export interface ComparisonFindingResult {
  id: string;
  finding: DashboardFindingSummary;
  classification: ComparisonClassification;
  regressionFlags: RegressionFlag[];
  coverageState: string;
  reasonCode: string;
  explanation: string;
  olderOccurrenceId?: string;
  newerOccurrenceId?: string;
  materialChanges: Array<{ field: string; older?: string; newer?: string; direction?: string }>;
  evidenceDelta: Record<string, unknown>;
}

export interface ComparisonResult {
  schemaVersion: 3;
  comparisonId: string;
  state: ComparisonState;
  engineVersion: string;
  oldScanId: string;
  newScanId: string;
  compatible: boolean;
  compatibilityState: string;
  sourceQuality: { older: string; newer: string };
  warnings: string[];
  coverage: {
    sameTarget: boolean;
    scopeState: "EXPANDED" | "REDUCED" | "EQUIVALENT_FOR_FINDING" | "MATERIALLY_CHANGED" | "INCOMPARABLE";
    authenticationState: "EQUIVALENT" | "CHANGED" | "INCOMPARABLE";
    identityState: "EQUIVALENT" | "CHANGED" | "INCOMPARABLE";
    oldProfile: string;
    newProfile: string;
    oldCompletedModules: string[];
    newCompletedModules: string[];
    sharedModules: string[];
    omittedModules: string[];
    addedModules: string[];
    modules: Array<{ moduleId: string; olderState: string; newerState: string; comparable: boolean; reasonCode: string; reason: string }>;
    workflows: Array<{ workflowId: string; olderConfigured: boolean; newerConfigured: boolean; olderCaseCount: number; newerCaseCount: number; matchedCases: number; missingCases: number; changedCases: number; executedMatchedCases: number; comparable: boolean; reason: string }>;
    cases: Array<{ workflowId: string; safeCaseFingerprint: string; safeCaseAlias: string; state: string; compatibility: string; reasonCode: string; reason: string }>;
  };
  planDiff: Array<{ area: string; key: string; category: "UNCHANGED" | "ADDED" | "REMOVED" | "CHANGED" | "EXPANDED" | "REDUCED"; older?: unknown; newer?: unknown; affectsComparability: boolean }>;
  summary: { new: number; regressions: number; recurrences: number; persisting: number; changed: number; resolved: number; notRetested: number; incomparable: number; severityIncreases: number };
  items: ComparisonFindingResult[];
  findingPage?: { page: number; pageSize: number; total: number; totalPages: number };
  findings: {
    new: ComparisonFindingResult[];
    persisting: ComparisonFindingResult[];
    changed: ComparisonFindingResult[];
    resolved: ComparisonFindingResult[];
    notRetested: ComparisonFindingResult[];
    incomparable: ComparisonFindingResult[];
    regressions: ComparisonFindingResult[];
  };
}

export interface ImportResult {
  scanId: string;
  warnings: string[];
}

export interface ReportWithPath {
  report: RouteCairnReport;
  path: string;
}
