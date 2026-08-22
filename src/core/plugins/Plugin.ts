import type { Finding } from "../findings/Finding.js";
import type { ScanContext } from "../engine/ScanContext.js";
import type {
  ApiMapperReport,
  ApiProbeReport,
  AuthSurfaceReport,
  AuthenticatedScanReport,
  AuthorizationMatrixReport,
  CollectionAuthorizationReport,
  BulkAuthorizationReport,
  FileAuthorizationReport,
  EquivalentRouteReport,
  BaselineReport,
  BrowserCrawlReport,
  DetectedTechnology,
  FieldExposureTestingReport,
  JsIntelligenceReport,
  NextJsReviewReport,
  ObjectPairTestingReport,
  ParameterAnalysisReport,
  ProofModeReport,
  ResponseObservation,
  RoleComparisonReport,
  StateAwareApiReport,
  VulnerabilityWorkflowReport,
  WorkflowValidationReport
} from "../../reports/ReportTypes.js";
import type { PrivilegeMutationReport } from "../../reports/PrivilegeMutationReport.js";

export type PluginPhase = "baseline" | "fingerprint" | "intelligence" | "discovery" | "analysis";

export interface ModuleResult {
  pluginName: string;
  baseline?: BaselineReport;
  technologies?: DetectedTechnology[];
  jsIntelligence?: JsIntelligenceReport;
  browserCrawl?: BrowserCrawlReport;
  apiMapper?: ApiMapperReport;
  apiProbe?: ApiProbeReport;
  authSurface?: AuthSurfaceReport;
  authenticatedScan?: AuthenticatedScanReport;
  roleComparison?: RoleComparisonReport;
  stateAwareApi?: StateAwareApiReport;
  objectPairTesting?: ObjectPairTestingReport;
  fieldExposureTesting?: FieldExposureTestingReport;
  authorizationMatrix?: AuthorizationMatrixReport;
  collectionAuthorization?: CollectionAuthorizationReport;
  bulkAuthorization?: BulkAuthorizationReport;
  fileAuthorization?: FileAuthorizationReport;
  equivalentRouteTesting?: EquivalentRouteReport;
  parameterAnalysis?: ParameterAnalysisReport;
  nextJsReview?: NextJsReviewReport;
  vulnerabilityWorkflows?: VulnerabilityWorkflowReport;
  workflowValidation?: WorkflowValidationReport;
  proofMode?: ProofModeReport;
  privilegeMutation?: PrivilegeMutationReport;
  discoveredUrls?: ResponseObservation[];
  findings?: Finding[];
  notes?: string[];
}

export interface RouteCairnPlugin {
  name: string;
  description: string;
  phase: PluginPhase;
  run(context: ScanContext): Promise<ModuleResult>;
}
