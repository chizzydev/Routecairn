import type { Finding } from "../findings/Finding.js";
import type { ScanContext } from "../engine/ScanContext.js";
import type {
  ApiMapperReport,
  ApiProbeReport,
  AuthSurfaceReport,
  AuthenticatedScanReport,
  BaselineReport,
  BrowserCrawlReport,
  DetectedTechnology,
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
  parameterAnalysis?: ParameterAnalysisReport;
  nextJsReview?: NextJsReviewReport;
  vulnerabilityWorkflows?: VulnerabilityWorkflowReport;
  workflowValidation?: WorkflowValidationReport;
  proofMode?: ProofModeReport;
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
