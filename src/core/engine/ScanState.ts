import type { HttpResponse, RequestAuditEntry } from "../http/HttpTypes.js";
import type { ResolvedScanPlan } from "../planning/ScanPlan.js";
import type { ScopeDecision } from "../scope/ScopeTypes.js";
import { redactBodyPreview, redactHeaders } from "../evidence/EvidenceBuilder.js";
import type {
  ApiMapperReport,
  ApiProbeReport,
  AuthSurfaceReport,
  AuthenticatedScanReport,
  AuthorizationMatrixReport,
  BaselineReport,
  BrowserCrawlReport,
  BulkAuthorizationReport,
  CollectionAuthorizationReport,
  DetectedTechnology,
  EquivalentRouteReport,
  FileAuthorizationReport,
  FieldExposureTestingReport,
  IdentityVerificationReport,
  JsIntelligenceReport,
  NextJsReviewReport,
  ObjectPairTestingReport,
  ParameterAnalysisReport,
  PathCandidate,
  ProofModeReport,
  ResponseObservation,
  RoleComparisonReport,
  StateAwareApiReport,
  VulnerabilityWorkflowReport,
  WorkflowValidationReport
} from "../../reports/ReportTypes.js";
import type { PrivilegeMutationReport } from "../../reports/PrivilegeMutationReport.js";
import type { SupabaseAuthorizationReport } from "../../reports/SupabaseAuthorizationReport.js";
import type { AuthenticationLifecycleReport } from "../../reports/AuthenticationLifecycleReport.js";
import type { BusinessInvariantReport } from "../../reports/BusinessInvariantReport.js";
import type { ControlledRaceReport } from "../../reports/ControlledRaceReport.js";
import type { ApiGraphqlReviewReport } from "../../reports/ApiGraphqlReport.js";
import type { LinkPortalSecurityReport } from "../../reports/LinkPortalSecurityReport.js";
import type { OperationalEndpointSecurityReport } from "../../reports/OperationalEndpointSecurityReport.js";
import type { BillingEntitlementReport } from "../../reports/BillingEntitlementReport.js";
import type { SecretBoundaryReport } from "../../reports/SecretBoundaryReport.js";
import type { Finding } from "../findings/Finding.js";
import type { ModuleResult } from "../plugins/Plugin.js";
import type { ValuePresenceAttestation } from "../evidence/ValuePresenceAttestation.js";
import type { ScanRequestLedgerSnapshot } from "../http/ScanRequestLedger.js";

export class ScanState {
  private assistedReview: import("../../reports/AssistedReviewReport.js").AssistedReviewReport | undefined;
  public getAssistedReview() { return this.assistedReview; }
  public getAuthenticationLifecycle() { return this.authenticationLifecycle; }
  public getBusinessInvariant() { return this.businessInvariant; }
  public getControlledRace() { return this.controlledRace; }
  public getSupabaseAuthorization() { return this.supabaseAuthorization; }
  public getPrivilegeMutation() { return this.privilegeMutation; }
  public getModuleResults(): readonly ModuleResult[] { return [...this.moduleResults]; }
  private readonly responses: HttpResponse[] = [];
  private readonly requestAudit: RequestAuditEntry[] = [];
  private requestBudget: ScanRequestLedgerSnapshot | undefined;
  private readonly scopeDecisions: ScopeDecision[] = [];
  private readonly discoveredUrls: ResponseObservation[] = [];
  private readonly findings: Finding[] = [];
  private readonly moduleResults: ModuleResult[] = [];
  private readonly technologies: DetectedTechnology[] = [];
  private readonly queuedPathCandidates: PathCandidate[] = [];
  private jsIntelligence: JsIntelligenceReport | undefined;
  private browserCrawl: BrowserCrawlReport | undefined;
  private apiMapper: ApiMapperReport | undefined;
  private apiProbe: ApiProbeReport | undefined;
  private authSurface: AuthSurfaceReport | undefined;
  private authenticatedScan: AuthenticatedScanReport | undefined;
  private identityVerification: IdentityVerificationReport | undefined;
  private roleComparison: RoleComparisonReport | undefined;
  private stateAwareApi: StateAwareApiReport | undefined;
  private objectPairTesting: ObjectPairTestingReport | undefined;
  private fieldExposureTesting: FieldExposureTestingReport | undefined;
  private authorizationMatrix: AuthorizationMatrixReport | undefined;
  private collectionAuthorization: CollectionAuthorizationReport | undefined;
  private bulkAuthorization: BulkAuthorizationReport | undefined;
  private fileAuthorization: FileAuthorizationReport | undefined;
  private equivalentRouteTesting: EquivalentRouteReport | undefined;
  private parameterAnalysis: ParameterAnalysisReport | undefined;
  private nextJsReview: NextJsReviewReport | undefined;
  private vulnerabilityWorkflows: VulnerabilityWorkflowReport | undefined;
  private workflowValidation: WorkflowValidationReport | undefined;
  private proofMode: ProofModeReport | undefined;
  private privilegeMutation: PrivilegeMutationReport | undefined;
  private supabaseAuthorization: SupabaseAuthorizationReport | undefined;
  private authenticationLifecycle: AuthenticationLifecycleReport | undefined;
  private businessInvariant: BusinessInvariantReport | undefined;
  private controlledRace: ControlledRaceReport | undefined;
  private apiGraphql: ApiGraphqlReviewReport | undefined;
  private linkPortalSecurity: LinkPortalSecurityReport | undefined;
  private operationalEndpointSecurity: OperationalEndpointSecurityReport | undefined;
  private billingEntitlement: BillingEntitlementReport | undefined;
  private secretBoundary: SecretBoundaryReport | undefined;
  private baseline: BaselineReport | undefined;
  private startedAt = new Date();
  private completedAt: Date | undefined;

  public recordResponse(response: HttpResponse): void {
    this.responses.push(response);
  }

  public recordRequestAudit(entry: RequestAuditEntry): void {
    this.requestAudit.push(entry);
  }

  public recordRequestBudget(snapshot: ScanRequestLedgerSnapshot): void {
    this.requestBudget = { ...snapshot };
  }

  public recordScopeDecision(decision: ScopeDecision): void {
    this.scopeDecisions.push(decision);
  }

  public recordBaseline(baseline: BaselineReport): void {
    this.baseline = baseline;
  }

  public recordDiscoveredUrls(observations: ResponseObservation[]): void {
    this.discoveredUrls.push(...observations);
  }

  public recordFindings(findings: Finding[]): void {
    for (const finding of findings) {
      if (!this.findings.some((existing) => existing.id === finding.id)) {
        this.findings.push(finding);
      }
    }
  }

  public recordTechnologies(technologies: DetectedTechnology[]): void {
    for (const technology of technologies) {
      const existing = this.technologies.find((item) => item.name === technology.name);

      if (!existing) {
        this.technologies.push(technology);
        continue;
      }

      existing.signals = [...new Set([...existing.signals, ...technology.signals])];
      existing.confidence = strongerConfidence(existing.confidence, technology.confidence);
    }
  }

  public recordJsIntelligence(report: JsIntelligenceReport): void {
    this.jsIntelligence = report;
    this.queuePathCandidates(report.queuedEndpoints);
  }

  public recordBrowserCrawl(report: BrowserCrawlReport): void {
    this.browserCrawl = report;
    this.queuePathCandidates(report.renderedLinks);
  }

  public recordApiMapper(report: ApiMapperReport): void {
    this.apiMapper = report;
  }

  public recordApiProbe(report: ApiProbeReport): void {
    this.apiProbe = report;
  }

  public recordAuthSurface(report: AuthSurfaceReport): void {
    this.authSurface = report;
  }

  public recordVulnerabilityWorkflows(report: VulnerabilityWorkflowReport): void {
    this.vulnerabilityWorkflows = report;
  }

  public recordAuthenticatedScan(report: AuthenticatedScanReport): void {
    this.authenticatedScan = report;
  }

  public recordIdentityVerification(report: IdentityVerificationReport): void {
    this.identityVerification = report;
  }

  public recordRoleComparison(report: RoleComparisonReport): void {
    this.roleComparison = report;
  }

  public recordStateAwareApi(report: StateAwareApiReport): void {
    this.stateAwareApi = report;
  }

  public recordObjectPairTesting(report: ObjectPairTestingReport): void {
    this.objectPairTesting = report;
  }

  public recordFieldExposureTesting(report: FieldExposureTestingReport): void {
    this.fieldExposureTesting = report;
  }

  public recordAuthorizationMatrix(report: AuthorizationMatrixReport): void {
    this.authorizationMatrix = report;
  }

  public recordCollectionAuthorization(report: CollectionAuthorizationReport): void {
    this.collectionAuthorization = report;
  }

  public recordBulkAuthorization(report: BulkAuthorizationReport): void {
    this.bulkAuthorization = report;
  }

  public recordFileAuthorization(report: FileAuthorizationReport): void {
    this.fileAuthorization = report;
  }

  public recordEquivalentRouteTesting(report: EquivalentRouteReport): void {
    this.equivalentRouteTesting = report;
  }

  public recordParameterAnalysis(report: ParameterAnalysisReport): void {
    this.parameterAnalysis = report;
  }

  public recordNextJsReview(report: NextJsReviewReport): void {
    this.nextJsReview = report;
  }

  public recordWorkflowValidation(report: WorkflowValidationReport): void {
    this.workflowValidation = report;
  }

  public recordProofMode(report: ProofModeReport): void {
    this.proofMode = report;
  }

  public queuePathCandidates(candidates: PathCandidate[]): void {
    for (const candidate of candidates) {
      if (!this.queuedPathCandidates.some((existing) => existing.path === candidate.path && existing.source === candidate.source)) {
        this.queuedPathCandidates.push(candidate);
      }
    }
  }

  public recordModuleResult(result: ModuleResult): void {
    this.moduleResults.push(result);

    if (result.baseline) {
      this.recordBaseline(result.baseline);
    }

    if (result.discoveredUrls) {
      this.recordDiscoveredUrls(result.discoveredUrls);
    }

    if (result.technologies) {
      this.recordTechnologies(result.technologies);
    }

    if (result.jsIntelligence) {
      this.recordJsIntelligence(result.jsIntelligence);
    }

    if (result.browserCrawl) {
      this.recordBrowserCrawl(result.browserCrawl);
    }

    if (result.apiMapper) {
      this.recordApiMapper(result.apiMapper);
    }

    if (result.apiProbe) {
      this.recordApiProbe(result.apiProbe);
    }

    if (result.authSurface) {
      this.recordAuthSurface(result.authSurface);
    }

    if (result.vulnerabilityWorkflows) {
      this.recordVulnerabilityWorkflows(result.vulnerabilityWorkflows);
    }

    if (result.authenticatedScan) {
      this.recordAuthenticatedScan(result.authenticatedScan);
    }

    if (result.roleComparison) {
      this.recordRoleComparison(result.roleComparison);
    }

    if (result.stateAwareApi) {
      this.recordStateAwareApi(result.stateAwareApi);
    }

    if (result.objectPairTesting) {
      this.recordObjectPairTesting(result.objectPairTesting);
    }

    if (result.fieldExposureTesting) {
      this.recordFieldExposureTesting(result.fieldExposureTesting);
    }

    if (result.authorizationMatrix) {
      this.recordAuthorizationMatrix(result.authorizationMatrix);
    }

    if (result.collectionAuthorization) {
      this.recordCollectionAuthorization(result.collectionAuthorization);
    }

    if (result.bulkAuthorization) {
      this.recordBulkAuthorization(result.bulkAuthorization);
    }

    if (result.fileAuthorization) {
      this.recordFileAuthorization(result.fileAuthorization);
    }

    if (result.equivalentRouteTesting) {
      this.recordEquivalentRouteTesting(result.equivalentRouteTesting);
    }

    if (result.parameterAnalysis) {
      this.recordParameterAnalysis(result.parameterAnalysis);
    }

    if (result.nextJsReview) {
      this.recordNextJsReview(result.nextJsReview);
    }

    if (result.workflowValidation) {
      this.recordWorkflowValidation(result.workflowValidation);
    }

    if (result.proofMode) {
      this.recordProofMode(result.proofMode);
    }

    if (result.privilegeMutation) this.privilegeMutation = result.privilegeMutation;
    if (result.supabaseAuthorization) this.supabaseAuthorization = result.supabaseAuthorization;
    if (result.authenticationLifecycle) this.authenticationLifecycle = result.authenticationLifecycle;
    if (result.businessInvariant) this.businessInvariant = result.businessInvariant;
    if (result.controlledRace) this.controlledRace = result.controlledRace;
    if (result.apiGraphql) this.apiGraphql = result.apiGraphql;
    if (result.linkPortalSecurity) this.linkPortalSecurity = result.linkPortalSecurity;
    if (result.operationalEndpointSecurity) this.operationalEndpointSecurity = result.operationalEndpointSecurity;
    if (result.billingEntitlement) this.billingEntitlement = result.billingEntitlement;
    if (result.secretBoundary) this.secretBoundary = result.secretBoundary;
    if (result.assistedReview) this.assistedReview = result.assistedReview;

    if (result.findings) {
      this.recordFindings(result.findings);
    }
  }

  public getBaseline(): BaselineReport | undefined {
    return this.baseline;
  }

  public recordApiGraphql(report: ApiGraphqlReviewReport): void { this.apiGraphql = report; }
  public getApiGraphql(): ApiGraphqlReviewReport | undefined { return this.apiGraphql; }
  public getLinkPortalSecurity(): LinkPortalSecurityReport | undefined { return this.linkPortalSecurity; }
  public getOperationalEndpointSecurity(): OperationalEndpointSecurityReport | undefined { return this.operationalEndpointSecurity; }
  public getBillingEntitlement(): BillingEntitlementReport | undefined { return this.billingEntitlement; }
  public getSecretBoundary(): SecretBoundaryReport | undefined { return this.secretBoundary; }

  public getResponses(): HttpResponse[] {
    return [...this.responses];
  }

  public getRequestAudit(): RequestAuditEntry[] {
    return this.requestAudit.map(serializeRequestAuditEntry);
  }

  public getTechnologies(): DetectedTechnology[] {
    return [...this.technologies];
  }

  public getQueuedPathCandidates(): PathCandidate[] {
    return [...this.queuedPathCandidates];
  }

  public getJsIntelligence(): JsIntelligenceReport | undefined {
    return this.jsIntelligence;
  }

  public getBrowserCrawl(): BrowserCrawlReport | undefined {
    return this.browserCrawl;
  }

  public getDiscoveredUrls(): ResponseObservation[] {
    return [...this.discoveredUrls];
  }

  public getFindings(): Finding[] {
    return [...this.findings];
  }

  public getApiMapper(): ApiMapperReport | undefined {
    return this.apiMapper;
  }

  public getApiProbe(): ApiProbeReport | undefined {
    return this.apiProbe;
  }

  public getAuthSurface(): AuthSurfaceReport | undefined {
    return this.authSurface;
  }

  public getAuthenticatedScan(): AuthenticatedScanReport | undefined {
    return this.authenticatedScan;
  }

  public getIdentityVerification(): IdentityVerificationReport | undefined {
    return this.identityVerification;
  }

  public getRoleComparison(): RoleComparisonReport | undefined {
    return this.roleComparison;
  }

  public getStateAwareApi(): StateAwareApiReport | undefined {
    return this.stateAwareApi;
  }

  public getObjectPairTesting(): ObjectPairTestingReport | undefined {
    return this.objectPairTesting;
  }

  public getFieldExposureTesting(): FieldExposureTestingReport | undefined {
    return this.fieldExposureTesting;
  }

  public getAuthorizationMatrix(): AuthorizationMatrixReport | undefined {
    return this.authorizationMatrix;
  }

  public getCollectionAuthorization(): CollectionAuthorizationReport | undefined {
    return this.collectionAuthorization;
  }

  public getBulkAuthorization(): BulkAuthorizationReport | undefined {
    return this.bulkAuthorization;
  }

  public getFileAuthorization(): FileAuthorizationReport | undefined {
    return this.fileAuthorization;
  }

  public getEquivalentRouteTesting(): EquivalentRouteReport | undefined {
    return this.equivalentRouteTesting;
  }

  public getParameterAnalysis(): ParameterAnalysisReport | undefined {
    return this.parameterAnalysis;
  }

  public getVulnerabilityWorkflows(): VulnerabilityWorkflowReport | undefined {
    return this.vulnerabilityWorkflows;
  }

  public getWorkflowValidation(): WorkflowValidationReport | undefined {
    return this.workflowValidation;
  }

  public getNextJsReview(): NextJsReviewReport | undefined {
    return this.nextJsReview;
  }

  public getProofMode(): ProofModeReport | undefined {
    return this.proofMode;
  }

  public complete(): void {
    this.completedAt = new Date();
  }

  public toReport(plan: ResolvedScanPlan) {
    const completedAt = this.completedAt ?? new Date();
    const responses = this.responses.map((response) => serializeResponse(response, plan.evidence.collectBodyPreview));
    const discoveredUrls = this.discoveredUrls.map((observation) => serializeObservation(observation, plan.evidence.collectBodyPreview));
    const findings = this.findings.map((finding) => serializeFinding(finding, plan.evidence.collectBodyPreview));

    return {
      metadata: {
        startedAt: this.startedAt.toISOString(),
        completedAt: completedAt.toISOString(),
        durationMs: completedAt.getTime() - this.startedAt.getTime(),
        totalRequests: this.requestBudget?.totalTransmitted ?? this.responses.filter((response) => !response.error || response.error.name !== "DuplicateRequest").length,
        failedRequests: this.responses.filter((response) => response.error).length
      },
      ...(this.requestBudget ? { requestBudget: { ...this.requestBudget } } : {}),
      ...(this.baseline ? { baseline: this.baseline } : {}),
      scopeDecisions: this.scopeDecisions,
      requestAudit: plan.evidence.collectRequestAudit ? this.requestAudit.map(serializeRequestAuditEntry) : [],
      responses,
      technologies: this.technologies,
      ...(this.jsIntelligence ? { jsIntelligence: this.jsIntelligence } : {}),
      ...(this.browserCrawl ? { browserCrawl: this.browserCrawl } : {}),
      ...(this.apiMapper ? { apiMapper: this.apiMapper } : {}),
      ...(this.apiProbe ? { apiProbe: this.apiProbe } : {}),
      ...(this.authSurface ? { authSurface: this.authSurface } : {}),
      ...(this.authenticatedScan ? { authenticatedScan: this.authenticatedScan } : {}),
      ...(this.identityVerification ? { identityVerification: this.identityVerification } : {}),
      ...(this.roleComparison ? { roleComparison: this.roleComparison } : {}),
      ...(this.stateAwareApi ? { stateAwareApi: this.stateAwareApi } : {}),
      ...(this.objectPairTesting ? { objectPairTesting: this.objectPairTesting } : {}),
      ...(this.fieldExposureTesting ? { fieldExposureTesting: this.fieldExposureTesting } : {}),
      ...(this.authorizationMatrix ? { authorizationMatrix: this.authorizationMatrix } : {}),
      ...(this.collectionAuthorization ? { collectionAuthorization: this.collectionAuthorization } : {}),
      ...(this.bulkAuthorization ? { bulkAuthorization: this.bulkAuthorization } : {}),
      ...(this.fileAuthorization ? { fileAuthorization: this.fileAuthorization } : {}),
      ...(this.equivalentRouteTesting ? { equivalentRouteTesting: this.equivalentRouteTesting } : {}),
      ...(this.parameterAnalysis ? { parameterAnalysis: this.parameterAnalysis } : {}),
      ...(this.nextJsReview ? { nextJsReview: this.nextJsReview } : {}),
      ...(this.vulnerabilityWorkflows ? { vulnerabilityWorkflows: this.vulnerabilityWorkflows } : {}),
      ...(this.workflowValidation ? { workflowValidation: this.workflowValidation } : {}),
      ...(this.proofMode ? { proofMode: this.proofMode } : {}),
      ...(this.privilegeMutation ? { privilegeMutation: this.privilegeMutation } : {}),
      ...(this.supabaseAuthorization ? { supabaseAuthorization: this.supabaseAuthorization } : {}),
      ...(this.authenticationLifecycle ? { authenticationLifecycle: this.authenticationLifecycle } : {}),
      ...(this.businessInvariant ? { businessInvariant: this.businessInvariant } : {}),
      ...(this.controlledRace ? { controlledRace: this.controlledRace } : {}),
      ...(this.apiGraphql ? { apiGraphql: this.apiGraphql } : {}),
      ...(this.linkPortalSecurity ? { linkPortalSecurity: this.linkPortalSecurity } : {}),
      ...(this.operationalEndpointSecurity ? { operationalEndpointSecurity: this.operationalEndpointSecurity } : {}),
      ...(this.billingEntitlement ? { billingEntitlement: this.billingEntitlement } : {}),
      ...(this.secretBoundary ? { secretBoundary: this.secretBoundary } : {}),
      ...(this.assistedReview ? { assistedReview: this.assistedReview } : {}),
      discoveredUrls,
      findings
    };
  }
}

function serializeResponse(response: HttpResponse, includePreview: boolean): HttpResponse {
  const copy = {
    ...response,
    headers: redactHeaders(response.headers),
    ...(response.valueAttestations ? { valueAttestations: cloneValueAttestations(response.valueAttestations) } : {})
  };
  if (copy.bodyPreview && includePreview) {
    copy.bodyPreview = redactBodyPreview(copy.bodyPreview);
  } else {
    delete copy.bodyPreview;
  }
  return copy;
}

function serializeObservation(observation: ResponseObservation, includePreview: boolean): ResponseObservation {
  const copy = { ...observation };
  if (copy.responseHeaders) {
    copy.responseHeaders = redactHeaders(copy.responseHeaders);
  }
  if (copy.bodyPreview && includePreview) {
    copy.bodyPreview = redactBodyPreview(copy.bodyPreview);
  } else {
    delete copy.bodyPreview;
  }
  return copy;
}

function serializeFinding(finding: Finding, includePreview: boolean): Finding {
  const evidence = {
    ...finding.evidence,
    ...(finding.evidence.valueAttestations
      ? { valueAttestations: cloneValueAttestations(finding.evidence.valueAttestations) }
      : {})
  };
  if (evidence.responseHeaders) {
    evidence.responseHeaders = redactHeaders(evidence.responseHeaders);
  }
  if (evidence.bodyPreview && includePreview) {
    evidence.bodyPreview = redactBodyPreview(evidence.bodyPreview);
  } else {
    delete evidence.bodyPreview;
  }
  return { ...finding, evidence };
}

function serializeRequestAuditEntry(entry: RequestAuditEntry): RequestAuditEntry {
  return {
    ...entry,
    requestHeaders: { ...entry.requestHeaders },
    redirectChain: entry.redirectChain.map((redirect) => ({ ...redirect })),
    ...(entry.valueAttestations ? { valueAttestations: cloneValueAttestations(entry.valueAttestations) } : {})
  };
}

function cloneValueAttestations(attestations: readonly ValuePresenceAttestation[]): ValuePresenceAttestation[] {
  return attestations.map((attestation) => ({
    ...attestation,
    reproductionSteps: [...attestation.reproductionSteps]
  }));
}

function strongerConfidence(left: DetectedTechnology["confidence"], right: DetectedTechnology["confidence"]): DetectedTechnology["confidence"] {
  const order: Record<DetectedTechnology["confidence"], number> = {
    Low: 0,
    Medium: 1,
    High: 2
  };

  return order[right] > order[left] ? right : left;
}
