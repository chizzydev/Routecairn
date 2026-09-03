import type { HttpMethod } from "../http/HttpTypes.js";
import { AppError } from "../errors/AppError.js";
import { normalizeUrl } from "../urls/UrlNormalizer.js";
import { ScanContext } from "./ScanContext.js";
import { ModuleRunner } from "../plugins/ModuleRunner.js";
import { PluginRegistry } from "../plugins/PluginRegistry.js";
import { moduleMetadata } from "../planning/ModuleCatalog.js";
import { throwIfScanAborted } from "./ScanEvents.js";
import { ApiMapperModule } from "../../modules/apiMapper/ApiMapperModule.js";
import { ApiProbeModule } from "../../modules/apiProbe/ApiProbeModule.js";
import { AuthSurfaceModule } from "../../modules/authSurface/AuthSurfaceModule.js";
import { AuthenticatedTestingModule } from "../../modules/authenticatedTesting/AuthenticatedTestingModule.js";
import { AuthorizationMatrixModule } from "../../modules/authorizationMatrix/AuthorizationMatrixModule.js";
import { BaselineDetector } from "../../modules/baseline/BaselineDetector.js";
import { BrowserCrawlerModule } from "../../modules/browserCrawler/BrowserCrawlerModule.js";
import { BulkAuthorizationModule } from "../../modules/bulkAuthorization/BulkAuthorizationModule.js";
import { FileAuthorizationModule } from "../../modules/fileAuthorization/FileAuthorizationModule.js";
import { CollectionAuthorizationModule } from "../../modules/collectionAuthorization/CollectionAuthorizationModule.js";
import { CookieReviewModule } from "../../modules/cookieReview/CookieReviewModule.js";
import { CorsReviewModule } from "../../modules/corsReview/CorsReviewModule.js";
import { ExposureReviewModule } from "../../modules/exposureReview/ExposureReviewModule.js";
import { EquivalentRouteModule } from "../../modules/equivalentRouteTesting/EquivalentRouteModule.js";
import { FieldExposureTestingModule } from "../../modules/fieldExposureTesting/FieldExposureTestingModule.js";
import { PrivilegeMutationModule } from "../../modules/privilegeMutation/PrivilegeMutationModule.js";
import { HeaderReviewModule } from "../../modules/headerReview/HeaderReviewModule.js";
import { JsDiscoveryModule } from "../../modules/jsIntelligence/JsDiscoveryModule.js";
import { MethodReviewModule } from "../../modules/methodReview/MethodReviewModule.js";
import { NextJsReviewModule } from "../../modules/nextjsReview/NextJsReviewModule.js";
import { ObjectPairTestingModule } from "../../modules/objectPairTesting/ObjectPairTestingModule.js";
import { ParameterAnalysisModule } from "../../modules/parameterAnalysis/ParameterAnalysisModule.js";
import { PathDiscoveryModule } from "../../modules/pathDiscovery/PathDiscoveryModule.js";
import { ProofModeModule } from "../../modules/proofMode/ProofModeModule.js";
import { RoleComparisonModule } from "../../modules/roleComparison/RoleComparisonModule.js";
import { StateAwareApiModule } from "../../modules/stateAwareApi/StateAwareApiModule.js";
import { TechFingerprintModule } from "../../modules/techFingerprint/TechFingerprintModule.js";
import { VulnerabilityWorkflowModule } from "../../modules/vulnerabilityWorkflows/VulnerabilityWorkflowModule.js";
import { WorkflowValidationModule } from "../../modules/workflowValidation/WorkflowValidationModule.js";
import { SupabaseAuthorizationModule } from "../../modules/supabaseAuthorization/SupabaseAuthorizationModule.js";
import { AuthenticationLifecycleModule } from "../../modules/authenticationLifecycle/AuthenticationLifecycleModule.js";
import { BusinessInvariantModule } from "../../modules/businessInvariant/BusinessInvariantModule.js";
import { ControlledRaceModule } from "../../modules/controlledRace/ControlledRaceModule.js";
import { ApiGraphqlModule } from "../../modules/apiGraphql/ApiGraphqlModule.js";
import { LinkPortalSecurityModule } from "../../modules/linkPortalSecurity/LinkPortalSecurityModule.js";
import { OperationalEndpointSecurityModule } from "../../modules/operationalEndpointSecurity/OperationalEndpointSecurityModule.js";
import { BillingEntitlementModule } from "../../modules/billingEntitlement/BillingEntitlementModule.js";
import { SecretBoundaryModule } from "../../modules/secretBoundary/SecretBoundaryModule.js";
import { AssistedReviewModule } from "../../modules/assistedReview/AssistedReviewModule.js";

export class ScanOrchestrator {
  private readonly moduleRunner: ModuleRunner;

  public constructor() {
    this.moduleRunner = new ModuleRunner(createDefaultPluginRegistry());
  }

  public async run(context: ScanContext): Promise<void> {
    throwIfScanAborted(context.options.abortSignal);
    await context.eventSink.emit({ type: "SCAN_STARTED", message: "Scan execution started." });
    const targetUrl = normalizeUrl(context.options.target);
    const method: HttpMethod = "GET";
    const decision = context.scopeMatcher.decide(targetUrl, method);

    context.state.recordScopeDecision(decision);

    if (!decision.allowed || !decision.normalizedUrl) {
      throw new AppError(`Target is out of scope: ${decision.reason}`, "TARGET_OUT_OF_SCOPE");
    }

    await context.eventSink.emit({ type: "BASELINE_STARTED", message: "Baseline request started." });
    const response = await context.httpClient.send({
      url: decision.normalizedUrl,
      method
    });

    context.state.recordResponse(response);
    await context.eventSink.emit({
      type: "BASELINE_COMPLETED",
      message: "Baseline request completed.",
      metadata: { statusCode: response.statusCode, error: response.error?.name }
    });
    await this.moduleRunner.runPlan(context, context.options.plan);

    throwIfScanAborted(context.options.abortSignal);
    context.state.complete();
    await context.eventSink.emit({ type: "SCAN_COMPLETED", message: "Scan execution completed." });
  }
}

export function createDefaultPluginRegistry(): PluginRegistry {
  const registry = new PluginRegistry();
  registry.register(new BaselineDetector(), moduleMetadata("baseline"));
  registry.register(new TechFingerprintModule(), moduleMetadata("tech-fingerprint"));
  registry.register(new JsDiscoveryModule(), moduleMetadata("js-intelligence"));
  registry.register(new BrowserCrawlerModule(), moduleMetadata("browser-crawler"));
  registry.register(new PathDiscoveryModule(), moduleMetadata("path-discovery"));
  registry.register(new ApiMapperModule(), moduleMetadata("api-mapper"));
  registry.register(new ApiProbeModule(), moduleMetadata("api-probe"));
  registry.register(new AuthSurfaceModule(), moduleMetadata("auth-surface"));
  registry.register(new ParameterAnalysisModule(), moduleMetadata("parameter-analysis"));
  registry.register(new NextJsReviewModule(), moduleMetadata("nextjs-review"));
  registry.register(new VulnerabilityWorkflowModule(), moduleMetadata("vulnerability-workflows"));
  registry.register(new WorkflowValidationModule(), moduleMetadata("workflow-validation"));
  registry.register(new AuthenticatedTestingModule(), moduleMetadata("authenticated-testing"));
  registry.register(new RoleComparisonModule(), moduleMetadata("role-comparison"));
  registry.register(new StateAwareApiModule(), moduleMetadata("state-aware-api"));
  registry.register(new ObjectPairTestingModule(), moduleMetadata("object-pair-testing"));
  registry.register(new FieldExposureTestingModule(), moduleMetadata("field-exposure-testing"));
  registry.register(new AuthorizationMatrixModule(), moduleMetadata("authorization-matrix-testing"));
  registry.register(new CollectionAuthorizationModule(), moduleMetadata("collection-authorization-testing"));
  registry.register(new BulkAuthorizationModule(), moduleMetadata("bulk-authorization-testing"));
  registry.register(new FileAuthorizationModule(), moduleMetadata("file-authorization-testing"));
  registry.register(new EquivalentRouteModule(), moduleMetadata("equivalent-route-testing"));
  registry.register(new PrivilegeMutationModule(), moduleMetadata("privilege-mutation-testing"));
  registry.register(new SupabaseAuthorizationModule(), moduleMetadata("supabase-authorization"));
  registry.register(new AuthenticationLifecycleModule(), moduleMetadata("authentication-lifecycle"));
  registry.register(new BusinessInvariantModule(), moduleMetadata("business-invariant"));
  registry.register(new ControlledRaceModule(), moduleMetadata("controlled-race"));
  registry.register(new ApiGraphqlModule(), moduleMetadata("api-graphql-authorization"));
  registry.register(new LinkPortalSecurityModule(), moduleMetadata("link-portal-export-security"));
  registry.register(new OperationalEndpointSecurityModule(), moduleMetadata("operational-endpoint-security"));
  registry.register(new BillingEntitlementModule(), moduleMetadata("billing-entitlement-security"));
  registry.register(new SecretBoundaryModule(), moduleMetadata("secret-boundary"));
  registry.register(new AssistedReviewModule(), moduleMetadata("assisted-review"));
  registry.register(new HeaderReviewModule(), moduleMetadata("header-review"));
  registry.register(new CookieReviewModule(), moduleMetadata("cookie-review"));
  registry.register(new CorsReviewModule(), moduleMetadata("cors-review"));
  registry.register(new MethodReviewModule(), moduleMetadata("method-review"));
  registry.register(new ExposureReviewModule(), moduleMetadata("exposure-review"));
  registry.register(new ProofModeModule(), moduleMetadata("proof-mode"));
  return registry;
}
