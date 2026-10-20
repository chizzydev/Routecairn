import { DeferredPlugin } from "../plugins/DeferredPlugin.js";
import type { HttpMethod } from "../http/HttpTypes.js";
import { AppError } from "../errors/AppError.js";
import { normalizeUrl } from "../urls/UrlNormalizer.js";
import { ScanContext } from "./ScanContext.js";
import { ModuleRunner } from "../plugins/ModuleRunner.js";
import { PluginRegistry } from "../plugins/PluginRegistry.js";
import { moduleMetadata } from "../planning/ModuleCatalog.js";
import { throwIfScanAborted } from "./ScanEvents.js";

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
  registry.register(
    new DeferredPlugin(
      moduleMetadata("baseline"),
      async () => new (await import("../../modules/baseline/BaselineDetector.js")).BaselineDetector()
    ),
    moduleMetadata("baseline")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("tech-fingerprint"),
      async () => new (await import("../../modules/techFingerprint/TechFingerprintModule.js")).TechFingerprintModule()
    ),
    moduleMetadata("tech-fingerprint")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("js-intelligence"),
      async () => new (await import("../../modules/jsIntelligence/JsDiscoveryModule.js")).JsDiscoveryModule()
    ),
    moduleMetadata("js-intelligence")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("browser-crawler"),
      async () => new (await import("../../modules/browserCrawler/BrowserCrawlerModule.js")).BrowserCrawlerModule()
    ),
    moduleMetadata("browser-crawler")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("path-discovery"),
      async () => new (await import("../../modules/pathDiscovery/PathDiscoveryModule.js")).PathDiscoveryModule()
    ),
    moduleMetadata("path-discovery")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("api-mapper"),
      async () => new (await import("../../modules/apiMapper/ApiMapperModule.js")).ApiMapperModule()
    ),
    moduleMetadata("api-mapper")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("api-probe"),
      async () => new (await import("../../modules/apiProbe/ApiProbeModule.js")).ApiProbeModule()
    ),
    moduleMetadata("api-probe")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("auth-surface"),
      async () => new (await import("../../modules/authSurface/AuthSurfaceModule.js")).AuthSurfaceModule()
    ),
    moduleMetadata("auth-surface")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("parameter-analysis"),
      async () =>
        new (await import("../../modules/parameterAnalysis/ParameterAnalysisModule.js")).ParameterAnalysisModule()
    ),
    moduleMetadata("parameter-analysis")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("nextjs-review"),
      async () => new (await import("../../modules/nextjsReview/NextJsReviewModule.js")).NextJsReviewModule()
    ),
    moduleMetadata("nextjs-review")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("vulnerability-workflows"),
      async () =>
        new (
          await import("../../modules/vulnerabilityWorkflows/VulnerabilityWorkflowModule.js")
        ).VulnerabilityWorkflowModule()
    ),
    moduleMetadata("vulnerability-workflows")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("active-vulnerability-validation"),
      async () =>
        new (await import("../../modules/activeVulnerability/ActiveVulnerabilityModule.js")).ActiveVulnerabilityModule()
    ),
    moduleMetadata("active-vulnerability-validation")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("workflow-validation"),
      async () =>
        new (await import("../../modules/workflowValidation/WorkflowValidationModule.js")).WorkflowValidationModule()
    ),
    moduleMetadata("workflow-validation")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("authenticated-testing"),
      async () =>
        new (
          await import("../../modules/authenticatedTesting/AuthenticatedTestingModule.js")
        ).AuthenticatedTestingModule()
    ),
    moduleMetadata("authenticated-testing")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("role-comparison"),
      async () => new (await import("../../modules/roleComparison/RoleComparisonModule.js")).RoleComparisonModule()
    ),
    moduleMetadata("role-comparison")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("state-aware-api"),
      async () => new (await import("../../modules/stateAwareApi/StateAwareApiModule.js")).StateAwareApiModule()
    ),
    moduleMetadata("state-aware-api")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("object-pair-testing"),
      async () =>
        new (await import("../../modules/objectPairTesting/ObjectPairTestingModule.js")).ObjectPairTestingModule()
    ),
    moduleMetadata("object-pair-testing")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("field-exposure-testing"),
      async () =>
        new (
          await import("../../modules/fieldExposureTesting/FieldExposureTestingModule.js")
        ).FieldExposureTestingModule()
    ),
    moduleMetadata("field-exposure-testing")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("authorization-matrix-testing"),
      async () =>
        new (await import("../../modules/authorizationMatrix/AuthorizationMatrixModule.js")).AuthorizationMatrixModule()
    ),
    moduleMetadata("authorization-matrix-testing")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("collection-authorization-testing"),
      async () =>
        new (
          await import("../../modules/collectionAuthorization/CollectionAuthorizationModule.js")
        ).CollectionAuthorizationModule()
    ),
    moduleMetadata("collection-authorization-testing")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("bulk-authorization-testing"),
      async () =>
        new (await import("../../modules/bulkAuthorization/BulkAuthorizationModule.js")).BulkAuthorizationModule()
    ),
    moduleMetadata("bulk-authorization-testing")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("file-authorization-testing"),
      async () =>
        new (await import("../../modules/fileAuthorization/FileAuthorizationModule.js")).FileAuthorizationModule()
    ),
    moduleMetadata("file-authorization-testing")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("equivalent-route-testing"),
      async () =>
        new (await import("../../modules/equivalentRouteTesting/EquivalentRouteModule.js")).EquivalentRouteModule()
    ),
    moduleMetadata("equivalent-route-testing")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("privilege-mutation-testing"),
      async () =>
        new (await import("../../modules/privilegeMutation/PrivilegeMutationModule.js")).PrivilegeMutationModule()
    ),
    moduleMetadata("privilege-mutation-testing")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("supabase-authorization"),
      async () =>
        new (
          await import("../../modules/supabaseAuthorization/SupabaseAuthorizationModule.js")
        ).SupabaseAuthorizationModule()
    ),
    moduleMetadata("supabase-authorization")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("authentication-lifecycle"),
      async () =>
        new (
          await import("../../modules/authenticationLifecycle/AuthenticationLifecycleModule.js")
        ).AuthenticationLifecycleModule()
    ),
    moduleMetadata("authentication-lifecycle")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("business-invariant"),
      async () =>
        new (await import("../../modules/businessInvariant/BusinessInvariantModule.js")).BusinessInvariantModule()
    ),
    moduleMetadata("business-invariant")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("controlled-race"),
      async () => new (await import("../../modules/controlledRace/ControlledRaceModule.js")).ControlledRaceModule()
    ),
    moduleMetadata("controlled-race")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("api-graphql-authorization"),
      async () => new (await import("../../modules/apiGraphql/ApiGraphqlModule.js")).ApiGraphqlModule()
    ),
    moduleMetadata("api-graphql-authorization")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("protocol-security"),
      async () =>
        new (await import("../../modules/protocolSecurity/ProtocolSecurityModule.js")).ProtocolSecurityModule()
    ),
    moduleMetadata("protocol-security")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("link-portal-export-security"),
      async () =>
        new (await import("../../modules/linkPortalSecurity/LinkPortalSecurityModule.js")).LinkPortalSecurityModule()
    ),
    moduleMetadata("link-portal-export-security")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("operational-endpoint-security"),
      async () =>
        new (
          await import("../../modules/operationalEndpointSecurity/OperationalEndpointSecurityModule.js")
        ).OperationalEndpointSecurityModule()
    ),
    moduleMetadata("operational-endpoint-security")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("billing-entitlement-security"),
      async () =>
        new (await import("../../modules/billingEntitlement/BillingEntitlementModule.js")).BillingEntitlementModule()
    ),
    moduleMetadata("billing-entitlement-security")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("secret-boundary"),
      async () => new (await import("../../modules/secretBoundary/SecretBoundaryModule.js")).SecretBoundaryModule()
    ),
    moduleMetadata("secret-boundary")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("assisted-review"),
      async () => new (await import("../../modules/assistedReview/AssistedReviewModule.js")).AssistedReviewModule()
    ),
    moduleMetadata("assisted-review")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("header-review"),
      async () => new (await import("../../modules/headerReview/HeaderReviewModule.js")).HeaderReviewModule()
    ),
    moduleMetadata("header-review")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("cookie-review"),
      async () => new (await import("../../modules/cookieReview/CookieReviewModule.js")).CookieReviewModule()
    ),
    moduleMetadata("cookie-review")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("cors-review"),
      async () => new (await import("../../modules/corsReview/CorsReviewModule.js")).CorsReviewModule()
    ),
    moduleMetadata("cors-review")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("method-review"),
      async () => new (await import("../../modules/methodReview/MethodReviewModule.js")).MethodReviewModule()
    ),
    moduleMetadata("method-review")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("exposure-review"),
      async () => new (await import("../../modules/exposureReview/ExposureReviewModule.js")).ExposureReviewModule()
    ),
    moduleMetadata("exposure-review")
  );
  registry.register(
    new DeferredPlugin(
      moduleMetadata("proof-mode"),
      async () => new (await import("../../modules/proofMode/ProofModeModule.js")).ProofModeModule()
    ),
    moduleMetadata("proof-mode")
  );
  return registry;
}
