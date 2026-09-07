import { AppError } from "../errors/AppError.js";
import { compareMetadata, PluginRegistry } from "../plugins/PluginRegistry.js";
import { scanProfileDefinitions } from "./ProfileDefinitions.js";
import type { ScanProfileName } from "../../config/ScanProfiles.js";
import type { EvidenceLevel, EvidencePolicy, ModuleId, ModulePlan, ModuleSettings, ResolvedScanPlan, ScanLimits, ScanPlannerInput, ScanProfileDefinition } from "./ScanPlan.js";
import { scanPlanSchemaVersion } from "./ScanPlan.js";
import { validatePreHandoverBindings } from "../../modules/preHandover/PreHandoverPlanner.js";
import { targetAuthorizationSchema } from "../authorization/TargetAuthorization.js";

const defaultRetry = { maxAttempts: 2, baseDelayMs: 250, maxDelayMs: 2000, retryStatusCodes: [408, 429, 500, 502, 503, 504] };
const hardSafetyCeilings = {
  maxDepth: 10,
  rateLimitPerSecond: 50,
  concurrency: 50,
  bodyPreviewBytes: 1024 * 1024,
  maxResponseBytes: 4 * 1024 * 1024,
  maxRequests: 10000,
  cleanupReservedRequests: 5000,
  maxScanDurationMs: 60 * 60 * 1000,
  retryMaxAttempts: 5
};

const browserResourceTypes = new Set([
  "document",
  "stylesheet",
  "image",
  "media",
  "font",
  "script",
  "texttrack",
  "xhr",
  "fetch",
  "eventsource",
  "websocket",
  "manifest",
  "other"
]);

export class ScanPlanner {
  public constructor(
    private readonly registry: PluginRegistry,
    private readonly definitions: Partial<Record<ScanProfileName, ScanProfileDefinition>> = scanProfileDefinitions
  ) {}

  public resolve(input: ScanPlannerInput): ResolvedScanPlan {
    validatePreHandoverBindings(input);
    if (input.targetAuthorization) {
      const authorization = targetAuthorizationSchema.parse(input.targetAuthorization);
      if (authorization.bugBounty && !authorization.bugBounty.authenticationPermitted && (input.authProfile || input.authProfileSet)) throw new Error("TARGET_AUTHENTICATION_PROHIBITED");
      input = { ...input, targetAuthorization: authorization };
    }
    if (input.preHandover) {
      if (input.assistedReview && JSON.stringify(input.assistedReview) !== JSON.stringify(input.preHandover.review)) throw new Error("PRE_HANDOVER_REVIEW_CONFLICT");
      const selected = new Set<ModuleId>([...(input.overrides?.includeModules ?? []), ...input.preHandover.sequence, "assisted-review"]);
      const addDependencies = (module: ModuleId): void => { for (const dependency of this.registry.get(module)?.metadata.dependencies ?? []) if (!selected.has(dependency)) { selected.add(dependency); addDependencies(dependency); } };
      for (const module of selected) addDependencies(module);
      if (input.overrides?.excludeModules?.some((module) => selected.has(module))) throw new Error("PRE_HANDOVER_REQUIRED_MODULE_EXCLUDED");
      input = { ...input, assistedReview: input.preHandover.review, overrides: { ...input.overrides, includeModules: [...selected] } };
    }
    const definition = this.definitions[input.requestedProfile];
    if (!definition) {
      throw new AppError(`Unknown scan profile "${input.requestedProfile}".`, "SCAN_PROFILE_INVALID");
    }

    const authentication = {
      ...definition.authentication,
      hasSingleProfile: Boolean(input.authProfile),
      hasAccountPair: Boolean(input.authProfileSet)
    };

    if (authentication.requireSingleProfile && !authentication.hasSingleProfile) {
      throw new AppError(`Profile "${definition.name}" requires --auth.`, "SCAN_AUTH_REQUIRED");
    }

    if (authentication.requireAccountPair && !authentication.hasAccountPair) {
      throw new AppError(`Profile "${definition.name}" requires --auth-a and --auth-b.`, "SCAN_AUTH_PAIR_REQUIRED");
    }
    const resolvedLimits = resolveLimits(definition, input);
    const program = input.targetAuthorization?.bugBounty;
    const limits = freezeLimits(program ? {
      ...resolvedLimits,
      rateLimitPerSecond: Math.min(resolvedLimits.rateLimitPerSecond, program.rateLimitPerSecond),
      maxRequests: Math.min(resolvedLimits.maxRequests, program.maxRequests),
      cleanupReservedRequests: Math.min(resolvedLimits.cleanupReservedRequests, resolvedLimits.maxRequests, program.maxRequests)
    } : resolvedLimits);
    if (input.assistedReview?.requireVerifiedIdentity && !input.authProfile && !input.authProfileSet) throw new AppError("This review requires an authenticated identity profile.", "ASSISTED_REVIEW_AUTH_REQUIRED");
    if (input.assistedReview?.requireAccountPair && !input.authProfileSet) throw new AppError("This review requires an Account A/B profile pair.", "ASSISTED_REVIEW_AUTH_PAIR_REQUIRED");
    const { modules, skippedModules } = this.resolveModules(definition, limits, authentication, input);

    const plan: ResolvedScanPlan = deepFreeze({
      schemaVersion: scanPlanSchemaVersion,
      profile: definition.name,
      displayName: definition.displayName,
      description: definition.description,
      metadata: {
        requestedProfile: input.requestedProfile,
        resolvedProfile: definition.name,
        ...(input.legacyMode ? { legacyMode: input.legacyMode } : {}),
        ...(input.legacyModeTranslation ? { legacyModeTranslation: input.legacyModeTranslation } : {}),
        createdAt: new Date().toISOString()
      },
      modules,
      skippedModules: [...definition.disabledModules.map((id) => ({ id, reason: "disabled-by-profile" })), ...skippedModules],
      limits,
      authentication,
      evidence: resolveEvidencePolicy(definition.evidence, input.overrides?.evidenceLevel),
      output: { ...definition.output },
      failurePolicy: definition.failurePolicy,
      optionalModulesMayBeSkipped: definition.optionalModulesMayBeSkipped,
      reportFocus: [...definition.reportFocus],
      ...(input.targetAuthorization ? { targetAuthorization: input.targetAuthorization } : {}),
      ...(input.preHandover ? { preHandover: input.preHandover } : {}),
      ...(input.assistedReview ? { assistedReview: input.assistedReview } : {}),
      ...(input.objectPairTesting ? { objectPairTesting: input.objectPairTesting } : {}),
      ...(input.fieldExposureTesting ? { fieldExposureTesting: input.fieldExposureTesting } : {}),
      ...(input.authorizationMatrixTesting ? { authorizationMatrixTesting: input.authorizationMatrixTesting } : {}),
      ...(input.collectionAuthorizationTesting ? { collectionAuthorizationTesting: input.collectionAuthorizationTesting } : {}),
      ...(input.bulkAuthorizationTesting ? { bulkAuthorizationTesting: input.bulkAuthorizationTesting } : {}),
      ...(input.fileAuthorizationTesting ? { fileAuthorizationTesting: input.fileAuthorizationTesting } : {}),
      ...(input.equivalentRouteTesting ? { equivalentRouteTesting: input.equivalentRouteTesting } : {}),
      ...(input.privilegeMutationTesting ? { privilegeMutationTesting: input.privilegeMutationTesting } : {}),
      ...(input.supabaseAuthorization ? { supabaseAuthorization: input.supabaseAuthorization } : {}),
      ...(input.authenticationLifecycle ? { authenticationLifecycle: input.authenticationLifecycle } : {}),
      ...(input.businessInvariant ? { businessInvariant: input.businessInvariant } : {}),
      ...(input.controlledRace ? { controlledRace: input.controlledRace } : {}),
      ...(input.apiGraphql ? { apiGraphql: input.apiGraphql } : {}),
      ...(input.linkPortalSecurity ? { linkPortalSecurity: input.linkPortalSecurity } : {}),
      ...(input.operationalEndpointSecurity ? { operationalEndpointSecurity: input.operationalEndpointSecurity } : {})
      ,...(input.billingEntitlement ? { billingEntitlement: input.billingEntitlement } : {})
    });

    this.validate(plan);
    return plan;
  }

  private resolveModules(
    definition: ScanProfileDefinition,
    limits: ScanLimits,
    authentication: ResolvedScanPlan["authentication"],
    input: ScanPlannerInput
  ): { modules: readonly ModulePlan[]; skippedModules: Array<{ id: ModuleId; reason: string }> } {
    const seen = new Set<ModuleId>();
    const modulePlans: ModulePlan[] = [];
    const skippedModules: Array<{ id: ModuleId; reason: string }> = [];
    const explicitIncludes = new Set(input.overrides?.includeModules ?? []);
    const explicitExcludes = new Set(input.overrides?.excludeModules ?? []);
    const exactModuleSubset = Boolean(input.overrides?.includeModules);
    const enabledModules = (exactModuleSubset ? [...explicitIncludes] : [...definition.enabledModules]).filter((id) => !explicitExcludes.has(id));

    for (const id of enabledModules) {
      if (seen.has(id)) {
        throw new AppError(`Profile "${definition.name}" references duplicate module "${id}".`, "SCAN_PLAN_DUPLICATE_MODULE");
      }
      seen.add(id);

      if (!exactModuleSubset && definition.disabledModules.includes(id)) {
        throw new AppError(`Profile "${definition.name}" both enables and disables module "${id}".`, "SCAN_PLAN_CONFLICT");
      }

      const registration = this.registry.get(id);
      if (!registration) {
        throw new AppError(`Profile "${definition.name}" references unknown module "${id}".`, "SCAN_PLAN_UNKNOWN_MODULE");
      }
      const authSkipReason = authSkipForModule(registration.metadata.requiresAuthentication, authentication);
      if (authSkipReason) {
        if (explicitIncludes.has(id) || !definition.optionalModulesMayBeSkipped) {
          throw new AppError(`Module "${id}" requires ${authSkipReason}.`, "SCAN_AUTH_MODULE_REQUIRED");
        }
        skippedModules.push({ id, reason: `missing-${authSkipReason}` });
        continue;
      }

      const overrides = { ...(definition.moduleSettings[id] ?? {}), ...(input.overrides?.moduleSettings?.[id] ?? {}) };
      this.validateSettings(id, overrides, registration.metadata.supportedSettings);
      const settings = { ...registration.metadata.defaultSettings, ...overrides };

      modulePlans.push({
        id,
        phase: registration.metadata.phase,
        settings,
        limits: { ...(definition.perModuleLimits[id] ?? {}) },
        includedBecause: [`profile:${definition.name}`, ...registration.metadata.capabilities.map((capability) => `capability:${capability}`)]
      });
    }

    const sorted = this.orderModules(modulePlans, input.preHandover?.sequence);

    this.validateDependencies(definition.name, sorted);
    this.validateEvidence(definition, sorted);
    this.validateMonitoring(definition, sorted);
    validatePositiveLimits(limits);
    return { modules: sorted, skippedModules };
  }

  private orderModules(modulePlans: readonly ModulePlan[], sequence: readonly ModuleId[] = []): ModulePlan[] {
    const remaining = new Map(modulePlans.map((modulePlan) => [modulePlan.id, modulePlan]));
    const ordered: ModulePlan[] = [];

    while (remaining.size > 0) {
      const ready = [...remaining.values()]
        .filter((modulePlan) => this.constraintsFor(modulePlan.id).every((dependency) => !remaining.has(dependency)) && sequence.slice(0, Math.max(0, sequence.indexOf(modulePlan.id))).every((dependency) => !remaining.has(dependency)))
        .sort((left, right) => {
          const leftMetadata = this.registry.get(left.id)?.metadata;
          const rightMetadata = this.registry.get(right.id)?.metadata;
          if (!leftMetadata || !rightMetadata) return left.id.localeCompare(right.id);
          return compareMetadata(leftMetadata, rightMetadata);
        });

      const next = ready[0];
      if (!next) {
        throw new AppError(`Module ordering contains a dependency cycle or unsatisfied ordering constraint.`, "SCAN_PLAN_INVALID_ORDER");
      }

      ordered.push(next);
      remaining.delete(next.id);
    }

    return ordered;
  }

  private constraintsFor(id: ModuleId): readonly ModuleId[] {
    const metadata = this.registry.get(id)?.metadata;
    return metadata ? [...metadata.dependencies, ...metadata.orderAfter] : [];
  }

  private validateSettings(id: ModuleId, settings: ModuleSettings, supportedSettings: readonly (keyof ModuleSettings)[]): void {
    const supported = new Set<keyof ModuleSettings>(supportedSettings);
    for (const key of Object.keys(settings) as Array<keyof ModuleSettings>) {
      if (!supported.has(key)) {
        throw new AppError(`Module "${id}" does not support setting "${key}".`, "SCAN_PLAN_UNSUPPORTED_MODULE_OVERRIDE");
      }

      const value = settings[key];
      const zeroAllowed = key === "maxNextJsCacheDifferentialRequests";
      if (typeof value === "number" && (!Number.isFinite(value) || (zeroAllowed ? value < 0 : value <= 0))) {
        throw new AppError(`Module "${id}" setting "${key}" must be a positive number.`, "SCAN_PLAN_INVALID_MODULE_SETTING");
      }

      if (key === "nextJsCacheReviewMode" && value !== "PASSIVE_CACHE_REVIEW" && value !== "CONTROLLED_CACHE_DIFFERENTIAL") {
        throw new AppError(`Module "${id}" setting "${key}" is invalid.`, "SCAN_PLAN_INVALID_MODULE_SETTING");
      }

      if (key === "browserAllowedResourceTypes" && Array.isArray(value)) {
        for (const resourceType of value) {
          if (!browserResourceTypes.has(resourceType)) {
            throw new AppError(`Module "${id}" setting "${key}" contains unsupported resource type "${resourceType}".`, "SCAN_PLAN_INVALID_MODULE_SETTING");
          }
        }
      }

      if ((key === "browserAllowedThirdPartyOrigins" || key === "browserAllowedPrivateOrigins") && Array.isArray(value)) {
        for (const origin of value) {
          if (typeof origin !== "string" || !isBrowserOrigin(origin)) {
            throw new AppError(`Module "${id}" setting "${key}" contains invalid origin "${origin}".`, "SCAN_PLAN_INVALID_MODULE_SETTING");
          }
        }
      }
    }
  }

  private validateDependencies(profileName: string, modules: readonly ModulePlan[]): void {
    const positions = new Map(modules.map((modulePlan, index) => [modulePlan.id, index]));

    for (const modulePlan of modules) {
      const metadata = this.registry.get(modulePlan.id)?.metadata;
      if (!metadata) continue;

      for (const dependency of metadata.dependencies) {
        const dependencyPosition = positions.get(dependency);
        if (typeof dependencyPosition !== "number") {
          throw new AppError(`Profile "${profileName}" includes "${modulePlan.id}" without required dependency "${dependency}".`, "SCAN_PLAN_MISSING_DEPENDENCY");
        }
        if ((positions.get(modulePlan.id) ?? 0) < dependencyPosition) {
          throw new AppError(`Profile "${profileName}" orders "${modulePlan.id}" before dependency "${dependency}".`, "SCAN_PLAN_INVALID_ORDER");
        }
      }

      for (const predecessor of metadata.orderAfter) {
        const predecessorPosition = positions.get(predecessor);
        if (typeof predecessorPosition === "number" && (positions.get(modulePlan.id) ?? 0) < predecessorPosition) {
          throw new AppError(`Profile "${profileName}" orders "${modulePlan.id}" before required predecessor "${predecessor}".`, "SCAN_PLAN_INVALID_ORDER");
        }
      }
    }
  }

  private validateEvidence(definition: ScanProfileDefinition, modules: readonly ModulePlan[]): void {
    if (!definition.evidence.requireReproducibleEvidence) {
      return;
    }

    const incapable = modules.filter((modulePlan) => this.registry.get(modulePlan.id)?.metadata.supportsEvidence === false);
    if (incapable.length > 0) {
      throw new AppError(
        `Profile "${definition.name}" requires reproducible evidence but includes evidence-incompatible module(s): ${incapable.map((modulePlan) => modulePlan.id).join(", ")}.`,
        "SCAN_PLAN_EVIDENCE_INCOMPATIBLE"
      );
    }
  }

  private validateMonitoring(definition: ScanProfileDefinition, modules: readonly ModulePlan[]): void {
    if (definition.name !== "monitor") {
      return;
    }

    const incompatible = modules.filter((modulePlan) => this.registry.get(modulePlan.id)?.metadata.monitoringCompatible === false);
    if (incompatible.length > 0) {
      throw new AppError(`Monitor profile includes non-monitoring module(s): ${incompatible.map((modulePlan) => modulePlan.id).join(", ")}.`, "SCAN_PLAN_MONITORING_INCOMPATIBLE");
    }
  }

  private validate(plan: ResolvedScanPlan): void {
    const assistedSelected = plan.modules.some((module) => module.id === "assisted-review");
    if (assistedSelected !== Boolean(plan.assistedReview)) throw new AppError("Assisted review requires both its explicit review manifest and selected module.", "ASSISTED_REVIEW_PLAN_REQUIRED");
    if (plan.modules.length === 0) {
      throw new AppError(`Profile "${plan.profile}" resolved to an empty module plan.`, "SCAN_PLAN_EMPTY");
    }

    const hasObjectPairModule = plan.modules.some((modulePlan) => modulePlan.id === "object-pair-testing");
    if (hasObjectPairModule && !plan.objectPairTesting) {
      throw new AppError(`Object pair testing module requires a resolved object-pair request matrix.`, "OBJECT_PAIR_PLAN_REQUIRED");
    }

    if (plan.objectPairTesting && !hasObjectPairModule) {
      throw new AppError(`Object pair testing input was supplied but the object-pair-testing module was not selected.`, "OBJECT_PAIR_MODULE_REQUIRED");
    }

    const hasFieldExposureModule = plan.modules.some((modulePlan) => modulePlan.id === "field-exposure-testing");
    if (hasFieldExposureModule && !plan.fieldExposureTesting) {
      throw new AppError(`Field exposure testing module requires a resolved field-exposure request matrix.`, "FIELD_EXPOSURE_PLAN_REQUIRED");
    }

    if (plan.fieldExposureTesting && !hasFieldExposureModule) {
      throw new AppError(`Field exposure testing input was supplied but the field-exposure-testing module was not selected.`, "FIELD_EXPOSURE_MODULE_REQUIRED");
    }

    const hasAuthorizationMatrixModule = plan.modules.some((modulePlan) => modulePlan.id === "authorization-matrix-testing");
    if (hasAuthorizationMatrixModule && !plan.authorizationMatrixTesting) {
      throw new AppError(`Authorization matrix testing module requires a resolved authorization matrix.`, "AUTHORIZATION_MATRIX_PLAN_REQUIRED");
    }

    if (plan.authorizationMatrixTesting && !hasAuthorizationMatrixModule) {
      throw new AppError(`Authorization matrix input was supplied but the authorization-matrix-testing module was not selected.`, "AUTHORIZATION_MATRIX_MODULE_REQUIRED");
    }

    const hasCollectionAuthorizationModule = plan.modules.some((modulePlan) => modulePlan.id === "collection-authorization-testing");
    if (hasCollectionAuthorizationModule && !plan.collectionAuthorizationTesting) {
      throw new AppError(`Collection authorization testing module requires a resolved collection authorization plan.`, "COLLECTION_AUTHORIZATION_PLAN_REQUIRED");
    }

    if (plan.collectionAuthorizationTesting && !hasCollectionAuthorizationModule) {
      throw new AppError(`Collection authorization input was supplied but the collection-authorization-testing module was not selected.`, "COLLECTION_AUTHORIZATION_MODULE_REQUIRED");
    }

    const hasBulkAuthorizationModule = plan.modules.some((modulePlan) => modulePlan.id === "bulk-authorization-testing");
    if (hasBulkAuthorizationModule && !plan.bulkAuthorizationTesting) {
      throw new AppError(`Bulk authorization testing module requires a resolved bulk authorization plan.`, "BULK_AUTHORIZATION_PLAN_REQUIRED");
    }

    if (plan.bulkAuthorizationTesting && !hasBulkAuthorizationModule) {
      throw new AppError(`Bulk authorization input was supplied but the bulk-authorization-testing module was not selected.`, "BULK_AUTHORIZATION_MODULE_REQUIRED");
    }

    const hasFileAuthorizationModule = plan.modules.some((modulePlan) => modulePlan.id === "file-authorization-testing");
    if (hasFileAuthorizationModule && !plan.fileAuthorizationTesting) {
      throw new AppError(`File authorization testing module requires a resolved file authorization plan.`, "FILE_AUTHORIZATION_PLAN_REQUIRED");
    }

    if (plan.fileAuthorizationTesting && !hasFileAuthorizationModule) {
      throw new AppError(`File authorization input was supplied but the file-authorization-testing module was not selected.`, "FILE_AUTHORIZATION_MODULE_REQUIRED");
    }

    const hasEquivalentRouteModule = plan.modules.some((modulePlan) => modulePlan.id === "equivalent-route-testing");
    if (hasEquivalentRouteModule && !plan.equivalentRouteTesting) {
      throw new AppError(`Equivalent route testing module requires a resolved equivalent-route request matrix.`, "EQUIVALENT_ROUTE_PLAN_REQUIRED");
    }

    if (plan.equivalentRouteTesting && !hasEquivalentRouteModule) {
      throw new AppError(`Equivalent route input was supplied but the equivalent-route-testing module was not selected.`, "EQUIVALENT_ROUTE_MODULE_REQUIRED");
    }

    const hasPrivilegeMutationModule = plan.modules.some((modulePlan) => modulePlan.id === "privilege-mutation-testing");
    if (hasPrivilegeMutationModule && !plan.privilegeMutationTesting) throw new AppError("Privilege mutation testing requires a resolved explicit mutation plan.", "PRIVILEGE_MUTATION_PLAN_REQUIRED");
    if (plan.privilegeMutationTesting && !hasPrivilegeMutationModule) throw new AppError("Privilege mutation input was supplied but the privilege-mutation-testing module was not selected.", "PRIVILEGE_MUTATION_MODULE_REQUIRED");

    const hasSupabaseModule = plan.modules.some((modulePlan) => modulePlan.id === "supabase-authorization");
    if (hasSupabaseModule && !plan.supabaseAuthorization) throw new AppError("Supabase authorization requires a resolved explicit test plan.", "SUPABASE_AUTH_PLAN_REQUIRED");
    if (plan.supabaseAuthorization && !hasSupabaseModule) throw new AppError("Supabase authorization input was supplied but the supabase-authorization module was not selected.", "SUPABASE_AUTH_MODULE_REQUIRED");

    const hasAuthenticationLifecycleModule = plan.modules.some((modulePlan) => modulePlan.id === "authentication-lifecycle");
    if (hasAuthenticationLifecycleModule && !plan.authenticationLifecycle) throw new AppError("Authentication lifecycle testing requires a resolved explicit lifecycle plan.", "AUTH_LIFECYCLE_PLAN_REQUIRED");
    if (plan.authenticationLifecycle && !hasAuthenticationLifecycleModule) throw new AppError("Authentication lifecycle input was supplied but the authentication-lifecycle module was not selected.", "AUTH_LIFECYCLE_MODULE_REQUIRED");

    const hasBusinessInvariantModule = plan.modules.some((modulePlan) => modulePlan.id === "business-invariant");
    if (hasBusinessInvariantModule && !plan.businessInvariant) throw new AppError("Business invariant testing requires a resolved explicit invariant plan.", "BUSINESS_INVARIANT_PLAN_REQUIRED");
    if (plan.businessInvariant && !hasBusinessInvariantModule) throw new AppError("Business invariant input was supplied but the business-invariant module was not selected.", "BUSINESS_INVARIANT_MODULE_REQUIRED");

    const hasControlledRaceModule = plan.modules.some((modulePlan) => modulePlan.id === "controlled-race");
    if (hasControlledRaceModule && !plan.controlledRace) throw new AppError("Controlled race testing requires a resolved explicit race plan.", "CONTROLLED_RACE_PLAN_REQUIRED");
    if (plan.controlledRace && !hasControlledRaceModule) throw new AppError("Controlled race input was supplied but the controlled-race module was not selected.", "CONTROLLED_RACE_MODULE_REQUIRED");
    const hasApiGraphqlModule = plan.modules.some((modulePlan) => modulePlan.id === "api-graphql-authorization");
    if (hasApiGraphqlModule && !plan.apiGraphql) throw new AppError("API/GraphQL authorization requires a resolved explicit review plan.", "API_GRAPHQL_PLAN_REQUIRED");
    if (plan.apiGraphql && !hasApiGraphqlModule) throw new AppError("API/GraphQL input was supplied but the api-graphql-authorization module was not selected.", "API_GRAPHQL_MODULE_REQUIRED");
    const hasLinkPortalModule = plan.modules.some((modulePlan) => modulePlan.id === "link-portal-export-security");
    if (hasLinkPortalModule && !plan.linkPortalSecurity) throw new AppError("Link/portal/export security requires a resolved explicit plan.", "LINK_PORTAL_PLAN_REQUIRED");
    if (plan.linkPortalSecurity && !hasLinkPortalModule) throw new AppError("Link/portal/export input was supplied but its module was not selected.", "LINK_PORTAL_MODULE_REQUIRED");
    const hasOperationalModule = plan.modules.some((modulePlan) => modulePlan.id === "operational-endpoint-security");
    if (hasOperationalModule && !plan.operationalEndpointSecurity) throw new AppError("Operational endpoint security requires a resolved explicit plan.", "OPERATIONAL_ENDPOINT_PLAN_REQUIRED");
    if (plan.operationalEndpointSecurity && !hasOperationalModule) throw new AppError("Operational endpoint input was supplied but its module was not selected.", "OPERATIONAL_ENDPOINT_MODULE_REQUIRED");
    const hasBillingModule = plan.modules.some((modulePlan) => modulePlan.id === "billing-entitlement-security");
    if (hasBillingModule && !plan.billingEntitlement) throw new AppError("Billing and entitlement security requires a resolved explicit synthetic plan.", "BILLING_ENTITLEMENT_PLAN_REQUIRED");
    if (plan.billingEntitlement && !hasBillingModule) throw new AppError("Billing input was supplied but its module was not selected.", "BILLING_ENTITLEMENT_MODULE_REQUIRED");
  }
}

function resolveLimits(definition: ScanProfileDefinition, input: ScanPlannerInput): ScanLimits {
  const base: ScanLimits = {
    maxDepth: input.scope.maxDepth,
    rateLimitPerSecond: input.scope.rateLimitPerSecond,
    concurrency: input.scope.concurrency,
    requestTimeoutMs: input.config.requestTimeoutMs,
    bodyPreviewBytes: input.config.bodyPreviewBytes,
    maxResponseBytes: input.config.bodyPreviewBytes * 4,
    maxRequests: 200,
    cleanupReservedRequests: 0,
    maxScanDurationMs: 300000,
    retry: defaultRetry
  };

  const merged = {
    ...base,
    ...definition.limits,
    ...(definition.limits.bodyPreviewBytes ? { maxResponseBytes: definition.limits.bodyPreviewBytes * 4 } : {}),
    ...(input.overrides?.rateLimitPerSecond ? { rateLimitPerSecond: input.overrides.rateLimitPerSecond } : {}),
    ...(input.overrides?.concurrency ? { concurrency: input.overrides.concurrency } : {}),
    ...(input.overrides?.maxRequests ? { maxRequests: input.overrides.maxRequests } : {})
  };

  // The declared scope is an authorization boundary, not a set of soft profile
  // defaults. A profile or per-run override may make execution more restrictive,
  // but must never increase network pressure or crawl reach beyond that boundary.
  merged.maxDepth = Math.min(merged.maxDepth, input.scope.maxDepth);
  merged.rateLimitPerSecond = Math.min(merged.rateLimitPerSecond, input.scope.rateLimitPerSecond);
  merged.concurrency = Math.min(merged.concurrency, input.scope.concurrency);

  const minimumCleanup = minimumCleanupRequests(input);
  const cleanupReservedRequests = input.overrides?.cleanupReservedRequests
    ?? definition.limits.cleanupReservedRequests
    ?? (minimumCleanup > 0 ? Math.min(merged.maxRequests, Math.max(minimumCleanup, Math.ceil(merged.maxRequests * 0.2))) : 0);
  if (cleanupReservedRequests < minimumCleanup) {
    throw new AppError(`cleanupReservedRequests (${cleanupReservedRequests}) is below the ${minimumCleanup}-request minimum required by the selected restoration workflows.`, "SCAN_PLAN_CLEANUP_RESERVE_INSUFFICIENT");
  }
  if (minimumCleanup > 0 && cleanupReservedRequests >= merged.maxRequests) {
    throw new AppError("The total request budget must exceed the cleanup reserve so the authorized workflow can reach its restoration phase.", "SCAN_PLAN_ATTACK_CAPACITY_EMPTY");
  }

  return {
    ...merged,
    cleanupReservedRequests,
    retry: { ...base.retry, ...(definition.limits.retry ?? {}) }
  };
}

function minimumCleanupRequests(input: ScanPlannerInput): number {
  let total = 0;
  total += input.privilegeMutationTesting?.cases.reduce((count, item) => count + 1 + item.rollback.verification.attempts + (input.authProfile?.browserBootstrap?.proofCases.some((proof) => proof.caseId === item.caseId) ? 20 : 0), 0) ?? 0;
  total += (input.supabaseAuthorization?.cases.filter((item) => item.mutationContractCaseId).length ?? 0) * 2;
  total += input.authenticationLifecycle?.cases.reduce((count, item) => count + item.steps.filter((step) => step.phase === "CLEANUP").length, 0) ?? 0;
  total += input.authenticationLifecycle?.automation?.categories.length ?? 0;
  total += input.businessInvariant?.cases.reduce((count, item) => count + item.cleanup.length + item.cleanupVerification.length, 0) ?? 0;
  total += input.controlledRace?.cases.reduce((count, item) => count + item.cleanup.length + item.cleanupVerification.length, 0) ?? 0;
  total += input.linkPortalSecurity?.cases.reduce((count, item) => count + item.steps.filter((step) => step.phase === "CLEANUP").length, 0) ?? 0;
  total += input.operationalEndpointSecurity?.cases.reduce((count, item) => count + item.steps.filter((step) => step.phase === "CLEANUP").length, 0) ?? 0;
  total += input.billingEntitlement?.cases.reduce((count, item) => count + item.steps.filter((step) => step.phase === "CLEANUP").reduce((stepCount, step) => stepCount + step.execution.attempts, 0), 0) ?? 0;
  return total;
}

function validatePositiveLimits(limits: ScanLimits): void {
  const numericLimits = {
    maxDepth: limits.maxDepth,
    rateLimitPerSecond: limits.rateLimitPerSecond,
    concurrency: limits.concurrency,
    requestTimeoutMs: limits.requestTimeoutMs,
    bodyPreviewBytes: limits.bodyPreviewBytes,
    maxResponseBytes: limits.maxResponseBytes,
    maxRequests: limits.maxRequests,
    cleanupReservedRequests: limits.cleanupReservedRequests,
    maxScanDurationMs: limits.maxScanDurationMs,
    retryMaxAttempts: limits.retry.maxAttempts
  };

  for (const [name, value] of Object.entries(numericLimits)) {
    if (!Number.isFinite(value) || value < 0 || (!["maxDepth", "cleanupReservedRequests"].includes(name) && value === 0)) {
      throw new AppError(`Invalid scan limit "${name}": ${value}.`, "SCAN_PLAN_INVALID_LIMIT");
    }
  }

  if (limits.maxDepth > hardSafetyCeilings.maxDepth) throw new AppError(`maxDepth exceeds hard safety ceiling ${hardSafetyCeilings.maxDepth}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.rateLimitPerSecond > hardSafetyCeilings.rateLimitPerSecond) throw new AppError(`rateLimitPerSecond exceeds hard safety ceiling ${hardSafetyCeilings.rateLimitPerSecond}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.concurrency > hardSafetyCeilings.concurrency) throw new AppError(`concurrency exceeds hard safety ceiling ${hardSafetyCeilings.concurrency}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.bodyPreviewBytes > hardSafetyCeilings.bodyPreviewBytes) throw new AppError(`bodyPreviewBytes exceeds hard safety ceiling ${hardSafetyCeilings.bodyPreviewBytes}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.maxResponseBytes > hardSafetyCeilings.maxResponseBytes) throw new AppError(`maxResponseBytes exceeds hard safety ceiling ${hardSafetyCeilings.maxResponseBytes}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.maxRequests > hardSafetyCeilings.maxRequests) throw new AppError(`maxRequests exceeds hard safety ceiling ${hardSafetyCeilings.maxRequests}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (!Number.isInteger(limits.cleanupReservedRequests) || limits.cleanupReservedRequests < 0 || limits.cleanupReservedRequests > limits.maxRequests) throw new AppError("cleanupReservedRequests must be an integer between zero and maxRequests.", "SCAN_PLAN_INVALID_CLEANUP_RESERVE");
  if (limits.cleanupReservedRequests > hardSafetyCeilings.cleanupReservedRequests) throw new AppError(`cleanupReservedRequests exceeds hard safety ceiling ${hardSafetyCeilings.cleanupReservedRequests}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.maxScanDurationMs > hardSafetyCeilings.maxScanDurationMs) throw new AppError(`maxScanDurationMs exceeds hard safety ceiling ${hardSafetyCeilings.maxScanDurationMs}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.retry.maxAttempts > hardSafetyCeilings.retryMaxAttempts) throw new AppError(`retry.maxAttempts exceeds hard safety ceiling ${hardSafetyCeilings.retryMaxAttempts}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
}

function authSkipForModule(
  requirement: "none" | "single-profile" | "account-pair",
  availability: { hasSingleProfile: boolean; hasAccountPair: boolean }
): "single-profile" | "account-pair" | undefined {
  if (requirement === "single-profile" && !availability.hasSingleProfile) {
    return "single-profile";
  }

  if (requirement === "account-pair" && !availability.hasAccountPair) {
    return "account-pair";
  }

  return undefined;
}

function freezeLimits(limits: ScanLimits): ScanLimits {
  return {
    ...limits,
    retry: { ...limits.retry }
  };
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) {
    return value;
  }

  Object.freeze(value);
  for (const item of Object.values(value)) {
    deepFreeze(item);
  }
  return value;
}

function isBrowserOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:" || url.protocol === "ws:" || url.protocol === "wss:") && url.origin === value.replace(/\/$/, "");
  } catch {
    return false;
  }
}

function resolveEvidencePolicy(profilePolicy: Readonly<EvidencePolicy>, requested: EvidenceLevel | undefined): EvidencePolicy {
  const rank: Record<EvidenceLevel, number> = { minimal: 0, normal: 1, strong: 2 };
  if (!requested || rank[requested] <= rank[profilePolicy.level]) return { ...profilePolicy };
  if (requested === "normal") return { level: "normal", collectRequestAudit: true, collectBodyPreview: true, requireReproducibleEvidence: false, retainProofBlocks: false };
  return { level: "strong", collectRequestAudit: true, collectBodyPreview: true, requireReproducibleEvidence: true, retainProofBlocks: true };
}
