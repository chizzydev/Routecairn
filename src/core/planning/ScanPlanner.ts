import { AppError } from "../errors/AppError.js";
import { compareMetadata, PluginRegistry } from "../plugins/PluginRegistry.js";
import { scanProfileDefinitions } from "./ProfileDefinitions.js";
import type { ScanProfileName } from "../../config/ScanProfiles.js";
import type { ModuleId, ModulePlan, ModuleSettings, ResolvedScanPlan, ScanLimits, ScanPlannerInput, ScanProfileDefinition } from "./ScanPlan.js";
import { scanPlanSchemaVersion } from "./ScanPlan.js";

const defaultRetry = { maxAttempts: 2, baseDelayMs: 250, maxDelayMs: 2000, retryStatusCodes: [408, 429, 500, 502, 503, 504] };
const hardSafetyCeilings = {
  maxDepth: 10,
  rateLimitPerSecond: 50,
  concurrency: 50,
  bodyPreviewBytes: 1024 * 1024,
  maxResponseBytes: 4 * 1024 * 1024,
  maxRequests: 10000,
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
    const limits = freezeLimits(resolveLimits(definition, input));
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
      evidence: { ...definition.evidence },
      output: { ...definition.output },
      failurePolicy: definition.failurePolicy,
      optionalModulesMayBeSkipped: definition.optionalModulesMayBeSkipped,
      reportFocus: [...definition.reportFocus],
      ...(input.objectPairTesting ? { objectPairTesting: input.objectPairTesting } : {}),
      ...(input.fieldExposureTesting ? { fieldExposureTesting: input.fieldExposureTesting } : {})
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

    const sorted = this.orderModules(modulePlans);

    this.validateDependencies(definition.name, sorted);
    this.validateEvidence(definition, sorted);
    this.validateMonitoring(definition, sorted);
    validatePositiveLimits(limits);
    return { modules: sorted, skippedModules };
  }

  private orderModules(modulePlans: readonly ModulePlan[]): ModulePlan[] {
    const remaining = new Map(modulePlans.map((modulePlan) => [modulePlan.id, modulePlan]));
    const ordered: ModulePlan[] = [];

    while (remaining.size > 0) {
      const ready = [...remaining.values()]
        .filter((modulePlan) => this.constraintsFor(modulePlan.id).every((dependency) => !remaining.has(dependency)))
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
      if (typeof value === "number" && (!Number.isFinite(value) || value <= 0)) {
        throw new AppError(`Module "${id}" setting "${key}" must be a positive number.`, "SCAN_PLAN_INVALID_MODULE_SETTING");
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
    if (!definition.output.stableForDiff) {
      return;
    }

    const incompatible = modules.filter((modulePlan) => this.registry.get(modulePlan.id)?.metadata.monitoringCompatible === false);
    if (incompatible.length > 0) {
      throw new AppError(`Monitor profile includes non-monitoring module(s): ${incompatible.map((modulePlan) => modulePlan.id).join(", ")}.`, "SCAN_PLAN_MONITORING_INCOMPATIBLE");
    }
  }

  private validate(plan: ResolvedScanPlan): void {
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
    maxScanDurationMs: 300000,
    retry: defaultRetry
  };

  const merged = {
    ...base,
    ...definition.limits,
    ...(definition.limits.bodyPreviewBytes ? { maxResponseBytes: definition.limits.bodyPreviewBytes * 4 } : {}),
    ...(input.overrides?.rateLimitPerSecond ? { rateLimitPerSecond: input.overrides.rateLimitPerSecond } : {}),
    ...(input.overrides?.concurrency ? { concurrency: input.overrides.concurrency } : {})
  };

  return {
    ...merged,
    retry: { ...base.retry, ...(definition.limits.retry ?? {}) }
  };
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
    maxScanDurationMs: limits.maxScanDurationMs,
    retryMaxAttempts: limits.retry.maxAttempts
  };

  for (const [name, value] of Object.entries(numericLimits)) {
    if (!Number.isFinite(value) || value < 0 || (name !== "maxDepth" && value === 0)) {
      throw new AppError(`Invalid scan limit "${name}": ${value}.`, "SCAN_PLAN_INVALID_LIMIT");
    }
  }

  if (limits.maxDepth > hardSafetyCeilings.maxDepth) throw new AppError(`maxDepth exceeds hard safety ceiling ${hardSafetyCeilings.maxDepth}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.rateLimitPerSecond > hardSafetyCeilings.rateLimitPerSecond) throw new AppError(`rateLimitPerSecond exceeds hard safety ceiling ${hardSafetyCeilings.rateLimitPerSecond}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.concurrency > hardSafetyCeilings.concurrency) throw new AppError(`concurrency exceeds hard safety ceiling ${hardSafetyCeilings.concurrency}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.bodyPreviewBytes > hardSafetyCeilings.bodyPreviewBytes) throw new AppError(`bodyPreviewBytes exceeds hard safety ceiling ${hardSafetyCeilings.bodyPreviewBytes}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.maxResponseBytes > hardSafetyCeilings.maxResponseBytes) throw new AppError(`maxResponseBytes exceeds hard safety ceiling ${hardSafetyCeilings.maxResponseBytes}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
  if (limits.maxRequests > hardSafetyCeilings.maxRequests) throw new AppError(`maxRequests exceeds hard safety ceiling ${hardSafetyCeilings.maxRequests}.`, "SCAN_PLAN_LIMIT_EXCEEDS_CEILING");
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
