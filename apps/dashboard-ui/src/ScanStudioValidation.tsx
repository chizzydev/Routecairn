

import { containsUnsafeGeneratedValue, workflowCaseCount, workflowEnabledCaseCount, workflowForRequest, type WorkflowDraft } from "./AuthorizationWorkflowStudio";
import { immediateWorkflowDiagnostics } from "./WorkflowDiagnostics";

import { advancedEngineRequestValues, type AdvancedEngineDraft } from "./AdvancedEngineStudio";

import { type StudioState, type ValidationError, fieldPathPattern, type ActorState, headerNamePattern, forbiddenHeaders } from "./ScanStudioModel";

export function splitTags(value: string): string[] {
  return [
    ...new Set(
      value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ].slice(0, 20);
}

export function validate(state: StudioState): ValidationError[] {
  const errors: ValidationError[] = [];
  let target: URL | undefined;
  try {
    target = new URL(state.target);
    if (!/^https?:$/.test(target.protocol)) throw new Error();
  } catch {
    errors.push({
      step: 0,
      message: "Enter a valid HTTP or HTTPS target URL.",
    });
  }
  if (!state.scanName.trim())
    errors.push({ step: 0, message: "Scan name is required." });
  if (!state.authorizationConfirmed)
    errors.push({
      step: 0,
      message: "Explicit authorization confirmation is required.",
    });
  if (!state.scope.allowedDomains.length)
    errors.push({
      step: 1,
      message: "At least one allowed domain is required.",
    });
  if (
    target &&
    !state.scope.allowedDomains.some(
      (domain) =>
        domain.replace(/^\*\./, "") === target!.hostname ||
        (domain.startsWith("*.") && target!.hostname.endsWith(domain.slice(1))),
    )
  )
    errors.push({
      step: 1,
      message: "The target host must be covered by an allowed domain rule.",
    });
  const maxRequests = state.maxRequestsOverride === "" ? undefined : Number(state.maxRequestsOverride);
  const cleanupReserve = state.cleanupReservedRequestsOverride === "" ? undefined : Number(state.cleanupReservedRequestsOverride);
  if (maxRequests !== undefined && (!Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > 10000)) {
    errors.push({ step: 5, message: "Total scan request budget must be an integer between 1 and 10000." });
  }
  if (cleanupReserve !== undefined && (!Number.isInteger(cleanupReserve) || cleanupReserve < 0 || cleanupReserve > 5000)) {
    errors.push({ step: 5, message: "Cleanup reserve must be an integer between 0 and 5000." });
  }
  if (maxRequests !== undefined && cleanupReserve !== undefined && cleanupReserve > maxRequests) {
    errors.push({ step: 5, message: "Cleanup reserve cannot exceed the total scan request budget." });
  }
  const transportBounds: Array<[number, number, number]> = [
    [state.transport.maxOrigins, 1, 1024], [state.transport.maxConnectionsPerOrigin, 1, 32], [state.transport.maxConcurrentHttp2Streams, 1, 256], [state.transport.maxHeaderSizeBytes, 4096, 65536],
    [state.transport.keepAliveTimeoutMs, 100, 120000], [state.transport.keepAliveMaxTimeoutMs, 100, 300000], [state.transport.maxConnectionLifetimeMs, 1000, 900000],
    [state.transport.maxRequestsPerConnection, 1, 10000], [state.transport.dnsCacheTtlMs, 0, 60000]
  ];
  if (transportBounds.some(([value, min, max]) => !Number.isInteger(value) || value < min || value > max)) errors.push({ step: 5, message: "Transport settings are outside their safe bounds." });
  if (state.transport.keepAliveMaxTimeoutMs < state.transport.keepAliveTimeoutMs) errors.push({ step: 5, message: "Maximum keep-alive must be greater than or equal to the keep-alive timeout." });
  if (state.scope.allowedMethods.length === 0)
    errors.push({ step: 1, message: "At least one safe method is required." });
  if (!state.profile)
    errors.push({ step: 2, message: "Select a scan profile." });
  if (state.selectedModules.includes("nextjs-review")) {
    const limits: Array<[number, number, number]> = [
      [state.nextJsReview.maxNextJsManifestRequests, 1, 32],
      [state.nextJsReview.maxNextJsDataSurfaceRequests, 1, 64],
      [state.nextJsReview.maxNextJsSourceMapRequests, 1, 32],
      [state.nextJsReview.maxNextJsCacheDifferentialRequests, 0, 12],
      [state.nextJsReview.maxNextJsRoutesProcessed, 1, 2000],
    ];
    if (limits.some(([value, min, max]) => !Number.isInteger(value) || value < min || value > max)) errors.push({ step: 2, message: "Next.js Deep Review limits are outside their safe bounds." });
    if (state.nextJsReview.nextJsCacheReviewMode === "CONTROLLED_CACHE_DIFFERENTIAL" && state.nextJsReview.maxNextJsCacheDifferentialRequests < 2) errors.push({ step: 2, message: "Controlled Next.js cache review requires a cache differential budget of at least 2 requests." });
  }
  if (state.authMode === "primary")
    validateActor(state.primary, "Primary", 3, errors);
  if (state.authMode === "account-pair") {
    validateActor(state.accountA, "Account A", 3, errors);
    validateActor(state.accountB, "Account B", 3, errors);
    if (
      state.accountA.source === "saved" &&
      state.accountB.source === "saved" &&
      state.accountA.savedId === state.accountB.savedId &&
      state.accountA.savedId
    )
      errors.push({
        step: 3,
        message: "Account A and Account B must use different saved profiles.",
      });
  }
  for (const actor of applicableActors(state)) {
    if (actor.identity.mode !== "disabled") {
      if (
        !actor.identity.endpoint ||
        !actor.identity.principalIdField ||
        !actor.identity.expectedPrincipal
      )
        errors.push({
          step: 4,
          message: `${actor.safeAlias}: endpoint, principal path, and expected principal are required.`,
        });
      for (const path of [
        actor.identity.principalIdField,
        actor.identity.tenantIdField,
        actor.identity.roleField,
        actor.identity.accountStateField,
      ].filter(Boolean))
        if (
          !fieldPathPattern.test(path) ||
          /(?:^|\.)(__proto__|prototype|constructor)(?:\.|$)/.test(path)
        )
          errors.push({
            step: 4,
            message: `${actor.safeAlias}: unsupported identity field path.`,
          });
    }
  }
  if (
    state.scope.rateLimitPerSecond < 1 ||
    state.scope.rateLimitPerSecond > 50 ||
    state.scope.concurrency < 1 ||
    state.scope.concurrency > 50
  )
    errors.push({
      step: 5,
      message: "Rate and concurrency must remain between 1 and 50.",
    });
  if (!Object.values(state.outputs).some(Boolean))
    errors.push({ step: 6, message: "Select at least one report output." });
  for (const workflow of state.workflows.filter((item) => item.enabled)) {
    const moduleId = workflowModuleId(workflow.workflowId);
    if (!state.selectedModules.includes(moduleId))
      errors.push({
        step: 7,
        message: `${workflow.workflowId} requires module ${moduleId}.`,
      });
    if (state.authMode !== "account-pair")
      errors.push({
        step: 7,
        message: `${workflow.workflowId} requires Account A and Account B authentication.`,
      });
    if (workflowEnabledCaseCount(workflow) < 1)
      errors.push({
        step: 7,
        message: `${workflow.workflowId} requires at least one enabled explicit case.`,
      });
    if (containsUnsafeWorkflowIdentifier(workflow.config))
      errors.push({
        step: 7,
        message: `${workflow.workflowId} contains a wildcard, range, or generator-like exact reference.`,
      });
    for (const diagnostic of immediateWorkflowDiagnostics(workflow))
      errors.push({
        step: 7,
        message: `${workflow.workflowId}: ${diagnostic.safeMessage}`,
      });
  }
  return errors;
}

export function validateActor(
  actor: ActorState,
  label: string,
  step: number,
  errors: ValidationError[],
) {
  if (actor.source === "saved") {
    if (!actor.savedId)
      errors.push({
        step,
        message: `${label} requires a saved credential profile.`,
      });
    return;
  }
  if (
    !actor.bearerToken &&
    actor.headers.length === 0 &&
    actor.cookies.length === 0
  )
    errors.push({
      step,
      message: `${label} requires bearer, header, or cookie authentication material.`,
    });
  if (actor.headers.length > 24 || actor.cookies.length > 24)
    errors.push({
      step,
      message: `${label} exceeds the maximum credential row count.`,
    });
  for (const row of actor.headers) {
    const name = row.name.trim().toLowerCase();
    if (
      !headerNamePattern.test(row.name) ||
      forbiddenHeaders.has(name) ||
      /[\r\n]/.test(row.value)
    )
      errors.push({
        step,
        message: `${label} contains an invalid or forbidden header.`,
      });
  }
  for (const row of actor.cookies)
    if (!row.name || /[\r\n;=]/.test(row.name) || /[\r\n]/.test(row.value))
      errors.push({ step, message: `${label} contains an invalid cookie.` });
  const total =
    actor.bearerToken.length +
    actor.headers.reduce(
      (sum, row) => sum + row.name.length + row.value.length,
      0,
    ) +
    actor.cookies.reduce(
      (sum, row) => sum + row.name.length + row.value.length,
      0,
    );
  if (total > 32 * 1024)
    errors.push({ step, message: `${label} authentication exceeds 32 KiB.` });
}

export function applicableActors(state: StudioState): ActorState[] {
  return state.authMode === "primary"
    ? [state.primary]
    : state.authMode === "account-pair"
      ? [state.accountA, state.accountB]
      : [];
}

export function buildRequest(state: StudioState): Record<string, unknown> {
  const actor = (value: ActorState) =>
    value.source === "saved"
      ? { source: "saved", credentialProfileId: value.savedId }
      : { source: "ephemeral", profile: actorProfile(value) };
  const authentication =
    state.authMode === "public"
      ? { mode: "public" }
      : state.authMode === "primary"
        ? { mode: "primary", primary: actor(state.primary) }
        : {
            mode: "account-pair",
            accountA: actor(state.accountA),
            accountB: actor(state.accountB),
          };
  const workflows = state.workflows.map(workflowForRequest);
  return {
    target: state.target,
    profile: state.profile,
    ...(state.projectId ? { projectId: state.projectId } : {}),
    ...(state.targetId ? { targetId: state.targetId } : {}),
    authorizationDeclaration: `${state.authorizationCategory}: ${state.authorizationNote || "Authorized in Scan Studio"}`,
    rateLimitPerSecond: state.scope.rateLimitPerSecond,
    concurrency: state.scope.concurrency,
    transport: state.transport,
    ...(state.maxRequestsOverride !== "" ? { maxRequests: Number(state.maxRequestsOverride) } : {}),
    ...(state.cleanupReservedRequestsOverride !== "" ? { cleanupReservedRequests: Number(state.cleanupReservedRequestsOverride) } : {}),
    ...(state.selectedModules.length
      ? { includeModules: state.selectedModules }
      : {}),
    ...(state.providerAdapterBinding ? { providerAdapterBinding: state.providerAdapterBinding } : {}),
    ...(state.adaptiveExecutionBinding ? { adaptiveExecutionBinding: state.adaptiveExecutionBinding } : {}),
    ...advancedEngineRequestValues(state.advancedEngines),
    ...(state.authenticationLifecycleFile ? { authenticationLifecycleFile: state.authenticationLifecycleFile } : {}),
    ...(state.authenticationLifecycleAutoFile ? { authenticationLifecycleAutoFile: state.authenticationLifecycleAutoFile } : {}),
    ...(state.businessInvariantFile ? { businessInvariantFile: state.businessInvariantFile } : {}),
    ...(state.controlledRaceFile ? { controlledRaceFile: state.controlledRaceFile } : {}),
    ...(state.apiGraphqlFile ? { apiGraphqlFile: state.apiGraphqlFile } : {}),
    ...(state.linkPortalSecurityFile ? { linkPortalSecurityFile: state.linkPortalSecurityFile } : {}),
    ...(state.operationalEndpointSecurityFile ? { operationalEndpointSecurityFile: state.operationalEndpointSecurityFile } : {}),
    ...(state.billingEntitlementFile ? { billingEntitlementFile: state.billingEntitlementFile } : {}),
    ...(state.assistedReviewFile ? { assistedReviewFile: state.assistedReviewFile } : {}),
    ...(state.preHandoverFile ? { preHandoverFile: state.preHandoverFile } : {}),
    ...(state.targetAuthorizationFile ? { targetAuthorizationFile: state.targetAuthorizationFile } : {}),
    studio: {
      version: 1,
      scanName: state.scanName,
      ...(state.operatorNote ? { operatorNote: state.operatorNote } : {}),
      authorization: {
        category: state.authorizationCategory,
        confirmed: true,
        ...(state.authorizationNote ? { note: state.authorizationNote } : {}),
      },
      scope: state.scope,
      authentication,
      evidenceLevel: state.evidenceLevel,
      outputs: state.outputs,
      moduleSettings: state.selectedModules.includes("nextjs-review") ? { nextJsReview: state.nextJsReview } : {},
      workflows,
      workflowSummary: workflows.map((workflow) => ({
        type: workflow.workflowId,
        caseCount: workflowCaseCount(workflow),
        valid: workflow.enabled,
      })),
      ...(state.retestContext ? { retestContext: state.retestContext } : {}),
      ...(state.preview?.previewIdentity
        ? { previewIdentity: state.preview.previewIdentity }
        : {}),
    },
  };
}

export function actorProfile(actor: ActorState) {
  const identity = actor.identity;
  return {
    label: actor.safeAlias,
    safeAlias: actor.safeAlias,
    ...(identity.expectedPrincipal
      ? { principalId: identity.expectedPrincipal }
      : {}),
    ...(identity.expectedTenant ? { tenantId: identity.expectedTenant } : {}),
    ...(identity.expectedRole ? { role: identity.expectedRole } : {}),
    ...(identity.expectedState ? { accountState: identity.expectedState } : {}),
    headers: {
      ...(actor.bearerToken
        ? { Authorization: `Bearer ${actor.bearerToken}` }
        : {}),
      ...Object.fromEntries(actor.headers.map((row) => [row.name, row.value])),
    },
    cookies: actor.cookies.map((row) => ({ name: row.name, value: row.value })),
    identityVerification: {
      mode: identity.mode,
      method: identity.method,
      ...(identity.endpoint ? { endpoint: identity.endpoint } : {}),
      ...(identity.principalIdField
        ? { principalIdField: identity.principalIdField }
        : {}),
      ...(identity.tenantIdField
        ? { tenantIdField: identity.tenantIdField }
        : {}),
      ...(identity.roleField ? { roleField: identity.roleField } : {}),
      ...(identity.accountStateField
        ? { accountStateField: identity.accountStateField }
        : {}),
      expectedContentType: "application/json",
      successStatusCodes: [200],
      maxResponseBytes: identity.maxResponseBytes,
      anonymousMarkers: [],
    },
    notes: [],
  };
}

export function clearSecrets(state: StudioState): StudioState {
  const clear = (actor: ActorState): ActorState => ({
    ...actor,
    bearerToken: "",
    headers: [],
    cookies: [],
  });
  return {
    ...state,
    primary: clear(state.primary),
    accountA: clear(state.accountA),
    accountB: clear(state.accountB),
  };
}

export function safeAuthReview(state: StudioState) {
  const actor = (value: ActorState) =>
    value.source === "saved"
      ? { source: "saved", credentialProfileId: value.savedId }
      : {
          source: "ephemeral",
          safeAlias: value.safeAlias,
          headerNames: [
            ...(value.bearerToken ? ["Authorization"] : []),
            ...value.headers.map((row) => row.name),
          ],
          cookieNames: value.cookies.map((row) => row.name),
          redactionApplied: true,
        };
  return state.authMode === "public"
    ? { mode: "public" }
    : state.authMode === "primary"
      ? { mode: "primary", primary: actor(state.primary) }
      : {
          mode: "account-pair",
          accountA: actor(state.accountA),
          accountB: actor(state.accountB),
        };
}

export function safeIdentityReview(state: StudioState) {
  return applicableActors(state).map((actor) => ({
    alias: actor.safeAlias,
    source: actor.source,
    mode: actor.identity.mode,
    endpoint: actor.identity.endpoint,
    principalField: actor.identity.principalIdField,
    tenantField: actor.identity.tenantIdField,
    roleField: actor.identity.roleField,
    accountStateField: actor.identity.accountStateField,
  }));
}

export function errorText(value: unknown): string {
  return value instanceof Error
    ? value.message
    : "Scan Studio operation failed.";
}

export function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function advancedPreviewId(id: AdvancedEngineDraft["id"]): string {
  return id === "authentication-lifecycle-automation" ? "authentication-lifecycle" : id;
}

export function workflowModuleId(id: WorkflowDraft["workflowId"]): string {
  return id === "object-pair"
    ? "object-pair-testing"
    : id === "field-exposure"
      ? "field-exposure-testing"
      : id === "authorization-matrix"
        ? "authorization-matrix-testing"
        : id === "equivalent-route"
          ? "equivalent-route-testing"
          : id === "collection-authorization"
            ? "collection-authorization-testing"
            : id === "bulk-authorization"
              ? "bulk-authorization-testing"
              : "file-authorization-testing";
}

export function containsUnsafeWorkflowIdentifier(value: unknown, key = ""): boolean {
  if (typeof value === "string")
    return (
      /(?:objectId|fileRef|objectIdList|fileKey)/i.test(key) &&
      containsUnsafeGeneratedValue(value)
    );
  if (Array.isArray(value))
    return value.some((item) => containsUnsafeWorkflowIdentifier(item, key));
  if (value && typeof value === "object")
    return Object.entries(value).some(([childKey, child]) =>
      containsUnsafeWorkflowIdentifier(child, childKey),
    );
  return false;
}
