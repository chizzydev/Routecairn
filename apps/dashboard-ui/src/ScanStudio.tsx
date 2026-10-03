import { useEffect, useMemo, useRef, useState } from "react";
import { apiGet, apiMutation, DashboardApiError, type PlanPreview, type ProjectSummary, type TargetSummary } from "./api";
import { AuthorizationWorkflowStudio, type WorkflowDraft } from "./AuthorizationWorkflowStudio";
import { mapWorkflowApiError, type WorkflowValidationDiagnostic } from "./WorkflowDiagnostics";
import type { RetestDraft } from "./FindingsCommandCenter";
import { AdvancedEngineStudio, type AdvancedEngineDraft } from "./AdvancedEngineStudio";
import { type CredentialSummary } from "./CredentialLifecycle";
import { type ScopeState, type CapabilityRegistry, type StudioState, emptyActor, steps } from "./ScanStudioModel";
import { clearSecrets, validate, buildRequest, errorText } from "./ScanStudioValidation";
import { TargetStep, ScopeStep, ProfileStep, AuthenticationStep, IdentityStep, LimitsStep, EvidenceStep, ReviewStep, LaunchStep } from "./ScanStudioSteps";

export function ScanStudio({
  onLaunched,
  initialDraft,
  initialAdaptiveDraft,
  initialAdapterDraft,
}: {
  onLaunched: (scanId: string) => void;
  initialDraft?: RetestDraft;
  initialAdaptiveDraft?: { target: TargetSummary; engineId: AdvancedEngineDraft["id"]; engineConfiguration?: Record<string, unknown>; binding?: { recommendationId: string; sourceFingerprint: string; executionFingerprint: string; compilerVersion: 1 | 2 }; authentication?: { mode: "public" } | { mode: "primary"; primary: { source: "saved"; credentialProfileId: string } } | { mode: "account-pair"; accountA: { source: "saved"; credentialProfileId: string }; accountB: { source: "saved"; credentialProfileId: string } }; limits?: { maxRequests: number; cleanupReservedRequests: number; evidenceLevel: "strong" } };
  initialAdapterDraft?: { target: TargetSummary; engineId: AdvancedEngineDraft["id"]; engineConfiguration: Record<string, unknown>; authentication: { mode: "public" } | { mode: "primary"; credentialProfileId: string } | { mode: "account-pair"; accountAProfileId: string; accountBProfileId: string }; binding: { profileId: string; versionId: string; adapterDigest: string }; limits: { maxRequests: number; cleanupReservedRequests: number; rateLimitPerSecond: number; concurrency: number; evidenceLevel: "minimal" | "normal" | "strong" } };
}) {
  const savedConfiguration = initialDraft || initialAdaptiveDraft || initialAdapterDraft ? undefined : readPendingConfiguration();
  const retestScope = initialDraft?.scope as Partial<ScopeState> | undefined;
  const adaptiveTargetScope = readTargetScope(initialAdaptiveDraft?.target ?? initialAdapterDraft?.target);
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [capabilities, setCapabilities] = useState<CapabilityRegistry>();
  const [moduleSearch, setModuleSearch] = useState("");
  const [message, setMessage] = useState("");
  const [launching, setLaunching] = useState(false);
  const launchLock = useRef(false);
  const [workflowDiagnostics, setWorkflowDiagnostics] = useState<
    WorkflowValidationDiagnostic[]
  >([]);
  const [identityResult, setIdentityResult] =
    useState<Record<string, unknown>>();
  const [dirty, setDirty] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [state, setState] = useState<StudioState>(() => ({
    currentStep: initialAdaptiveDraft || initialAdapterDraft ? 7 : 0,
    scanName: initialDraft?.context.purpose ?? (initialAdapterDraft ? `Reusable ${initialAdapterDraft.engineId} fixture` : initialAdaptiveDraft ? `Adaptive ${initialAdaptiveDraft.engineId} assessment` : "Authorized assessment"),
    operatorNote: "",
    projectId: initialDraft?.projectId ?? initialAdapterDraft?.target.projectId ?? initialAdaptiveDraft?.target.projectId ?? "",
    targetId: initialDraft?.targetId ?? initialAdapterDraft?.target.id ?? initialAdaptiveDraft?.target.id ?? "",
    target: initialDraft?.target ?? initialAdapterDraft?.target.baseOrigin ?? initialAdaptiveDraft?.target.baseOrigin ?? "",
    authorizationCategory: (initialAdapterDraft?.target ?? initialAdaptiveDraft?.target)?.authorizationType === "BUG_BOUNTY" ? "BUG_BOUNTY" : "OWNED",
    authorizationConfirmed: Boolean(initialAdaptiveDraft),
    authorizationNote: initialAdaptiveDraft ? "Evidence-bound read-only adaptive execution from the registered target and approved scope." : "",
    scope: {
      program: retestScope?.program ?? adaptiveTargetScope?.program ?? "Authorized Security Test",
      allowedDomains: retestScope?.allowedDomains ?? adaptiveTargetScope?.allowedDomains ?? (initialDraft?.target ? [new URL(initialDraft.target).hostname] : initialAdapterDraft ? [new URL(initialAdapterDraft.target.baseOrigin).hostname] : initialAdaptiveDraft ? [new URL(initialAdaptiveDraft.target.baseOrigin).hostname] : []),
      disallowedPaths: retestScope?.disallowedPaths ?? adaptiveTargetScope?.disallowedPaths ?? ["/logout", "/delete", "/checkout", "/payment"],
      allowedMethods: retestScope?.allowedMethods ?? adaptiveTargetScope?.allowedMethods ?? ["GET", "HEAD", "OPTIONS"],
      rateLimitPerSecond: initialAdapterDraft?.limits.rateLimitPerSecond ?? retestScope?.rateLimitPerSecond ?? adaptiveTargetScope?.rateLimitPerSecond ?? 3,
      concurrency: initialAdapterDraft?.limits.concurrency ?? retestScope?.concurrency ?? adaptiveTargetScope?.concurrency ?? 3,
      maxDepth: retestScope?.maxDepth ?? adaptiveTargetScope?.maxDepth ?? 2,
      sameOriginOnly: retestScope?.sameOriginOnly ?? adaptiveTargetScope?.sameOriginOnly ?? true,
      includeSubdomains: retestScope?.includeSubdomains ?? adaptiveTargetScope?.includeSubdomains ?? false,
      respectRobotsTxt: retestScope?.respectRobotsTxt ?? adaptiveTargetScope?.respectRobotsTxt ?? false,
      userAgent: retestScope?.userAgent ?? adaptiveTargetScope?.userAgent ?? "RouteCairn/0.1",
    },
    profile: initialDraft?.profile ?? (initialAdapterDraft ? initialAdapterDraft.authentication.mode === "public" ? "full" : "authenticated" : initialAdaptiveDraft ? "full" : savedConfiguration?.profile ?? "quick"),
    selectedModules: initialDraft?.selectedModules ?? savedConfiguration?.modules ?? [],
    nextJsReview: {
      inspectNextJsSourceMaps: true,
      inspectKnownNextJsDataSurfaces: true,
      nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW",
      maxNextJsManifestRequests: 4,
      maxNextJsDataSurfaceRequests: 8,
      maxNextJsSourceMapRequests: 4,
      maxNextJsCacheDifferentialRequests: 0,
      maxNextJsAssetsInspected: 50,
      maxNextJsRoutesProcessed: 200,
    },
    transport: {
      poolingEnabled: true,
      http2Enabled: false,
      maxOrigins: 64,
      maxConnectionsPerOrigin: 4,
      maxConcurrentHttp2Streams: 32,
      maxHeaderSizeBytes: 16384,
      keepAliveTimeoutMs: 10000,
      keepAliveMaxTimeoutMs: 30000,
      maxConnectionLifetimeMs: 120000,
      maxRequestsPerConnection: 1000,
      dnsCacheTtlMs: 0,
    },
    authMode: initialAdapterDraft?.authentication.mode ?? initialAdaptiveDraft?.authentication?.mode ?? (initialDraft?.historicalAuthenticationMode === "account-pair" ? "account-pair" : initialDraft?.historicalAuthenticationMode === "primary" ? "primary" : "public"),
    primary: initialAdapterDraft?.authentication.mode === "primary" ? { ...emptyActor("primary"), source: "saved", savedId: initialAdapterDraft.authentication.credentialProfileId } : initialAdaptiveDraft?.authentication?.mode === "primary" ? { ...emptyActor("primary"), source: "saved", savedId: initialAdaptiveDraft.authentication.primary.credentialProfileId } : initialDraft?.savedCredentialReferences[0] ? { ...emptyActor("primary"), source: "saved", savedId: initialDraft.savedCredentialReferences[0] } : emptyActor("primary"),
    accountA: initialAdapterDraft?.authentication.mode === "account-pair" ? { ...emptyActor("Account A"), source: "saved", savedId: initialAdapterDraft.authentication.accountAProfileId } : initialAdaptiveDraft?.authentication?.mode === "account-pair" ? { ...emptyActor("Account A"), source: "saved", savedId: initialAdaptiveDraft.authentication.accountA.credentialProfileId } : initialDraft?.savedCredentialReferences[0] ? { ...emptyActor("Account A"), source: "saved", savedId: initialDraft.savedCredentialReferences[0] } : emptyActor("Account A"),
    accountB: initialAdapterDraft?.authentication.mode === "account-pair" ? { ...emptyActor("Account B"), source: "saved", savedId: initialAdapterDraft.authentication.accountBProfileId } : initialAdaptiveDraft?.authentication?.mode === "account-pair" ? { ...emptyActor("Account B"), source: "saved", savedId: initialAdaptiveDraft.authentication.accountB.credentialProfileId } : initialDraft?.savedCredentialReferences[1] ? { ...emptyActor("Account B"), source: "saved", savedId: initialDraft.savedCredentialReferences[1] } : emptyActor("Account B"),
    evidenceLevel: initialAdapterDraft?.limits.evidenceLevel ?? initialAdaptiveDraft?.limits?.evidenceLevel ?? (initialDraft?.evidenceLevel === "strong" || initialDraft?.evidenceLevel === "normal" ? initialDraft.evidenceLevel : savedConfiguration?.evidenceLevel ?? "minimal"),
    maxRequestsOverride: initialAdapterDraft ? String(initialAdapterDraft.limits.maxRequests) : initialAdaptiveDraft?.limits ? String(initialAdaptiveDraft.limits.maxRequests) : "",
    cleanupReservedRequestsOverride: initialAdapterDraft ? String(initialAdapterDraft.limits.cleanupReservedRequests) : initialAdaptiveDraft?.limits ? String(initialAdaptiveDraft.limits.cleanupReservedRequests) : "",
    outputs: initialDraft?.outputs && initialDraft.outputs.json && initialDraft.outputs.markdown && initialDraft.outputs.html ? { json: true, markdown: true, html: true } : { json: true, markdown: true, html: true },
    workflows: (initialDraft?.reusableWorkflows ?? []) as WorkflowDraft[],
    advancedEngines: [],
    ...(initialAdapterDraft ? { providerAdapterBinding: initialAdapterDraft.binding } : {}),
    ...(initialAdaptiveDraft ? { adaptiveExecutionBinding: initialAdaptiveDraft.binding } : {}),
    authenticationLifecycleFile: "",
    authenticationLifecycleAutoFile: "",
    businessInvariantFile: "",
    controlledRaceFile: "",
    apiGraphqlFile: "",
    linkPortalSecurityFile: "",
    operationalEndpointSecurityFile: "",
    billingEntitlementFile: "",
    assistedReviewFile: "",
    preHandoverFile: "",
    targetAuthorizationFile: "",
    ...(initialDraft ? { retestContext: initialDraft.context } : {}),
    preview: undefined,
  }));

  useEffect(() => {
    void Promise.all([
      apiGet<CapabilityRegistry>("/api/capabilities"),
      apiGet<{ projects: ProjectSummary[] }>("/api/projects"),
      apiGet<{ targets: TargetSummary[] }>("/api/targets"),
      apiGet<{ profiles: typeof credentials }>(
        "/api/credential-profiles",
      ).catch(() => ({ profiles: [] })),
    ]).then(([caps, projectBody, targetBody, credentialBody]) => {
      setCapabilities(caps);
      setProjects(projectBody.projects);
      setTargets(targetBody.targets);
      setCredentials(credentialBody.profiles);
    });
  }, []);
  const refreshProjectsAndTargets = async () => {
    const [projectBody, targetBody] = await Promise.all([
      apiGet<{ projects: ProjectSummary[] }>("/api/projects"),
      apiGet<{ targets: TargetSummary[] }>("/api/targets"),
    ]);
    setProjects(projectBody.projects);
    setTargets(targetBody.targets);
  };
  useEffect(() => {
    const handler = (event: BeforeUnloadEvent) => {
      if (dirty) event.preventDefault();
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [dirty]);
  useEffect(() => {
    const clear = () => setState((current) => clearSecrets(current));
    window.addEventListener("routecairn:session-expired", clear);
    return () =>
      window.removeEventListener("routecairn:session-expired", clear);
  }, []);
  useEffect(() => {
    headingRef.current?.focus();
  }, [state.currentStep]);

  const update = (patch: Partial<StudioState>) => {
    setDirty(true);
    if (patch.workflows) setWorkflowDiagnostics([]);
    setState((current) => ({ ...current, ...patch, preview: undefined }));
  };
  const selectedTarget = targets.find((target) => target.id === state.targetId);
  const profile = capabilities?.profiles.find(
    (item) => item.name === state.profile,
  );
  const errors = validate(state);
  const stepErrors = errors.filter((error) => error.step === state.currentStep);
  const request = useMemo(() => buildRequest(state), [state]);
  const retestCoverageChanged = Boolean(initialDraft && (
    (state.selectedModules.length > 0 && !state.selectedModules.includes(initialDraft.context.relevantModule)) ||
    (initialDraft.context.relevantWorkflow && !state.workflows.some((workflow) => workflow.workflowId === initialDraft.context.relevantWorkflow && workflow.enabled)) ||
    state.targetId !== (initialDraft.targetId ?? "")
  ));

  const selectTarget = (targetId: string) => {
    const target = targets.find((item) => item.id === targetId);
    if (!target) {
      update({ targetId });
      return;
    }
    const url = new URL(target.baseOrigin);
    update({
      targetId,
      projectId: target.projectId ?? "",
      target: target.baseOrigin,
      authorizationCategory:
        target.authorizationType as StudioState["authorizationCategory"],
      authorizationNote: target.authorizationSummary,
      profile: target.defaultProfile ?? state.profile,
      scope: { ...state.scope, allowedDomains: [url.hostname] },
    });
  };
  const go = (step: number) => {
    const blockingError = step > state.currentStep
      ? errors
          .filter((error) => error.step >= state.currentStep && error.step < step)
          .sort((left, right) => left.step - right.step)[0]
      : undefined;
    if (blockingError) {
      setMessage(
        `Complete ${steps[blockingError.step]} before opening ${steps[step]}: ${blockingError.message}`,
      );
      if (blockingError.step !== state.currentStep) {
        setState((current) => ({
          ...current,
          currentStep: blockingError.step,
        }));
      } else {
        headingRef.current?.focus();
      }
      return;
    }
    setMessage("");
    setState((current) => ({ ...current, currentStep: step }));
  };
  const preview = async () => {
    try {
      const result = await apiMutation<PlanPreview>(
        "/api/scans/plan-preview",
        "POST",
        request,
      );
      setWorkflowDiagnostics([]);
      setState((current) => ({ ...current, preview: result, currentStep: 8 }));
      setMessage("Plan resolved by RouteCairn ScanPlanner.");
    } catch (cause) {
      if (cause instanceof DashboardApiError)
        setWorkflowDiagnostics(mapWorkflowApiError(cause, state.workflows));
      setMessage(errorText(cause));
    }
  };
  const testIdentity = async () => {
    try {
      setIdentityResult(
        await apiMutation<Record<string, unknown>>(
          "/api/scans/identity-test",
          "POST",
          request,
        ),
      );
      setMessage(
        "Identity verification completed through the shared request safety path.",
      );
    } catch (cause) {
      setIdentityResult(undefined);
      setMessage(errorText(cause));
    }
  };
  const launch = async () => {
    if (launchLock.current) return;
    if (errors.length > 0 || !state.preview) {
      setMessage(
        errors[0]?.message ?? "Preview the current plan before launch.",
      );
      return;
    }
    launchLock.current = true;
    setLaunching(true);
    try {
      const body = buildRequest({ ...state, preview: state.preview });
      const result = await apiMutation<{ scanId: string }>(
        "/api/scans",
        "POST",
        body,
      );
      setState((current) => clearSecrets({ ...current, preview: undefined }));
      setDirty(false);
      onLaunched(result.scanId);
    } catch (cause) {
      setMessage(errorText(cause));
    } finally {
      launchLock.current = false;
      setLaunching(false);
    }
  };

  return (
    <section className="studio">
      <div className="page-header">
        <h2>Scan Studio</h2>
        <p>
          Build a bounded authorized scan, inspect the real planner result, then
          launch through an isolated worker.
        </p>
      </div>
      {initialDraft && <div className="retest-banner" role="status"><strong>{initialDraft.context.purpose}</strong><span>{initialDraft.warning}</span>{initialDraft.freshCredentialsRequired && <span>Fresh credentials required for this retest.</span>}{initialDraft.context.relevantWorkflow && <span>Required coverage: {initialDraft.context.relevantWorkflow}{initialDraft.context.relevantCase ? ` / ${initialDraft.context.relevantCase}` : ""}.</span>}</div>}
      {retestCoverageChanged && <p className="review-owner-warning">This configuration may not provide compatible retest coverage for the selected finding.</p>}
      <nav className="studio-steps" aria-label="Scan Studio steps">
        {steps.map((label, index) => {
          const invalid = validate(state).some((error) => error.step === index);
          const completed = index < state.currentStep && !invalid;
          return (
            <button
              type="button"
              key={label}
              aria-current={index === state.currentStep ? "step" : undefined}
              className={`${index === state.currentStep ? "current" : ""} ${completed ? "complete" : ""} ${invalid ? "invalid" : ""}`}
              onClick={() => go(index)}
            >
              <span>{index + 1}</span>
              {label}
              <small>
                {invalid
                  ? "Needs attention"
                  : completed
                    ? "Complete"
                    : index === state.currentStep
                      ? "Current"
                      : "Required"}
              </small>
            </button>
          );
        })}
      </nav>
      <div className="studio-layout">
        <div className="studio-workspace">
          <h3 tabIndex={-1} ref={headingRef}>
            {steps[state.currentStep]}
          </h3>
          {stepErrors.length > 0 && (
            <div className="validation-summary" role="alert">
              <strong>Complete this step</strong>
              {stepErrors.map((error) => (
                <p key={error.message}>{error.message}</p>
              ))}
            </div>
          )}
          {state.currentStep === 0 && (
            <TargetStep
              state={state}
              projects={projects}
              targets={targets}
              selectedTarget={selectedTarget}
              update={update}
              selectTarget={selectTarget}
              onResourcesChanged={refreshProjectsAndTargets}
            />
          )}
          {state.currentStep === 1 && (
            <ScopeStep
              scope={state.scope}
              setScope={(scope) => update({ scope })}
              setMessage={setMessage}
            />
          )}
          {state.currentStep === 2 && (
            <ProfileStep
              state={state}
              profile={profile!}
              capabilities={capabilities!}
              search={moduleSearch}
              setSearch={setModuleSearch}
              update={update}
            />
          )}
          {state.currentStep === 3 && (
            <AuthenticationStep
              state={state}
              credentials={credentials}
              update={update}
            />
          )}
          {state.currentStep === 4 && (
            <IdentityStep
              state={state}
              update={update}
              result={identityResult!}
              onTest={testIdentity}
            />
          )}
          {state.currentStep === 5 && (
            <LimitsStep state={state} profile={profile!} update={update} />
          )}
          {state.currentStep === 6 && (
            <EvidenceStep
              state={state}
              capabilities={capabilities!}
              update={update}
            />
          )}
          {state.currentStep === 7 && (
            <div className="studio-panel">
              <AdvancedEngineStudio
                target={state.target}
                initialEngineId={initialAdapterDraft?.engineId ?? initialAdaptiveDraft?.engineId}
                initialEngineValue={(initialAdapterDraft?.engineConfiguration ?? initialAdaptiveDraft?.engineConfiguration) as never}
                drafts={state.advancedEngines}
                selectedModules={state.selectedModules}
                onChange={(advancedEngines) => {
                  const hasBugBounty = advancedEngines.some((engine) => engine.enabled && engine.id === "bug-bounty-authorization");
                  const hasPreHandover = advancedEngines.some((engine) => engine.enabled && engine.id === "pre-handover-assault");
                  update({
                    advancedEngines,
                    ...(hasBugBounty ? { authorizationCategory: "BUG_BOUNTY" as const } : !state.targetAuthorizationFile && state.authorizationCategory === "BUG_BOUNTY" && selectedTarget?.authorizationType !== "BUG_BOUNTY" ? { authorizationCategory: "OWNED" as const } : {}),
                    ...(hasPreHandover ? { authorizationCategory: "CONTROLLED_LAB" as const, profile: "pre-handover" } : !state.preHandoverFile && state.profile === "pre-handover" ? { profile: "full" } : {})
                  });
                }}
                onEnableModule={(moduleId) => update({ selectedModules: [...new Set([...state.selectedModules, moduleId])] })}
                onPreview={preview}
              />
              <details className="legacy-manifest-inputs">
                <summary>Legacy server-side manifest paths</summary>
                <p className="muted">Compatibility-only. Prefer the dashboard builders and browser-side JSON import/export above.</p>
                <label>Authentication lifecycle file<input value={state.authenticationLifecycleFile} onChange={(event) => update({ authenticationLifecycleFile: event.target.value })} /></label>
                <label>Learned lifecycle policy file<input value={state.authenticationLifecycleAutoFile} onChange={(event) => update({ authenticationLifecycleAutoFile: event.target.value })} /></label>
                <label>Business invariant file<input value={state.businessInvariantFile} onChange={(event) => update({ businessInvariantFile: event.target.value })} /></label>
                <label>Controlled race file<input value={state.controlledRaceFile} onChange={(event) => update({ controlledRaceFile: event.target.value })} /></label>
                <label>API / GraphQL file<input value={state.apiGraphqlFile} onChange={(event) => update({ apiGraphqlFile: event.target.value })} /></label>
                <label>Signed-link / portal file<input value={state.linkPortalSecurityFile} onChange={(event) => update({ linkPortalSecurityFile: event.target.value })} /></label>
                <label>Operational endpoint file<input value={state.operationalEndpointSecurityFile} onChange={(event) => update({ operationalEndpointSecurityFile: event.target.value })} /></label>
                <label>Billing / entitlement file<input value={state.billingEntitlementFile} onChange={(event) => update({ billingEntitlementFile: event.target.value })} /></label>
                <label>Assisted review file<input value={state.assistedReviewFile} onChange={(event) => update({ assistedReviewFile: event.target.value })} /></label>
                <label>Pre-handover file<input value={state.preHandoverFile} onChange={(event) => update({ preHandoverFile: event.target.value })} /></label>
                <label>Target authorization file<input value={state.targetAuthorizationFile} onChange={(event) => update({ targetAuthorizationFile: event.target.value })} /></label>
              </details>
              <AuthorizationWorkflowStudio
              workflows={state.workflows}
              diagnostics={workflowDiagnostics}
              capabilities={capabilities?.controlledWorkflows ?? []}
              selectedModules={state.selectedModules}
              target={state.target}
              principalA={state.accountA.identity.expectedPrincipal}
              principalB={state.accountB.identity.expectedPrincipal}
              onChange={(workflows) => update({ workflows })}
              onEnableModule={(moduleId) =>
                update({
                  selectedModules: [
                    ...new Set([...state.selectedModules, moduleId]),
                  ],
                })
              }
              onPreview={preview}
              />
            </div>
          )}
          {state.currentStep === 8 && (
            <ReviewStep state={state} profile={profile!} />
          )}
          {state.currentStep === 9 && (
            <LaunchStep
              state={state}
              errors={errors}
              launching={launching}
              onLaunch={launch}
            />
          )}
          {message && (
            <p className="studio-message" role="status">
              {message}
            </p>
          )}
          <div className="studio-actions">
            <button
              type="button"
              disabled={state.currentStep === 0}
              onClick={() => go(state.currentStep - 1)}
            >
              Back
            </button>
            {state.currentStep < 8 && (
              <button
                type="button"
                className="primary"
                onClick={() => go(state.currentStep + 1)}
              >
                Next
              </button>
            )}
            {state.currentStep === 8 && (
              <button
                type="button"
                className="primary"
                onClick={() => void preview()}
              >
                Resolve Plan
              </button>
            )}
            {state.currentStep === 8 && state.preview && (
              <button type="button" onClick={() => go(9)}>
                Continue to Launch
              </button>
            )}
            {state.currentStep === 9 && (
              <span className="studio-launch-status" role="status">
                {launching ? "Launching scan..." : "Ready to launch"}
              </span>
            )}
            <button
              type="button"
              onClick={() => {
                if (
                  !dirty ||
                  window.confirm(
                    "Reset Scan Studio and clear ephemeral secrets?",
                  )
                ) {
                  setState((current) => ({
                    ...clearSecrets(current),
                    currentStep: 0,
                    preview: undefined,
                  }));
                  setDirty(false);
                }
              }}
            >
              Reset
            </button>
          </div>
        </div>
        <aside className="studio-summary" aria-label="Scan summary">
          <h3>Current scan</h3>
          <dl>
            <dt>Target</dt>
            <dd>{state.target || "Not selected"}</dd>
            <dt>Profile</dt>
            <dd>{profile?.displayName ?? state.profile}</dd>
            <dt>Scope</dt>
            <dd>{state.scope.allowedDomains.length} domain rule(s)</dd>
            <dt>Authentication</dt>
            <dd>{state.authMode}</dd>
            <dt>Modules</dt>
            <dd>
              {state.selectedModules.length || profile?.modules.length || 0}
            </dd>
            <dt>Planner</dt>
            <dd>{state.preview ? "Resolved" : "Not previewed"}</dd>
          </dl>
          <p className="secret-note">
            Ephemeral secrets stay in this page's live memory and are sent only
            in a job-bound worker envelope.
          </p>
        </aside>
      </div>
    </section>
  );
}

export function readTargetScope(target: TargetSummary | undefined): Partial<ScopeState> | undefined {
  if (!target) return undefined;
  const value = target.approvedScope;
  const methods = Array.isArray(value.allowedMethods) ? value.allowedMethods.filter((item): item is ScopeState["allowedMethods"][number] => typeof item === "string" && ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE", "CONNECT"].includes(item)) : undefined;
  return {
    ...(typeof value.program === "string" ? { program: value.program } : {}),
    ...(Array.isArray(value.allowedDomains) ? { allowedDomains: value.allowedDomains.filter((item): item is string => typeof item === "string") } : {}),
    ...(Array.isArray(value.disallowedPaths) ? { disallowedPaths: value.disallowedPaths.filter((item): item is string => typeof item === "string") } : {}),
    ...(methods?.length ? { allowedMethods: methods } : {}),
    ...(typeof value.rateLimitPerSecond === "number" ? { rateLimitPerSecond: value.rateLimitPerSecond } : {}),
    ...(typeof value.concurrency === "number" ? { concurrency: value.concurrency } : {}),
    ...(typeof value.maxDepth === "number" ? { maxDepth: value.maxDepth } : {}),
    ...(typeof value.sameOriginOnly === "boolean" ? { sameOriginOnly: value.sameOriginOnly } : {}),
    ...(typeof value.includeSubdomains === "boolean" ? { includeSubdomains: value.includeSubdomains } : {}),
    ...(typeof value.respectRobotsTxt === "boolean" ? { respectRobotsTxt: value.respectRobotsTxt } : {}),
    ...(typeof value.userAgent === "string" ? { userAgent: value.userAgent } : {})
  };
}

export function readPendingConfiguration(): { profile?: string; modules?: string[]; evidenceLevel?: "minimal" | "normal" | "strong" } | undefined {
  try {
    const raw = window.sessionStorage.getItem("routecairn.scan-studio.configuration");
    if (!raw) return undefined;
    window.sessionStorage.removeItem("routecairn.scan-studio.configuration");
    const value = JSON.parse(raw) as Record<string, unknown>;
    return {
      ...(typeof value.profile === "string" ? { profile: value.profile } : {}),
      ...(Array.isArray(value.modules) ? { modules: value.modules.filter((item): item is string => typeof item === "string") } : {}),
      ...(["minimal", "normal", "strong"].includes(String(value.evidenceLevel)) ? { evidenceLevel: value.evidenceLevel as "minimal" | "normal" | "strong" } : {})
    };
  } catch {
    return undefined;
  }
}
