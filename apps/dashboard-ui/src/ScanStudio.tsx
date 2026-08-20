import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  apiGet,
  apiMutation,
  DashboardApiError,
  type PlanPreview,
  type ProjectSummary,
  type TargetSummary,
} from "./api";
import {
  AuthorizationWorkflowStudio,
  containsUnsafeGeneratedValue,
  workflowCaseCount,
  workflowEnabledCaseCount,
  workflowForRequest,
  type WorkflowCapability,
  type WorkflowDraft,
} from "./AuthorizationWorkflowStudio";
import {
  immediateWorkflowDiagnostics,
  mapWorkflowApiError,
  type WorkflowValidationDiagnostic,
} from "./WorkflowDiagnostics";
import type { RetestDraft } from "./FindingsCommandCenter";

type AuthSource = "ephemeral" | "saved";
type AuthMode = "public" | "primary" | "account-pair";
type HeaderRow = { id: string; name: string; value: string };
type CookieRow = { id: string; name: string; value: string };
type IdentityState = {
  mode: "disabled" | "optional" | "required";
  endpoint: string;
  method: "GET" | "HEAD";
  principalIdField: string;
  tenantIdField: string;
  roleField: string;
  accountStateField: string;
  expectedPrincipal: string;
  expectedTenant: string;
  expectedRole: string;
  expectedState: string;
  maxResponseBytes: number;
};
type ActorState = {
  source: AuthSource;
  savedId: string;
  safeAlias: string;
  bearerToken: string;
  headers: HeaderRow[];
  cookies: CookieRow[];
  identity: IdentityState;
};
type ScopeState = {
  program: string;
  allowedDomains: string[];
  disallowedPaths: string[];
  allowedMethods: Array<"GET" | "HEAD" | "OPTIONS" | "POST">;
  rateLimitPerSecond: number;
  concurrency: number;
  maxDepth: number;
  sameOriginOnly: boolean;
  includeSubdomains: boolean;
  respectRobotsTxt: boolean;
  userAgent: string;
};
type NextJsReviewSettings = {
  inspectNextJsSourceMaps: boolean;
  inspectKnownNextJsDataSurfaces: boolean;
  nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW" | "CONTROLLED_CACHE_DIFFERENTIAL";
  maxNextJsManifestRequests: number;
  maxNextJsDataSurfaceRequests: number;
  maxNextJsSourceMapRequests: number;
  maxNextJsCacheDifferentialRequests: number;
  maxNextJsAssetsInspected: number;
  maxNextJsRoutesProcessed: number;
};
type StudioState = {
  currentStep: number;
  scanName: string;
  operatorNote: string;
  projectId: string;
  targetId: string;
  target: string;
  authorizationCategory:
    | "OWNED"
    | "CLIENT_AUTHORIZED"
    | "BUG_BOUNTY"
    | "CONTROLLED_LAB"
    | "OTHER_AUTHORIZED";
  authorizationConfirmed: boolean;
  authorizationNote: string;
  scope: ScopeState;
  profile: string;
  selectedModules: string[];
  nextJsReview: NextJsReviewSettings;
  authMode: AuthMode;
  primary: ActorState;
  accountA: ActorState;
  accountB: ActorState;
  evidenceLevel: "minimal" | "normal" | "strong";
  outputs: { json: boolean; markdown: boolean; html: boolean };
  workflows: WorkflowDraft[];
  retestContext?: RetestDraft["context"];
  preview: PlanPreview | undefined;
};
type CapabilityRegistry = {
  profiles: Array<{
    name: string;
    displayName: string;
    description: string;
    modules: string[];
    limits: Record<string, unknown>;
    browserUse: string;
    authComparisonDepth: string;
    proofMode: boolean;
    reportFocus: string[];
  }>;
  modules: Array<{
    id: string;
    displayName: string;
    description: string;
    phase: string;
    capabilities: string[];
    requiresAuthentication: string;
    dependencies: string[];
    cost: string;
    supportedSettings: string[];
  }>;
  controlledWorkflows: WorkflowCapability[];
  evidenceLevels: Array<{
    id: "minimal" | "normal" | "strong";
    retention: string;
  }>;
};

const steps = [
  "Target",
  "Scope",
  "Profile & Modules",
  "Authentication",
  "Verified Identity",
  "Browser & Limits",
  "Evidence & Outputs",
  "Controlled Workflows",
  "Plan Review",
  "Launch",
];
const headerNamePattern = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
const forbiddenHeaders = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "upgrade",
  "expect",
  "te",
  "trailer",
]);
const fieldPathPattern =
  /^[A-Za-z_$][A-Za-z0-9_$]*(?:\[(?:0|[1-9][0-9]{0,2})\]|\.[A-Za-z_$][A-Za-z0-9_$]*){0,8}$/;
const emptyIdentity = (): IdentityState => ({
  mode: "disabled",
  endpoint: "",
  method: "GET",
  principalIdField: "id",
  tenantIdField: "",
  roleField: "",
  accountStateField: "",
  expectedPrincipal: "",
  expectedTenant: "",
  expectedRole: "",
  expectedState: "",
  maxResponseBytes: 8192,
});
const emptyActor = (alias: string): ActorState => ({
  source: "ephemeral",
  savedId: "",
  safeAlias: alias,
  bearerToken: "",
  headers: [],
  cookies: [],
  identity: emptyIdentity(),
});

export function ScanStudio({
  onLaunched,
  initialDraft,
}: {
  onLaunched: (scanId: string) => void;
  initialDraft?: RetestDraft;
}) {
  const savedConfiguration = initialDraft ? undefined : readPendingConfiguration();
  const retestScope = initialDraft?.scope as Partial<ScopeState> | undefined;
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [credentials, setCredentials] = useState<
    Array<{
      id: string;
      safeAlias: string;
      enabled: boolean;
      credentialTypeSummary: string;
    }>
  >([]);
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
    currentStep: 0,
    scanName: initialDraft?.context.purpose ?? "Authorized assessment",
    operatorNote: "",
    projectId: initialDraft?.projectId ?? "",
    targetId: initialDraft?.targetId ?? "",
    target: initialDraft?.target ?? "",
    authorizationCategory: "OWNED",
    authorizationConfirmed: false,
    authorizationNote: "",
    scope: {
      program: retestScope?.program ?? "Authorized Security Test",
      allowedDomains: retestScope?.allowedDomains ?? (initialDraft?.target ? [new URL(initialDraft.target).hostname] : []),
      disallowedPaths: retestScope?.disallowedPaths ?? ["/logout", "/delete", "/checkout", "/payment"],
      allowedMethods: retestScope?.allowedMethods ?? ["GET", "HEAD", "OPTIONS"],
      rateLimitPerSecond: retestScope?.rateLimitPerSecond ?? 3,
      concurrency: retestScope?.concurrency ?? 3,
      maxDepth: retestScope?.maxDepth ?? 2,
      sameOriginOnly: retestScope?.sameOriginOnly ?? true,
      includeSubdomains: retestScope?.includeSubdomains ?? false,
      respectRobotsTxt: retestScope?.respectRobotsTxt ?? false,
      userAgent: retestScope?.userAgent ?? "RouteCairn/0.1",
    },
    profile: initialDraft?.profile ?? savedConfiguration?.profile ?? "quick",
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
    authMode: initialDraft?.historicalAuthenticationMode === "account-pair" ? "account-pair" : initialDraft?.historicalAuthenticationMode === "primary" ? "primary" : "public",
    primary: initialDraft?.savedCredentialReferences[0] ? { ...emptyActor("primary"), source: "saved", savedId: initialDraft.savedCredentialReferences[0] } : emptyActor("primary"),
    accountA: initialDraft?.savedCredentialReferences[0] ? { ...emptyActor("Account A"), source: "saved", savedId: initialDraft.savedCredentialReferences[0] } : emptyActor("Account A"),
    accountB: initialDraft?.savedCredentialReferences[1] ? { ...emptyActor("Account B"), source: "saved", savedId: initialDraft.savedCredentialReferences[1] } : emptyActor("Account B"),
    evidenceLevel: (initialDraft?.evidenceLevel === "strong" || initialDraft?.evidenceLevel === "normal" ? initialDraft.evidenceLevel : savedConfiguration?.evidenceLevel ?? "minimal"),
    outputs: initialDraft?.outputs && initialDraft.outputs.json && initialDraft.outputs.markdown && initialDraft.outputs.html ? { json: true, markdown: true, html: true } : { json: true, markdown: true, html: true },
    workflows: (initialDraft?.reusableWorkflows ?? []) as WorkflowDraft[],
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

function readPendingConfiguration(): { profile?: string; modules?: string[]; evidenceLevel?: "minimal" | "normal" | "strong" } | undefined {
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

function TargetStep({
  state,
  projects,
  targets,
  selectedTarget,
  update,
  selectTarget,
  onResourcesChanged,
}: {
  state: StudioState;
  projects: ProjectSummary[];
  targets: TargetSummary[];
  selectedTarget: TargetSummary | undefined;
  update: (value: Partial<StudioState>) => void;
  selectTarget: (id: string) => void;
  onResourcesChanged: () => Promise<void>;
}) {
  return (
    <div className="studio-panel">
      <div className="grid two">
        <label>
          Project
          <select
            value={state.projectId}
            onChange={(event) =>
              update({ projectId: event.target.value, targetId: "" })
            }
          >
            <option value="">Ad-hoc scan</option>
            {projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Saved target
          <select
            value={state.targetId}
            onChange={(event) => selectTarget(event.target.value)}
          >
            <option value="">Ad-hoc target</option>
            {targets
              .filter(
                (target) =>
                  !state.projectId || target.projectId === state.projectId,
              )
              .map((target) => (
                <option key={target.id} value={target.id}>
                  {target.displayName} - {target.baseOrigin}
                </option>
              ))}
          </select>
        </label>
        <label>
          Scan name
          <input
            value={state.scanName}
            maxLength={160}
            onChange={(event) => update({ scanName: event.target.value })}
          />
        </label>
        <label>
          Target base URL
          <input
            type="url"
            value={state.target}
            onChange={(event) => {
              const target = event.target.value;
              let scope = state.scope;
              try {
                scope = {
                  ...scope,
                  allowedDomains: [new URL(target).hostname],
                };
              } catch {
                /* validated below */
              }
              update({ target, scope });
            }}
            placeholder="https://app.example.test"
          />
        </label>
      </div>
      <ResourceCreator
        state={state}
        update={update}
        onChanged={onResourcesChanged}
      />
      {selectedTarget && (
        <p className="context-strip">
          {selectedTarget.scanCount} previous scans ·{" "}
          {selectedTarget.openFindingCount} open findings ·{" "}
          {selectedTarget.classification}
        </p>
      )}
      <fieldset>
        <legend>Authorization declaration</legend>
        <label>
          Category
          <select
            value={state.authorizationCategory}
            onChange={(event) =>
              update({
                authorizationCategory: event.target
                  .value as StudioState["authorizationCategory"],
              })
            }
          >
            <option value="OWNED">Owned target</option>
            <option value="CLIENT_AUTHORIZED">Client authorized</option>
            <option value="BUG_BOUNTY">Bug bounty</option>
            <option value="CONTROLLED_LAB">Controlled lab</option>
            <option value="OTHER_AUTHORIZED">Other authorized target</option>
          </select>
        </label>
        <label>
          Safe note
          <textarea
            value={state.authorizationNote}
            maxLength={1000}
            onChange={(event) =>
              update({ authorizationNote: event.target.value })
            }
          />
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={state.authorizationConfirmed}
            onChange={(event) =>
              update({ authorizationConfirmed: event.target.checked })
            }
          />{" "}
          I confirm I am authorized to assess this target and declared scope.
        </label>
      </fieldset>
      <label>
        Safe operator note
        <textarea
          value={state.operatorNote}
          maxLength={1000}
          onChange={(event) => update({ operatorNote: event.target.value })}
        />
      </label>
    </div>
  );
}

function ResourceCreator({
  state,
  update,
  onChanged,
}: {
  state: StudioState;
  update: (value: Partial<StudioState>) => void;
  onChanged: () => Promise<void>;
}) {
  const [projectName, setProjectName] = useState("");
  const [targetName, setTargetName] = useState("");
  const [tags, setTags] = useState("");
  const [status, setStatus] = useState("");
  const createProject = async () => {
    try {
      const result = await apiMutation<{ projectId: string }>(
        "/api/projects",
        "POST",
        {
          name: projectName,
          tags: splitTags(tags),
          defaultProfile: state.profile,
          defaultScope: state.scope,
        },
      );
      await onChanged();
      update({ projectId: result.projectId });
      setStatus("Project created.");
    } catch (cause) {
      setStatus(errorText(cause));
    }
  };
  const createTarget = async () => {
    try {
      const result = await apiMutation<{ targetId: string }>(
        "/api/targets",
        "POST",
        {
          ...(state.projectId ? { projectId: state.projectId } : {}),
          displayName: targetName,
          baseOrigin: new URL(state.target).origin,
          tags: splitTags(tags),
          classification: "UNKNOWN",
          authorizationType: state.authorizationCategory,
          authorizationSummary:
            state.authorizationNote ||
            "Authorized through RouteCairn Scan Studio.",
          approvedScope: state.scope,
          defaultProfile: state.profile,
        },
      );
      await onChanged();
      update({ targetId: result.targetId });
      setStatus("Target created.");
    } catch (cause) {
      setStatus(errorText(cause));
    }
  };
  return (
    <details>
      <summary>Create project or target</summary>
      <div className="grid two">
        <label>
          New project name
          <input
            value={projectName}
            onChange={(event) => setProjectName(event.target.value)}
          />
        </label>
        <label>
          New target display name
          <input
            value={targetName}
            onChange={(event) => setTargetName(event.target.value)}
          />
        </label>
        <label>
          Tags, comma separated
          <input
            value={tags}
            onChange={(event) => setTags(event.target.value)}
          />
        </label>
      </div>
      <div className="actions">
        <button
          type="button"
          disabled={!projectName.trim()}
          onClick={() => void createProject()}
        >
          Create Project
        </button>
        <button
          type="button"
          disabled={!targetName.trim() || !state.target}
          onClick={() => void createTarget()}
        >
          Create Target
        </button>
      </div>
      {status && <small role="status">{status}</small>}
    </details>
  );
}
function splitTags(value: string): string[] {
  return [
    ...new Set(
      value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ].slice(0, 20);
}

function ScopeStep({
  scope,
  setScope,
  setMessage,
}: {
  scope: ScopeState;
  setScope: (scope: ScopeState) => void;
  setMessage: (message: string) => void;
}) {
  const importScope = async (file?: File) => {
    if (!file) return;
    if (file.size > 128 * 1024) {
      setMessage("Scope import exceeds the 128 KiB limit.");
      return;
    }
    try {
      const value = JSON.parse(await file.text()) as ScopeState;
      setScope({ ...scope, ...value });
      setMessage(
        "Scope imported into the visual builder. Backend validation still applies.",
      );
    } catch {
      setMessage("Scope import is not valid JSON.");
    }
  };
  return (
    <div className="studio-panel">
      <p>
        The core scope model supports domain rules, denied paths, safe methods,
        depth, origin/subdomain policy, robots handling, rate, concurrency, and
        user agent. Browser-only origin exceptions are resolved by the browser
        module policy.
      </p>
      <RuleEditor
        label="Allowed domains"
        values={scope.allowedDomains}
        placeholder="app.example.test or *.example.test"
        normalize={(value) => value.trim().toLowerCase().replace(/\.$/, "")}
        validate={(value) => /^(\*\.)?[a-z0-9.-]+$/i.test(value)}
        onChange={(allowedDomains) => setScope({ ...scope, allowedDomains })}
      />
      <RuleEditor
        label="Denied paths"
        values={scope.disallowedPaths}
        placeholder="/logout"
        normalize={(value) => value.trim()}
        validate={(value) => value.startsWith("/")}
        onChange={(disallowedPaths) => setScope({ ...scope, disallowedPaths })}
      />
      <div className="grid two">
        <label>
          Maximum crawl depth
          <input
            type="number"
            min="0"
            max="10"
            value={scope.maxDepth}
            onChange={(event) =>
              setScope({ ...scope, maxDepth: Number(event.target.value) })
            }
          />
        </label>
        <label>
          User agent
          <input
            value={scope.userAgent}
            onChange={(event) =>
              setScope({ ...scope, userAgent: event.target.value })
            }
          />
        </label>
      </div>
      <fieldset>
        <legend>Allowed methods</legend>
        <div className="check-row">
          {(["GET", "HEAD", "OPTIONS", "POST"] as const).map((method) => (
            <label className="checkbox" key={method}>
              <input
                type="checkbox"
                checked={scope.allowedMethods.includes(method)}
                onChange={(event) =>
                  setScope({
                    ...scope,
                    allowedMethods: event.target.checked
                      ? [...scope.allowedMethods, method]
                      : scope.allowedMethods.filter((item) => item !== method),
                  })
                }
              />
              {method}
            </label>
          ))}
        </div>
        <small>
          POST is available only to modules with an additional non-mutating
          safety contract.
        </small>
      </fieldset>
      <div className="check-row">
        <label className="checkbox">
          <input
            type="checkbox"
            checked={scope.sameOriginOnly}
            onChange={(event) =>
              setScope({ ...scope, sameOriginOnly: event.target.checked })
            }
          />
          Same origin only
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={scope.includeSubdomains}
            onChange={(event) =>
              setScope({ ...scope, includeSubdomains: event.target.checked })
            }
          />
          Include declared subdomains
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={scope.respectRobotsTxt}
            onChange={(event) =>
              setScope({ ...scope, respectRobotsTxt: event.target.checked })
            }
          />
          Respect robots.txt
        </label>
      </div>
      <label className="file-control">
        Import scope JSON (128 KiB maximum)
        <input
          type="file"
          accept="application/json,.json"
          onChange={(event) => void importScope(event.target.files?.[0])}
        />
      </label>
    </div>
  );
}

function RuleEditor({
  label,
  values,
  placeholder,
  normalize,
  validate,
  onChange,
}: {
  label: string;
  values: string[];
  placeholder: string;
  normalize: (value: string) => string;
  validate: (value: string) => boolean;
  onChange: (values: string[]) => void;
}) {
  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");
  const add = () => {
    const value = normalize(draft);
    if (!validate(value)) {
      setError(`Invalid ${label.toLowerCase()} rule.`);
      return;
    }
    if (values.includes(value)) {
      setError("Duplicate rule.");
      return;
    }
    onChange([...values, value]);
    setDraft("");
    setError("");
  };
  return (
    <fieldset>
      <legend>{label}</legend>
      <div className="rule-add">
        <input
          aria-label={`New ${label.toLowerCase()} rule`}
          value={draft}
          placeholder={placeholder}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              add();
            }
          }}
        />
        <button type="button" onClick={add}>
          Add
        </button>
      </div>
      {error && (
        <small className="error" role="alert">
          {error}
        </small>
      )}
      <ul className="rule-list">
        {values.map((value) => (
          <li key={value}>
            <code>{value}</code>
            <button
              type="button"
              aria-label={`Remove ${value}`}
              onClick={() => onChange(values.filter((item) => item !== value))}
            >
              Remove
            </button>
          </li>
        ))}
      </ul>
    </fieldset>
  );
}

function ProfileStep({
  state,
  profile,
  capabilities,
  search,
  setSearch,
  update,
}: {
  state: StudioState;
  profile?: CapabilityRegistry["profiles"][number];
  capabilities?: CapabilityRegistry;
  search: string;
  setSearch: (value: string) => void;
  update: (value: Partial<StudioState>) => void;
}) {
  const modules =
    capabilities?.modules.filter((module) =>
      `${module.displayName} ${module.description} ${module.capabilities.join(" ")}`
        .toLowerCase()
        .includes(search.toLowerCase()),
    ) ?? [];
  return (
    <div className="studio-panel">
      <div className="profile-options">
        {capabilities?.profiles.map((item) => (
          <label
            key={item.name}
            className={state.profile === item.name ? "selected" : ""}
          >
            <input
              type="radio"
              name="profile"
              checked={state.profile === item.name}
              onChange={() =>
                update({
                  profile: item.name,
                  selectedModules: [...item.modules],
                  evidenceLevel: item.proofMode
                    ? "strong"
                    : item.name === "quick"
                      ? "minimal"
                      : "normal",
                })
              }
            />
            <strong>{item.displayName}</strong>
            <span>{item.description}</span>
            <small>
              {item.modules.length} modules · auth {item.authComparisonDepth} ·
              browser {item.browserUse}
            </small>
          </label>
        ))}
      </div>
      {profile && (
        <p className="context-strip">
          Intensity and limits: {JSON.stringify(profile.limits)}
        </p>
      )}
      <div className="toolbar">
        <input
          aria-label="Search modules"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search modules or capabilities"
        />
        <button
          type="button"
          onClick={() =>
            update({ selectedModules: profile ? [...profile.modules] : [] })
          }
        >
          Reset to profile defaults
        </button>
      </div>
      <div className="module-grid">
        {modules.map((module) => (
          <label className="module-option" key={module.id}>
            <input
              type="checkbox"
              checked={state.selectedModules.includes(module.id)}
              onChange={(event) =>
                update({
                  selectedModules: event.target.checked
                    ? [...state.selectedModules, module.id]
                    : state.selectedModules.filter((id) => id !== module.id),
                })
              }
            />
            <strong>{module.displayName}</strong>
            <span>
              {module.phase} · {module.cost} · auth:{" "}
              {module.requiresAuthentication}
            </span>
            <small>{module.description}</small>
            {module.dependencies.length > 0 && (
              <small>Depends on: {module.dependencies.join(", ")}</small>
            )}
            {module.capabilities.some((item) =>
              capabilities?.controlledWorkflows.some(
                (workflow) => workflow.id === item,
              ),
            ) && <em>Controlled workflow configuration required.</em>}
          </label>
        ))}
      </div>
      {state.selectedModules.includes("nextjs-review") && (
        <fieldset className="studio-subpanel nextjs-review-settings">
          <legend>Next.js Deep Review settings</legend>
          <p className="muted">Only observed routes, directly referenced artifacts, and exact known Pages data relationships are reviewed. Server Actions and arbitrary RSC values are never invoked.</p>
          <label><input type="checkbox" checked={state.nextJsReview.inspectKnownNextJsDataSurfaces} onChange={(event) => update({ nextJsReview: { ...state.nextJsReview, inspectKnownNextJsDataSurfaces: event.target.checked } })} /> Review exact known Pages data surfaces</label>
          <label><input type="checkbox" checked={state.nextJsReview.inspectNextJsSourceMaps} onChange={(event) => update({ nextJsReview: { ...state.nextJsReview, inspectNextJsSourceMaps: event.target.checked } })} /> Review explicitly referenced source maps</label>
          <label>Cache review mode<select aria-label="Next.js cache review mode" value={state.nextJsReview.nextJsCacheReviewMode} onChange={(event) => update({ nextJsReview: { ...state.nextJsReview, nextJsCacheReviewMode: event.target.value as NextJsReviewSettings["nextJsCacheReviewMode"] } })}><option value="PASSIVE_CACHE_REVIEW">Passive signals only</option><option value="CONTROLLED_CACHE_DIFFERENTIAL">Controlled actor differential</option></select></label>
          <div className="compact-grid">
            <NumberSetting label="Manifest requests" value={state.nextJsReview.maxNextJsManifestRequests} min={1} max={32} onChange={(value) => update({ nextJsReview: { ...state.nextJsReview, maxNextJsManifestRequests: value } })} />
            <NumberSetting label="Data requests" value={state.nextJsReview.maxNextJsDataSurfaceRequests} min={1} max={64} onChange={(value) => update({ nextJsReview: { ...state.nextJsReview, maxNextJsDataSurfaceRequests: value } })} />
            <NumberSetting label="Source-map requests" value={state.nextJsReview.maxNextJsSourceMapRequests} min={1} max={32} onChange={(value) => update({ nextJsReview: { ...state.nextJsReview, maxNextJsSourceMapRequests: value } })} />
            <NumberSetting label="Cache differential requests" value={state.nextJsReview.maxNextJsCacheDifferentialRequests} min={0} max={12} onChange={(value) => update({ nextJsReview: { ...state.nextJsReview, maxNextJsCacheDifferentialRequests: value } })} />
            <NumberSetting label="Assets inspected" value={state.nextJsReview.maxNextJsAssetsInspected} min={1} max={500} onChange={(value) => update({ nextJsReview: { ...state.nextJsReview, maxNextJsAssetsInspected: value } })} />
            <NumberSetting label="Routes processed" value={state.nextJsReview.maxNextJsRoutesProcessed} min={1} max={2000} onChange={(value) => update({ nextJsReview: { ...state.nextJsReview, maxNextJsRoutesProcessed: value } })} />
          </div>
          {state.nextJsReview.nextJsCacheReviewMode === "CONTROLLED_CACHE_DIFFERENTIAL" && <p className="warning">Controlled cache differential requires configured actors with distinct declared/verified identities. It uses exact GET requests with tool-side cache reuse disabled and never sends cache-poisoning headers.</p>}
        </fieldset>
      )}
    </div>
  );
}

function NumberSetting({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (value: number) => void }) {
  return <label>{label}<input type="number" min={min} max={max} value={value} onChange={(event) => onChange(Number(event.target.value))} /></label>;
}

function AuthenticationStep({
  state,
  credentials,
  update,
}: {
  state: StudioState;
  credentials: Array<{
    id: string;
    safeAlias: string;
    enabled: boolean;
    credentialTypeSummary: string;
  }>;
  update: (value: Partial<StudioState>) => void;
}) {
  return (
    <div className="studio-panel">
      <label>
        Authentication model
        <select
          value={state.authMode}
          onChange={(event) =>
            update({ authMode: event.target.value as AuthMode })
          }
        >
          <option value="public">Public / none</option>
          <option value="primary">Primary account</option>
          <option value="account-pair">Account A and Account B</option>
        </select>
      </label>
      {state.authMode === "public" && (
        <p>No authentication material will be sent.</p>
      )}
      {state.authMode === "primary" && (
        <ActorEditor
          title="Primary authentication"
          actor={state.primary}
          credentials={credentials}
          onChange={(primary) => update({ primary })}
        />
      )}
      {state.authMode === "account-pair" && (
        <div className="actor-grid">
          <ActorEditor
            title="Account A"
            actor={state.accountA}
            credentials={credentials}
            onChange={(accountA) => update({ accountA })}
          />
          <ActorEditor
            title="Account B"
            actor={state.accountB}
            credentials={credentials}
            onChange={(accountB) => update({ accountB })}
          />
        </div>
      )}
      <p className="secret-note">
        Values marked secret remain browser-memory-only. JavaScript cannot
        guarantee physical erasure, but RouteCairn clears references after
        launch, reset, logout, or session expiry.
      </p>
    </div>
  );
}

function ActorEditor({
  title,
  actor,
  credentials,
  onChange,
}: {
  title: string;
  actor: ActorState;
  credentials: Array<{
    id: string;
    safeAlias: string;
    enabled: boolean;
    credentialTypeSummary: string;
  }>;
  onChange: (actor: ActorState) => void;
}) {
  return (
    <fieldset>
      <legend>{title}</legend>
      <label>
        Source
        <select
          value={actor.source}
          onChange={(event) =>
            onChange({
              ...actor,
              source: event.target.value as AuthSource,
              savedId: "",
              bearerToken: "",
              headers: [],
              cookies: [],
            })
          }
        >
          <option value="ephemeral">Ephemeral (memory only)</option>
          <option value="saved">Saved credential vault</option>
        </select>
      </label>
      {actor.source === "saved" ? (
        <label>
          Credential profile
          <select
            value={actor.savedId}
            onChange={(event) =>
              onChange({ ...actor, savedId: event.target.value })
            }
          >
            <option value="">Select credential</option>
            {credentials
              .filter((item) => item.enabled)
              .map((item) => (
                <option key={item.id} value={item.id}>
                  {item.safeAlias} - {item.credentialTypeSummary}
                </option>
              ))}
          </select>
        </label>
      ) : (
        <>
          <label>
            Safe alias
            <input
              value={actor.safeAlias}
              maxLength={160}
              onChange={(event) =>
                onChange({ ...actor, safeAlias: event.target.value })
              }
            />
          </label>
          <label>
            Bearer token <span className="secret-label">Secret</span>
            <input
              type="password"
              autoComplete="off"
              value={actor.bearerToken}
              maxLength={4000}
              onChange={(event) =>
                onChange({ ...actor, bearerToken: event.target.value })
              }
            />
          </label>
          <SecretRows
            label="Header"
            rows={actor.headers}
            onChange={(headers) => onChange({ ...actor, headers })}
          />
          <SecretRows
            label="Cookie"
            rows={actor.cookies}
            onChange={(cookies) => onChange({ ...actor, cookies })}
          />
        </>
      )}
    </fieldset>
  );
}

function SecretRows({
  label,
  rows,
  onChange,
}: {
  label: "Header" | "Cookie";
  rows: HeaderRow[] | CookieRow[];
  onChange: (rows: HeaderRow[]) => void;
}) {
  return (
    <fieldset>
      <legend>{label}s</legend>
      {rows.map((row, index) => (
        <div className="secret-row" key={row.id}>
          <input
            aria-label={`${label} name ${index + 1}`}
            placeholder="Name"
            value={row.name}
            onChange={(event) =>
              onChange(
                rows.map((item) =>
                  item.id === row.id
                    ? { ...item, name: event.target.value }
                    : item,
                ),
              )
            }
          />
          <input
            aria-label={`${label} value ${index + 1}`}
            type="password"
            autoComplete="off"
            placeholder="Secret value"
            value={row.value}
            onChange={(event) =>
              onChange(
                rows.map((item) =>
                  item.id === row.id
                    ? { ...item, value: event.target.value }
                    : item,
                ),
              )
            }
          />
          <button
            type="button"
            onClick={() => onChange(rows.filter((item) => item.id !== row.id))}
          >
            Remove
          </button>
        </div>
      ))}
      <button
        type="button"
        disabled={rows.length >= 24}
        onClick={() =>
          onChange([...rows, { id: crypto.randomUUID(), name: "", value: "" }])
        }
      >
        Add {label.toLowerCase()}
      </button>
    </fieldset>
  );
}

function IdentityStep({
  state,
  update,
  result,
  onTest,
}: {
  state: StudioState;
  update: (value: Partial<StudioState>) => void;
  result?: Record<string, unknown>;
  onTest: () => Promise<void>;
}) {
  const entries: Array<
    [keyof Pick<StudioState, "primary" | "accountA" | "accountB">, string]
  > =
    state.authMode === "primary"
      ? [["primary", "Primary"]]
      : state.authMode === "account-pair"
        ? [
            ["accountA", "Account A"],
            ["accountB", "Account B"],
          ]
        : [];
  return (
    <div className="studio-panel">
      {entries.length === 0 && (
        <p>
          Identity verification is available when authentication is configured.
        </p>
      )}
      {entries.map(([key, label]) => {
        const actor = state[key];
        return actor.source === "saved" ? (
          <fieldset key={key}>
            <legend>{label}</legend>
            <p>
              Saved profile identity configuration is encrypted in the
              credential vault and is tested without returning plaintext.
            </p>
          </fieldset>
        ) : (
          <IdentityEditor
            key={key}
            label={label}
            actor={actor}
            onChange={(value) => update({ [key]: value })}
          />
        );
      })}
      {entries.length > 0 && (
        <button type="button" onClick={() => void onTest()}>
          Test Identity
        </button>
      )}
      {result && (
        <pre className="code safe-result">
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  );
}

function IdentityEditor({
  label,
  actor,
  onChange,
}: {
  label: string;
  actor: ActorState;
  onChange: (actor: ActorState) => void;
}) {
  const value = actor.identity;
  const set = (patch: Partial<IdentityState>) =>
    onChange({ ...actor, identity: { ...value, ...patch } });
  return (
    <fieldset>
      <legend>{label} identity</legend>
      <div className="grid two">
        <label>
          Verification policy
          <select
            value={value.mode}
            onChange={(event) =>
              set({ mode: event.target.value as IdentityState["mode"] })
            }
          >
            <option value="disabled">Disabled</option>
            <option value="optional">Optional</option>
            <option value="required">Required</option>
          </select>
        </label>
        <label>
          Safe method
          <select
            value={value.method}
            onChange={(event) =>
              set({ method: event.target.value as "GET" | "HEAD" })
            }
          >
            <option>GET</option>
            <option>HEAD</option>
          </select>
        </label>
        <label>
          Identity endpoint
          <input
            value={value.endpoint}
            onChange={(event) => set({ endpoint: event.target.value })}
            placeholder="/api/me"
          />
        </label>
        <label>
          Principal field path
          <input
            value={value.principalIdField}
            onChange={(event) => set({ principalIdField: event.target.value })}
            placeholder="user.id"
          />
        </label>
        <label>
          Expected principal
          <input
            value={value.expectedPrincipal}
            onChange={(event) => set({ expectedPrincipal: event.target.value })}
          />
        </label>
        <label>
          Tenant field path
          <input
            value={value.tenantIdField}
            onChange={(event) => set({ tenantIdField: event.target.value })}
          />
        </label>
        <label>
          Expected tenant
          <input
            value={value.expectedTenant}
            onChange={(event) => set({ expectedTenant: event.target.value })}
          />
        </label>
        <label>
          Role field path
          <input
            value={value.roleField}
            onChange={(event) => set({ roleField: event.target.value })}
          />
        </label>
        <label>
          Expected role
          <input
            value={value.expectedRole}
            onChange={(event) => set({ expectedRole: event.target.value })}
          />
        </label>
        <label>
          Account-state field path
          <input
            value={value.accountStateField}
            onChange={(event) => set({ accountStateField: event.target.value })}
          />
        </label>
        <label>
          Expected account state
          <input
            value={value.expectedState}
            onChange={(event) => set({ expectedState: event.target.value })}
          />
        </label>
        <label>
          Maximum response bytes
          <input
            type="number"
            min="1"
            max="65536"
            value={value.maxResponseBytes}
            onChange={(event) =>
              set({ maxResponseBytes: Number(event.target.value) })
            }
          />
        </label>
      </div>
      <small>
        Simple dotted paths and bounded array indexes are supported. Wildcards,
        JSONPath, scripts, and prototype traversal are rejected.
      </small>
    </fieldset>
  );
}

function LimitsStep({
  state,
  profile,
  update,
}: {
  state: StudioState;
  profile?: CapabilityRegistry["profiles"][number];
  update: (value: Partial<StudioState>) => void;
}) {
  return (
    <div className="studio-panel">
      <p>
        Browser policy is resolved from the selected profile and browser-crawler
        module settings. Service workers, popups, downloads, uploads,
        WebSockets, third-party traffic, private destinations, redirects, and
        attempt budgets remain controlled by the resolved plan.
      </p>
      <pre className="safe-summary">
        {JSON.stringify(profile?.limits ?? {}, null, 2)}
      </pre>
      <div className="grid two">
        <label>
          Rate limit per second
          <input
            type="number"
            min="1"
            max="50"
            value={state.scope.rateLimitPerSecond}
            onChange={(event) =>
              update({
                scope: {
                  ...state.scope,
                  rateLimitPerSecond: Number(event.target.value),
                },
              })
            }
          />
        </label>
        <label>
          Concurrency
          <input
            type="number"
            min="1"
            max="50"
            value={state.scope.concurrency}
            onChange={(event) =>
              update({
                scope: {
                  ...state.scope,
                  concurrency: Number(event.target.value),
                },
              })
            }
          />
        </label>
      </div>
      <p className="muted">
        Advanced browser module settings remain profile-controlled in this
        milestone and are shown exactly in Plan Review.
      </p>
    </div>
  );
}

function EvidenceStep({
  state,
  capabilities,
  update,
}: {
  state: StudioState;
  capabilities?: CapabilityRegistry;
  update: (value: Partial<StudioState>) => void;
}) {
  return (
    <div className="studio-panel">
      <fieldset>
        <legend>Evidence policy</legend>
        {capabilities?.evidenceLevels.map((level) => (
          <label className="evidence-option" key={level.id}>
            <input
              type="radio"
              name="evidence"
              checked={state.evidenceLevel === level.id}
              onChange={() => update({ evidenceLevel: level.id })}
            />
            <strong>{level.id}</strong>
            <span>{level.retention}</span>
          </label>
        ))}
        <p className="muted">
          Evidence may be strengthened from the profile default.
          Safety-sensitive profiles cannot be downgraded; Plan Review shows the
          effective policy.
        </p>
      </fieldset>
      <fieldset>
        <legend>Reports</legend>
        {(["json", "markdown", "html"] as const).map((format) => (
          <label className="checkbox" key={format}>
            <input type="checkbox" checked disabled />
            {format.toUpperCase()} report
          </label>
        ))}
        <small>
          RouteCairn currently emits all three production report formats. PDF
          proof packs are outside this milestone.
        </small>
      </fieldset>
    </div>
  );
}

function ReviewStep({
  state,
  profile,
}: {
  state: StudioState;
  profile?: CapabilityRegistry["profiles"][number];
}) {
  return (
    <div className="studio-panel review">
      <Review
        title="General"
        value={{
          scanName: state.scanName,
          target: state.target,
          authorization: state.authorizationCategory,
          authorizationConfirmed: state.authorizationConfirmed,
        }}
      />
      <Review title="Scope" value={state.scope} />
      <Review
        title="Profile and modules"
        value={{
          profile: profile?.displayName ?? state.profile,
          modules: state.selectedModules.length
            ? state.selectedModules
            : profile?.modules,
        }}
      />
      <Review title="Authentication" value={safeAuthReview(state)} />
      <Review title="Identity" value={safeIdentityReview(state)} />
      <Review
        title="Controlled workflows"
        value={state.workflows.map((workflow) => ({
          workflowId: workflow.workflowId,
          enabled: workflow.enabled,
          editorMode: workflow.editorMode,
          caseCount: workflowCaseCount(workflow),
          exactPlannedRequests:
            state.preview?.controlledWorkflowRequests?.find(
              (item) => item.workflowId === workflow.workflowId,
            )?.exactRequests ?? "Unknown until planning",
        }))}
      />
      <Review
        title="Evidence and outputs"
        value={{
          requestedEvidence: state.evidenceLevel,
          outputs: state.outputs,
        }}
      />
      {state.preview ? (
        <Review title="Resolved ScanPlanner result" value={state.preview} />
      ) : (
        <p className="notice">
          Resolve the plan to see exact module order, dependencies, limits,
          authentication requirements, browser settings, evidence policy,
          warnings, and redacted plan data.
        </p>
      )}
    </div>
  );
}
function Review({ title, value }: { title: string; value: unknown }) {
  return (
    <section>
      <h4>{title}</h4>
      <pre className="safe-summary">{JSON.stringify(value, null, 2)}</pre>
    </section>
  );
}
function LaunchStep({
  state,
  errors,
  launching,
  onLaunch,
}: {
  state: StudioState;
  errors: ValidationError[];
  launching: boolean;
  onLaunch: () => Promise<void>;
}) {
  return (
    <div className="studio-panel">
      <h4>Ready for independent launch validation</h4>
      <p>
        Launch sends the current Studio configuration, not the previewed plan.
        The backend resolves saved credentials, validates scope and identity
        configuration, reruns ScanPlanner, verifies the safe preview identity,
        and only then queues a new worker job.
      </p>
      {errors.length > 0 && (
        <div className="validation-summary" role="alert">
          {errors.map((error) => (
            <p key={`${error.step}-${error.message}`}>
              {steps[error.step]}: {error.message}
            </p>
          ))}
        </div>
      )}
      <label className="checkbox">
        <input type="checkbox" checked readOnly /> Non-destructive safety policy
        remains enforced.
      </label>
      <button
        type="button"
        className="primary"
        disabled={!state.preview || errors.length > 0 || launching}
        onClick={() => void onLaunch()}
      >
        {launching ? "Launching..." : "Confirm and Launch"}
      </button>
    </div>
  );
}

type ValidationError = { step: number; message: string };
function validate(state: StudioState): ValidationError[] {
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
function validateActor(
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
function applicableActors(state: StudioState): ActorState[] {
  return state.authMode === "primary"
    ? [state.primary]
    : state.authMode === "account-pair"
      ? [state.accountA, state.accountB]
      : [];
}
function buildRequest(state: StudioState): Record<string, unknown> {
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
    ...(state.selectedModules.length
      ? { includeModules: state.selectedModules }
      : {}),
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
function actorProfile(actor: ActorState) {
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
function clearSecrets(state: StudioState): StudioState {
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
function safeAuthReview(state: StudioState) {
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
function safeIdentityReview(state: StudioState) {
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
function errorText(value: unknown): string {
  return value instanceof Error
    ? value.message
    : "Scan Studio operation failed.";
}
function workflowModuleId(id: WorkflowDraft["workflowId"]): string {
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
function containsUnsafeWorkflowIdentifier(value: unknown, key = ""): boolean {
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
