import { useState } from "react";
import { apiMutation, type ProjectSummary, type TargetSummary } from "./api";
import { workflowCaseCount } from "./AuthorizationWorkflowStudio";



import { accountPairIdentityWarnings, credentialUsable, type CredentialSummary } from "./CredentialLifecycle";
import { type StudioState, type ScopeState, type CapabilityRegistry, type NextJsReviewSettings, type AuthMode, type ActorState, type AuthSource, type HeaderRow, type CookieRow, type IdentityState, type ValidationError, steps } from "./ScanStudioModel";
import { splitTags, errorText, validate, safeAuthReview, safeIdentityReview, isObjectRecord, advancedPreviewId } from "./ScanStudioValidation";

export function TargetStep({
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

export function ResourceCreator({
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

export function ScopeStep({
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
          {(["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE", "CONNECT"] as const).map((method) => (
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

export function RuleEditor({
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

export function ProfileStep({
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

export function NumberSetting({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (value: number) => void }) {
  return <label>{label}<input type="number" min={min} max={max} value={value} onChange={(event) => onChange(Number(event.target.value))} /></label>;
}

export function AuthenticationStep({
  state,
  credentials,
  update,
}: {
  state: StudioState;
  credentials: CredentialSummary[];
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
          {accountPairIdentityWarnings(credentials.find((item) => item.id === state.accountA.savedId), credentials.find((item) => item.id === state.accountB.savedId)).map((warning) => <p className="warning" role="alert" key={warning}>{warning}</p>)}
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

export function ActorEditor({
  title,
  actor,
  credentials,
  onChange,
}: {
  title: string;
  actor: ActorState;
  credentials: CredentialSummary[];
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
              .filter(credentialUsable)
              .map((item) => (
                <option key={item.id} value={item.id}>
                  {item.safeAlias} - {item.credentialTypeSummary} - {item.health?.classification ?? "UNVERIFIED"}
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

export function SecretRows({
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

export function IdentityStep({
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

export function IdentityEditor({
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

export function LimitsStep({
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
        <label>
          Total scan request budget
          <input
            type="number"
            min="1"
            max="10000"
            placeholder={String(profile?.limits.maxRequests ?? "Profile default")}
            value={state.maxRequestsOverride}
            onChange={(event) => update({ maxRequestsOverride: event.target.value })}
          />
        </label>
        <label>
          Cleanup requests reserved
          <input
            type="number"
            min="0"
            max="5000"
            placeholder={String(profile?.limits.cleanupReservedRequests ?? "Automatic")}
            value={state.cleanupReservedRequestsOverride}
            onChange={(event) => update({ cleanupReservedRequestsOverride: event.target.value })}
          />
        </label>
      </div>
      <p className="muted">
        The total is enforced across every engine, retry, redirect, API broker,
        and browser request. Cleanup capacity is withheld from ordinary traffic
        and can only be used for restoration. Empty fields use the resolved
        profile and automatic cleanup reserve shown in Plan Review.
      </p>
      <fieldset>
        <legend>IP-bound transport</legend>
        <div className="grid two">
          <label className="checkbox"><input type="checkbox" checked={state.transport.poolingEnabled} onChange={(event) => update({ transport: { ...state.transport, poolingEnabled: event.target.checked } })} /> Reuse verified origin-isolated connections</label>
          <label className="checkbox"><input type="checkbox" checked={state.transport.http2Enabled} onChange={(event) => update({ transport: { ...state.transport, http2Enabled: event.target.checked } })} /> Allow constrained HTTP/2 for HTTPS origins</label>
          <TransportNumber label="Retained origin pools" value={state.transport.maxOrigins} min={1} max={1024} set={(value) => update({ transport: { ...state.transport, maxOrigins: value } })} />
          <TransportNumber label="Connections per origin" value={state.transport.maxConnectionsPerOrigin} min={1} max={32} set={(value) => update({ transport: { ...state.transport, maxConnectionsPerOrigin: value } })} />
          <TransportNumber label="HTTP/2 streams per connection" value={state.transport.maxConcurrentHttp2Streams} min={1} max={256} set={(value) => update({ transport: { ...state.transport, maxConcurrentHttp2Streams: value } })} />
          <TransportNumber label="Maximum response headers (bytes)" value={state.transport.maxHeaderSizeBytes} min={4096} max={65536} set={(value) => update({ transport: { ...state.transport, maxHeaderSizeBytes: value } })} />
          <TransportNumber label="Keep-alive timeout (ms)" value={state.transport.keepAliveTimeoutMs} min={100} max={120000} set={(value) => update({ transport: { ...state.transport, keepAliveTimeoutMs: value } })} />
          <TransportNumber label="Maximum keep-alive (ms)" value={state.transport.keepAliveMaxTimeoutMs} min={100} max={300000} set={(value) => update({ transport: { ...state.transport, keepAliveMaxTimeoutMs: value } })} />
          <TransportNumber label="Connection lifetime (ms)" value={state.transport.maxConnectionLifetimeMs} min={1000} max={900000} set={(value) => update({ transport: { ...state.transport, maxConnectionLifetimeMs: value } })} />
          <TransportNumber label="Requests per connection" value={state.transport.maxRequestsPerConnection} min={1} max={10000} set={(value) => update({ transport: { ...state.transport, maxRequestsPerConnection: value } })} />
          <TransportNumber label="Validated DNS pin lease (ms)" value={state.transport.dnsCacheTtlMs} min={0} max={60000} set={(value) => update({ transport: { ...state.transport, dnsCacheTtlMs: value } })} />
        </div>
        <small>Zero DNS lease revalidates before every dispatch. A lease caches only the already validated IP pin. HTTP/2 remains TLS-only and pools never span origins.</small>
      </fieldset>
    </div>
  );
}

export function TransportNumber({ label, value, min, max, set }: { label: string; value: number; min: number; max: number; set: (value: number) => void }) {
  return <label>{label}<input type="number" min={min} max={max} value={value} onChange={(event) => set(Number(event.target.value))} /></label>;
}

export function EvidenceStep({
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

export function ReviewStep({
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
      <Review title="IP-bound transport" value={state.transport} />
      <Review title="Identity" value={safeIdentityReview(state)} />
      <Review
        title="Controlled workflows"
        value={{
          dashboardNativeEngines: state.advancedEngines.filter((engine) => engine.enabled).map((engine) => ({ id: engine.id, caseCount: Array.isArray(engine.value.cases) ? engine.value.cases.length : isObjectRecord(engine.value.orchestration) && Array.isArray(engine.value.orchestration.criticalCases) ? engine.value.orchestration.criticalCases.length : undefined, exactPlannedRequests: state.preview?.controlledWorkflowRequests?.find((item) => item.workflowId === advancedPreviewId(engine.id))?.exactRequests ?? "Unknown until planning", source: "dashboard-inline" })),
          authenticationLifecycleFile: state.authenticationLifecycleFile || undefined,
          authenticationLifecycleAutoFile: state.authenticationLifecycleAutoFile || undefined,
          businessInvariantFile: state.businessInvariantFile || undefined,
          controlledRaceFile: state.controlledRaceFile || undefined,
          apiGraphqlFile: state.apiGraphqlFile || undefined,
          linkPortalSecurityFile: state.linkPortalSecurityFile || undefined,
          operationalEndpointSecurityFile: state.operationalEndpointSecurityFile || undefined,
          billingEntitlementFile: state.billingEntitlementFile || undefined,
          assistedReviewFile: state.assistedReviewFile || undefined,
          preHandoverFile: state.preHandoverFile || undefined,
          targetAuthorizationFile: state.targetAuthorizationFile || undefined,
          workflows: state.workflows.map((workflow) => ({
            workflowId: workflow.workflowId,
            enabled: workflow.enabled,
            editorMode: workflow.editorMode,
            caseCount: workflowCaseCount(workflow),
            exactPlannedRequests: state.preview?.controlledWorkflowRequests?.find((item) => item.workflowId === workflow.workflowId)?.exactRequests ?? "Unknown until planning",
          })),
        }}
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

export function Review({ title, value }: { title: string; value: unknown }) {
  return (
    <section>
      <h4>{title}</h4>
      <pre className="safe-summary">{JSON.stringify(value, null, 2)}</pre>
    </section>
  );
}

export function LaunchStep({
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
      {state.preview?.credentialReadiness && !state.preview.credentialReadiness.ready && (
        <div className="validation-summary" role="alert">
          {state.preview.credentialReadiness.blockers.map((blocker) => <p key={`${blocker.code}-${blocker.profileId}`}>{blocker.code}: {blocker.message}</p>)}
        </div>
      )}
      {state.preview?.credentialReadiness?.warnings?.map((warning) => <p className="warning" key={`${warning.code}-${warning.profileId ?? "pair"}`}>{warning.code}: {warning.message}</p>)}
      <label className="checkbox">
        <input type="checkbox" checked readOnly /> Non-destructive safety policy
        remains enforced.
      </label>
      <button
        type="button"
        className="primary"
        disabled={!state.preview || state.preview.credentialReadiness?.ready === false || errors.length > 0 || launching}
        onClick={() => void onLaunch()}
      >
        {launching ? "Launching..." : "Confirm and Launch"}
      </button>
    </div>
  );
}
