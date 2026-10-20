import { CollectionOwnershipControls, CollectionOwnershipSummary } from "./CollectionOwnership";
import type { IdentityModel } from "../../../src/core/auth/IdentityModel";
import { AssessmentJourney } from "./AssessmentJourney";
import { reviewedScalar, assertReviewedScalar } from "./ReviewedPolicyInput";
import { OwnedApplicationIntake } from "./OwnedApplicationIntake";
import { ApplicationOnboarding } from "./ApplicationOnboarding";
import { BoundedApplicationDiscovery } from "./BoundedApplicationDiscovery";
import { ApplicationSecurityHypotheses } from "./ApplicationSecurityHypotheses";
import { ApplicationSchemaImport } from "./ApplicationSchemaImport";
import { ApplicationMapComparison } from "./ApplicationMapComparison";
import React, { useState, useEffect } from "react";
import { apiGet, apiMutation } from "./api";
import type { ApplicationMappingInput } from "../../../src/dashboard/contracts/ApplicationMappingContracts";
import type { ApplicationMappingService } from "../../../src/dashboard/execution/ApplicationMappingService";
import type { AuthorizationWorkbenchInput } from "../../../src/dashboard/contracts/AuthorizationWorkbenchContracts";
import type { AuthorizationWorkbenchService } from "../../../src/dashboard/execution/AuthorizationWorkbenchService";
type Acquisition = ReturnType<ApplicationMappingService["result"]>;
type Matrix = Awaited<ReturnType<AuthorizationWorkbenchService["create"]>>;
type SeedRoute = ApplicationMappingInput["routes"][number];
interface Options {
  onboardingAllowed?: boolean;
  targets: { id: string; displayName: string; baseOrigin: string }[];
  credentials: {
    id: string;
    targetId?: string;
    alias: string;
    identity: { identityModel?: IdentityModel; principalId?: string; tenantId?: string; role?: string };
  }[];
  acquisitions: { id: string; version: number }[];
  comparisons?: { id: string }[];
}
const freshRoute = (n: number): SeedRoute => ({
  id: "operation-" + n,
  kind: "OBJECT",
  url: "",
  pathTemplate: "",
  method: "GET",
  identityPath: "id",
  tenantPath: "tenant"
});
export function GuidedApplicationMapping({
  canExecute,
  onMatrix,
  onScan
}: {
  canExecute: boolean;
  onMatrix: (matrix: Matrix) => void;
  onScan?: (id: string) => void;
}) {
  const [identityModel, setIdentityModel] = useState<IdentityModel>("TENANT_AWARE");
  const [options, setOptions] = useState<Options>(),
    [target, setTarget] = useState(""),
    [credentials, setCredentials] = useState({ primary: "", account_a: "", account_b: "" }),
    [intakeBinding, setIntakeBinding] = useState<ApplicationMappingInput["intakeBinding"]>(),
    [schemaBinding, setSchemaBinding] = useState<ApplicationMappingInput["schemaBinding"]>(),
    [discoveryBinding, setDiscoveryBinding] = useState<ApplicationMappingInput["discoveryBinding"]>(),
    [routes, setRoutes] = useState<SeedRoute[]>([freshRoute(1)]),
    [identityConfirmed, setIdentityConfirmed] = useState(false),
    [routesConfirmed, setRoutesConfirmed] = useState(false),
    [approval, setApproval] = useState(false),
    [policyConfirmed, setPolicyConfirmed] = useState(false),
    [acquisition, setAcquisition] = useState<Acquisition>(),
    [policy, setPolicy] = useState<AuthorizationWorkbenchInput["expectations"]>([]),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const load = async () => setOptions(await apiGet<Options>("/api/authorization-workbench/mapping"));
  useEffect(() => {
    void load().catch((e) => setError(e.message));
  }, []);
  const action = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Mapping evidence unavailable");
    } finally {
      setBusy(false);
    }
  };
  const invalidate = () => {
    setAcquisition(undefined);
    setApproval(false);
    setPolicy([]);
    setPolicyConfirmed(false);
  };
  const accept = (v: Acquisition) => {
    setAcquisition(v);
    if (v.status === "COMPLETED")
      setPolicy((p) =>
        p.length
          ? p
          : v.input.routes.map((r) => ({
              routeId: r.id,
              url: r.url,
              kind:
                r.kind === "FUNCTION"
                  ? "FUNCTION_AUTHORIZATION"
                  : r.tenantPath
                    ? "TENANT_ISOLATION"
                    : "OBJECT_AUTHORIZATION",
              ...(r.observation?.kind === "COLLECTION" ? { collection: r.observation } : {}),
              explanation: "Owner-declared access policy for this exact observed operation.",
              decisions: Object.fromEntries(v.actors.map((a) => [a.id, "UNKNOWN" as const]))
            }))
      );
  };
  useEffect(() => {
    if (!acquisition?.revisionId || !["QUEUED", "RUNNING", "PLANNING"].includes(acquisition.status)) return;
    let cancelled = false;
    const timer = setInterval(
      () =>
        void apiGet<Acquisition>("/api/authorization-workbench/mapping/" + acquisition.revisionId)
          .then((value) => {
            if (!cancelled) accept(value);
          })
          .catch((e) => setError(e.message)),
      1000
    );
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [acquisition?.revisionId, acquisition?.status]);
  const updateRoute = (index: number, value: Partial<SeedRoute>) => {
    setIntakeBinding(undefined);
    setSchemaBinding(undefined);
    if (value.url !== undefined || value.id !== undefined) setDiscoveryBinding(undefined);
    setRoutes((r) => r.map((v, i) => (i === index ? { ...v, ...value } : v)));
    invalidate();
    setRoutesConfirmed(false);
  };
  const updatePolicy = (index: number, value: Partial<AuthorizationWorkbenchInput["expectations"][number]>) => {
    setPolicy((p) => p.map((v, i) => (i === index ? { ...v, ...value } : v)));
    setPolicyConfirmed(false);
  };
  const scalarType = (routeId: string, path: string) =>
    acquisition?.observations
      .find((r) => r.routeId === routeId)
      ?.cells.find((c) => c.actorId === "primary")
      ?.observedMarkers.find((m) => m.path === path)?.scalarType;
  const scalarValue = (routeId: string, path: string, value: string) =>
    reviewedScalar(value, scalarType(routeId, path) === "number");
  return (
    <section className="guided-application-mapping" aria-label="Guided authenticated application mapping">
      <h3>Guided authenticated application mapping</h3>
      <p>
        Start with explicit permitted GET route seeds. Route templates and expected policy are your declarations;
        response decisions, identities and marker fingerprints come from the native worker. This is bounded observation,
        not automatic crawling.
      </p>
      <AssessmentJourney targetId={target} credentials={credentials} mapRevisionId={acquisition?.revisionId} />
      <ol aria-label="Application mapping stages">
        <li>Choose target and verified actor contracts</li>
        <li>Review schema suggestions or manual route declarations ({routes.length})</li>
        <li>Preview and separately approve native observation: {acquisition?.status ?? "NOT_APPROVED"}</li>
        <li>Declare policy, review matrix, then approve bounded proof</li>
      </ol>
      {options?.onboardingAllowed && canExecute && (
        <ApplicationOnboarding
          onSaved={(v) => {
            void action(async () => {
              await load();
              setIntakeBinding(undefined);
              setIdentityModel(v.input.identityModel ?? "TENANT_AWARE");
              setTarget(v.targetId);
              setCredentials(v.credentials);
              setRoutes(v.input.routes);
              setSchemaBinding(undefined);
              setDiscoveryBinding(undefined);
              invalidate();
              setIdentityConfirmed(false);
              setRoutesConfirmed(false);
            });
          }}
        />
      )}
      {error && <p role="alert">{error}</p>}
      <label>
        Retained application map
        <select
          aria-label="Retained application map"
          value={acquisition?.revisionId ?? ""}
          disabled={busy}
          onChange={(e) => {
            const id = e.target.value;
            if (!id) return;
            setPolicy([]);
            setPolicyConfirmed(false);
            setApproval(false);
            void action(async () => {
              const v = await apiGet<Acquisition>("/api/authorization-workbench/mapping/" + id);
              setIdentityModel(v.input.identityModel ?? "TENANT_AWARE");
              setTarget(v.input.targetId);
              setCredentials(v.input.credentials);
              setRoutes(v.input.routes);
              setIntakeBinding(v.input.intakeBinding);
              setSchemaBinding(v.input.schemaBinding);
              setDiscoveryBinding(v.input.discoveryBinding);
              accept(v);
            });
          }}
        >
          <option value="">Open retained observation and its exact scope</option>
          {options?.acquisitions?.map((a) => (
            <option key={a.id} value={a.id}>
              {a.id} · observation {a.version}
            </option>
          ))}
        </select>
      </label>
      {acquisition && (
        <ApplicationSecurityHypotheses
          key={acquisition.revisionId}
          mapId={acquisition.revisionId}
          canExecute={canExecute}
          onMatrix={onMatrix}
          onScan={onScan}
        />
      )}
      {acquisition && (
        <ApplicationMapComparison
          maps={options?.acquisitions ?? []}
          saved={options?.comparisons ?? []}
          currentId={acquisition?.revisionId}
          onSaved={() => void load().catch((e) => setError(e.message))}
        />
      )}
      <details open={!acquisition}>
        <summary>A–B. Configure permitted routes and actor identities</summary>
        <fieldset disabled={busy || !canExecute}>
          <legend>A. Select an owned target and saved identities</legend>
          <label>
            Mapping identity model
            <select
              aria-label="Mapping identity model"
              value={identityModel}
              onChange={(e) => {
                const next = e.target.value as IdentityModel;
                setIdentityModel(next);
                setIdentityConfirmed(false);
                setRoutesConfirmed(false);
                setIntakeBinding(undefined);
                setSchemaBinding(undefined);
                setDiscoveryBinding(undefined);
                setRoutes((v) =>
                  v.map((r) => {
                    const { tenantPath, ...rest } = r;
                    return next === "PRINCIPAL_ROLE" ? rest : { ...rest, tenantPath };
                  })
                );
                invalidate();
              }}
            >
              <option value="TENANT_AWARE">Tenant-aware</option>
              <option value="PRINCIPAL_ROLE">Tenantless principal and role</option>
            </select>
          </label>
          <label>
            Owned loopback target
            <select
              aria-label="Owned loopback target"
              value={target}
              onChange={(e) => {
                setIntakeBinding(undefined);
                setTarget(e.target.value);
                setCredentials({ primary: "", account_a: "", account_b: "" });
                setIdentityConfirmed(false);
                setRoutes([freshRoute(1)]);
                setSchemaBinding(undefined);
                setDiscoveryBinding(undefined);
                setRoutesConfirmed(false);
                invalidate();
              }}
            >
              <option value="">Choose a registered owned 127.0.0.1 target</option>
              {options?.targets?.map((t) => (
                <option value={t.id} key={t.id}>
                  {t.displayName} · {t.baseOrigin}
                </option>
              ))}
            </select>
          </label>
          <div className="mapping-actors">
            {(["primary", "account_a", "account_b"] as const).map((slot) => {
              const c = options?.credentials?.find((c) => c.id === credentials[slot]);
              return (
                <label key={slot}>
                  {slot === "primary"
                    ? "Primary test actor"
                    : slot === "account_a"
                      ? "Account A test actor"
                      : "Account B test actor"}
                  <select
                    aria-label={slot + " saved credential"}
                    value={credentials[slot]}
                    onChange={(e) => {
                      setCredentials((v) => ({ ...v, [slot]: e.target.value }));
                      setIntakeBinding(undefined);
                      setIdentityConfirmed(false);
                      invalidate();
                    }}
                  >
                    <option value="">Choose a target-bound saved credential</option>
                    {options?.credentials
                      ?.filter((c) => c.targetId === target)
                      .map((c) => (
                        <option value={c.id} key={c.id}>
                          {c.alias} · {c.identity.role ?? "role missing"} ·{" "}
                          {c.identity.identityModel === "PRINCIPAL_ROLE"
                            ? "tenant not applicable"
                            : (c.identity.tenantId ?? "tenant missing")}
                        </option>
                      ))}
                  </select>
                  {c && (
                    <small>
                      Saved identity: {c.identity.principalId} · role {c.identity.role} ·{" "}
                      {c.identity.identityModel === "PRINCIPAL_ROLE"
                        ? "tenant not applicable"
                        : "tenant " + c.identity.tenantId}
                      . Native verification is still required.
                    </small>
                  )}
                </label>
              );
            })}
          </div>
          <label>
            <input
              type="checkbox"
              checked={identityConfirmed}
              onChange={(e) => {
                setIdentityConfirmed(e.target.checked);
                invalidate();
              }}
            />
            {identityModel === "PRINCIPAL_ROLE"
              ? "I confirm these disposable principal and role bindings; tenant verification is not applicable."
              : "I confirm these disposable actor, role and tenant bindings."}
          </label>
          <h4>B. Enter permitted observation routes</h4>
          <OwnedApplicationIntake
            key={target + JSON.stringify(credentials)}
            target={target}
            credentials={credentials}
            disabled={busy || !canExecute}
            onApply={(draft) => {
              setRoutes(draft.routes);
              setIntakeBinding(draft.intakeBinding);
              setSchemaBinding(undefined);
              setDiscoveryBinding(undefined);
              invalidate();
              setIdentityConfirmed(false);
              setRoutesConfirmed(false);
            }}
          />
          <ApplicationSchemaImport
            key={target}
            target={target}
            disabled={busy || !canExecute}
            onApply={(selected, binding) => {
              setIntakeBinding(undefined);
              const base = options?.targets.find((t) => t.id === target)?.baseOrigin;
              if (!base) return;
              setRoutes(selected.map((r) => ({ ...r, url: new URL(r.url, base).href })));
              invalidate();
              setSchemaBinding(binding);
              setDiscoveryBinding(undefined);
              setRoutesConfirmed(false);
            }}
          />
          {discoveryBinding && (
            <p>
              Native-discovered selection remains bound to immutable proposal {discoveryBinding.proposalId}. Preview and
              separate GET consent are required.
            </p>
          )}
          {schemaBinding && (
            <p>
              Schema-suggested routes reviewed · immutable schema {schemaBinding.revisionId}. Edits switch to manual
              declarations; fresh exact preview and consent are required.
            </p>
          )}
          <p>
            No endpoint expansion, redirects, non-GET methods or secret marker paths. Confirm that these specific GET
            handlers are non-mutating; GET alone is not proof of safety.
          </p>
          {routes.map((r, i) => (
            <fieldset className="mapping-route" key={i}>
              <legend>Observation route {i + 1}</legend>
              <div className="mapping-fields">
                <label>
                  Operation label
                  <input
                    aria-label={"Route " + (i + 1) + " label"}
                    value={r.id}
                    onChange={(e) => updateRoute(i, { id: e.target.value })}
                  />
                </label>
                <label>
                  Operation kind
                  <select
                    aria-label={"Route " + (i + 1) + " kind"}
                    value={r.kind}
                    onChange={(e) => updateRoute(i, { kind: e.target.value as SeedRoute["kind"] })}
                  >
                    <option value="OBJECT">Object read</option>
                    <option value="FUNCTION">Role-restricted function read</option>
                  </select>
                </label>
                <label>
                  Exact GET URL
                  <input
                    aria-label={"Route " + (i + 1) + " exact URL"}
                    type="url"
                    value={r.url}
                    onChange={(e) => updateRoute(i, { url: e.target.value })}
                  />
                </label>
                <label>
                  Declared route template
                  <input
                    aria-label={"Route " + (i + 1) + " template"}
                    placeholder="/api/documents/:id"
                    value={r.pathTemplate}
                    onChange={(e) => updateRoute(i, { pathTemplate: e.target.value })}
                  />
                </label>
                <label>
                  <input
                    type="checkbox"
                    aria-label={"Route " + (i + 1) + " bounded collection"}
                    checked={r.observation?.kind === "COLLECTION"}
                    onChange={(e) =>
                      updateRoute(
                        i,
                        e.target.checked
                          ? {
                              kind: "OBJECT",
                              identityPath: "id",
                              tenantPath: undefined,
                              statePaths: undefined,
                              observation: {
                                kind: "COLLECTION",
                                algorithm: "bounded-native-collection-v1",
                                collectionPath: "data",
                                itemIdentityPath: "id",
                                ownerPath: "owner",
                                ownerRule: "EXACT_VERIFIED_ACTOR_PRINCIPAL_STRING",
                                maxItems: 32,
                                maxResponseBytes: 8192,
                                coverage: "THIS_RESPONSE_ONLY",
                                pagination: { kind: "HAS_MORE_BOOLEAN", path: "hasMore" }
                              }
                            }
                          : { observation: undefined }
                      )
                    }
                  />
                  Observe bounded entry ownership
                </label>
                {r.observation?.kind === "COLLECTION" && (
                  <CollectionOwnershipControls
                    value={r.observation}
                    onChange={(observation) =>
                      updateRoute(i, { observation, identityPath: observation.itemIdentityPath })
                    }
                  />
                )}
                <label>
                  Object/function identity JSON field
                  <input
                    aria-label={"Route " + (i + 1) + " identity path"}
                    disabled={r.observation?.kind === "COLLECTION"}
                    value={r.identityPath}
                    onChange={(e) => updateRoute(i, { identityPath: e.target.value })}
                  />
                </label>
                <label>
                  Tenant JSON field
                  <input
                    aria-label={"Route " + (i + 1) + " tenant path"}
                    disabled={identityModel === "PRINCIPAL_ROLE" || r.observation?.kind === "COLLECTION"}
                    value={r.tenantPath ?? ""}
                    onChange={(e) => updateRoute(i, { tenantPath: e.target.value || undefined })}
                  />
                </label>
                <label>
                  Optional non-secret business-state fields (at most two, comma-separated)
                  <input
                    aria-label={"Route " + (i + 1) + " state paths"}
                    disabled={r.observation?.kind === "COLLECTION"}
                    value={(r.statePaths ?? []).join(",")}
                    onChange={(e) =>
                      updateRoute(i, {
                        statePaths: e.target.value ? e.target.value.split(",").map((v) => v.trim()) : undefined
                      })
                    }
                  />
                </label>
              </div>
              {routes.length > 1 && (
                <button
                  onClick={() => {
                    setIntakeBinding(undefined);
                    setSchemaBinding(undefined);
                    setDiscoveryBinding((b) =>
                      b ? { ...b, selections: b.selections.filter((s) => s.routeId !== r.id) } : undefined
                    );
                    setRoutes((v) => v.filter((_, n) => n !== i));
                    invalidate();
                    setRoutesConfirmed(false);
                  }}
                >
                  Remove route {i + 1}
                </button>
              )}
            </fieldset>
          ))}
          <button
            disabled={routes.length >= 8}
            onClick={() => {
              setIntakeBinding(undefined);
              setSchemaBinding(undefined);
              setDiscoveryBinding(undefined);
              setRoutes((v) => [...v, freshRoute(v.length + 1)]);
              invalidate();
              setRoutesConfirmed(false);
            }}
          >
            Add permitted route
          </button>
          <label>
            <input
              type="checkbox"
              checked={routesConfirmed}
              onChange={(e) => {
                setRoutesConfirmed(e.target.checked);
                invalidate();
              }}
            />
            I confirm the exact listed GET handlers are authorized and non-mutating.
          </label>
          <button
            disabled={
              !target ||
              !Object.values(credentials).every(Boolean) ||
              !identityConfirmed ||
              !routesConfirmed ||
              routes.some((r) => !r.url || !r.pathTemplate)
            }
            onClick={() =>
              void action(async () => {
                const r = await apiMutation<Acquisition>("/api/authorization-workbench/mapping/acquisitions", "POST", {
                  targetId: target,
                  identityModel,
                  ...(intakeBinding ? { intakeBinding } : {}),
                  ...(schemaBinding ? { schemaBinding } : {}),
                  ...(discoveryBinding ? { discoveryBinding } : {}),
                  credentials,
                  routes,
                  identityContextConfirmed: true,
                  readOnlyRoutesConfirmed: true
                });
                accept({
                  ...r,
                  status: "REVIEW_REQUIRED",
                  observations: [],
                  verifiedApplicationPass: false,
                  observationIsPolicyOrFinding: false
                });
                setApproval(false);
                await load();
              })
            }
          >
            Review observation requests
          </button>
        </fieldset>
      </details>
      {acquisition && (
        <>
          <h4>C. Approve the exact bounded observation</h4>
          <p role="status">Observation status: {acquisition.status}</p>
          <p>
            Maximum {acquisition.proofBudget.totalRequestCeiling} shared requests; {acquisition.proofBudget.checks}{" "}
            selected observations, three identity verifications and a baseline GET. Response cap{" "}
            {acquisition.proofBudget.maxResponseBytes} bytes; concurrency one. No authorization finding is inferred from
            observation.
          </p>
          <details open={acquisition.status === "REVIEW_REQUIRED"}>
            <summary>Inspect exact observation requests ({acquisition.transportIntents.length})</summary>
            <table>
              <caption>Exact observation request preview</caption>
              <thead>
                <tr>
                  <th>Purpose</th>
                  <th>Actor</th>
                  <th>Method and URL</th>
                </tr>
              </thead>
              <tbody>
                {acquisition.transportIntents.map((r, i) => (
                  <tr key={i}>
                    <td>{r.purpose}</td>
                    <td>{r.actorId}</td>
                    <td>
                      {r.method} {r.url}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
          <label>
            <input
              type="checkbox"
              checked={approval}
              disabled={busy || !canExecute || acquisition.status !== "REVIEW_REQUIRED"}
              onChange={(e) => setApproval(e.target.checked)}
            />
            I approve only these exact bounded native observation requests.
          </label>
          <button
            disabled={busy || !canExecute || !approval || acquisition.status !== "REVIEW_REQUIRED"}
            onClick={() =>
              void action(async () => {
                const r = await apiMutation<{ status: string; scanId: string | null }>(
                  "/api/authorization-workbench/mapping/" + acquisition.revisionId + "/execute",
                  "POST",
                  { digest: acquisition.digest, confirmation: "I_AUTHORIZE_THE_EXACT_READ_ONLY_OBSERVATIONS" }
                );
                setApproval(false);
                setAcquisition((v) => (v ? { ...v, scanId: r.scanId ?? undefined, status: r.status } : v));
              })
            }
          >
            Authorize native observations
          </button>
          <button
            disabled={busy}
            onClick={() =>
              void action(async () =>
                accept(await apiGet<Acquisition>("/api/authorization-workbench/mapping/" + acquisition.revisionId))
              )
            }
          >
            Refresh application map
          </button>
          {acquisition.failureReason && (
            <p role="alert">
              Observation stopped: {acquisition.failureReason}. Retain the scan evidence and review current bindings
              before creating another approval.
            </p>
          )}
          {acquisition.scanId && onScan && (
            <button onClick={() => onScan(acquisition.scanId!)}>Open observation scan evidence</button>
          )}
          {acquisition.status === "UNKNOWN" && (
            <p role="note">
              Dispatch custody is uncertain. No replay is offered. Retain this evidence for operator review; a new
              observation needs a separately reviewed revision.
            </p>
          )}
          {acquisition.status === "COMPLETED" && (
            <BoundedApplicationDiscovery
              key={acquisition.revisionId}
              mapRevisionId={acquisition.revisionId}
              canExecute={canExecute}
              onSelect={(binding, selected) => {
                setIntakeBinding(undefined);
                setSchemaBinding(undefined);
                setDiscoveryBinding(binding);
                setRoutes(selected);
                setRoutesConfirmed(false);
                invalidate();
              }}
            />
          )}
          {discoveryBinding && (
            <p>
              Native-discovered selection remains bound to immutable proposal {discoveryBinding.proposalId}; separate
              execution approval required.
            </p>
          )}
          {acquisition.status === "COMPLETED" && (
            <>
              <h4>D. Inspect native observations and declare policy</h4>
              <p>
                Response access is observed, not authorized by inference. Marker values remain omitted; fingerprints
                prove selected scalar identity fields. Enter the exact expected object/tenant values and declare each
                actor’s intended access. Missing controls or mismatched fingerprints remain REQUIRES_BINDINGS.
              </p>
              <table>
                <caption>Observed application map</caption>
                <thead>
                  <tr>
                    <th>Seed / template</th>
                    <th>Actor / role / tenant</th>
                    <th>Native response</th>
                    <th>Observed identity markers</th>
                  </tr>
                </thead>
                <tbody>
                  {acquisition.observations.flatMap((r) =>
                    r.cells.map((c) => (
                      <tr key={r.routeId + c.actorId}>
                        <td>
                          {r.routeId}
                          <small>{r.template}</small>
                          <small>Operator seed + native evidence</small>
                        </td>
                        <td>
                          {c.alias} · {c.role ?? "public"}
                          <small>
                            {c.identityModel === "PRINCIPAL_ROLE"
                              ? "tenant not applicable"
                              : (c.tenantFingerprint ?? "anonymous")}{" "}
                            · {c.identityVerified ? "identity verified" : "no authenticated identity"}
                          </small>
                        </td>
                        <td>
                          HTTP {c.statusCode ?? "not observed"} · {c.nativeDecision}
                          <small>{c.nativeOutcome} observation only</small>
                        </td>
                        <td>
                          {c.collection && <CollectionOwnershipSummary evidence={c.collection} />}
                          {c.observedMarkers.length
                            ? c.observedMarkers.map((m) => (
                                <small key={m.path}>
                                  {m.path}: {m.valueFingerprint.slice(0, 16)}… ({m.scalarType})
                                </small>
                              ))
                            : "No identity marker proven"}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
              <details>
                <summary>Existing IR and attack-graph provenance</summary>
                <pre>{JSON.stringify(acquisition.provenance, null, 2)}</pre>
              </details>
              <fieldset disabled={!canExecute || busy}>
                <legend>Explicit access-policy and object bindings</legend>
                {policy.map((p, i) => {
                  const r = acquisition.input.routes.find((r) => r.id === p.routeId)!;
                  return (
                    <fieldset className="mapping-route" key={p.routeId}>
                      <legend>{p.routeId}</legend>
                      <label>
                        Expected object/function marker
                        <input
                          aria-label={p.routeId + " expected identity"}
                          disabled={!!p.collection}
                          value={String(p.identity?.expectedValue ?? "")}
                          onChange={(e) =>
                            updatePolicy(i, {
                              identity: e.target.value
                                ? {
                                    path: r.identityPath,
                                    expectedValue: scalarValue(p.routeId, r.identityPath, e.target.value)
                                  }
                                : undefined
                            })
                          }
                        />
                      </label>
                      {r.tenantPath && (
                        <label>
                          Expected tenant marker
                          <input
                            aria-label={p.routeId + " expected tenant"}
                            value={String(p.tenant?.expectedValue ?? "")}
                            onChange={(e) =>
                              updatePolicy(i, {
                                tenant: e.target.value
                                  ? {
                                      path: r.tenantPath!,
                                      expectedValue: scalarValue(p.routeId, r.tenantPath!, e.target.value)
                                    }
                                  : undefined
                              })
                            }
                          />
                        </label>
                      )}
                      <label>
                        Security question
                        <select
                          aria-label={p.routeId + " security question"}
                          value={p.kind}
                          onChange={(e) => updatePolicy(i, { kind: e.target.value as typeof p.kind })}
                        >
                          {r.kind === "FUNCTION" ? (
                            <option value="FUNCTION_AUTHORIZATION">Function / role restriction</option>
                          ) : (
                            <>
                              <option value="TENANT_ISOLATION">Tenant and object ownership boundary</option>
                              <option value="OBJECT_AUTHORIZATION">Object ownership boundary</option>
                            </>
                          )}
                        </select>
                      </label>
                      <label>
                        Why should this boundary hold?
                        <input
                          aria-label={p.routeId + " policy rationale"}
                          value={p.explanation}
                          onChange={(e) => updatePolicy(i, { explanation: e.target.value })}
                        />
                      </label>
                      <div className="mapping-actors">
                        {acquisition.actors.map((a) => (
                          <label key={a.id}>
                            {a.alias} intended access
                            <select
                              aria-label={p.routeId + " policy " + a.id}
                              value={p.decisions[a.id] ?? "UNKNOWN"}
                              onChange={(e) =>
                                updatePolicy(i, {
                                  decisions: { ...p.decisions, [a.id]: e.target.value as "ALLOW" | "DENY" | "UNKNOWN" }
                                })
                              }
                            >
                              <option value="UNKNOWN">Unknown — requires binding</option>
                              <option value="ALLOW">Allow — positive control</option>
                              <option value="DENY">Deny — boundary check</option>
                            </select>
                          </label>
                        ))}
                      </div>
                    </fieldset>
                  );
                })}
                <label>
                  <input
                    type="checkbox"
                    checked={policyConfirmed}
                    onChange={(e) => setPolicyConfirmed(e.target.checked)}
                  />
                  I confirm these are declared policy expectations, not discovered authorization truth.
                </label>
                <button
                  disabled={!policyConfirmed}
                  onClick={() =>
                    void action(async () => {
                      for (const expectation of policy) {
                        for (const marker of [expectation.identity, expectation.tenant])
                          if (marker)
                            assertReviewedScalar(marker.expectedValue, scalarType(expectation.routeId, marker.path));
                      }
                      const matrix = await apiMutation<Matrix>(
                        "/api/authorization-workbench/mapping/" + acquisition.revisionId + "/bindings",
                        "POST",
                        { expectations: policy, policyConfirmed: true }
                      );
                      onMatrix(matrix);
                    })
                  }
                >
                  Build reviewed authorization matrix
                </button>
              </fieldset>
            </>
          )}
        </>
      )}
      {!canExecute && (
        <p>Read-only mapping access. An authorized operator must approve observations and policy execution.</p>
      )}
    </section>
  );
}
