import { useEffect, useRef, useState } from "react";
import { apiMutation } from "./api";
import type { CredentialSummary } from "./CredentialLifecycle";
import type { ActorRegistry } from "../../../src/core/auth/ActorRegistry";
import { ReviewedAssessmentResources } from "./ReviewedAssessmentResources";
import type { ResourcePolicyDraft } from "./ReviewedAssessmentResources";
export interface FlexibleAssessmentPreview {
  registry: ActorRegistry;
  actorCredentials: Record<string, string>;
  apiGraphql: unknown;
  targetAuthorization?: unknown;
  digest: string;
  capabilities: {
    actors: Array<{ id: string; assurance: string }>;
    workflows: Array<{ workflowId: string; family: string; status: string; reason: string }>;
  };
  executionAuthority: string;
  requestsSent: number;
  targetId?: string;
}
export function FlexibleAuthentication({
  targetId,
  credentials,
  onChange,
  onInvalidated
}: {
  targetId: string;
  credentials: CredentialSummary[];
  onChange: (v: FlexibleAssessmentPreview) => void;
  onInvalidated: () => void;
}) {
  const [actors, setActors] = useState<
      Array<{
        id: string;
        label: string;
        credentialProfileId: string;
        mechanism: "BEARER" | "COOKIE" | "API_KEY" | "BROWSER_SESSION";
        accountProvenance: "OWNER_APPROVED_EXISTING_TEST";
      }>
    >([]),
    [readPath, setReadPath] = useState("/"),
    [confirmed, setConfirmed] = useState(false),
    [sessionEffects, setSessionEffects] = useState(false),
    [role, setRole] = useState(false),
    [tenant, setTenant] = useState(false),
    [result, setResult] = useState<FlexibleAssessmentPreview>(),
    [message, setMessage] = useState(""),
    [pending, setPending] = useState(false);
  const [resources, setResources] = useState<ResourcePolicyDraft[]>([]);
  const credentialState = JSON.stringify(
    credentials
      .map((c) => ({
        id: c.id,
        targetId: c.targetId,
        enabled: c.enabled,
        expiresAt: c.expiresAt,
        secretVersion: c.secretVersion,
        updatedAt: c.updatedAt,
        health: c.health,
        identity: c.safeIdentitySummary
      }))
      .sort((a, b) => a.id.localeCompare(b.id))
  );
  const generation = useRef(0),
    mounted = useRef(true),
    nextId = useRef(0),
    changed = () => {
      generation.current++;
      setResult(undefined);
      setPending(false);
      onInvalidated();
    };
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current++;
    };
  }, []);
  useEffect(() => {
    generation.current++;
    setResult(undefined);
    setPending(false);
    setActors([]);
    setResources([]);
    onInvalidated();
  }, [targetId]);
  useEffect(() => {
    generation.current++;
    setResult(undefined);
    setPending(false);
    onInvalidated();
  }, [credentialState]);
  const preview = async () => {
    const g = ++generation.current;
    setPending(true);
    setMessage("");
    try {
      const v = await apiMutation<FlexibleAssessmentPreview>("/api/scans/actor-registry", "POST", {
        targetId,
        readPath,
        actors,
        resources,
        credentialValidUntil: new Date(Date.now() + 3600000).toISOString(),
        ownerTestAccountsConfirmed: confirmed,
        readOnlyEffectConfirmed: confirmed,
        sessionHousekeepingApproved: sessionEffects,
        roleSeparationApplicable: role,
        tenantSeparationApplicable: tenant
      });
      if (!mounted.current || generation.current !== g) return;
      setResult(v);
      onChange({ ...v, targetId });
    } catch (e) {
      if (mounted.current && generation.current === g)
        setMessage(e instanceof Error ? e.message : "Registry review failed");
    } finally {
      if (mounted.current && generation.current === g) setPending(false);
    }
  };
  return (
    <section aria-label="Flexible authentication and assessment capabilities">
      <h3>Configure the accounts you actually have</h3>
      <p>
        Public checks need no account. Add one account for credential-bound observations, two verified principals for
        ownership checks, or up to eight for reviewed matrices. No role, tenant, bearer token or identity endpoint is
        universally required.
      </p>
      <p>
        Credentials stay in the encrypted vault. Configure cookie, API key, bearer or supported browser-session profiles
        in Credentials. Supplied identity labels are declarations; the native engine verifies stronger claims
        separately.
      </p>
      <label>
        Exact reviewed read-only path
        <input
          value={readPath}
          onChange={(e) => {
            changed();
            setReadPath(e.target.value);
          }}
        />
      </label>
      {actors.map((a, i) => (
        <fieldset key={a.id}>
          <legend>
            Actor {i + 1} · {a.id}
          </legend>
          <label>
            Display label
            <input
              value={a.label}
              onChange={(e) => {
                changed();
                setActors((s) => s.map((x) => (x.id === a.id ? { ...x, label: e.target.value } : x)));
              }}
            />
          </label>
          <label>
            Saved credential
            <select
              value={a.credentialProfileId}
              onChange={(e) => {
                changed();
                setActors((s) => s.map((x) => (x.id === a.id ? { ...x, credentialProfileId: e.target.value } : x)));
              }}
            >
              <option value="">Select an owner-approved test credential</option>
              {credentials
                .filter((c) => c.enabled && c.targetId === targetId)
                .map((c) => (
                  <option value={c.id} key={c.id}>
                    {c.safeAlias}
                  </option>
                ))}
            </select>
          </label>
          <label>
            Mechanism
            <select
              value={a.mechanism}
              onChange={(e) => {
                changed();
                const mechanism = e.target.value as typeof a.mechanism;
                setActors((s) => s.map((x) => (x.id === a.id ? { ...x, mechanism } : x)));
              }}
            >
              <option value="BEARER">Bearer token</option>
              <option value="COOKIE">Session cookie</option>
              <option value="API_KEY">API key</option>
              <option value="BROWSER_SESSION">Browser session / reviewed login</option>
            </select>
          </label>
          <button
            type="button"
            onClick={() => {
              changed();
              setActors((s) => s.filter((x) => x.id !== a.id));
            }}
          >
            Remove {a.label}
          </button>
        </fieldset>
      ))}
      <button
        type="button"
        disabled={actors.length >= 8}
        onClick={() => {
          changed();
          const id = "actor" + nextId.current++;
          setActors((s) => [
            ...s,
            {
              id,
              label: "Test actor " + (s.length + 1),
              credentialProfileId: "",
              mechanism: "BEARER",
              accountProvenance: "OWNER_APPROVED_EXISTING_TEST"
            }
          ]);
        }}
      >
        Add account
      </button>
      <label>
        <input
          type="checkbox"
          checked={role}
          onChange={(e) => {
            changed();
            setRole(e.target.checked);
          }}
        />
        Application has role separation
      </label>
      <ReviewedAssessmentResources
        actors={actors}
        resources={resources}
        onChange={(v) => {
          changed();
          setResources(v);
        }}
      />
      <label>
        <input
          type="checkbox"
          checked={tenant}
          onChange={(e) => {
            changed();
            setTenant(e.target.checked);
          }}
        />
        Application has tenant separation
      </label>
      <label>
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => {
            changed();
            setConfirmed(e.target.checked);
          }}
        />
        I approve the exact GET path as read-only and any selected existing test accounts for up to the next hour
        (earlier expiry prevails)
      </label>
      <label>
        <input
          type="checkbox"
          checked={sessionEffects}
          onChange={(e) => {
            changed();
            setSessionEffects(e.target.checked);
          }}
        />
        I approve known authenticated-read session housekeeping effects
      </label>
      <button
        type="button"
        disabled={
          pending ||
          !targetId ||
          !confirmed ||
          actors.some((a) => !a.credentialProfileId) ||
          resources.some((r) => !r.reviewed) ||
          (actors.length > 0 && !sessionEffects)
        }
        onClick={() => void preview()}
      >
        Review available checks
      </button>
      <p role="status">
        {message ||
          (!targetId
            ? "Select a registered, authorized target first."
            : pending
              ? "Reviewing credential references without target traffic."
              : "")}
      </p>
      {result && (
        <>
          <details>
            <summary>Exact proposed campaign for review</summary>
            <pre>{JSON.stringify(result.targetAuthorization, null, 2)}</pre>
          </details>
          <p>
            Registry {result.registry.registryId}: no target requests sent. Eligibility is not a security result.
            Existing test accounts are accepted; newly created accounts are optional.
          </p>
          <table>
            <caption>Checks, missing evidence and additional opportunities</caption>
            <thead>
              <tr>
                <th>Family</th>
                <th>Status</th>
                <th>Reason / next action</th>
              </tr>
            </thead>
            <tbody>
              {result.capabilities.workflows.map((w) => (
                <tr key={w.workflowId}>
                  <td>{w.family}</td>
                  <td>{w.status}</td>
                  <td>{w.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p>
            Ownership, role and tenant results require reviewed resource policies plus exact native identity evidence.
            HTTPS browser authentication remains blocked by the existing transport boundary. Human verification remains
            explicitly human, never scanner-native proof.
          </p>
        </>
      )}
    </section>
  );
}
