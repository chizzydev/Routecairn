import { ApplicationOnboardingCompatibility } from "./ApplicationOnboardingCompatibility";
import "./ApplicationOnboarding.css";
import React, { useEffect, useRef, useState } from "react";
import { apiMutation } from "./api";
import {
  applicationOnboardingSchema,
  type ApplicationOnboardingInput
} from "../../../src/dashboard/contracts/ApplicationOnboardingContracts";
import type { ApplicationOnboardingService } from "../../../src/dashboard/execution/ApplicationOnboardingService";
export function ApplicationOnboarding({
  onSaved
}: {
  onSaved: (v: ReturnType<ApplicationOnboardingService["create"]>) => void;
}) {
  const [origin, setOrigin] = useState(""),
    [name, setName] = useState(""),
    [summary, setSummary] = useState(""),
    [identity, setIdentity] = useState("/identity"),
    [seed, setSeed] = useState(""),
    [fields, setFields] = useState({
      principalField: "principal",
      tenantField: "tenant",
      roleField: "role",
      objectField: "id",
      objectTenantField: "tenant"
    }),
    [actors, setActors] = useState(
      Object.fromEntries(
        ["primary", "account_a", "account_b"].map((s) => [
          s,
          { principal: "", tenant: "", role: "", authorizationHeader: "", expiresAt: "" }
        ])
      ) as ApplicationOnboardingInput["actors"]
    ),
    [confirmed, setConfirmed] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [saved, setSaved] = useState(false);
  const generation = useRef(0),
    mounted = useRef(true);
  const [step, setStep] = useState(0);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current++;
    };
  }, []);
  const dirty = () => {
    generation.current++;
    setError("");
    setConfirmed(false);
    setSaved(false);
  };
  const validation = applicationOnboardingSchema.safeParse({
    displayName: name,
    origin,
    authorizationSummary: summary,
    identityPath: identity,
    seedPath: seed,
    ...fields,
    actors,
    ownedReadOnlyConfirmed: true
  });
  const fieldLabels: Record<string, string> = {
    principalField: "Principal identifier field",
    tenantField: "Tenant identifier field",
    roleField: "Role field",
    objectField: "Object identifier field",
    objectTenantField: "Object tenant field"
  };
  return (
    <details>
      <summary>Set up an owned local application and actors</summary>
      <section aria-label="Application onboarding" aria-busy={busy}>
        <h3>Connect an owned application</h3>
        <ApplicationOnboardingCompatibility />
        <p>1. Establish scope → 2. Declare actors → 3. Choose evidence fields → 4. Review and save.</p>
        <fieldset className="onboarding-steps">
          <legend>Setup step (arrow keys change selection)</legend>
          {["Scope", "Test actors", "Evidence fields", "Review"].map((label, i) => (
            <label key={label}>
              <input type="radio" name="onboarding-step" checked={step === i} onChange={() => setStep(i)} />
              {label}
            </label>
          ))}
        </fieldset>
        <p>
          Save three encrypted credentials and a declared identity contract. No request is sent. Native identity
          verification, observed links, hypotheses, policy review and proof each remain separate steps. Available only
          with target and credential creation authority.
        </p>
        <details open={step === 0}>
          <summary onClick={() => setStep(0)}>1. Scope and authorization</summary>
          <p>
            Only an exact owned 127.0.0.1 origin is supported. Saving never verifies identities or authorizes a scan.
          </p>
          <label>
            Application name
            <input
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                dirty();
              }}
            />
          </label>
          <label>
            Owned application origin
            <input
              value={origin}
              placeholder="http://127.0.0.1:3000"
              onChange={(e) => {
                setOrigin(e.target.value);
                dirty();
              }}
            />
          </label>
          <label>
            Owner authorization explanation
            <textarea
              value={summary}
              onChange={(e) => {
                setSummary(e.target.value);
                dirty();
              }}
            />
          </label>
          <label>
            Identity verification path
            <input
              value={identity}
              onChange={(e) => {
                setIdentity(e.target.value);
                dirty();
              }}
            />
          </label>
          <label>
            Initial permitted GET path
            <input
              value={seed}
              onChange={(e) => {
                setSeed(e.target.value);
                dirty();
              }}
            />
          </label>
        </details>
        <details open={step === 1}>
          <summary onClick={() => setStep(1)}>2. Test actors</summary>
          <p>
            Declare three distinct disposable principals, their actual roles and tenants, and future credential expiry.
            Use the primary owner, a same-tenant peer and a different-tenant peer when the application supports them.
            These are declarations until separately verified.
          </p>
          {(["primary", "account_a", "account_b"] as const).map((slot) => (
            <fieldset key={slot}>
              <legend>{slot} actor declaration</legend>
              {(["principal", "tenant", "role", "expiresAt", "authorizationHeader"] as const).map((k) => (
                <label key={k}>
                  {fieldLabels[k] ?? k}
                  <input
                    aria-label={slot + " " + k}
                    type={k === "authorizationHeader" ? "password" : "text"}
                    autoComplete="off"
                    value={actors[slot][k]}
                    onChange={(e) => {
                      setActors((p) => ({ ...p, [slot]: { ...p[slot], [k]: e.target.value } }));
                      dirty();
                    }}
                  />
                </label>
              ))}
            </fieldset>
          ))}
        </details>
        <details open={step === 2}>
          <summary onClick={() => setStep(2)}>3. Evidence fields</summary>
          <p>
            Use explicit non-secret scalar JSON paths such as record.id and record.tenant. Values are fingerprinted
            during later native observations. HTML navigation alone cannot prove object ownership.
          </p>
          {Object.entries(fields).map(([k, v]) => (
            <label key={k}>
              {fieldLabels[k] ?? k}
              <input
                aria-label={"Onboarding " + k}
                value={v}
                onChange={(e) => {
                  setFields((p) => ({ ...p, [k]: e.target.value }));
                  dirty();
                }}
              />
            </label>
          ))}
        </details>
        <details open={step === 3}>
          <summary onClick={() => setStep(3)}>4. Review declarations and next action</summary>
          <dl>
            <dt>Scope</dt>
            <dd>{origin || "Not entered"} · GET only</dd>
            <dt>Actors</dt>
            <dd>Three encrypted declarations; identities unverified</dd>
            <dt>Observation budget</dt>
            <dd>
              Initial route: at most 8 shared requests (4 identity/control + 4 actor observations), reviewed separately.
              Saving: 0 target requests.
            </dd>
          </dl>
          <p>
            After saving, review the native observation plan in guided mapping. Confirm its exact routes, actors and
            request ceiling before authorizing. Then inspect source provenance, review hypotheses and declare policy
            before any proof.
          </p>
          <details>
            <summary>Validation and advanced details</summary>
            <p>
              Origin must be exact with no trailing slash, query or credentials. Paths must be literal safe GET paths.
              Principal values must be distinct. Field names must not include secret, token, session, key or prototype
              paths. Server validation is authoritative; refused saves leave the draft available for correction.
            </p>
          </details>
        </details>
        <label>
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />I own this local
          application, authorize only separately reviewed GET observations, and confirm the three actor declarations.
        </label>
        <p aria-live="polite">
          {validation.success
            ? "Declarations pass local validation. Review authorization before saving."
            : "Setup is incomplete or invalid. Check scope, all three actors, future expiry and non-secret evidence fields. Server validation remains authoritative."}
        </p>
        {busy && (
          <p role="status">
            Saving encrypted declarations only. Editing invalidates this response for selection; a server commit may
            still occur.
          </p>
        )}
        {error && <p role="alert">{error}</p>}
        {saved && (
          <p role="status">Application declarations saved. Identity remains unverified until native observation.</p>
        )}
        <button
          disabled={!confirmed || busy || saved}
          onClick={() => {
            const requestGeneration = generation.current;
            setBusy(true);
            setError("");
            void apiMutation<ReturnType<ApplicationOnboardingService["create"]>>(
              "/api/authorization-workbench/mapping/onboarding",
              "POST",
              {
                displayName: name,
                origin,
                authorizationSummary: summary,
                identityPath: identity,
                seedPath: seed,
                ...fields,
                actors,
                ownedReadOnlyConfirmed: true
              }
            )
              .then((v) => {
                if (!mounted.current) return;
                const stale = generation.current !== requestGeneration;
                setActors(
                  (p) =>
                    Object.fromEntries(
                      Object.entries(p).map(([k, a]) => [k, { ...a, authorizationHeader: "" }])
                    ) as typeof p
                );
                setConfirmed(false);
                if (stale) {
                  setError(
                    "An earlier request may have saved declarations. Your edited draft was not selected. Inspect the target and credential inventory before saving again; no scan was started."
                  );
                  return;
                }
                setSaved(true);
                onSaved(v);
              })
              .catch(() => {
                if (!mounted.current) return;
                setActors(
                  (p) =>
                    Object.fromEntries(
                      Object.entries(p).map(([k, a]) => [k, { ...a, authorizationHeader: "" }])
                    ) as typeof p
                );
                setConfirmed(false);
                setError(
                  "Application setup could not be confirmed. A request may have saved declarations. Inspect target and credential inventory before trying again. Check scope, actor expiry, fields and permissions; no scan was started."
                );
              })
              .finally(() => {
                if (mounted.current) setBusy(false);
              });
          }}
        >
          Save declarations without sending requests
        </button>
      </section>
    </details>
  );
}
