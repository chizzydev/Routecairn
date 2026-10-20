import React, { useState } from "react";
import { apiGet, apiMutation } from "./api";
import type { ApplicationHypothesisService } from "../../../src/dashboard/execution/ApplicationHypothesisService";
import type { TransitionReview } from "../../../src/dashboard/contracts/ApplicationTransitionContracts";
type Proposal = ReturnType<ApplicationHypothesisService["generate"]>;
export function ApplicationTransitionPanel({
  proposal,
  canExecute,
  onProposal,
  onReview
}: {
  proposal: Proposal;
  canExecute: boolean;
  onProposal: (p: Proposal) => void;
  onReview: (r: TransitionReview | undefined) => void;
}) {
  const [before, setBefore] = useState(""),
    [choices, setChoices] = useState<{ id: string; created_at: string }[]>([]),
    [signed, setSigned] = useState<{ publicKeySpki: string; signature: string; event: unknown }>(),
    [purpose, setPurpose] = useState(""),
    [policy, setPolicy] = useState("LEGITIMATE"),
    [authority, setAuthority] = useState(""),
    [trust, setTrust] = useState(false),
    [consents, setConsents] = useState<Record<string, boolean>>({}),
    [purposes, setPurposes] = useState<Record<string, string>>({}),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const flow = proposal.flow,
    t = proposal.transition,
    base = "/api/authorization-workbench/mapping/hypotheses";
  if (!flow || flow.steps.length < 2) return null;
  const action = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "UNKNOWN transition evidence");
    } finally {
      setBusy(false);
    }
  };
  const checks = flow.steps.flatMap((s) =>
    ["primary", "account-a", "account-b", "anonymous"].map((actorId) => ({
      routeId: s.routeId,
      actorId: actorId as TransitionReview["checks"][number]["actorId"]
    }))
  );
  const key = (c: { routeId: string; actorId: string }) => c.routeId + ":" + c.actorId;
  const text = (c: { routeId: string; actorId: string }) =>
    purposes[key(c)] ??
    ("Observe " + c.routeId + " as " + c.actorId + "; " + (t?.declaration.purpose ?? purpose)).slice(0, 240);
  const emit = (c: Record<string, boolean>, trusted: boolean, p: Record<string, string> = purposes) => {
    const rows = checks.map((v) => ({ ...v, purpose: p[key(v)] ?? text(v), consent: true as const }));
    onReview(
      t?.eligibility === "EVIDENCE_READY_FOR_POLICY_REVIEW" &&
        trusted &&
        checks.every((v) => c[key(v)] && rows.find((r) => key(r) === key(v))!.purpose.trim().length >= 10)
        ? { authorityConfirmed: true, authorityKeySha256: t.declaration.authorityKeySha256, checks: rows }
        : undefined
    );
  };
  return (
    <section className="transition-observation-panel" aria-label="Reviewed state-transition observations">
      <h4>Reviewed state-transition observations</h4>
      <p>
        Observe before and after an owner-controlled change. RouteCairn sends no transition or rollback request. A
        signature needs independently trusted key authority; temporal correlation is not causal proof. State-changing
        execution remains HOLD.
      </p>
      {!t ? (
        <>
          <button
            disabled={busy}
            onClick={() =>
              void action(async () => {
                const m = await apiGet<{ acquisitions: { id: string; target_id: string; created_at: string }[] }>(
                  "/api/authorization-workbench/mapping"
                );
                setChoices(
                  m.acquisitions.filter(
                    (v) => v.target_id === proposal.source.targetId && v.id !== proposal.source.mapRevisionId
                  )
                );
              })
            }
          >
            Load before observations
          </button>
          <label>
            Before native observation
            <select
              aria-label="Transition before observation"
              value={before}
              onChange={(e) => setBefore(e.target.value)}
            >
              <option value="">Choose immutable before map</option>
              {choices.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.created_at} · {c.id}
                </option>
              ))}
            </select>
          </label>
          <label>
            Signed target event JSON
            <input
              aria-label="Signed target event JSON"
              type="file"
              accept=".json,application/json"
              disabled={!canExecute || busy}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file)
                  void action(async () => {
                    setSigned(undefined);
                    if (file.size > 16384) throw Error("Target event must be at most 16KiB");
                    const v = JSON.parse(await file.text());
                    if (
                      !v ||
                      Array.isArray(v) ||
                      Object.keys(v).sort().join(",") !== "event,publicKeySpki,signature" ||
                      typeof v.publicKeySpki !== "string" ||
                      typeof v.signature !== "string" ||
                      !v.event ||
                      typeof v.event !== "object" ||
                      Array.isArray(v.event)
                    )
                      throw Error(
                        "Only publicKeySpki, signature and a typed event are accepted; never upload a private key"
                      );
                    setSigned(v);
                  });
              }}
            />
          </label>
          <label>
            Independently trusted public-key SHA-256
            <input
              aria-label="Transition authority SHA-256"
              maxLength={64}
              value={authority}
              onChange={(e) => setAuthority(e.target.value)}
            />
          </label>
          <label>
            Declared transition policy
            <select aria-label="Transition declared policy" value={policy} onChange={(e) => setPolicy(e.target.value)}>
              <option>LEGITIMATE</option>
              <option>FORBIDDEN</option>
            </select>
          </label>
          <label>
            Purpose of these read-only observations
            <textarea
              aria-label="Transition purpose"
              maxLength={160}
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
            />
          </label>
          {signed && <pre aria-label="Public target event preview">{JSON.stringify(signed.event, null, 2)}</pre>}
          <button
            disabled={
              !canExecute ||
              busy ||
              !before ||
              !signed ||
              purpose.trim().length < 10 ||
              !/^[a-f0-9]{64}$/.test(authority)
            }
            onClick={() =>
              void action(async () => {
                onProposal(
                  await apiMutation(base, "POST", {
                    mapRevisionId: proposal.source.mapRevisionId,
                    workflow: { name: flow.name, routeIds: flow.steps.map((s) => s.routeId) },
                    transition: {
                      beforeMapRevisionId: before,
                      ...signed,
                      authorityKeySha256: authority,
                      policy,
                      purpose
                    }
                  })
                );
              })
            }
          >
            Draft reviewed state-transition contract
          </button>
        </>
      ) : (
        <>
          <p>
            Transition evidence: {t.eligibility}. {t.policyOutcome}. {t.eventEvidence}. No finding is inferred.
          </p>
          <p>
            Before map {t.beforeSource.mapRevisionId}, native {t.beforeSource.sourceScanId}, hash{" "}
            {t.beforeSource.sourceHash}; after map {t.afterSource.mapRevisionId}, native {t.afterSource.sourceScanId},
            hash {t.afterSource.sourceHash}.
          </p>
          <p>
            Event {t.declaration.event.eventId}: {t.declaration.event.actorId} · {t.declaration.event.role},{" "}
            {t.declaration.event.statePath} {JSON.stringify(t.declaration.event.beforeState)} →{" "}
            {JSON.stringify(t.declaration.event.afterState)}, revision {t.declaration.event.fromRevision} →{" "}
            {t.declaration.event.toRevision}. Policy {t.declaration.policy}.
          </p>
          <p>
            {t.missingControls.join("; ") ||
              "Typed, signed and temporal evidence is ready for explicit authority review."}
          </p>
          <p>
            Key SHA-256 {t.declaration.authorityKeySha256}. {t.keyAuthority}. {t.causality}.
          </p>
          <label>
            <input
              type="checkbox"
              aria-label="I independently trust this exact target event key"
              disabled={!canExecute || t.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW"}
              checked={trust}
              onChange={(e) => {
                setTrust(e.target.checked);
                emit(consents, e.target.checked);
              }}
            />
            I independently trust this exact target event key and its event/revision authority.
          </label>
          {checks.map((c) => (
            <div key={key(c)}>
              <label>
                Purpose for {c.routeId} as {c.actorId}
                <input
                  aria-label={"Transition check purpose " + key(c)}
                  maxLength={240}
                  value={text(c)}
                  disabled={!canExecute}
                  onChange={(e) => {
                    const p = { ...purposes, [key(c)]: e.target.value },
                      next = { ...consents, [key(c)]: false };
                    setPurposes(p);
                    setConsents(next);
                    emit(next, trust, p);
                  }}
                />
              </label>
              <label>
                <input
                  aria-label={"Consent transition observation " + key(c)}
                  type="checkbox"
                  disabled={!canExecute || t.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW"}
                  checked={!!consents[key(c)]}
                  onChange={(e) => {
                    const next = { ...consents, [key(c)]: e.target.checked };
                    setConsents(next);
                    emit(next, trust);
                  }}
                />
                I consent to this exact bounded GET observation.
              </label>
            </div>
          ))}
        </>
      )}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
