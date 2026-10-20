import React, { useState, useEffect, useRef } from "react";
import { apiMutation } from "./api";
import type { ApplicationMappingInput } from "../../../src/dashboard/contracts/ApplicationMappingContracts";
import type { ApplicationDiscoveryService } from "../../../src/dashboard/execution/ApplicationDiscoveryService";
type Proposal = ReturnType<ApplicationDiscoveryService["create"]>;
export function BoundedApplicationDiscovery({
  mapRevisionId,
  canExecute,
  onSelect
}: {
  mapRevisionId: string;
  canExecute: boolean;
  onSelect: (
    binding: NonNullable<ApplicationMappingInput["discoveryBinding"]>,
    routes: ApplicationMappingInput["routes"]
  ) => void;
}) {
  const [prefix, setPrefix] = useState("/"),
    [maxRoutes, setMaxRoutes] = useState(8),
    [maxRequests, setMaxRequests] = useState(36),
    [proposal, setProposal] = useState<Proposal>(),
    [selected, setSelected] = useState<string[]>([]),
    [identity, setIdentity] = useState("id"),
    [tenant, setTenant] = useState("tenant"),
    [confirmed, setConfirmed] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [expired, setExpired] = useState(false);
  const generation = useRef(0);
  useEffect(() => {
    generation.current++;
    setBusy(false);
    setError("");
    setProposal(undefined);
    setSelected([]);
    setConfirmed(false);
    return () => {
      generation.current++;
    };
  }, [mapRevisionId]);
  useEffect(() => {
    const tick = () => setExpired(Boolean(proposal && Date.parse(proposal.expiresAt) <= Date.now()));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [proposal]);
  const invalidate = () => {
    generation.current++;
    setBusy(false);
    setError("");
    setProposal(undefined);
    setSelected([]);
    setConfirmed(false);
  };
  return (
    <section aria-label="Bounded application discovery">
      <h3>Discover additional read-only routes</h3>
      <p>
        Inspect links already captured by approved native GET observations. Suggestions carry no ownership, policy or
        execution authority. Selecting routes requires a separate mapping preview and explicit GET approval.
      </p>
      <label>
        Approved discovery path prefixes (one per line)
        <textarea
          value={prefix}
          onChange={(e) => {
            setPrefix(e.target.value);
            invalidate();
          }}
        />
      </label>
      <label>
        Discovery route ceiling
        <input
          type="number"
          min={1}
          max={8}
          value={maxRoutes}
          onChange={(e) => {
            setMaxRoutes(Number(e.target.value));
            invalidate();
          }}
        />
      </label>
      <label>
        Discovery request ceiling
        <input
          type="number"
          min={8}
          max={36}
          value={maxRequests}
          onChange={(e) => {
            setMaxRequests(Number(e.target.value));
            invalidate();
          }}
        />
      </label>
      <label>
        <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />I reviewed this
        local scope and understand links remain unapproved suggestions.
      </label>
      <button
        disabled={!canExecute || !confirmed || busy}
        onClick={() => {
          const requestGeneration = ++generation.current;
          setBusy(true);
          setError("");
          void apiMutation<Proposal>("/api/authorization-workbench/mapping/discovery", "POST", {
            mapRevisionId,
            allowedPathPrefixes: prefix
              .split(/\r?\n/)
              .map((s) => s.trim())
              .filter(Boolean),
            maxRoutes,
            maxRequests,
            scopeConfirmed: true
          })
            .then((p) => {
              if (requestGeneration !== generation.current) return;
              if (
                !p ||
                !Array.isArray(p.candidates) ||
                !p.source ||
                !p.coverage ||
                !Array.isArray(p.excluded) ||
                !Array.isArray(p.missingControls)
              )
                throw Error("UNKNOWN_DISCOVERY_RESPONSE");
              setProposal(p);
              setSelected([]);
            })
            .catch((e) => {
              if (requestGeneration === generation.current) setError(e.message);
            })
            .finally(() => {
              if (requestGeneration === generation.current) setBusy(false);
            });
        }}
      >
        Review discovery suggestions
      </button>
      {error && <p role="alert">{error}</p>}
      {proposal && (
        <>
          <p role="status">
            {proposal.candidates.length} scoped suggestions · round {proposal.round}/3 · no requests sent by discovery
            review.
          </p>
          <p>
            Review expires {proposal.expiresAt}.{" "}
            {expired ? "STALE REVIEW: request a new proposal before selection." : "Review is time bounded."} Selected
            observation cost: at most {4 + 4 * selected.length} shared requests, ceiling {proposal.requestCeiling}.
            Candidates are not observed routes, reviewed policies, hypotheses or findings.
          </p>
          <p>
            Native source {proposal.source.sourceHash} · actor/credential binding SHA256 {proposal.source.contextDigest}{" "}
            · native scan {proposal.source.sourceScanId} · observed routes {proposal.coverage.observedRoutes} ·
            completeness {proposal.coverage.complete ? "complete within declared limits" : "partial / controls missing"}
            .
          </p>
          <details>
            <summary>Exclusions and missing controls</summary>
            {proposal.excluded.map((e) => (
              <p key={e.reason}>
                {e.reason}: {e.count}
              </p>
            ))}
            {proposal.missingControls.map((m, i) => (
              <p key={i}>{m}</p>
            ))}
          </details>
          <label>
            Discovered object identity field
            <input value={identity} onChange={(e) => setIdentity(e.target.value)} />
          </label>
          <label>
            Discovered tenant field (optional)
            <input value={tenant} onChange={(e) => setTenant(e.target.value)} />
          </label>
          {proposal.candidates.map((c) => (
            <div key={c.candidateId}>
              <label>
                <input
                  type="checkbox"
                  aria-label={"Select discovered " + c.path}
                  checked={selected.includes(c.candidateId)}
                  onChange={(e) =>
                    setSelected((v) =>
                      e.target.checked ? [...v, c.candidateId] : v.filter((id) => id !== c.candidateId)
                    )
                  }
                />
                {c.path} · GET suggestion · {c.provenance.length} actor/source witnesses
              </label>
              <p>
                Observed route shape: {c.routePattern?.suggestedTemplate ?? c.path}. Advertisement is not access
                permission; exact URL remains unchanged.
              </p>
              <details>
                <summary>Source witnesses for {c.path}</summary>
                <ul>
                  {c.provenance.map((p, i) => (
                    <li key={i}>
                      Route {p.routeId} · actor {p.actorId} · native check {p.checkId} · response SHA256{" "}
                      {p.responseFingerprint} · link SHA256 {p.evidenceFingerprint}
                    </li>
                  ))}
                </ul>
              </details>
            </div>
          ))}
          <p>
            Ownership and role policy are declared in the existing workbench after native observation. Exact URLs remain
            source-bound; route templates and marker fields require operator review.
          </p>
          <button
            disabled={
              !canExecute ||
              expired ||
              !selected.length ||
              !identity ||
              4 + 4 * selected.length > proposal.requestCeiling
            }
            onClick={() => {
              const candidates = proposal.candidates.filter((c) => selected.includes(c.candidateId));
              onSelect(
                {
                  proposalId: proposal.proposalId,
                  digest: proposal.digest,
                  selections: candidates.map((c, i) => ({
                    routeId: "discovered-" + (i + 1),
                    candidateId: c.candidateId
                  }))
                },
                candidates.map((c, i) => ({
                  id: "discovered-" + (i + 1),
                  kind: "OBJECT",
                  url: c.url,
                  pathTemplate: c.path,
                  method: "GET",
                  identityPath: identity,
                  ...(tenant ? { tenantPath: tenant } : {})
                }))
              );
            }}
          >
            Use selected routes in mapping review
          </button>
        </>
      )}
    </section>
  );
}
