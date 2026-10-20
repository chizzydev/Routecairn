import React, { useEffect, useRef, useState } from "react";
import { apiGet } from "./api";
import type { ApplicationAnalystHandoff as Service } from "../../../src/dashboard/execution/ApplicationAnalystHandoff";
type Page = ReturnType<Service["page"]>;
type Packet = ReturnType<Service["export"]>;
export function AnalystHandoff({ proposalId }: { proposalId: string }) {
  const [query, setQuery] = useState(""),
    [kind, setKind] = useState("proofs"),
    [page, setPage] = useState<Page>(),
    [packet, setPacket] = useState<Packet>(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    generation = useRef(0);
  useEffect(() => {
    generation.current++;
    setPage(undefined);
    setPacket(undefined);
    setBusy(false);
    setError("");
    return () => {
      generation.current++;
    };
  }, [proposalId]);
  const base = "/api/authorization-workbench/mapping/hypotheses/" + proposalId;
  const clear = () => {
    generation.current++;
    setPage(undefined);
    setBusy(false);
    setError("");
  };
  const load = (cursor?: string) => {
    const n = ++generation.current;
    setBusy(true);
    setError("");
    void apiGet<Page>(base + "/history?" + new URLSearchParams({ kind, query, ...(cursor ? { cursor } : {}) }))
      .then((r) => {
        if (n === generation.current) setPage(r);
      })
      .catch(() => {
        if (n === generation.current) {
          setPage(undefined);
          setError(
            "History unavailable or snapshot changed. Restart this search; no missing history is a successful assessment."
          );
        }
      })
      .finally(() => {
        if (n === generation.current) setBusy(false);
      });
  };
  return (
    <section aria-label="Analyst handoff and complete history">
      <h5>Review history and hand off the case</h5>
      <p>
        Read-only and redacted. Notes cannot suppress findings. Search IDs, native state or disposition; each
        continuation is bound to the same retained history snapshot. A filtered page is never complete assessment
        coverage.
      </p>
      <label>
        History type
        <select
          aria-label="History type"
          value={kind}
          onChange={(e) => {
            clear();
            setKind(e.target.value);
          }}
        >
          <option value="proofs">Native proof history</option>
          <option value="notes">Analyst context history</option>
          <option value="comparisons">Comparison history, including failed or incomplete</option>
        </select>
      </label>
      <label>
        History search
        <input
          aria-label="History search"
          maxLength={80}
          value={query}
          onChange={(e) => {
            clear();
            setQuery(e.target.value);
          }}
        />
      </label>
      <button disabled={busy} onClick={() => load()}>
        Search retained history
      </button>
      {error && <p role="alert">{error}</p>}
      {page && (
        <>
          <p role="status">
            {page.matching} matching of {page.total} retained records. Showing {page.offset + 1}–
            {page.offset + page.entries.length}. Snapshot {page.snapshot}. Native COMPLETED alone is not a healthy
            verdict.
          </p>
          <ul aria-label="Retained history page">
            {page.entries.map((r) => (
              <li key={r.id}>
                <details>
                  <summary>
                    {r.id} · {r.state}
                  </summary>
                  <pre>{JSON.stringify(r.detail, null, 2)}</pre>
                </details>
              </li>
            ))}
          </ul>
          <button disabled={busy || !page.nextCursor} onClick={() => load(page.nextCursor!)}>
            Next history page
          </button>
        </>
      )}
      <button
        disabled={busy}
        onClick={() => {
          const n = ++generation.current;
          setBusy(true);
          setError("");
          void apiGet<Packet>(base + "/handoff")
            .then((r) => {
              if (n === generation.current) setPacket(r);
            })
            .catch(() => {
              if (n === generation.current) {
                setPacket(undefined);
                setError("Handoff unavailable. Retained source or history needs review; no healthy outcome inferred.");
              }
            })
            .finally(() => {
              if (n === generation.current) setBusy(false);
            });
        }}
      >
        Prepare redacted analyst handoff
      </button>
      {packet && (
        <>
          <p role="status">
            Case packet {packet.packetSha256}. Human review required. Execution authority: {packet.executionAuthority}.
            Causal proof: not tested.
          </p>
          <p>
            {packet.proofIndex.length} proof history references; {packet.noteIndex.length} context references. Bounded
            detail omissions: {packet.historyIncomplete ? "yes; use retained history search" : "none reported"}.
          </p>
          {packet.analystBrief && (
            <section aria-label="Analyst case brief">
              <h5>Evidence and next action</h5>
              <dl>
                <dt>Observed</dt>
                <dd>
                  {packet.analystBrief.observed.relationshipCount} linked resource relationships; native source{" "}
                  {packet.analystBrief.observed.scanId ?? "UNOBSERVED"}.
                </dd>
                <dt>Actually verified</dt>
                <dd>
                  {packet.analystBrief.verified.proofCount} retained proof references; latest{" "}
                  {packet.analystBrief.verified.latestStatus}, {packet.analystBrief.verified.latestFindingCount}{" "}
                  deviations against explicit reviewed policy.
                </dd>
                <dt>Uncertain</dt>
                <dd>
                  Source {packet.analystBrief.uncertain.freshness};{" "}
                  {packet.analystBrief.uncertain.relationshipCounterevidence.length} actor relationship concerns;{" "}
                  {packet.analystBrief.uncertain.missing.length +
                    packet.analystBrief.uncertain.relationshipControls.length}{" "}
                  missing controls. Incomplete history: {String(packet.analystBrief.uncertain.incompleteHistory)}.
                </dd>
                <dt>Remediation</dt>
                <dd>
                  {packet.analystBrief.remediation.completeComparisons} complete of{" "}
                  {packet.analystBrief.remediation.comparisonCount} retained comparisons. Review exact check coverage;
                  no whole-application verdict.
                </dd>
                <dt>Next</dt>
                <dd>
                  {packet.analystBrief.nextAction}. Notes never suppress findings. GET observations do not prove state
                  mutations.
                </dd>
              </dl>
            </section>
          )}
          <details>
            <summary>Inspect and copy source-bound analyst packet</summary>
            <textarea aria-label="Redacted analyst packet" readOnly rows={12} value={JSON.stringify(packet, null, 2)} />
          </details>
          <button
            onClick={() => {
              const url = URL.createObjectURL(
                  new Blob([JSON.stringify(packet, null, 2) + "\n"], { type: "application/json" })
                ),
                a = document.createElement("a");
              a.href = url;
              a.download = "routecairn-case-" + proposalId + ".json";
              a.click();
              setTimeout(() => URL.revokeObjectURL(url), 1000);
            }}
          >
            Download redacted analyst packet
          </button>
        </>
      )}
    </section>
  );
}
