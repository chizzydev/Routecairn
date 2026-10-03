import { useMemo, useState } from "react";

interface Evidence { producer: string; fingerprint: string; strength: string }
export interface AttackStateGraphView {
  graphFingerprint: string;
  bounds: { maxNodes: number; maxEdges: number; maxPaths: number; truncated: boolean };
  coverage: Record<string, number>;
  producers: string[];
  nodes: Array<{ id: string; kind: string; label: string; attributes?: Record<string, unknown>; evidence?: Evidence[] }>;
  edges: Array<{ id: string; kind: string; from: string; to: string; stateChanging: boolean; evidence?: Evidence[] }>;
  paths: Array<{ id: string; label: string; mutability: "READ_ONLY" | "STATE_CHANGING"; automationState: string; contractReadiness: string; engineId: string; requiredBindings: string[]; nodeIds?: string[]; edgeIds?: string[]; sourceCaseFingerprints?: string[]; evidence?: Evidence[] }>;
}

/** Review relationships and proof without exposing capture or credential values. */
export function AttackStateGraphPanel({ graph }: { graph?: AttackStateGraphView | undefined }) {
  const [search, setSearch] = useState("");
  const [mutability, setMutability] = useState("ALL");
  const [offset, setOffset] = useState(0);
  const paths = useMemo(() => [...(graph?.paths ?? [])].filter((path) => (mutability === "ALL" || path.mutability === mutability) && `${path.label} ${path.engineId} ${path.requiredBindings.join(" ")}`.toLowerCase().includes(search.toLowerCase())).sort((left, right) => Number(right.mutability === "STATE_CHANGING") - Number(left.mutability === "STATE_CHANGING") || left.label.localeCompare(right.label)), [graph, mutability, search]);
  const start = Math.min(offset, Math.max(0, Math.floor((paths.length - 1) / 50) * 50));
  const nodes = new Map(graph?.nodes.map((node) => [node.id, node]) ?? []);
  const edges = new Map(graph?.edges.map((edge) => [edge.id, edge]) ?? []);
  return <section className="panel"><h3>Attack-state graph</h3>{graph ? <>
    <div className="cards"><div className="metric"><strong>{graph.nodes.length}</strong><span>Evidence-backed states</span></div><div className="metric"><strong>{graph.edges.length}</strong><span>Relationships</span></div><div className="metric"><strong>{graph.paths.length}</strong><span>Attack paths</span></div><div className="metric"><strong>{graph.coverage.STATE_CHANGING_PATHS ?? 0}</strong><span>Approval-gated paths</span></div></div>
    <p className="muted">Actors {graph.coverage.ACTOR ?? 0} · roles {graph.coverage.ROLE ?? 0} · tenants {graph.coverage.TENANT ?? 0} · objects {graph.coverage.OBJECT ?? 0} · routes {graph.coverage.ROUTE ?? 0} · operations {graph.coverage.OPERATION ?? 0} · capabilities {graph.coverage.CAPABILITY ?? 0} · graph <code>{graph.graphFingerprint.slice(0, 12)}…</code>{graph.bounds.truncated ? " · bounded limit reached" : ""}</p>
    <div className="form"><label>Search graph paths<input value={search} onChange={(event) => { setSearch(event.target.value); setOffset(0); }} /></label><label>Path mutability<select value={mutability} onChange={(event) => { setMutability(event.target.value); setOffset(0); }}><option value="ALL">All paths</option><option value="READ_ONLY">Read-only</option><option value="STATE_CHANGING">State-changing</option></select></label></div>
    {paths.length ? <div className="table compact-table"><div className="row"><span>Path</span><span>Mutability</span><span>Contract state</span><span>Bindings and evidence</span></div>{paths.slice(start, start + 50).map((path) => <div className="row" key={path.id}>
      <span><strong>{path.label}</strong><small>{path.engineId}</small><small><code>{path.id.slice(0, 12)}…</code></small></span><span><strong>{path.mutability}</strong></span><span>{path.automationState}<small>{path.contractReadiness}</small></span>
      <span>{path.requiredBindings.length ? path.requiredBindings.map((binding) => <small key={binding}>{binding}</small>) : <small>Evidence contract complete</small>}
        <details><summary>Inspect path {path.label}</summary>
          <h4>States</h4><ul>{path.nodeIds?.map((id) => { const node = nodes.get(id); return node ? <li key={id}>{node.kind}: {node.label}{typeof node.attributes?.origin === "string" && <small>{node.attributes.origin}</small>}</li> : null; })}</ul>
          <h4>Relationships</h4><ul>{path.edgeIds?.map((id) => { const edge = edges.get(id); return edge ? <li key={id}>{nodes.get(edge.from)?.label ?? edge.from} → {edge.kind} → {nodes.get(edge.to)?.label ?? edge.to}{edge.stateChanging && " (state-changing)"}</li> : null; })}</ul>
          <h4>Evidence</h4><ul>{path.evidence?.map((item) => <li key={item.fingerprint}>{item.producer} · {item.strength} · <code>{item.fingerprint}</code></li>)}</ul>
          {path.sourceCaseFingerprints?.map((value) => <p key={value}>Source case <code>{value}</code></p>)}
        </details>
      </span>
    </div>)}</div> : <p className="muted">{graph.paths.length ? "No paths match these filters." : "No evidence-backed paths were derived from the latest scan."}</p>}
    {paths.length > 50 && <nav aria-label="Graph path pages"><button disabled={start === 0} onClick={() => setOffset(Math.max(0, start - 50))}>Previous paths</button><span> Showing {start + 1}–{Math.min(start + 50, paths.length)} of {paths.length} </span><button disabled={start + 50 >= paths.length} onClick={() => setOffset(start + 50)}>Next paths</button></nav>}
  </> : <p className="muted">Analyze a completed scan to construct actors, objects, routes, browser states, capabilities, transitions, and request dependencies.</p>}</section>;
}
