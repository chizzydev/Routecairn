import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  apiGet,
  apiMutation,
  type FindingDetailData,
  type FindingPage,
  type FindingSummary
} from "./api";
import { EvidenceViewerRegistry } from "./EvidenceViewers";

type Workspace = "findings" | "queue";
type DetailTab = "overview" | "evidence" | "occurrences" | "reproduction" | "remediation" | "history" | "related" | "proof";

interface Filters {
  q: string;
  severity: string;
  confidence: string;
  review: string;
  remediation: string;
  module: string;
  category: string;
  assignee: string;
  retest: string;
  proof: string;
  source: string;
  evidence: string;
  newOccurrence: boolean;
  sort: string;
  projectId: string;
  targetId: string;
}

const emptyFilters: Filters = {
  q: "", severity: "", confidence: "", review: "", remediation: "", module: "",
  category: "", assignee: "", retest: "", proof: "", source: "", evidence: "",
  newOccurrence: false, sort: "last_seen_desc", projectId: "", targetId: ""
};

const reviewStates = ["UNREVIEWED", "IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE", "RESOLVED", "REOPENED"];
const remediationStates = ["OPEN", "ASSIGNED", "FIX_IN_PROGRESS", "FIXED_PENDING_RETEST", "FIXED_VERIFIED", "WONT_FIX"];
const queueModes = ["UNREVIEWED", "IN_REVIEW", "REOPENED", "HIGH_SEVERITY", "HIGH_CONFIDENCE", "NEW_OCCURRENCE", "AFTER_FALSE_POSITIVE", "MISSING_EVIDENCE", "PROOF_READY"];

export function FindingsCommandCenter(props: { initialFilters?: Partial<Filters>; principal?: { userId?: string; login?: string; role?: string }; onRetest?: (draft: RetestDraft) => void } = {}): React.ReactElement {
  const [workspace, setWorkspace] = useState<Workspace>("findings");
  const [queueMode, setQueueMode] = useState("UNREVIEWED");
  const [filters, setFilters] = useState<Filters>({ ...emptyFilters, ...props.initialFilters });
  const [page, setPage] = useState(1);
  const [data, setData] = useState<FindingPage>({ findings: [], page: 1, pageSize: 25, total: 0, totalPages: 1 });
  const [selected, setSelected] = useState<string[]>([]);
  const [openId, setOpenId] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(true);
  const [views, setViews] = useState<SavedView[]>([]);
  const [viewName, setViewName] = useState("");
  const [selectedViewId, setSelectedViewId] = useState("");
  const [columns, setColumns] = useState<string[]>(defaultColumns);
  const [draggedColumn, setDraggedColumn] = useState("");
  const [viewsInitialized, setViewsInitialized] = useState(false);
  const [savingView, setSavingView] = useState(false);
  const [bulkState, setBulkState] = useState("IN_REVIEW");
  const [bulkReason, setBulkReason] = useState("");
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [assignees, setAssignees] = useState<Array<{ id: string; login: string; role: string }>>([]);
  const query = useMemo(() => findingQuery(filters, page), [filters, page]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const path = workspace === "queue"
        ? `/api/findings/queue?mode=${encodeURIComponent(queueMode)}&${query}`
        : `/api/findings?${query}`;
      setData(await apiGet<FindingPage>(path));
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setLoading(false);
    }
  }, [workspace, queueMode, query]);

  const loadViews = useCallback(() => {
    void apiGet<{ views: SavedView[] }>("/api/finding-views").then((body) => {
      setViews(body.views);
      if (!viewsInitialized && !props.initialFilters) {
        const personalDefault = body.views.find((view) => view.is_default && !view.shared_installation_wide);
        if (personalDefault) { applySavedView(personalDefault.id, body.views, setFilters, setColumns); setSelectedViewId(personalDefault.id); }
      }
      setViewsInitialized(true);
    }).catch(() => undefined);
  }, [props.initialFilters, viewsInitialized]);

  useEffect(() => { void load(); }, [load]);
  useEffect(loadViews, [loadViews]);
  useEffect(() => { void apiGet<{ users: Array<{ id: string; login: string; role: string }> }>("/api/finding-assignees").then((body) => setAssignees(body.users)).catch(() => undefined); }, []);
  useEffect(() => { setPage(1); setSelected([]); }, [workspace, queueMode, filters]);

  const bulkReview = async (): Promise<void> => {
    if (!selected.length) return;
    if (["FALSE_POSITIVE", "ACCEPTED_RISK", "REMEDIATION:WONT_FIX", "NOTE"].includes(bulkState) && !bulkReason.trim()) {
      setMessage(`${label(bulkState)} requires a reason.`);
      return;
    }
    if (bulkState === "REMEDIATION:ASSIGNED" && !bulkAssignee) { setMessage("Bulk assignment requires an assignee."); return; }
    if (!window.confirm(`Apply ${label(bulkState)} to ${selected.length} selected finding${selected.length === 1 ? "" : "s"}?`)) return;
    try {
      const versions = Object.fromEntries(data.findings.filter((item) => selected.includes(item.id)).map((item) => [item.id, item.rowVersion]));
      const route = bulkState === "NOTE" ? "/api/findings/bulk-note" : bulkState.startsWith("REMEDIATION:") ? "/api/findings/bulk-remediation" : "/api/findings/bulk-review";
      const body = bulkState === "NOTE"
        ? { findingIds: selected, text: bulkReason.trim() }
        : bulkState.startsWith("REMEDIATION:")
          ? { findingIds: selected, newState: bulkState.split(":")[1], versions,
              ...(bulkAssignee ? { assigneeUserId: bulkAssignee } : {}),
              ...(bulkReason.trim() ? { note: bulkReason.trim() } : {}) }
          : { findingIds: selected, newStatus: bulkState, versions,
              ...(bulkReason.trim() ? { reason: bulkReason.trim(), note: bulkReason.trim() } : {}) };
      const result = await apiMutation<{ succeeded: string[]; failed: Array<{ findingId: string; reason: string }> }>(route, "POST", body);
      setMessage(`${result.succeeded.length} updated; ${result.failed.length} failed.${result.failed[0] ? ` ${result.failed[0].reason}` : ""}`);
      setSelected([]);
      await load();
    } catch (error) { setMessage(errorMessage(error)); }
  };

  const saveView = async (): Promise<void> => {
    if (!viewName.trim()) { setMessage("Enter a saved-view name."); return; }
    setSavingView(true);
    try {
      const result = await apiMutation<{ viewId: string }>("/api/finding-views", "POST", {
        name: viewName.trim(), query: savedViewQuery(filters), columns,
        isDefault: false, shared: false
      });
      setSelectedViewId(result.viewId);
      setViewName("");
      setMessage("Finding view saved.");
      loadViews();
    } catch (error) { setMessage(errorMessage(error)); }
    finally { setSavingView(false); }
  };

  const updateSelectedView = async (patch: Partial<{ name: string; isDefault: boolean; shared: boolean }>): Promise<void> => {
    const selectedView = views.find((view) => view.id === selectedViewId);
    if (!selectedView) return;
    try {
      await apiMutation("/api/finding-views", "PATCH", { id: selectedView.id, name: patch.name ?? selectedView.safe_name,
        query: savedViewQuery(filters), columns, isDefault: patch.isDefault ?? Boolean(selectedView.is_default),
        shared: patch.shared ?? Boolean(selectedView.shared_installation_wide), expectedVersion: selectedView.row_version });
      setMessage("Saved view updated."); loadViews();
    } catch (error) { setMessage(errorMessage(error)); }
  };

  const setDefaultView = async (id: string | null): Promise<void> => {
    try { await apiMutation("/api/finding-views/default", "POST", { id }); setMessage(id ? "Personal default view set." : "Personal default cleared."); loadViews(); }
    catch (error) { setMessage(errorMessage(error)); }
  };

  const deleteView = async (): Promise<void> => {
    if (!selectedViewId || !window.confirm("Delete this saved finding view?")) return;
    try {
      await apiMutation("/api/finding-views/delete", "POST", { id: selectedViewId });
      setSelectedViewId(""); setMessage("Finding view deleted."); loadViews();
    } catch (error) { setMessage(errorMessage(error)); }
  };

  return (
    <section className="finding-command-center">
      <header className="page-header command-header">
        <div><h2>Findings Command Center</h2><p>Review durable findings, their scan occurrences, evidence, remediation, and retests.</p></div>
        <div className="segmented" role="tablist" aria-label="Finding workspace">
          <button role="tab" aria-selected={workspace === "findings"} className={workspace === "findings" ? "selected" : ""} onClick={() => setWorkspace("findings")}>All Findings</button>
          <button role="tab" aria-selected={workspace === "queue"} className={workspace === "queue" ? "selected" : ""} onClick={() => setWorkspace("queue")}>Review Queue</button>
        </div>
      </header>

      <div className="finding-toolbar-band">
        {workspace === "queue" && <label>Queue<select value={queueMode} onChange={(event) => setQueueMode(event.target.value)}>{queueModes.map((value) => <option key={value} value={value}>{label(value)}</option>)}</select></label>}
        <label className="search-control">Search<input value={filters.q} onChange={(event) => changeFilter(setFilters, "q", event.target.value)} placeholder="ID, title, endpoint, module, project or target" /></label>
        <label>Severity<select value={filters.severity} onChange={(event) => changeFilter(setFilters, "severity", event.target.value)}><option value="">Any</option>{["Critical", "High", "Medium", "Low", "Info"].map(option)}</select></label>
        <label>Review<select value={filters.review} onChange={(event) => changeFilter(setFilters, "review", event.target.value)}><option value="">Any</option>{reviewStates.map(option)}</select></label>
        <label>Remediation<select value={filters.remediation} onChange={(event) => changeFilter(setFilters, "remediation", event.target.value)}><option value="">Any</option>{remediationStates.map(option)}</select></label>
        <label>Sort<select value={filters.sort} onChange={(event) => changeFilter(setFilters, "sort", event.target.value)}><option value="last_seen_desc">Last seen</option><option value="severity_desc">Severity</option><option value="confidence_desc">Confidence</option><option value="first_seen_desc">First seen</option><option value="occurrences_desc">Occurrences</option><option value="review">Review state</option><option value="remediation">Remediation</option><option value="target">Target</option><option value="project">Project</option></select></label>
        <details className="more-filters"><summary>More filters</summary><div>
          <label>Confidence<select value={filters.confidence} onChange={(event) => changeFilter(setFilters, "confidence", event.target.value)}><option value="">Any</option>{["High", "Medium", "Low"].map(option)}</select></label>
          <label>Module<input value={filters.module} onChange={(event) => changeFilter(setFilters, "module", event.target.value)} /></label>
          <label>Category<input value={filters.category} onChange={(event) => changeFilter(setFilters, "category", event.target.value)} /></label>
          <label>Retest<select value={filters.retest} onChange={(event) => changeFilter(setFilters, "retest", event.target.value)}><option value="">Any</option>{["NOT_RETESTED", "RETEST_SCHEDULED", "RETEST_RUNNING", "RETEST_PASSED", "RETEST_FAILED", "RETEST_INCONCLUSIVE"].map(option)}</select></label>
          <label>Proof<select value={filters.proof} onChange={(event) => changeFilter(setFilters, "proof", event.target.value)}><option value="">Any</option>{["NOT_READY", "MISSING_REVIEW", "MISSING_EVIDENCE", "READY", "IN_PROOF_PACK"].map(option)}</select></label>
          <label>Source<select value={filters.source} onChange={(event) => changeFilter(setFilters, "source", event.target.value)}><option value="">Any</option><option value="NATIVE">Native</option><option value="IMPORTED">Imported</option></select></label>
          <label>Evidence<select value={filters.evidence} onChange={(event) => changeFilter(setFilters, "evidence", event.target.value)}><option value="">Any</option><option value="HAS_EVIDENCE">Has evidence</option><option value="MISSING_EVIDENCE">Missing evidence</option></select></label>
          <label className="checkbox"><input type="checkbox" checked={filters.newOccurrence} onChange={(event) => changeFilter(setFilters, "newOccurrence", event.target.checked)} /> New occurrence</label>
        </div></details>
        <button onClick={() => setFilters(emptyFilters)}>Reset</button>
      </div>

      <div className="saved-view-bar">
        <label>Saved view<select value={selectedViewId} onChange={(event) => { setSelectedViewId(event.target.value); applySavedView(event.target.value, views, setFilters, setColumns); }}><option value="">Choose view</option>{views.map((view) => <option key={view.id} value={view.id}>{view.safe_name}{view.shared_installation_wide ? " (shared)" : ""}{view.is_default ? " (default)" : ""}</option>)}</select></label>
        <label>View name<input value={viewName} maxLength={120} onChange={(event) => setViewName(event.target.value)} /></label>
        <button disabled={savingView} onClick={() => void saveView()}>{savingView ? "Saving View..." : "Save Current View"}</button>
        <button disabled={!selectedViewId || !viewName.trim()} onClick={() => void updateSelectedView({ name: viewName.trim() })}>Rename</button>
        <button disabled={!selectedViewId} onClick={() => void setDefaultView(selectedViewId)}>Set Default</button>
        <button onClick={() => void setDefaultView(null)}>Clear Default</button>
        <button disabled={!selectedViewId} onClick={() => void updateSelectedView({ shared: !Boolean(views.find((view) => view.id === selectedViewId)?.shared_installation_wide) })}>{views.find((view) => view.id === selectedViewId)?.shared_installation_wide ? "Unshare" : "Share"}</button>
        <button disabled={!selectedViewId} onClick={() => void deleteView()}>Delete View</button>
        <details className="column-picker"><summary>Columns</summary><div className="column-manager">
          <strong>Visible order</strong>
          <ol>{columns.map((id, index) => {
            const column = columnOptions.find((item) => item.id === id)!;
            return <li key={id} draggable onDragStart={(event) => { setDraggedColumn(id); event.dataTransfer.effectAllowed = "move"; }} onDragEnd={() => setDraggedColumn("")} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); if (draggedColumn) setColumns((current) => moveColumn(current, draggedColumn, id)); setDraggedColumn(""); }} className={draggedColumn === id ? "dragging" : ""}>
              <span className="column-grip" aria-hidden="true">&#x2630;</span><span>{column.label}</span>
              <button aria-label={`Move ${column.label} earlier`} disabled={index === 0} onClick={() => setColumns((current) => moveColumnBy(current, id, -1))}>&#x2191;</button>
              <button aria-label={`Move ${column.label} later`} disabled={index === columns.length - 1} onClick={() => setColumns((current) => moveColumnBy(current, id, 1))}>&#x2193;</button>
              <button aria-label={`Hide ${column.label} column`} disabled={id === "title"} onClick={() => setColumns((current) => current.filter((value) => value !== id))}>Hide</button>
            </li>;
          })}</ol>
          <strong>Hidden columns</strong>
          <div className="hidden-columns">{columnOptions.filter((column) => !columns.includes(column.id)).map((column) => <button key={column.id} onClick={() => setColumns((current) => [...current, column.id])}>Add {column.label}</button>)}</div>
          <button onClick={() => setColumns(defaultColumns)}>Reset Columns</button>
        </div></details>
      </div>
      <p className="sr-status saved-view-status" role="status" aria-live="polite">{message}</p>

      {selected.length > 0 && <div className="bulk-bar" aria-label="Bulk triage">
        <strong>{selected.length} selected</strong>
        <label>Action<select value={bulkState} onChange={(event) => setBulkState(event.target.value)}><optgroup label="Review">{["IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK"].map(option)}</optgroup><optgroup label="Remediation">{["REMEDIATION:ASSIGNED", "REMEDIATION:FIX_IN_PROGRESS", "REMEDIATION:FIXED_PENDING_RETEST", "REMEDIATION:WONT_FIX"].map(option)}</optgroup><option value="NOTE">Add safe note</option></select></label>
        {bulkState === "REMEDIATION:ASSIGNED" && <label>Assignee<select value={bulkAssignee} onChange={(event) => setBulkAssignee(event.target.value)}><option value="">Choose owner or analyst</option>{assignees.map((user) => <option key={user.id} value={user.id}>{user.login} · {user.role}</option>)}</select></label>}
        <label className="bulk-reason">Reason<input value={bulkReason} onChange={(event) => setBulkReason(event.target.value)} placeholder="Required for false positive and accepted risk" /></label>
        <button className="primary" onClick={() => void bulkReview()}>Apply to Selection</button>
        <button onClick={() => setSelected([])}>Clear</button>
      </div>}

      {loading ? <div className="empty">Loading findings...</div> : data.findings.length === 0 ? <div className="empty">No findings match this review view.</div> :
        <ConfigurableFindingTable data={data} columns={columns} selected={selected} setSelected={setSelected} open={setOpenId} />}
      <div className="pagination" aria-label="Finding pages">
        <span>{data.total} findings · page {data.page} of {data.totalPages}</span>
        <button disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button>
        <button disabled={page >= data.totalPages} onClick={() => setPage((value) => value + 1)}>Next</button>
      </div>
      {openId && <FindingWorkspace findingId={openId} queue={data.findings} {...(props.principal ? { principal: props.principal } : {})} {...(props.onRetest ? { onRetest: props.onRetest } : {})} onClose={() => setOpenId("")} onMove={setOpenId} onChanged={load} />}
    </section>
  );
}

function ConfigurableFindingTable(props: { data: FindingPage; columns: string[]; selected: string[]; setSelected(value: string[]): void; open(id: string): void }): React.ReactElement {
  const all = props.data.findings.every((finding) => props.selected.includes(finding.id));
  return <div className="finding-table-wrap"><table className="finding-table configurable">
    <thead><tr><th><input aria-label="Select page" type="checkbox" checked={all} onChange={(event) => props.setSelected(event.target.checked ? props.data.findings.map((item) => item.id) : [])} /></th>{props.columns.map((id) => <th key={id}>{columnOptions.find((column) => column.id === id)?.label ?? id}</th>)}</tr></thead>
    <tbody>{props.data.findings.map((finding) => <tr key={finding.id} className={finding.newOccurrenceKind ? "new-occurrence" : ""}><td><input aria-label={`Select ${finding.title}`} type="checkbox" checked={props.selected.includes(finding.id)} onChange={(event) => props.setSelected(event.target.checked ? [...props.selected, finding.id] : props.selected.filter((id) => id !== finding.id))} /></td>{props.columns.map((id) => <td key={id}>{findingCell(id, finding, props.open)}</td>)}</tr>)}</tbody>
  </table></div>;
}

function findingCell(id: string, finding: FindingSummary, open: (id: string) => void): React.ReactNode {
  switch (id) {
    case "severity": return <Status value={finding.effectiveSeverity} />;
    case "confidence": return `${finding.confidence} confidence`;
    case "review": return <><Status value={finding.reviewStatus} />{finding.newOccurrenceKind && <small>{label(finding.newOccurrenceKind)}</small>}</>;
    case "remediation": return <Status value={finding.remediationStatus} />;
    case "title": return <><button className="link finding-title" onClick={() => open(finding.id)}>{finding.title}</button><small>RC-FIND-{finding.id.slice(0, 8)}</small></>;
    case "project": return finding.projectName ?? "Unassigned project";
    case "target": return finding.targetName ?? "Ad hoc target";
    case "module": return finding.module;
    case "category": return finding.category;
    case "endpoint": return <small>{finding.method} {finding.endpoint}</small>;
    case "firstSeen": return date(finding.firstSeenAt);
    case "lastSeen": return date(finding.lastSeenAt);
    case "occurrences": return finding.occurrenceCount;
    case "assignee": return finding.assigneeLabel ?? "Unassigned";
    case "retest": return label(finding.retestStatus);
    case "proof": return <Status value={finding.proofReadiness} />;
    case "newOccurrence": return finding.newOccurrenceKind ? label(finding.newOccurrenceKind) : "None";
    default: return null;
  }
}

function FindingTable(props: { data: FindingPage; selected: string[]; setSelected(value: string[]): void; open(id: string): void }): React.ReactElement {
  const all = props.data.findings.every((finding) => props.selected.includes(finding.id));
  return <div className="finding-table-wrap"><table className="finding-table">
    <thead><tr><th><input aria-label="Select page" type="checkbox" checked={all} onChange={(event) => props.setSelected(event.target.checked ? props.data.findings.map((item) => item.id) : [])} /></th><th>Severity / confidence</th><th>Review</th><th>Remediation</th><th>Finding</th><th>Project / target</th><th>Module / category</th><th>Seen</th><th>Owner / retest</th><th>Proof</th></tr></thead>
    <tbody>{props.data.findings.map((finding) => <tr key={finding.id} className={finding.newOccurrenceKind ? "new-occurrence" : ""}>
      <td><input aria-label={`Select ${finding.title}`} type="checkbox" checked={props.selected.includes(finding.id)} onChange={(event) => props.setSelected(event.target.checked ? [...props.selected, finding.id] : props.selected.filter((id) => id !== finding.id))} /></td>
      <td><Status value={finding.effectiveSeverity} /><small>{finding.confidence} confidence{finding.effectiveSeverity !== finding.severity ? ` · scanner ${finding.severity}` : ""}</small></td>
      <td><Status value={finding.reviewStatus} />{finding.newOccurrenceKind && <small>{label(finding.newOccurrenceKind)}</small>}</td>
      <td><Status value={finding.remediationStatus} /></td>
      <td><button className="link finding-title" onClick={() => props.open(finding.id)}>{finding.title}</button><small>RC-FIND-{finding.id.slice(0, 8)} · {finding.method} {finding.endpoint}</small></td>
      <td>{finding.projectName ?? "Unassigned project"}<small>{finding.targetName ?? "Ad hoc target"}</small></td>
      <td>{finding.module}<small>{finding.category}</small></td>
      <td>{date(finding.lastSeenAt)}<small>First {date(finding.firstSeenAt)} · {finding.occurrenceCount} occurrence{finding.occurrenceCount === 1 ? "" : "s"}</small></td>
      <td>{finding.assigneeLabel ?? "Unassigned"}<small>{label(finding.retestStatus)}</small></td>
      <td><Status value={finding.proofReadiness} /></td>
    </tr>)}</tbody>
  </table></div>;
}

function FindingWorkspace(props: { findingId: string; queue: FindingSummary[]; principal?: { userId?: string; login?: string; role?: string }; onRetest?: (draft: RetestDraft) => void; onClose(): void; onMove(id: string): void; onChanged(): Promise<void> }): React.ReactElement {
  const [detail, setDetail] = useState<FindingDetailData>();
  const [tab, setTab] = useState<DetailTab>("overview");
  const [reason, setReason] = useState("");
  const [note, setNote] = useState("");
  const [message, setMessage] = useState("");
  const [retestCandidates, setRetestCandidates] = useState<Array<Record<string, unknown>>>([]);
  const [retestScanId, setRetestScanId] = useState("");
  const [assignees, setAssignees] = useState<Array<{ id: string; login: string; role: string }>>([]);
  const [assignee, setAssignee] = useState("");
  const [remediationState, setRemediationState] = useState("OPEN");
  const [targetDate, setTargetDate] = useState("");
  const [canonicalId, setCanonicalId] = useState("");
  const [duplicateSearch, setDuplicateSearch] = useState("");
  const [duplicateCandidates, setDuplicateCandidates] = useState<FindingSummary[]>([]);
  const [severityOverride, setSeverityOverride] = useState("High");

  const load = useCallback(async () => {
    const body = await apiGet<FindingDetailData>(`/api/findings/${props.findingId}`);
    setDetail(body);
    setAssignee(body.finding.assigneeUserId ?? "");
    setRemediationState(body.finding.remediationStatus);
    setSeverityOverride(body.finding.effectiveSeverity);
  }, [props.findingId]);
  useEffect(() => { void load().catch((error) => setMessage(errorMessage(error))); }, [load]);
  useEffect(() => {
    void apiGet<{ scans: Array<Record<string, unknown>> }>(`/api/findings/${props.findingId}/retest-candidates`).then((body) => setRetestCandidates(body.scans)).catch(() => undefined);
    void apiGet<{ users: Array<{ id: string; login: string; role: string }> }>("/api/finding-assignees").then((body) => setAssignees(body.users)).catch(() => undefined);
  }, [props.findingId]);

  const position = props.queue.findIndex((item) => item.id === props.findingId);
  const move = (delta: number): void => {
    const target = props.queue[position + delta];
    if (target) props.onMove(target.id);
  };
  const mutateReview = useCallback(async (newStatus: string): Promise<void> => {
    if (!detail) return;
    if (["FALSE_POSITIVE", "ACCEPTED_RISK", "REOPENED"].includes(newStatus) && !reason.trim()) { setMessage(`${label(newStatus)} requires a reason.`); return; }
    if (newStatus === "DUPLICATE" && !canonicalId) { setMessage("Choose a canonical finding."); return; }
    const anotherReviewer = detail.finding.reviewStatus === "IN_REVIEW" && detail.finding.reviewerUserId && detail.finding.reviewerUserId !== props.principal?.userId;
    const takeover = Boolean(anotherReviewer && window.confirm(`This finding is currently being reviewed by ${detail.finding.reviewerLabel ?? "another analyst"} since ${dateTime(detail.finding.reviewStartedAt ?? "")}. Continue and take over?`));
    if (anotherReviewer && !takeover) { setMessage("Review ownership preserved."); return; }
    try {
      await apiMutation(`/api/findings/${detail.finding.id}/review`, "PATCH", {
        newStatus, expectedVersion: detail.finding.rowVersion,
        ...(reason.trim() ? { reason: reason.trim(), note: reason.trim() } : {}),
        ...(canonicalId ? { duplicateTargetFindingId: canonicalId } : {}),
        takeover
      });
      setReason(""); setMessage(`${label(newStatus)} recorded.`); await load(); await props.onChanged();
    } catch (error) { setMessage(errorMessage(error)); }
  }, [detail, reason, canonicalId, load, props]);

  const searchDuplicates = async (): Promise<void> => {
    if (!duplicateSearch.trim()) { setDuplicateCandidates([]); return; }
    try {
      const page = await apiGet<FindingPage>(`/api/findings?q=${encodeURIComponent(duplicateSearch.trim())}&pageSize=20`);
      setDuplicateCandidates(page.findings.filter((item) => item.id !== props.findingId));
    } catch (error) { setMessage(errorMessage(error)); }
  };

  useEffect(() => {
    const handler = (event: KeyboardEvent): void => {
      const target = event.target as HTMLElement | null;
      if (target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return;
      if (event.key.toLowerCase() === "j") move(1);
      if (event.key.toLowerCase() === "k") move(-1);
      if (event.key.toLowerCase() === "c") void mutateReview("CONFIRMED");
      if (event.key.toLowerCase() === "f") { setTab("overview"); document.getElementById("review-reason")?.focus(); }
      if (event.key.toLowerCase() === "r") void mutateReview(detail?.finding.reviewStatus === "RESOLVED" ? "REOPENED" : "IN_REVIEW");
      if (event.key.toLowerCase() === "a") { setTab("overview"); document.getElementById("review-reason")?.focus(); }
      if (event.key.toLowerCase() === "n") { setTab("history"); document.getElementById("finding-note")?.focus(); }
      if (event.key.toLowerCase() === "e") setTab("evidence");
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [detail?.finding.reviewStatus, mutateReview, position]);

  if (!detail) return <div className="finding-drawer"><div className="empty">Loading finding workspace...</div></div>;
  const finding = detail.finding;
  const tabs: Array<[DetailTab, string]> = [["overview", "Overview"], ["evidence", "Evidence"], ["occurrences", "Occurrences"], ["reproduction", "Reproduction"], ["remediation", "Remediation"], ["history", "History & Notes"], ["related", "Related"], ["proof", "Proof Readiness"]];

  return <div className="finding-drawer" role="dialog" aria-modal="true" aria-labelledby="finding-workspace-title">
    <header><div><small>RC-FIND-{finding.id.slice(0, 8)} · {position + 1} of {props.queue.length}</small><h2 id="finding-workspace-title">{finding.title}</h2><p>{finding.method} {finding.endpoint}</p></div><div className="actions"><button disabled={position <= 0} onClick={() => move(-1)}>Previous</button><button disabled={position < 0 || position >= props.queue.length - 1} onClick={() => move(1)}>Next</button><button aria-label="Close finding workspace" onClick={props.onClose}>Close</button></div></header>
    <div className="chips"><Status value={finding.effectiveSeverity} /><Status value={finding.confidence} /><Status value={finding.reviewStatus} /><Status value={finding.remediationStatus} />{finding.newOccurrenceKind && <Status value={finding.newOccurrenceKind} />}</div>
    <nav className="detail-tabs" role="tablist" aria-label="Finding detail sections">{tabs.map(([value, text]) => <button role="tab" aria-selected={tab === value} className={tab === value ? "selected" : ""} key={value} onClick={() => setTab(value)}>{text}</button>)}</nav>
    <p className="sr-status" role="status" aria-live="polite">{message}</p>
    {finding.reviewStatus === "IN_REVIEW" && finding.reviewerLabel && finding.reviewerUserId !== props.principal?.userId && <p className="review-owner-warning">This finding is currently being reviewed by {finding.reviewerLabel}. Review started {dateTime(finding.reviewStartedAt ?? "")}{finding.reviewStartedAt && Date.now() - new Date(finding.reviewStartedAt).getTime() > 4 * 60 * 60 * 1000 ? " and appears stale" : ""}.</p>}
    {tab === "overview" && <div className="detail-grid">
      <section><h3>Finding Summary</h3><dl className="dense-dl"><dt>Project</dt><dd>{finding.projectName ?? "Unassigned"}</dd><dt>Target</dt><dd>{finding.targetName ?? "Ad hoc"}</dd><dt>Module</dt><dd>{finding.module}</dd><dt>Category</dt><dd>{finding.category}</dd><dt>Scanner severity</dt><dd>{finding.severity}</dd><dt>Effective severity</dt><dd>{finding.effectiveSeverity}</dd><dt>First seen</dt><dd>{dateTime(finding.firstSeenAt)}</dd><dt>Last seen</dt><dd>{dateTime(finding.lastSeenAt)}</dd><dt>Occurrences</dt><dd>{finding.occurrenceCount}</dd></dl>{detail.description && <p>{detail.description}</p>}<div className="inline-control"><label>Override effective severity<select value={severityOverride} onChange={(event) => setSeverityOverride(event.target.value)}>{["Critical", "High", "Medium", "Low", "Info"].map(option)}</select></label><button disabled={!reason.trim()} onClick={() => void apiMutation(`/api/findings/${finding.id}/severity`, "PATCH", { severity: severityOverride, reason, expectedVersion: finding.rowVersion }).then(async () => { setMessage("Effective severity updated; scanner severity preserved."); await load(); await props.onChanged(); }).catch((error) => setMessage(errorMessage(error)))}>Apply Override</button></div></section>
      <section><h3>Review Decision</h3><label>Safe reason<textarea id="review-reason" value={reason} maxLength={1000} onChange={(event) => setReason(event.target.value)} placeholder="Required for false positive, accepted risk, duplicate context, severity override, or reopen. Do not paste credentials." /></label><div className="actions"><button onClick={() => void mutateReview("IN_REVIEW")}>Start Review</button><button className="primary" onClick={() => void mutateReview("CONFIRMED")}>Confirm</button><button onClick={() => void mutateReview("FALSE_POSITIVE")}>False Positive</button><button onClick={() => void mutateReview("ACCEPTED_RISK")}>Accept Risk</button>{finding.reviewStatus === "RESOLVED" && <button onClick={() => void mutateReview("REOPENED")}>Reopen</button>}</div><div className="inline-control"><label>Find canonical finding<input value={duplicateSearch} onChange={(event) => setDuplicateSearch(event.target.value)} placeholder="ID, title, target, module, category or endpoint" /></label><button onClick={() => void searchDuplicates()}>Search</button></div><label>Duplicate of<select value={canonicalId} onChange={(event) => setCanonicalId(event.target.value)}><option value="">Choose canonical finding</option>{duplicateCandidates.map((item) => <option value={item.id} key={item.id}>RC-FIND-{item.id.slice(0, 8)} · {item.title} · {item.targetName ?? item.endpoint}</option>)}</select></label><button disabled={!canonicalId} onClick={() => void mutateReview("DUPLICATE")}>Mark Duplicate</button></section>
      <section className="shortcut-help"><h3>Review Shortcuts</h3><p><kbd>J</kbd>/<kbd>K</kbd> next/previous · <kbd>C</kbd> confirm · <kbd>R</kbd> start/reopen · <kbd>F</kbd> false-positive reason · <kbd>A</kbd> accepted-risk reason · <kbd>N</kbd> note · <kbd>E</kbd> evidence</p><small>Shortcuts are disabled while typing in a form control.</small></section>
    </div>}
    {tab === "evidence" && <EvidenceWorkspace detail={detail} />}
    {tab === "occurrences" && <OccurrenceWorkspace detail={detail} />}
    {tab === "reproduction" && <ReproductionWorkspace detail={detail} />}
    {tab === "remediation" && <div className="detail-grid">
      {props.onRetest && <section><h3>Re-run for Retest</h3><p>Create a reviewed Scan Studio session from safe historical configuration. The scan will not start automatically.</p><button className="primary" onClick={() => void apiGet<RetestDraft>(`/api/findings/${finding.id}/retest-draft`).then(props.onRetest).catch((error) => setMessage(errorMessage(error)))}>Re-run for Retest</button></section>}
      <section><h3>Remediation State</h3><label>State<select value={remediationState} onChange={(event) => setRemediationState(event.target.value)}>{remediationStates.filter((value) => value !== "FIXED_VERIFIED").map(option)}</select></label><label>Assignee<select value={assignee} onChange={(event) => setAssignee(event.target.value)}><option value="">Unassigned</option>{assignees.map((user) => <option value={user.id} key={user.id}>{user.login} · {user.role}</option>)}</select></label><label>Target fix date<input type="date" value={targetDate} onChange={(event) => setTargetDate(event.target.value)} /></label><label>Safe remediation note<textarea value={reason} onChange={(event) => setReason(event.target.value)} /></label><button onClick={() => void apiMutation(`/api/findings/${finding.id}/remediation`, "PATCH", { newState: remediationState, assigneeUserId: assignee || null, targetFixDate: targetDate || null, ...(reason.trim() ? { note: reason.trim() } : {}), expectedVersion: finding.rowVersion }).then(async () => { setMessage("Remediation updated."); await load(); await props.onChanged(); }).catch((error) => setMessage(errorMessage(error)))}>Update Remediation</button></section>
      <section><h3>Retest</h3><label>Completed candidate scan<select value={retestScanId} onChange={(event) => setRetestScanId(event.target.value)}><option value="">Select retest</option>{retestCandidates.map((scan) => <option value={String(scan.id)} key={String(scan.id)}>{String(scan.id).slice(0, 8)} · {String(scan.status)} · module {scan.relevant_module_completed ? "covered" : "missing"}</option>)}</select></label><button disabled={!retestScanId} onClick={() => void apiMutation(`/api/findings/${finding.id}/retest`, "POST", { scanId: retestScanId, expectedVersion: finding.rowVersion }).then(async (result) => { setMessage(`Retest result: ${String((result as Record<string, unknown>).state)}.`); await load(); await props.onChanged(); }).catch((error) => setMessage(errorMessage(error)))}>Evaluate Retest</button><label>Verification reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} /></label><div className="actions"><button disabled={finding.retestStatus !== "RETEST_PASSED" || !reason.trim()} onClick={() => void apiMutation(`/api/findings/${finding.id}/verify-fixed`, "POST", { reason, ownerOverride: false, expectedVersion: finding.rowVersion }).then(async () => { setMessage("Compatible retest verified remediation."); await load(); await props.onChanged(); }).catch((error) => setMessage(errorMessage(error)))}>Verify Fixed</button><button disabled={!reason.trim()} onClick={() => { if (window.confirm("Owner override bypasses compatible retest evidence. Continue?")) void apiMutation(`/api/findings/${finding.id}/verify-fixed`, "POST", { reason, ownerOverride: true, expectedVersion: finding.rowVersion }).then(async () => { setMessage("Owner verification override recorded."); await load(); await props.onChanged(); }).catch((error) => setMessage(errorMessage(error))); }}>Owner Override</button></div><p className="muted">Absence is only accepted when the target matches and the relevant module and controlled case coverage completed. Owner override is separately permissioned and audited.</p></section>
      <Timeline title="Remediation History" items={detail.remediationHistory} />
    </div>}
    {tab === "history" && <div className="detail-grid"><Timeline title="Review History" items={detail.reviews} /><section><h3>Analyst Notes</h3><ul className="timeline">{detail.notes.map((item) => <li key={item.id}><strong>{item.author_label ?? "Local operator"}</strong><time>{dateTime(item.created_at)}</time><p>{item.safe_text}</p></li>)}</ul><label>Safe note<textarea id="finding-note" value={note} maxLength={4000} onChange={(event) => setNote(event.target.value)} placeholder="Do not paste credentials, tokens, cookies, or raw secrets." /></label><button onClick={() => void apiMutation(`/api/findings/${finding.id}/notes`, "POST", { text: note }).then(async () => { setNote(""); setMessage("Note added."); await load(); }).catch((error) => setMessage(errorMessage(error)))}>Add Note</button></section></div>}
    {tab === "related" && <div className="detail-grid"><section><h3>Related Findings</h3><p className="muted">Deterministic relationships are based on target, module, category, endpoint, or explicit duplicate links. Related does not mean duplicate.</p><SafeObjectList values={detail.related} /></section><section><h3>Canonical Duplicates</h3><SafeObjectList values={detail.duplicates} /></section></div>}
    {tab === "proof" && <section><h3>Proof Readiness</h3><Status value={finding.proofReadiness} /><p>A confirmed finding with retained evidence is ready for later proof-pack selection. This workspace does not generate new proof evidence.</p></section>}
  </div>;
}

function EvidenceWorkspace({ detail }: { detail: FindingDetailData }): React.ReactElement {
  if (!detail.evidence.length) return <div className="empty">Evidence unavailable for this finding. Imported reports may not contain retained evidence.</div>;
  return <div className="evidence-list">{detail.evidence.map((item) => <article key={item.id} className="evidence-item"><header><div><strong>{item.evidence_type}</strong><small>{item.evidence_level} · occurrence {item.finding_occurrence_id.slice(0, 8)}</small></div><Status value={item.missing_file_flag ? "UNAVAILABLE" : "AVAILABLE"} /></header><p>{item.safe_summary}</p><EvidenceViewerRegistry evidence={item} />{item.artifact_id && !item.missing_file_flag && !/browser|screenshot/i.test(item.evidence_type) && <a href={`/api/artifacts/${item.artifact_id}/download`}>Download retained artifact</a>}<p className="muted">Target-controlled content is rendered as escaped text. HTTP headers and bodies remain subject to evidence policy and redaction.</p></article>)}</div>;
}

function OccurrenceWorkspace({ detail }: { detail: FindingDetailData }): React.ReactElement {
  return <div className="detail-grid"><section><h3>Occurrence Timeline</h3><ol className="timeline">{detail.occurrences.map((item) => <li key={item.id}><time>{dateTime(item.created_at)}</time><strong>{item.severity} · {item.confidence}</strong><p>{item.evidence_summary}</p><small>Scan {item.scan_id.slice(0, 8)}</small></li>)}</ol></section><section><h3>Finding-Specific Changes</h3><SafeObjectList values={detail.occurrenceDifferences} /><p className="muted">These are bounded occurrence differences, not whole-scan regression classifications.</p></section></div>;
}

function ReproductionWorkspace({ detail }: { detail: FindingDetailData }): React.ReactElement {
  return <div className="evidence-list">{detail.occurrences.map((item) => <article className="evidence-item" key={item.id}><h3>{String(item.title)}</h3><dl className="dense-dl"><dt>Endpoint</dt><dd>{String(item.safe_endpoint)}</dd><dt>Actor boundary</dt><dd>{String(item.safe_actor_relationship ?? "Not supplied")}</dd><dt>Tenant/role</dt><dd>{String(item.safe_tenant_or_role_boundary ?? "Not supplied")}</dd><dt>State</dt><dd>{String(item.safe_state_boundary ?? "Not supplied")}</dd><dt>Expected/observed</dt><dd>{String(item.description ?? item.evidence_summary)}</dd><dt>Limitations</dt><dd>{String(item.limitations ?? "Needs manual verification.")}</dd></dl><p className="pre-wrap">{String(item.reproduction_steps ?? "No retained reproduction steps.")}</p></article>)}</div>;
}

function Timeline({ title, items }: { title: string; items: Array<Record<string, unknown>> }): React.ReactElement {
  return <section><h3>{title}</h3>{items.length === 0 ? <p className="muted">No history yet.</p> : <ol className="timeline">{items.map((item, index) => <li key={String(item.id ?? index)}><strong>{String(item.actor_label ?? item.local_reviewer_label ?? "System")}</strong><time>{dateTime(String(item.created_at ?? ""))}</time><p>{String(item.new_review_status ?? item.new_state ?? "Updated")}{item.previous_review_status || item.previous_state ? ` · from ${String(item.previous_review_status ?? item.previous_state)}` : ""}</p>{item.reason || item.safe_note ? <small>{String(item.reason ?? item.safe_note)}</small> : null}</li>)}</ol>}</section>;
}

function SafeObjectList({ values }: { values: Array<Record<string, unknown>> }): React.ReactElement {
  if (!values.length) return <p className="muted">No records.</p>;
  return <ul className="safe-object-list">{values.map((value, index) => <li key={String(value.id ?? index)}>{Object.entries(value).filter(([, item]) => typeof item !== "object").slice(0, 6).map(([key, item]) => <span key={key}><strong>{label(key)}</strong> {String(item ?? "")}</span>)}</li>)}</ul>;
}

function SafeJson({ value }: { value: string }): React.ReactElement {
  let parsed: unknown = value;
  try { parsed = JSON.parse(value); } catch { parsed = value; }
  return <pre className="safe-evidence-json">{JSON.stringify(parsed, null, 2)}</pre>;
}

function Status({ value }: { value: string }): React.ReactElement {
  return <span className={`badge ${value.toLowerCase().replaceAll("_", "-")}`}>{label(value)}</span>;
}

function option(value: string): React.ReactElement { return <option key={value} value={value}>{label(value)}</option>; }
function label(value: string): string { return value.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase()); }
function date(value: string): string { return value ? new Date(value).toLocaleDateString() : "Unknown"; }
function dateTime(value: string): string { return value ? new Date(value).toLocaleString() : "Unknown"; }
function errorMessage(value: unknown): string { return value instanceof Error ? value.message : "Finding operation failed."; }

function changeFilter<K extends keyof Filters>(setFilters: React.Dispatch<React.SetStateAction<Filters>>, key: K, value: Filters[K]): void {
  setFilters((current) => ({ ...current, [key]: value }));
}

function findingQuery(filters: Filters, page: number): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filterPayload(filters))) {
    if (value !== "" && value !== false && value !== undefined) params.set(key, String(value));
  }
  params.set("page", String(page)); params.set("pageSize", "25");
  return params.toString();
}

function filterPayload(filters: Filters): Record<string, string | boolean> {
  return { ...filters };
}

interface SavedViewQuery {
  search?: string;
  projectId?: string;
  targetId?: string;
  module?: string;
  category?: string;
  severity?: string;
  confidence?: string;
  reviewStatus?: string;
  remediationStatus?: string;
  assigneeUserId?: string;
  retestStatus?: string;
  proofReadiness?: string;
  sourceKind?: string;
  evidence?: string;
  newOccurrence?: boolean;
  sort?: string;
}

function savedViewQuery(filters: Filters): SavedViewQuery {
  return {
    ...(filters.q ? { search: filters.q } : {}),
    ...(filters.projectId ? { projectId: filters.projectId } : {}),
    ...(filters.targetId ? { targetId: filters.targetId } : {}),
    ...(filters.module ? { module: filters.module } : {}),
    ...(filters.category ? { category: filters.category } : {}),
    ...(filters.severity ? { severity: filters.severity } : {}),
    ...(filters.confidence ? { confidence: filters.confidence } : {}),
    ...(filters.review ? { reviewStatus: filters.review } : {}),
    ...(filters.remediation ? { remediationStatus: filters.remediation } : {}),
    ...(filters.assignee ? { assigneeUserId: filters.assignee } : {}),
    ...(filters.retest ? { retestStatus: filters.retest } : {}),
    ...(filters.proof ? { proofReadiness: filters.proof } : {}),
    ...(filters.source ? { sourceKind: filters.source } : {}),
    ...(filters.evidence ? { evidence: filters.evidence } : {}),
    ...(filters.newOccurrence ? { newOccurrence: true } : {}),
    ...(filters.sort ? { sort: filters.sort } : {})
  };
}

interface SavedView { id: string; safe_name: string; query_json: string; columns_json: string; is_default: number; shared_installation_wide: number; row_version: number; }

export interface RetestDraft {
  context: { findingId: string; sourceOccurrenceId: string; sourceScanId: string; relevantModule: string; relevantWorkflow?: string; relevantCase?: string; purpose: string };
  projectId?: string; targetId?: string; target: string; profile: string; scope?: Record<string, unknown>;
  selectedModules: string[]; evidenceLevel: string; outputs: Record<string, boolean>;
  historicalAuthenticationMode: string; freshCredentialsRequired: boolean; savedCredentialReferences: string[];
  reusableWorkflows?: unknown[];
  warning: string;
}

function applySavedView(id: string, views: SavedView[], setFilters: React.Dispatch<React.SetStateAction<Filters>>, setColumns: React.Dispatch<React.SetStateAction<string[]>>): void {
  const view = views.find((item) => item.id === id);
  if (!view) return;
  try {
    const parsed = JSON.parse(view.query_json) as unknown;
    if (isRecord(parsed)) {
      setFilters({
        ...emptyFilters,
        q: stringValue(parsed.search ?? parsed.q),
        projectId: stringValue(parsed.projectId), targetId: stringValue(parsed.targetId),
        module: stringValue(parsed.module), category: stringValue(parsed.category),
        severity: stringValue(parsed.severity), confidence: stringValue(parsed.confidence),
        review: stringValue(parsed.reviewStatus ?? parsed.review),
        remediation: stringValue(parsed.remediationStatus ?? parsed.remediation),
        assignee: stringValue(parsed.assigneeUserId ?? parsed.assignee),
        retest: stringValue(parsed.retestStatus ?? parsed.retest),
        proof: stringValue(parsed.proofReadiness ?? parsed.proof),
        source: stringValue(parsed.sourceKind ?? parsed.source), evidence: stringValue(parsed.evidence),
        newOccurrence: parsed.newOccurrence === true,
        sort: stringValue(parsed.sort) || emptyFilters.sort
      });
    }
  } catch { /* Invalid legacy query data remains inert. */ }
  try { const parsed = JSON.parse(view.columns_json) as unknown; if (Array.isArray(parsed) && parsed.includes("title")) setColumns(parsed.filter((value): value is string => typeof value === "string" && columnOptions.some((column) => column.id === value))); } catch { /* Invalid legacy columns use defaults. */ }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

const defaultColumns = ["severity", "confidence", "review", "remediation", "title", "project", "target", "module", "category", "endpoint", "lastSeen", "occurrences", "assignee", "retest", "proof", "newOccurrence"];
const columnOptions = [
  ["severity", "Severity"], ["confidence", "Confidence"], ["review", "Review"], ["remediation", "Remediation"],
  ["title", "Title"], ["project", "Project"], ["target", "Target"], ["module", "Module"], ["category", "Category"],
  ["endpoint", "Endpoint"], ["firstSeen", "First seen"], ["lastSeen", "Last seen"], ["occurrences", "Occurrences"],
  ["assignee", "Assignee"], ["retest", "Retest"], ["proof", "Proof readiness"], ["newOccurrence", "New occurrence"]
].map(([id, label]) => ({ id: id!, label: label! }));

function moveColumn(columns: string[], source: string, target: string): string[] {
  const from = columns.indexOf(source);
  const to = columns.indexOf(target);
  if (from < 0 || to < 0 || from === to) return columns;
  const next = [...columns];
  next.splice(from, 1);
  next.splice(to, 0, source);
  return next;
}

function moveColumnBy(columns: string[], id: string, offset: -1 | 1): string[] {
  const index = columns.indexOf(id);
  const target = index + offset;
  if (index < 0 || target < 0 || target >= columns.length) return columns;
  const next = [...columns];
  [next[index], next[target]] = [next[target]!, next[index]!];
  return next;
}
