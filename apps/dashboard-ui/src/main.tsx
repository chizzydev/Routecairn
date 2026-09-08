import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { apiGet, apiMutation, bootstrap, DashboardApiError, setCsrfToken, type AuditEvent, type FindingSummary, type PlanPreview, type ProjectSummary, type ScanSummary, type TargetSummary } from "./api";
import "./styles.css";
import { AssistedReviewPanel } from "./AssistedReviewPanel";
import { WorkflowRecoveryPanel } from "./WorkflowRecoveryPanel";
import { ScanCancellationNotice } from "./ScanCancellationNotice";
import { FindingsCommandCenter, type RetestDraft } from "./FindingsCommandCenter";
import type { ComparisonResult } from "../../../src/dashboard/types/DashboardTypes";
import { WorkerDiagnostics } from "./WorkerDiagnostics";
import { BrowserNetworkDiagnostics } from "./BrowserNetworkDiagnostics";
import { CredentialHealthBadge, CredentialHealthTimeline, CredentialImpactPanel, credentialExpiryLabel, credentialUsable, type CredentialDetailResponse, type CredentialSummary } from "./CredentialLifecycle";
import { ProductionMutationWorkspace } from "./ProductionMutationWorkspace";
import { LiveAcceptanceWorkspace } from "./LiveAcceptanceWorkspace";
import { AdaptiveSecurityWorkspace } from "./AdaptiveSecurityWorkspace";
import type { AdvancedEngineId } from "./AdvancedEngineStudio";
import { ProviderAdapterWorkspace } from "./ProviderAdapterWorkspace";
import { ContinuousAssuranceWorkspace } from "./ContinuousAssuranceWorkspace";
const ScanStudio = React.lazy(async () => ({ default: (await import("./ScanStudio")).ScanStudio }));

type View = "overview" | "projects" | "project-detail" | "targets" | "target-detail" | "scans" | "new-scan" | "scan-detail" | "findings" | "compare" | "proof" | "offensive" | "mutation" | "production-mutation" | "live-acceptance" | "adaptive-security" | "provider-adapters" | "continuous-assurance" | "configurations" | "credentials" | "workers" | "users" | "audit" | "settings";

export function App() {
  const [ready, setReady] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [principal, setPrincipal] = useState<any>();
  const [view, setView] = useState<View>("overview");
  const [selectedId, setSelectedId] = useState("");
  const [findingFilters, setFindingFilters] = useState<Record<string, string>>({});
  const [retestDraft, setRetestDraft] = useState<RetestDraft>();
  const [adaptiveDraft, setAdaptiveDraft] = useState<{ target: TargetSummary; engineId: AdvancedEngineId }>();
  const [adapterDraft, setAdapterDraft] = useState<any>();
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const initialize = (): void => {
      void bootstrap()
        .then(async () => {
          const session = await apiGet<any>("/api/auth/session");
          if (!active) return;
          setAuthenticated(true);
          setPrincipal(session.principal);
          setError("");
        })
        .catch((cause: unknown) => {
          if (active) setError(cause instanceof Error ? cause.message : "Session bootstrap failed.");
        })
        .finally(() => {
          if (active) setReady(true);
        });
    };
    window.addEventListener("hashchange", initialize);
    initialize();
    return () => {
      active = false;
      window.removeEventListener("hashchange", initialize);
    };
  }, []);

  if (!ready) return <main className="center">Starting RouteCairn Dashboard...</main>;
  if (!authenticated && error) return <Login onLogin={(user) => { setPrincipal(user); setAuthenticated(true); setError(""); }} />;
  if (error) return <main className="center error">{error}</main>;

  return (
    <div className="shell">
      <aside>
        <h1>RouteCairn</h1>
        <button className={view === "overview" ? "active" : ""} onClick={() => setView("overview")}>Overview</button>
        <button className={view === "projects" ? "active" : ""} onClick={() => setView("projects")}>Projects</button>
        <button className={view === "targets" ? "active" : ""} onClick={() => setView("targets")}>Targets</button>
        <button className={view === "scans" ? "active" : ""} onClick={() => setView("scans")}>Scans</button>
        <button className={view === "new-scan" ? "active" : ""} onClick={() => { setRetestDraft(undefined); setAdaptiveDraft(undefined); setAdapterDraft(undefined); setView("new-scan"); }}>New Scan</button>
        <button className={view === "findings" ? "active" : ""} onClick={() => { setFindingFilters({}); setView("findings"); }}>Findings</button>
        <button className={view === "compare" ? "active" : ""} onClick={() => setView("compare")}>Compare</button>
        <button className={view === "proof" ? "active" : ""} onClick={() => setView("proof")}>Proof Packs</button>
        <button className={view === "offensive" ? "active" : ""} onClick={() => setView("offensive")}>Offensive Safety</button>
        <button className={view === "mutation" ? "active" : ""} onClick={() => setView("mutation")}>Mutation Approval</button>
        <button className={view === "production-mutation" ? "active" : ""} onClick={() => setView("production-mutation")}>Production Mutation</button>
        <button className={view === "live-acceptance" ? "active" : ""} onClick={() => setView("live-acceptance")}>Live Acceptance</button>
        <button className={view === "adaptive-security" ? "active" : ""} onClick={() => setView("adaptive-security")}>Adaptive Security</button>
        <button className={view === "provider-adapters" ? "active" : ""} onClick={() => setView("provider-adapters")}>Fixture Adapters</button>
        <button className={view === "continuous-assurance" ? "active" : ""} onClick={() => setView("continuous-assurance")}>Continuous Assurance</button>
        <button className={view === "configurations" ? "active" : ""} onClick={() => setView("configurations")}>Configurations</button>
        <button className={view === "credentials" ? "active" : ""} onClick={() => setView("credentials")}>Credentials</button>
        <button className={view === "workers" ? "active" : ""} onClick={() => setView("workers")}>Workers</button>
        <button className={view === "users" ? "active" : ""} onClick={() => setView("users")}>Users</button>
        <button className={view === "audit" ? "active" : ""} onClick={() => setView("audit")}>Audit</button>
        <button className={view === "settings" ? "active" : ""} onClick={() => setView("settings")}>Settings</button>
        <button onClick={() => { window.dispatchEvent(new Event("routecairn:session-expired")); void apiMutation("/api/session/logout", "POST", {}).finally(() => { setAuthenticated(false); setError("Signed out."); }); }}>Log Out</button>
        <small>{principal?.login ?? "local"} · {principal?.role ?? "OWNER"}</small>
      </aside>
      <main><React.Suspense fallback={<p role="status">Loading workspace…</p>}>
        {view === "overview" && <Overview onOpenScan={(id) => { setSelectedId(id); setView("scan-detail"); }} />}
        {view === "projects" && <Projects onOpen={(id) => { setSelectedId(id); setView("project-detail"); }} />}
        {view === "project-detail" && <ProjectDetail projectId={selectedId} onFindings={(filters) => { setFindingFilters(filters); setView("findings"); }} onTarget={(id) => { setSelectedId(id); setView("target-detail"); }} />}
        {view === "targets" && <Targets onOpen={(id) => { setSelectedId(id); setView("target-detail"); }} />}
        {view === "target-detail" && <TargetDetail targetId={selectedId} onFindings={(filters) => { setFindingFilters(filters); setView("findings"); }} onScan={() => { setRetestDraft(undefined); setAdaptiveDraft(undefined); setView("new-scan"); }} />}
        {view === "scans" && <ScanOverview onOpenScan={(id) => { setSelectedId(id); setView("scan-detail"); }} />}
        {view === "new-scan" && <ScanStudio {...(retestDraft ? { initialDraft: retestDraft } : {})} {...(adaptiveDraft ? { initialAdaptiveDraft: adaptiveDraft } : {})} {...(adapterDraft ? { initialAdapterDraft: adapterDraft } : {})} onLaunched={(id) => { setRetestDraft(undefined); setAdaptiveDraft(undefined); setAdapterDraft(undefined); setSelectedId(id); setView("scan-detail"); }} />}
        {view === "scan-detail" && <ScanDetail scanId={selectedId} onRecovery={() => setView("offensive")} onReviewFindings={() => { setFindingFilters({ scanId: selectedId }); setView("findings"); }} />}
        {view === "findings" && <FindingsCommandCenter initialFilters={findingFilters} principal={principal} onRetest={(draft) => { setAdaptiveDraft(undefined); setRetestDraft(draft); setView("new-scan"); }} />}
        {view === "compare" && <Compare />}
        {view === "proof" && <ProofPacks />}
        {view === "offensive" && <OffensiveSafety />}
        {view === "mutation" && <ControlledMutationWorkspace />}
        {view === "production-mutation" && <ProductionMutationWorkspace />}
        {view === "live-acceptance" && <LiveAcceptanceWorkspace />}
        {view === "adaptive-security" && <AdaptiveSecurityWorkspace canApprove={principal?.role === "OWNER"} onOpenBuilder={(draft) => { setRetestDraft(undefined); setAdaptiveDraft({ target: draft.target, engineId: draft.engineId as AdvancedEngineId }); setView("new-scan"); }} />}
        {view === "provider-adapters" && <ProviderAdapterWorkspace canManage={principal?.role === "OWNER"} onUse={({ target, input, binding }) => { setRetestDraft(undefined); setAdaptiveDraft(undefined); setAdapterDraft({ target, engineId: input.engineId, engineConfiguration: input.engineConfiguration, authentication: input.authentication, binding, limits: input.limits }); setView("new-scan"); }} />}
        {view === "continuous-assurance" && <ContinuousAssuranceWorkspace canManage={principal?.role === "OWNER"} />}
        {view === "configurations" && <Configurations onRun={(config) => { window.sessionStorage.setItem("routecairn.scan-studio.configuration", JSON.stringify(config)); setRetestDraft(undefined); setAdaptiveDraft(undefined); setView("new-scan"); }} />}
        {view === "credentials" && <Credentials />}
        {view === "workers" && <WorkerDiagnostics canManage={principal?.role === "OWNER"} />}
        {view === "users" && <Users />}
        {view === "audit" && <AuditLog />}
        {view === "settings" && <Settings />}
      </React.Suspense></main>
    </div>
  );
}

function OffensiveSafety() {
  const [status, setStatus] = useState<any>();
  const [error, setError] = useState("");
  useEffect(() => {
    const load = () => void apiGet<any>("/api/offensive/status").then(setStatus).catch((cause: unknown) => setError(errorText(cause)));
    load();
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, []);
  return <section>
    <Header title="Offensive Safety" subtitle="Shared mutation coordination, encrypted cleanup checkpoints, and dashboard-operated recovery." />
    {error && <p className="error">{error}</p>}
    {status?.cleanupRequired > 0 && <div className="cleanup-emergency" role="alert" aria-live="assertive">
      <div>
        <strong>UNRESOLVED CLEANUP — TARGET STATE MAY STILL BE MODIFIED</strong>
        <p>RouteCairn cannot prove that every controlled mutation was restored. Stop new mutation work and perform explicit recovery for each case below.</p>
      </div>
      <span>{status.cleanupRequired} OPERATOR ACTION{status.cleanupRequired === 1 ? "" : "S"} REQUIRED</span>
    </div>}
    <div className="cards">
      <div className={`metric ${status?.globalMutationActive ? "danger-metric" : ""}`}><strong>{status?.globalMutationActive ? "BLOCKED" : "IDLE"}</strong><span>New mutation execution</span></div>
      <div className="metric"><strong>{status?.cleanupRequired ?? 0}</strong><span>Cleanup obligations</span></div>
      <div className="metric"><strong>{status?.modes?.CONTROLLED_MUTATION ?? "Loading"}</strong><span>Controlled mutation</span></div>
    </div>
    <div className="table compact-table">
      <div className="row cleanup-row head"><span>Case</span><span>Stage</span><span>Recovery</span><span>Warning</span><span>Updated</span></div>
      {(status?.cases ?? []).map((item: any) => <div className="row cleanup-row" key={`${item.journalId}:${item.caseId}`}>
        <span><strong>{item.caseId}</strong><small>{item.targetOrigin ?? "Target origin encrypted or unavailable"}</small></span>
        <span><Badge value={item.stage} /></span>
        <span><Badge value={item.recoveryBundleAvailable ? "AVAILABLE" : "MISSING"} /></span>
        <span className="cleanup-warning">{item.warning}</span>
        <span>{item.timestamp}</span>
      </div>)}
    </div>
    {status && status.cases.length === 0 && <EmptyState text="No unresolved controlled-mutation cleanup obligations were discovered across registered journal directories." />}
    <WorkflowRecoveryPanel />
  </section>;
}

function ControlledMutationWorkspace() {
  const [targets, setTargets] = useState<TargetSummary[]>([]); const [targetId, setTargetId] = useState(""); const [caseId, setCaseId] = useState(""); const [planIdentity, setPlanIdentity] = useState(""); const [authorizationDeclaration, setAuthorizationDeclaration] = useState(""); const [expiresAt, setExpiresAt] = useState(""); const [approval, setApproval] = useState<any>(); const [message, setMessage] = useState("");
  useEffect(() => { void apiGet<{ targets: TargetSummary[] }>("/api/targets").then((body) => { setTargets(body.targets); if (body.targets[0]) setTargetId(body.targets[0].id); }).catch((cause: unknown) => setMessage(errorText(cause))); }, []);
  const selected = targets.find((target) => target.id === targetId);
  const preview = async () => { if (!selected) throw new Error("Select a registered target."); const result = await apiMutation<{ approval: any }>("/api/controlled-mutations/approvals", "POST", { caseId, targetId, targetOrigin: selected.baseOrigin, planIdentity, authorizationDeclaration, expiresAt: new Date(expiresAt).toISOString(), confirmation: "I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY" }); setApproval(result.approval); setMessage("Exact approval preview persisted."); };
  const approve = async () => { if (!approval) return; const result = await apiMutation<{ approval: any }>(`/api/controlled-mutations/approvals/${approval.id}/approve`, "POST", {}); setApproval(result.approval); setMessage("Case approved. Worker execution remains contract-bound."); };
  useEffect(() => { if (!approval?.recoveryJobId || ["COMPLETED", "CLEANUP_FAILED"].includes(approval.status)) return; const load = () => void apiGet<{ recoveryJob: any }>(`/api/controlled-mutations/recovery/${approval.recoveryJobId}`).then((body) => setApproval(body.recoveryJob)).catch((cause: unknown) => setMessage(errorText(cause))); load(); const timer = window.setInterval(load, 2000); return () => window.clearInterval(timer); }, [approval?.recoveryJobId]);
  return <section><Header title="Controlled Mutation Workspace" subtitle="Explicit privilege-boundary cases with approval, expiry, and cleanup visibility." /><div className="cleanup-emergency" role="note"><div><strong>Deletion tiers unavailable</strong><p>Only reversible, operator-supplied mutations are eligible. Raw bodies and credentials are never entered here.</p></div><span>OWNER APPROVAL REQUIRED</span></div><form className="form" onSubmit={(event) => { event.preventDefault(); void preview().catch((cause: unknown) => setMessage(errorText(cause))); }}><label>Registered target<select value={targetId} onChange={(event) => setTargetId(event.target.value)}><option value="">Select target</option>{targets.map((target) => <option key={target.id} value={target.id}>{target.displayName} · {target.baseOrigin}</option>)}</select></label><label>Exact case ID<input value={caseId} onChange={(event) => setCaseId(event.target.value)} placeholder="role-boundary-001" /></label><label>Redacted plan identity<input value={planIdentity} onChange={(event) => setPlanIdentity(event.target.value)} placeholder="64-character plan hash" /></label><label>Authorization declaration<textarea value={authorizationDeclaration} onChange={(event) => setAuthorizationDeclaration(event.target.value)} placeholder="Owned staging environment and disposable target authorized for this case." /></label><label>Authorization expiry<input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label><button className="primary" disabled={!targetId || !caseId || planIdentity.length !== 64 || authorizationDeclaration.length < 20 || !expiresAt}>Create exact preview</button></form>{message && <p aria-live="polite">{message}</p>}<h3>Execution timeline</h3><div className="table compact-table"><div className="row cleanup-row head"><span>Case</span><span>Target</span><span>Plan</span><span>Status</span><span>Action</span></div>{approval && <div className="row cleanup-row"><span><strong>{approval.caseId}</strong><small>{approval.authorizationSummary}</small></span><span>{approval.targetOrigin}</span><span><code>{approval.planIdentity}</code></span><span><Badge value={approval.status} /><small>Expires {approval.expiresAt}</small>{approval.recoveryErrorSummary && <small className="error">{approval.recoveryErrorSummary}</small>}</span><span>{approval.status === "PREVIEWED" ? <button onClick={() => void approve().catch((cause: unknown) => setMessage(errorText(cause)))}>Approve case</button> : approval.status === "EXECUTING" ? <span>Recovery executing</span> : approval.status === "COMPLETED" ? <span>Rollback verified</span> : approval.status === "CLEANUP_FAILED" ? <span>Operator recovery required</span> : <span>Awaiting execution</span>}</span></div>}</div>{!approval && <EmptyState text="No mutation case previewed in this session." />}</section>;
}

function Login(props: { onLogin: (principal: unknown) => void }) {
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  return (
    <main className="center">
      <form className="login-panel" onSubmit={(event) => {
        event.preventDefault();
        void fetch("/api/auth/login", {
          method: "POST",
          headers: { "content-type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ login, password })
        })
          .then(async (response) => {
            if (!response.ok) throw new Error("Login failed.");
            return (await response.json()) as { csrfToken: string; user: unknown };
          })
          .then((body) => {
            setCsrfToken(body.csrfToken);
            setPassword("");
            props.onLogin(body.user);
          })
          .catch(() => setMessage("Invalid username or password, or login is temporarily rate limited."));
      }}>
        <h1>RouteCairn</h1>
        <label>Username or email<input autoComplete="username" value={login} onChange={(event) => setLogin(event.target.value)} /></label>
        <label>Password<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        <button>Log In</button>
        {message && <p className="error">{message}</p>}
      </form>
    </main>
  );
}

function Overview(props: { onOpenScan: (id: string) => void }) {
  const [overview, setOverview] = useState<any>();
  useEffect(() => {
    const load = () => void apiGet<any>("/api/overview").then(setOverview);
    load();
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, []);
  if (!overview) return <section><Header title="Overview" subtitle="Loading dashboard totals." /><EmptyState text="Loading..." /></section>;
  const cards = [
    ["Total scans", overview.scans.total],
    ["Queued", overview.scans.queued],
    ["Running", overview.scans.running],
    ["Completed", overview.scans.completed],
    ["Failed", overview.scans.failed],
    ["Interrupted", overview.scans.interrupted],
    ["Open findings", overview.findings.open],
    ["Unreviewed", overview.findings.unreviewed],
    ["Confirmed", overview.findings.confirmed],
    ["False positives", overview.findings.falsePositive],
    ["Accepted risks", overview.findings.acceptedRisk],
    ["Resolved", overview.findings.resolved],
    ["Reopened", overview.findings.reopened]
  ];
  return (
    <section>
      <Header title="Overview" subtitle="Persisted scan and triage totals from SQLite." />
      <div className="cards">{cards.map(([label, value]) => <div className="metric" key={label}><strong>{value}</strong><span>{label}</span></div>)}</div>
      <h3>Recent Scans</h3>
      <ScanTable scans={overview.recentScans ?? []} onOpenScan={props.onOpenScan} />
    </section>
  );
}

function Projects(props: { onOpen(id: string): void }) {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [editing, setEditing] = useState<ProjectSummary>();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [defaultProfile, setDefaultProfile] = useState("quick");
  const [defaultScope, setDefaultScope] = useState("{}");
  const [query, setQuery] = useState("");
  const [includeArchived, setIncludeArchived] = useState(false);
  const [message, setMessage] = useState("");
  const load = () => void apiGet<{ projects: ProjectSummary[] }>(`/api/projects?q=${encodeURIComponent(query)}&includeArchived=${includeArchived}`).then((body) => setProjects(body.projects));
  useEffect(load, [query, includeArchived]);
  const clear = () => { setEditing(undefined); setName(""); setDescription(""); setTags(""); setDefaultProfile("quick"); setDefaultScope("{}"); };
  const select = (project: ProjectSummary) => { setEditing(project); setName(project.name); setDescription(project.description ?? ""); setTags(project.tags.join(", ")); setDefaultProfile(project.defaultProfile ?? "quick"); setDefaultScope(JSON.stringify(project.defaultScope ?? {}, null, 2)); };
  const save = async () => {
    const body = { name, description, defaultProfile, tags: tags.split(",").map((value) => value.trim()).filter(Boolean), defaultScope: JSON.parse(defaultScope || "{}"), ...(editing ? { expectedVersion: editing.rowVersion } : {}) };
    if (editing) await apiMutation(`/api/projects/${editing.id}`, "PATCH", body); else await apiMutation("/api/projects", "POST", body);
    setMessage(editing ? "Project saved." : "Project created."); clear(); load();
  };
  return (
    <section>
      <Header title="Projects" subtitle="Organize authorized targets, scans, findings, and proof work." />
      <div className="toolbar"><input aria-label="Search projects" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search projects" /><label className="inline-check"><input type="checkbox" checked={includeArchived} onChange={(event) => setIncludeArchived(event.target.checked)} /> Include archived</label></div>
      <form className="form" onSubmit={(event) => event.preventDefault()}>
        <label>Project name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Client portal assessment" /></label>
        <label>Description<textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Safe operator notes only" /></label>
        <label>Tags<input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="client, production, retest" /></label>
        <label>Default profile<select value={defaultProfile} onChange={(event) => setDefaultProfile(event.target.value)}><option>quick</option><option>full</option><option>authenticated</option><option>monitor</option><option>proof</option></select></label>
        <label>Default scope JSON<textarea className="code-input" value={defaultScope} onChange={(event) => setDefaultScope(event.target.value)} spellCheck={false} /></label>
        <div className="actions"><button className="primary" disabled={!name.trim()} onClick={() => void save().catch((cause: unknown) => setMessage(errorText(cause)))}>{editing ? "Save Project" : "Create Project"}</button>{editing && <button onClick={clear}>Cancel Edit</button>}</div>
      </form>
      {message && <p aria-live="polite">{message}</p>}
      <div className="table compact-table">
        <div className="row project-row head"><span>Project</span><span>Targets</span><span>Scans</span><span>Open Findings</span><span>Actions</span></div>
        {projects.map((project) => (
          <div className="row project-row" key={project.id}>
            <span><strong>{project.name}</strong>{project.archived && <Badge value="ARCHIVED" />}<small>{project.description ?? "No description"} · {project.defaultProfile ?? "no default profile"} · {project.tags.join(", ") || "no tags"}</small></span>
            <span>{project.targetCount}</span>
            <span>{project.scanCount}</span>
            <span>{project.openFindingCount}</span>
            <span className="actions">{!project.archived && <button onClick={() => props.onOpen(project.id)}>Open Security</button>}{!project.archived && <button onClick={() => select(project)}>Edit</button>}<button onClick={() => window.confirm(`${project.archived ? "Restore" : "Archive"} this project?`) && void apiMutation(`/api/projects/${project.id}/${project.archived ? "restore" : "archive"}`, "POST", {}).then(load).catch((cause: unknown) => setMessage(errorText(cause)))}>{project.archived ? "Restore" : "Archive"}</button></span>
          </div>
        ))}
      </div>
      {projects.length === 0 && <EmptyState text="No projects yet. Create one to group authorized targets." />}
    </section>
  );
}

function Targets(props: { onOpen(id: string): void }) {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [configurations, setConfigurations] = useState<any[]>([]);
  const [credentialProfiles, setCredentialProfiles] = useState<any[]>([]);
  const [editing, setEditing] = useState<TargetSummary>();
  const [projectId, setProjectId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [baseOrigin, setBaseOrigin] = useState("");
  const [authorizationType, setAuthorizationType] = useState("OWNED");
  const [authorizationSummary, setAuthorizationSummary] = useState("");
  const [classification, setClassification] = useState("UNKNOWN");
  const [defaultProfile, setDefaultProfile] = useState("quick");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [defaultEvidenceLevel, setDefaultEvidenceLevel] = useState("normal");
  const [defaultConfigurationId, setDefaultConfigurationId] = useState("");
  const [defaultCredentialProfileId, setDefaultCredentialProfileId] = useState("");
  const [approvedScope, setApprovedScope] = useState("{}");
  const [defaultAuthTemplate, setDefaultAuthTemplate] = useState("{}");
  const [query, setQuery] = useState("");
  const [includeArchived, setIncludeArchived] = useState(false);
  const [message, setMessage] = useState("");
  const load = () => {
    void apiGet<{ projects: ProjectSummary[] }>("/api/projects").then((body) => setProjects(body.projects));
    void apiGet<{ targets: TargetSummary[] }>(`/api/targets?q=${encodeURIComponent(query)}&includeArchived=${includeArchived}`).then((body) => setTargets(body.targets));
    void apiGet<any>("/api/configurations").then((body) => setConfigurations(body.configurations ?? [])).catch(() => setConfigurations([]));
    void apiGet<any>("/api/credential-profiles").then((body) => setCredentialProfiles(body.profiles ?? [])).catch(() => setCredentialProfiles([]));
  };
  useEffect(load, [query, includeArchived]);
  const clear = () => { setEditing(undefined); setDisplayName(""); setBaseOrigin(""); setDescription(""); setTags(""); setAuthorizationSummary(""); setDefaultConfigurationId(""); setDefaultCredentialProfileId(""); setApprovedScope("{}"); setDefaultAuthTemplate("{}"); };
  const select = (target: TargetSummary) => { setEditing(target); setProjectId(target.projectId ?? ""); setDisplayName(target.displayName); setBaseOrigin(target.baseOrigin); setDescription(target.description ?? ""); setTags(target.tags.join(", ")); setAuthorizationType(target.authorizationType); setAuthorizationSummary(target.authorizationSummary); setClassification(target.classification); setDefaultProfile(target.defaultProfile ?? "quick"); setDefaultEvidenceLevel(target.defaultEvidenceLevel ?? "normal"); setDefaultConfigurationId(target.defaultConfigurationId ?? ""); setDefaultCredentialProfileId(target.defaultCredentialProfileId ?? ""); setApprovedScope(JSON.stringify(target.approvedScope ?? {}, null, 2)); setDefaultAuthTemplate(JSON.stringify(target.defaultAuthTemplate ?? {}, null, 2)); };
  const save = async () => {
    const body = { projectId: projectId || undefined, displayName, baseOrigin, description, tags: tags.split(",").map((value) => value.trim()).filter(Boolean), authorizationType, authorizationSummary, classification, defaultProfile, defaultEvidenceLevel, defaultConfigurationId: defaultConfigurationId || undefined, defaultCredentialProfileId: defaultCredentialProfileId || undefined, defaultAuthTemplate: JSON.parse(defaultAuthTemplate || "{}"), approvedScope: JSON.parse(approvedScope || "{}"), ...(editing ? { expectedVersion: editing.rowVersion } : {}) };
    if (editing) await apiMutation(`/api/targets/${editing.id}`, "PATCH", body); else await apiMutation("/api/targets", "POST", body);
    setMessage(editing ? "Target saved. Base origin remains immutable." : "Target created."); clear(); load();
  };
  return (
    <section>
      <Header title="Targets" subtitle="Approved origins and authorization declarations for dashboard scans." />
      <div className="toolbar"><input aria-label="Search targets" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search targets" /><label className="inline-check"><input type="checkbox" checked={includeArchived} onChange={(event) => setIncludeArchived(event.target.checked)} /> Include archived</label></div>
      <form className="form" onSubmit={(event) => event.preventDefault()}>
        <label>Project<select value={projectId} onChange={(event) => setProjectId(event.target.value)}><option value="">Ad hoc or no project</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>
        <label>Display name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="Production client portal" /></label>
        <label>Base origin<input value={baseOrigin} disabled={Boolean(editing)} onChange={(event) => setBaseOrigin(event.target.value)} placeholder="https://app.example.com" /><small>{editing ? "Stable target identity: origin changes require a controlled migration." : "Origin is immutable after creation."}</small></label>
        <label>Description<textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Safe target notes" /></label>
        <label>Tags<input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="production, api" /></label>
        <label>Authorization type<select value={authorizationType} onChange={(event) => setAuthorizationType(event.target.value)}><option>OWNED</option><option>CLIENT_AUTHORIZED</option><option>BUG_BOUNTY</option><option>CONTROLLED_LAB</option><option>OTHER_AUTHORIZED</option></select></label>
        <label>Authorization summary<textarea value={authorizationSummary} onChange={(event) => setAuthorizationSummary(event.target.value)} placeholder="Describe the permission boundary for this target." /></label>
        <label>Classification<select value={classification} onChange={(event) => setClassification(event.target.value)}><option>UNKNOWN</option><option>PUBLIC</option><option>PRIVATE</option><option>LOCAL</option></select></label>
        <label>Default profile<select value={defaultProfile} onChange={(event) => setDefaultProfile(event.target.value)}><option>quick</option><option>full</option><option>authenticated</option><option>monitor</option><option>proof</option></select></label>
        <label>Default evidence<select value={defaultEvidenceLevel} onChange={(event) => setDefaultEvidenceLevel(event.target.value)}><option>minimal</option><option>normal</option><option>strong</option></select></label>
        <label>Default configuration<select value={defaultConfigurationId} onChange={(event) => setDefaultConfigurationId(event.target.value)}><option value="">Use project/global defaults</option>{configurations.map((config) => <option key={config.id} value={config.id}>{config.name} · v{config.currentVersion}</option>)}</select></label>
        <label>Default credential profile<select value={defaultCredentialProfileId} onChange={(event) => setDefaultCredentialProfileId(event.target.value)}><option value="">No saved credential default</option>{credentialProfiles.filter(credentialUsable).map((profile) => <option key={profile.id} value={profile.id}>{profile.safeAlias} · {profile.health?.classification ?? "UNVERIFIED"}</option>)}</select></label>
        <label>Approved scope JSON<textarea className="code-input" value={approvedScope} onChange={(event) => setApprovedScope(event.target.value)} spellCheck={false} /></label>
        <label>Safe auth template JSON<textarea className="code-input" value={defaultAuthTemplate} onChange={(event) => setDefaultAuthTemplate(event.target.value)} spellCheck={false} /></label>
        <div className="actions"><button className="primary" disabled={!displayName.trim() || !baseOrigin || authorizationSummary.trim().length < 12} onClick={() => void save().catch((cause: unknown) => setMessage(errorText(cause)))}>{editing ? "Save Target" : "Create Target"}</button>{editing && <button onClick={clear}>Cancel Edit</button>}</div>
      </form>
      {message && <p>{message}</p>}
      <div className="table compact-table">
        <div className="row target-row head"><span>Target</span><span>Authorization</span><span>Profile</span><span>Scans</span><span>Actions</span></div>
        {targets.map((target) => (
          <div className="row target-row" key={target.id}>
            <span><strong>{target.displayName}</strong>{target.archived && <Badge value="ARCHIVED" />}<small>{target.baseOrigin} · {target.classification} · {target.tags.join(", ") || "no tags"}</small></span>
            <span><Badge value={target.authorizationType} /><small>{target.authorizationSummary}</small></span>
            <span>{target.defaultProfile ?? "none"}</span>
            <span>{target.scanCount}</span>
            <span className="actions">{!target.archived && <button onClick={() => props.onOpen(target.id)}>Open Security</button>}{!target.archived && <button onClick={() => select(target)}>Edit</button>}<button onClick={() => window.confirm(`${target.archived ? "Restore" : "Archive"} this target?`) && void apiMutation(`/api/targets/${target.id}/${target.archived ? "restore" : "archive"}`, "POST", {}).then(load).catch((cause: unknown) => setMessage(errorText(cause)))}>{target.archived ? "Restore" : "Archive"}</button></span>
          </div>
        ))}
      </div>
      {targets.length === 0 && <EmptyState text="No targets yet. Add an authorized origin before repeat scans." />}
    </section>
  );
}

interface FindingIntelligence {
  totalOpen: number; unreviewed: number; confirmed: number; reopened: number; acceptedRisk: number; falsePositive: number;
  resolved: number; fixedPendingRetest: number; fixedVerified: number;
  severity: Record<string, number>; remediation: Record<string, number>;
  byModule: Array<{ label: string; count: number }>;
  byTarget: Array<{ id?: string; label: string; count: number }>;
  recentOccurrences: Array<Record<string, unknown>>;
  recentReviews: Array<Record<string, unknown>>;
  retestNeeded: FindingSummary[];
  proofReady: FindingSummary[];
  firstLast: { first_seen_at?: string; last_seen_at?: string };
}

export function ProjectDetail(props: { projectId: string; onFindings(filters: Record<string, string>): void; onTarget(id: string): void }) {
  const [detail, setDetail] = useState<{ project: ProjectSummary; targets: TargetSummary[]; comparisons: Array<Record<string, unknown>>; findingIntelligence: FindingIntelligence }>();
  useEffect(() => { void apiGet<typeof detail>(`/api/projects/${props.projectId}`).then(setDetail); }, [props.projectId]);
  if (!detail) return <EmptyState text="Loading project security intelligence..." />;
  const base = { projectId: props.projectId };
  return <section><Header title={detail.project.name} subtitle="Project security posture from the Findings Command Center." /><FindingIntelligencePanel intelligence={detail.findingIntelligence} base={base} onFindings={props.onFindings} />
    <div className="detail-grid"><section><h3>Affected Targets</h3>{detail.targets.length ? <ul className="safe-object-list">{detail.targets.map((target) => <li key={target.id}><button className="link" onClick={() => props.onTarget(target.id)}>{target.displayName}</button><span>{target.openFindingCount} active findings</span></li>)}</ul> : <p className="muted">No targets are assigned to this project.</p>}</section><ComparisonTimeline title="Project regression intelligence" comparisons={detail.comparisons} /><ActivityList title="Recent Review Activity" values={detail.findingIntelligence.recentReviews} /></div>
  </section>;
}

export function TargetDetail(props: { targetId: string; onFindings(filters: Record<string, string>): void; onScan(): void }) {
  const [detail, setDetail] = useState<{ target: TargetSummary; comparisons: Array<Record<string, unknown>>; findingIntelligence: FindingIntelligence }>();
  useEffect(() => { void apiGet<typeof detail>(`/api/targets/${props.targetId}`).then(setDetail); }, [props.targetId]);
  if (!detail) return <EmptyState text="Loading target security intelligence..." />;
  const base = { targetId: props.targetId };
  return <section><Header title={detail.target.displayName} subtitle={detail.target.baseOrigin} /><div className="actions"><button className="primary" onClick={() => props.onFindings(base)}>Review Findings</button><button onClick={props.onScan}>Start New Scan</button><button onClick={() => props.onFindings({ ...base, remediation: "FIXED_PENDING_RETEST" })}>Retest Findings</button></div><FindingIntelligencePanel intelligence={detail.findingIntelligence} base={base} onFindings={props.onFindings} />
    <div className="detail-grid"><ComparisonTimeline title="Regression timeline" comparisons={detail.comparisons} /><ActivityList title="Recent Occurrences" values={detail.findingIntelligence.recentOccurrences} /><section><h3>Retest Needed</h3>{detail.findingIntelligence.retestNeeded.length ? detail.findingIntelligence.retestNeeded.map((finding) => <button className="link stacked" key={finding.id} onClick={() => props.onFindings({ ...base, remediation: "FIXED_PENDING_RETEST" })}>{finding.title}</button>) : <p className="muted">No findings are waiting for compatible retest coverage.</p>}</section></div>
  </section>;
}

function FindingIntelligencePanel(props: { intelligence: FindingIntelligence; base: Record<string, string>; onFindings(filters: Record<string, string>): void }) {
  const metrics: Array<[string, number, Record<string, string>]> = [
    ["Active", props.intelligence.totalOpen, {}], ["Unreviewed", props.intelligence.unreviewed, { review: "UNREVIEWED" }],
    ["Confirmed", props.intelligence.confirmed, { review: "CONFIRMED" }], ["Reopened", props.intelligence.reopened, { review: "REOPENED" }],
    ["Accepted risk", props.intelligence.acceptedRisk, { review: "ACCEPTED_RISK" }], ["False positives", props.intelligence.falsePositive, { review: "FALSE_POSITIVE" }],
    ["Resolved", props.intelligence.resolved, { review: "RESOLVED" }], ["Pending retest", props.intelligence.fixedPendingRetest, { remediation: "FIXED_PENDING_RETEST" }],
    ["Fixed verified", props.intelligence.fixedVerified, { remediation: "FIXED_VERIFIED" }]
  ];
  return <><div className="cards security-metrics">{metrics.map(([label, value, filter]) => <button className="metric" aria-label={`${value} ${label}`} key={label} onClick={() => props.onFindings({ ...props.base, ...filter })}><strong>{value}</strong><span>{label}</span></button>)}</div><div className="detail-grid"><Distribution title="Severity Distribution" values={props.intelligence.severity} onSelect={(severity) => props.onFindings({ ...props.base, severity })} /><Distribution title="Remediation Distribution" values={props.intelligence.remediation} onSelect={(remediation) => props.onFindings({ ...props.base, remediation })} /><Distribution title="Findings by Module" values={Object.fromEntries(props.intelligence.byModule.map((item) => [item.label, item.count]))} onSelect={(module) => props.onFindings({ ...props.base, module })} /><ActivityList title="Recent Occurrences" values={props.intelligence.recentOccurrences} /></div></>;
}

function Distribution(props: { title: string; values: Record<string, number>; onSelect(value: string): void }) { return <section><h3>{props.title}</h3><ul className="distribution-list">{Object.entries(props.values).map(([label, count]) => <li key={label}><button className="link" onClick={() => props.onSelect(label)}>{label}</button><strong>{count}</strong></li>)}</ul></section>; }
function ActivityList(props: { title: string; values: Array<Record<string, unknown>> }) { return <section><h3>{props.title}</h3>{props.values.length ? <ul className="timeline">{props.values.map((item, index) => <li key={String(item.id ?? index)}><strong>{String(item.title ?? item.new_review_status ?? "Activity")}</strong><small>{String(item.actor_label ?? item.severity ?? "")}</small><time>{String(item.created_at ?? "")}</time></li>)}</ul> : <p className="muted">No finding activity yet.</p>}</section>; }
function ComparisonTimeline(props: { title: string; comparisons?: Array<Record<string, unknown>> }) { const comparisons = props.comparisons ?? []; return <section><h3>{props.title}</h3>{comparisons.length ? <ul className="timeline">{comparisons.map((item) => { const summary = typeof item.summaryJson === "string" ? JSON.parse(item.summaryJson) as Record<string, number> : {}; return <li key={String(item.id)}><strong>{String(item.olderScanId).slice(0, 8)} → {String(item.newerScanId).slice(0, 8)}</strong><small>{summary.new ?? 0} new · {summary.resolved ?? 0} resolved · {summary.regressions ?? 0} regressions · {summary.notRetested ?? 0} not retested</small><time>{String(item.createdAt ?? "")}</time></li>; })}</ul> : <p className="muted">No persisted comparisons yet.</p>}</section>; }

function ScanOverview(props: { onOpenScan: (id: string) => void }) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  useEffect(() => {
    const load = () => void apiGet<{ scans: ScanSummary[] }>(`/api/scans?q=${encodeURIComponent(query)}&status=${encodeURIComponent(status)}`).then((body) => setScans(body.scans)).catch((cause: unknown) => setError(errorText(cause)));
    load();
    const timer = window.setInterval(load, 2000);
    return () => window.clearInterval(timer);
  }, [query, status]);
  return (
    <section>
      <Header title="Scan History" subtitle="Durable local history backed by SQLite." />
      <div className="toolbar"><input aria-label="Search scans" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search scans" /><select aria-label="Scan status" value={status} onChange={(event) => setStatus(event.target.value)}><option value="">Any status</option><option>QUEUED</option><option>RUNNING</option><option>COMPLETED</option><option>FAILED</option><option>CANCELLED</option><option>INTERRUPTED</option><option>IMPORTED</option></select></div>
      {error && <p className="error">{error}</p>}
      {scans.length === 0 ? <EmptyState text="No dashboard scans yet." /> : <ScanTable scans={scans} onOpenScan={props.onOpenScan} />}
    </section>
  );
}

function ScanTable(props: { scans: ScanSummary[]; onOpenScan: (id: string) => void }) {
  return (
    <div className="table scan-table">
      <div className="row head"><span>Scan</span><span>Status</span><span>Progress</span><span>Findings</span><span>Current Module</span><span>Actions</span></div>
      {props.scans.map((scan) => (
        <div className="row scan-row" key={scan.id}>
          <span data-label="Scan"><button className="link" onClick={() => props.onOpenScan(scan.id)}>{scan.target}</button><small>{scan.profile} · {scan.shortId} · {scan.startedAt ?? scan.createdAt}</small></span>
          <span data-label="Status"><Badge value={scan.status} /></span>
          <span data-label="Progress"><progress value={scan.progressPercent} max={100} /> {scan.progressPercent}%</span>
          <span data-label="Findings">{scan.findingCount}</span>
          <span data-label="Current Module">{scan.currentModule ?? "idle"}</span>
          <span className="actions compact" data-label="Actions">
            <button onClick={() => void apiMutation(`/api/scans/${scan.id}/cancel`, "POST", {}).catch(console.error)} disabled={!["QUEUED", "RUNNING", "PLANNING", "CANCEL_REQUESTED"].includes(scan.status)}>Cancel</button>
            <button onClick={() => void apiMutation(`/api/scans/${scan.id}/rerun`, "POST", {}).catch(console.error)}>Re-run</button>
            <button onClick={() => window.confirm("Archive this scan?") && void apiMutation(`/api/scans/${scan.id}/archive`, "POST", {}).then(() => location.reload()).catch(console.error)}>Archive</button>
            <button onClick={() => window.confirm("Delete this scan metadata?") && void apiMutation(`/api/scans/${scan.id}/delete`, "POST", {}).then(() => location.reload()).catch(console.error)}>Delete</button>
          </span>
        </div>
      ))}
    </div>
  );
}

function LegacyNewScanRemoved() {
  const [target, setTarget] = useState("");
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [projectId, setProjectId] = useState("");
  const [targetId, setTargetId] = useState("");
  const [authorizationDeclaration, setAuthorizationDeclaration] = useState("");
  const [scopeFile, setScopeFile] = useState("examples/scope.example.json");
  const [profile, setProfile] = useState("quick");
  const [authFile, setAuthFile] = useState("");
  const [authAFile, setAuthAFile] = useState("");
  const [authBFile, setAuthBFile] = useState("");
  const [credentialProfileId, setCredentialProfileId] = useState("");
  const [credentialProfileAId, setCredentialProfileAId] = useState("");
  const [credentialProfileBId, setCredentialProfileBId] = useState("");
  const [credentialProfiles, setCredentialProfiles] = useState<any[]>([]);
  const [rateLimitPerSecond, setRateLimitPerSecond] = useState("4");
  const [concurrency, setConcurrency] = useState("3");
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [capabilities, setCapabilities] = useState<any>();
  const [preview, setPreview] = useState<PlanPreview | undefined>();
  const [message, setMessage] = useState("");
  useEffect(() => {
    void apiGet<any>("/api/capabilities").then(setCapabilities);
    void apiGet<{ projects: ProjectSummary[] }>("/api/projects").then((body) => setProjects(body.projects));
    void apiGet<{ targets: TargetSummary[] }>("/api/targets").then((body) => setTargets(body.targets));
    void apiGet<{ profiles: any[] }>("/api/credential-profiles").then((body) => setCredentialProfiles(body.profiles)).catch(() => setCredentialProfiles([]));
  }, []);
  const selectedTarget = targets.find((item) => item.id === targetId);
  useEffect(() => {
    if (!selectedTarget) return;
    setTarget(selectedTarget.baseOrigin);
    setProjectId(selectedTarget.projectId ?? "");
    setAuthorizationDeclaration(`${selectedTarget.authorizationType}: ${selectedTarget.authorizationSummary}`);
    if (selectedTarget.defaultProfile) setProfile(selectedTarget.defaultProfile);
  }, [selectedTarget]);
  const body = useMemo(() => ({
    target,
    scopeFile,
    profile,
    ...(projectId ? { projectId } : {}),
    ...(targetId ? { targetId } : {}),
    ...(authorizationDeclaration ? { authorizationDeclaration } : {}),
    ...(authFile ? { authFile } : {}),
    ...(authAFile ? { authAFile } : {}),
    ...(authBFile ? { authBFile } : {}),
    ...(credentialProfileId ? { credentialProfileId } : {}),
    ...(credentialProfileAId ? { credentialProfileAId } : {}),
    ...(credentialProfileBId ? { credentialProfileBId } : {}),
    ...(Number(rateLimitPerSecond) > 0 ? { rateLimitPerSecond: Number(rateLimitPerSecond) } : {}),
    ...(Number(concurrency) > 0 ? { concurrency: Number(concurrency) } : {}),
    ...(selectedModules.length > 0 ? { includeModules: selectedModules } : {})
  }), [target, scopeFile, profile, projectId, targetId, authorizationDeclaration, authFile, authAFile, authBFile, credentialProfileId, credentialProfileAId, credentialProfileBId, rateLimitPerSecond, concurrency, selectedModules]);
  return (
    <section>
      <Header title="Scan Builder" subtitle="Configure, preview, and launch through the real RouteCairn planner." />
      <form className="builder" onSubmit={(event) => event.preventDefault()}>
        <fieldset><legend>1. Project and Target</legend><label>Project<select value={projectId} onChange={(event) => setProjectId(event.target.value)}><option value="">Ad hoc or no project</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label><label>Saved target<select value={targetId} onChange={(event) => setTargetId(event.target.value)}><option value="">Ad hoc target</option>{targets.filter((item) => !projectId || item.projectId === projectId).map((item) => <option key={item.id} value={item.id}>{item.displayName} · {item.baseOrigin}</option>)}</select></label><label>Target URL<input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://app.local.test" /></label><label>Authorization declaration<textarea value={authorizationDeclaration} onChange={(event) => setAuthorizationDeclaration(event.target.value)} placeholder="Describe why this scan is authorized." /></label><label><input type="checkbox" required /> I am authorized to assess this target and scope.</label></fieldset>
        <fieldset><legend>2. Scope</legend><label>Scope JSON file<input value={scopeFile} onChange={(event) => setScopeFile(event.target.value)} /></label><p className="muted">Guided scope editing is still file-backed; launch always revalidates through planner scope validation.</p></fieldset>
        <fieldset><legend>3. Profile</legend><label>Profile<select value={profile} onChange={(event) => setProfile(event.target.value)}><option>quick</option><option>full</option><option>authenticated</option><option>monitor</option><option>proof</option></select></label>{capabilities?.profiles?.map((item: any) => item.name === profile ? <p key={item.name}>{item.description}</p> : null)}</fieldset>
        <fieldset><legend>4. Modules</legend><div className="module-grid">{capabilities?.modules?.map((module: any) => <label className="module-option" key={module.id}><input type="checkbox" checked={selectedModules.includes(module.id)} onChange={(event) => setSelectedModules((current) => event.target.checked ? [...current, module.id] : current.filter((id) => id !== module.id))} /><strong>{module.displayName}</strong><span>{module.phase} · {module.cost} · auth: {module.requiresAuthentication}</span><small>{module.description}</small></label>)}</div><p className="muted">Leave all unchecked to use the selected profile defaults.</p></fieldset>
        <fieldset><legend>5. Authentication</legend>
          <div className="grid two">
            <label>Saved credential profile<select value={credentialProfileId} onChange={(event) => { setCredentialProfileId(event.target.value); if (event.target.value) { setCredentialProfileAId(""); setCredentialProfileBId(""); setAuthFile(""); } }}><option value="">Public or file-backed</option>{credentialProfiles.filter(credentialUsable).map((item) => <option key={item.id} value={item.id}>{item.safeAlias} · {item.credentialTypeSummary} · {item.health?.classification ?? "UNVERIFIED"}</option>)}</select></label>
            <label>Ephemeral auth profile file<input value={authFile} onChange={(event) => { setAuthFile(event.target.value); if (event.target.value) setCredentialProfileId(""); }} placeholder="Optional auth profile path" /></label>
            <label>Saved Account A<select value={credentialProfileAId} onChange={(event) => { setCredentialProfileAId(event.target.value); if (event.target.value) { setCredentialProfileId(""); setAuthAFile(""); } }}><option value="">No saved Account A</option>{credentialProfiles.filter(credentialUsable).map((item) => <option key={item.id} value={item.id}>{item.safeAlias} · {item.health?.classification ?? "UNVERIFIED"}</option>)}</select></label>
            <label>Saved Account B<select value={credentialProfileBId} onChange={(event) => { setCredentialProfileBId(event.target.value); if (event.target.value) { setCredentialProfileId(""); setAuthBFile(""); } }}><option value="">No saved Account B</option>{credentialProfiles.filter(credentialUsable).map((item) => <option key={item.id} value={item.id}>{item.safeAlias} · {item.health?.classification ?? "UNVERIFIED"}</option>)}</select></label>
            <label>Account A auth file<input value={authAFile} onChange={(event) => { setAuthAFile(event.target.value); if (event.target.value) setCredentialProfileAId(""); }} placeholder="Optional account A path" /></label>
            <label>Account B auth file<input value={authBFile} onChange={(event) => { setAuthBFile(event.target.value); if (event.target.value) setCredentialProfileBId(""); }} placeholder="Optional account B path" /></label>
          </div>
          <p className="muted">Saved credentials are referenced by UUID in scan rows. Plaintext is decrypted only for the assigned worker secret envelope and is never returned to the browser.</p>
        </fieldset>
        <fieldset><legend>6. Authorization Workflows</legend><p className="muted">Controlled workflow editors use existing schema-validated JSON files in this build. Guided case editors remain incomplete.</p></fieldset>
        <fieldset><legend>7. Browser Policy</legend><p className="muted">Browser module policy comes from profile/module settings and the resolved plan. Service workers, popups, downloads, uploads, and WebSockets remain blocked unless explicitly planned.</p></fieldset>
        <fieldset><legend>8. Limits</legend><label>Rate limit / second<input type="number" min="1" max="50" value={rateLimitPerSecond} onChange={(event) => setRateLimitPerSecond(event.target.value)} /></label><label>Concurrency<input type="number" min="1" max="50" value={concurrency} onChange={(event) => setConcurrency(event.target.value)} /></label></fieldset>
        <fieldset><legend>9. Evidence</legend><p className="muted">Evidence level is resolved by the selected profile and shown in plan preview before launch.</p></fieldset>
        <div className="actions">
          <button onClick={() => void apiMutation<PlanPreview>("/api/scans/plan-preview", "POST", body).then(setPreview).catch((cause: unknown) => setMessage(errorText(cause)))}>Preview Plan</button>
          <button onClick={() => void apiMutation<{ scanId: string }>("/api/scans", "POST", body).then((result) => setMessage(`Queued scan ${result.scanId.slice(0, 8)}`)).catch((cause: unknown) => setMessage(errorText(cause)))}>Queue Scan</button>
        </div>
      </form>
      {message && <p>{message}</p>}
      {preview && <pre className="code">{JSON.stringify(preview, null, 2)}</pre>}
    </section>
  );
}

function ScanDetail(props: { scanId: string; onReviewFindings: () => void; onRecovery: () => void }) {
  const [detail, setDetail] = useState<any>();
  useEffect(() => {
    if (!props.scanId) return;
    const load = () => void apiGet<any>(`/api/scans/${props.scanId}/detail`).then(setDetail);
    load();
    const timer = window.setInterval(load, detail?.scan?.status && ["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED", "IMPORTED"].includes(detail.scan.status) ? 10000 : 2000);
    return () => window.clearInterval(timer);
  }, [props.scanId, detail?.scan?.status]);
  if (!props.scanId) return <EmptyState text="Select a scan." />;
  if (!detail) return <EmptyState text="Loading scan detail." />;
  const requestBudget = [...detail.events].reverse().find((event: any) => event.eventType === "BUDGET_UPDATED")?.metadata;
  const browserNetwork = [...detail.events].reverse().find((event: any) => event.metadata?.kind === "BROWSER_NETWORK_BOUNDARY")?.metadata;
  return (
    <section>
      <Header title="Scan Detail" subtitle={`${detail.scan.target} · ${detail.scan.shortId}`} />
      <ScanCancellationNotice status={detail.scan.status} hasArtifacts={detail.artifacts.length > 0} onRecovery={props.onRecovery} />
      <button disabled={!["RUNNING", "PLANNING", "QUEUED"].includes(detail.scan.status)} onClick={() => void apiMutation(`/api/scans/${props.scanId}/cancel`, "POST", {}).then(() => apiGet<any>(`/api/scans/${props.scanId}/detail`)).then(setDetail)}>Cancel scan</button>
      <AssistedReviewPanel key={props.scanId} scanId={props.scanId} onReviewFindings={props.onReviewFindings} />
      <div className="cards"><div className="metric"><strong>{detail.scan.progressPercent}%</strong><span>Progress</span></div><div className="metric"><strong>{detail.modules.length}</strong><span>Modules</span></div><div className="metric"><strong>{detail.findings.length}</strong><span>Findings</span></div></div>
      {requestBudget && <>
        <h3>Scan-wide Request Ledger</h3>
        <div className="cards">
          <div className="metric"><strong>{requestBudget.totalTransmitted}/{requestBudget.maxRequests}</strong><span>Physical requests</span></div>
          <div className="metric"><strong>{requestBudget.scanRemaining}</strong><span>Ordinary remaining</span></div>
          <div className="metric"><strong>{requestBudget.cleanupRemaining}</strong><span>Cleanup reserve remaining</span></div>
        </div>
        <p className="muted">All engines, retries, redirects, browser traffic, and dedicated transports share this ledger. Ordinary traffic cannot consume cleanup capacity.</p>
      </>}
      <BrowserNetworkDiagnostics value={browserNetwork} />
      {detail.executablePlan && <>
        <h3>Immutable Execution Plan</h3>
        <div className="cards">
          <div className="metric"><strong>{detail.executablePlan.worker_verified_at ? "Verified" : "Pending"}</strong><span>Worker binding</span></div>
          <div className="metric"><strong>v{detail.executablePlan.schema_version}</strong><span>Snapshot format</span></div>
          <div className="metric"><strong>{String(detail.executablePlan.plan_binding).slice(0, 12)}</strong><span>Safe binding prefix</span></div>
        </div>
        <p className="muted">The reviewed executable plan is encrypted at enqueue, bound to this scan and target, and verified by the isolated worker before any scan request is sent.</p>
      </>}
      <h3>Module Timeline</h3><pre className="code">{JSON.stringify(detail.modules, null, 2)}</pre>
      <h3>Events</h3><pre className="code">{JSON.stringify(detail.events, null, 2)}</pre>
      <h3>Artifacts</h3>{detail.artifacts.map((artifact: any) => <p key={artifact.id}><a href={`/api/artifacts/${artifact.id}/download`}>{artifact.safe_display_name}</a> <small>{artifact.artifact_type}</small></p>)}
      <h3>Redacted Plan Snapshot</h3><pre className="code">{JSON.stringify(detail.planSnapshot ? JSON.parse(detail.planSnapshot.redacted_plan_json) : {}, null, 2)}</pre>
    </section>
  );
}

function Compare() {
  type Candidate = { id: string; shortId: string; target: string; targetId?: string; profile: string; status: string; source: string; createdAt: string; durationMs?: number; moduleCoverage: string; findingCount: number; compatibilityLabel: string };
  const [scans, setScans] = useState<Candidate[]>([]);
  const [oldScanId, setOldScanId] = useState("");
  const [newScanId, setNewScanId] = useState("");
  const [result, setResult] = useState<ComparisonResult>();
  const [error, setError] = useState("");
  useEffect(() => { void apiGet<{ scans: Candidate[] }>("/api/comparisons/candidates").then((body) => { setScans(body.scans); const compatible = body.scans.filter((scan) => ["COMPLETED", "IMPORTED"].includes(scan.status)); setNewScanId(compatible[0]?.id ?? ""); setOldScanId(compatible[1]?.id ?? ""); }); }, []);
  const option = (scan: Candidate) => `${scan.compatibilityLabel} · ${scan.target} · ${scan.profile} · ${scan.status} · ${scan.moduleCoverage} modules · ${scan.findingCount} findings · ${scan.shortId}`;
  return (
    <section>
      <Header title="Scan Comparison & Regression Intelligence" subtitle="Coverage-backed classification. Finding absence alone never proves resolution." />
      <form className="form compare-selectors" onSubmit={(event) => event.preventDefault()}>
        <label>Older scan<select aria-label="Older scan" value={oldScanId} onChange={(event) => setOldScanId(event.target.value)}>{scans.map((scan) => <option key={scan.id} value={scan.id}>{option(scan)}</option>)}</select></label>
        <label>Newer scan<select aria-label="Newer scan" value={newScanId} onChange={(event) => setNewScanId(event.target.value)}>{scans.map((scan) => <option key={scan.id} value={scan.id}>{option(scan)}</option>)}</select></label>
        <button disabled={!oldScanId || !newScanId || oldScanId === newScanId} onClick={() => void apiMutation<ComparisonResult>("/api/compare", "POST", { oldScanId, newScanId }).then((body) => { setResult(body); setError(""); }).catch((cause: unknown) => setError(errorText(cause)))}>Compare Scans</button>
      </form>
      {error && <p className="error">{error}</p>}
      {result && <ComparisonWorkspace result={result} />}
    </section>
  );
}

function ComparisonWorkspace({ result: initialResult }: { result: ComparisonResult }) {
  const [result, setResult] = useState(initialResult);
  const [tab, setTab] = useState("findings");
  const [classification, setClassification] = useState("");
  const [module, setModule] = useState("");
  const [severity, setSeverity] = useState("");
  const [coverage, setCoverage] = useState("");
  const [sort, setSort] = useState("classification");
  const [direction, setDirection] = useState("asc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [selected, setSelected] = useState<ComparisonResult["items"][number]>();
  useEffect(() => { setResult(initialResult); setPage(1); }, [initialResult]);
  useEffect(() => {
    const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize), sort, direction });
    if (classification === "REGRESSION") params.set("regression", "true"); else if (classification) params.set("classification", classification);
    if (module) params.set("module", module); if (severity) params.set("severity", severity); if (coverage) params.set("coverage", coverage);
    history.replaceState(null, "", `${window.location.pathname}?${params}`);
    void apiGet<ComparisonResult>(`/api/comparisons/${initialResult.comparisonId}?${params}`).then(setResult);
  }, [initialResult.comparisonId, page, pageSize, classification, module, severity, coverage, sort, direction]);
  const groups: Array<{ key: keyof ComparisonResult["summary"]; label: string; tone: string }> = [
    { key: "regressions", label: "Regressions", tone: "critical" }, { key: "new", label: "New", tone: "high" },
    { key: "changed", label: "Changed", tone: "medium" }, { key: "persisting", label: "Persisting", tone: "neutral" },
    { key: "resolved", label: "Resolved", tone: "success" }, { key: "notRetested", label: "Not retested", tone: "warning" },
    { key: "incomparable", label: "Incomparable", tone: "neutral" }, { key: "severityIncreases", label: "Severity ↑", tone: "high" }
  ];
  const visible = result.items;
  return <div className="comparison-workspace">
    <div className="comparison-meta"><strong>{result.compatibilityState.replaceAll("_", " ")}</strong><span>Engine {result.engineVersion}</span><span>{result.sourceQuality.older} → {result.sourceQuality.newer}</span><a href={`/api/comparisons/${result.comparisonId}/export/json`}>JSON export</a><a href={`/api/comparisons/${result.comparisonId}/export/markdown`}>Markdown export</a></div>
    <div className="comparison-summary">{groups.map((group) => <button className={`comparison-metric ${group.tone}`} key={group.key} onClick={() => { setClassification(group.key === "regressions" ? "REGRESSION" : group.key === "notRetested" ? "NOT_RETESTED" : group.key === "severityIncreases" ? "CHANGED" : group.key.toUpperCase()); setPage(1); setTab("findings"); }}><strong>{result.summary[group.key]}</strong><span>{group.label}</span></button>)}</div>
    {result.warnings.length > 0 && <div className="warning"><strong>Operator review required</strong><ul>{result.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></div>}
    <div className="comparison-tabs" role="tablist" aria-label="Comparison sections">{["summary","coverage","findings","plan","regressions","activity"].map((value) => <button role="tab" aria-selected={tab === value} className={tab === value ? "active" : ""} key={value} onClick={() => setTab(value)}>{value}</button>)}</div>
    {tab === "summary" && <section className="comparison-coverage"><h3>Summary</h3><dl className="dense-dl"><dt>Older scan</dt><dd>{result.oldScanId.slice(0, 8)}</dd><dt>Newer scan</dt><dd>{result.newScanId.slice(0, 8)}</dd><dt>Profiles</dt><dd>{result.coverage.oldProfile} → {result.coverage.newProfile}</dd><dt>Target</dt><dd>{result.coverage.sameTarget ? "Same durable target" : "Different target"}</dd></dl></section>}
    {tab === "coverage" && <><section className="comparison-coverage"><h3>Coverage proof</h3><dl className="dense-dl"><dt>Scope</dt><dd>{result.coverage.scopeState}</dd><dt>Authentication</dt><dd>{result.coverage.authenticationState}</dd><dt>Identity</dt><dd>{result.coverage.identityState}</dd><dt>Modules</dt><dd>{result.coverage.sharedModules.length} shared · {result.coverage.omittedModules.length} omitted · {result.coverage.addedModules.length} added</dd></dl></section><CoverageTable title="Module coverage" rows={result.coverage.modules} /><CoverageTable title="Workflow coverage" rows={result.coverage.workflows} /><CoverageTable title="Case coverage" rows={result.coverage.cases} /></>}
    {tab === "findings" && <section><div className="toolbar"><h3>Finding comparison</h3><select aria-label="Classification filter" value={classification} onChange={(event) => { setClassification(event.target.value); setPage(1); }}><option value="">All classifications</option>{["NEW","PERSISTING","CHANGED","RESOLVED","NOT_RETESTED","INCOMPARABLE","REGRESSION"].map((value) => <option key={value}>{value}</option>)}</select><input aria-label="Module filter" placeholder="Module" value={module} onChange={(event) => { setModule(event.target.value); setPage(1); }} /><select aria-label="Severity filter" value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(1); }}><option value="">Any severity</option>{["Critical","High","Medium","Low","Info"].map((value) => <option key={value}>{value}</option>)}</select><input aria-label="Coverage filter" placeholder="Coverage" value={coverage} onChange={(event) => { setCoverage(event.target.value); setPage(1); }} /><select aria-label="Comparison sort" value={sort} onChange={(event) => { setSort(event.target.value); setPage(1); }}>{["classification","severity","module","coverage","title","created"].map((value) => <option key={value}>{value}</option>)}</select><select aria-label="Sort direction" value={direction} onChange={(event) => { setDirection(event.target.value); setPage(1); }}><option value="asc">Ascending</option><option value="desc">Descending</option></select></div><div className="comparison-table-wrap"><table className="comparison-table"><thead><tr><th>Classification</th><th>Regression</th><th>Finding</th><th>Severity</th><th>Confidence</th><th>Module / endpoint</th><th>Coverage reason</th><th>Action</th></tr></thead><tbody>{visible.map((item) => <tr key={item.id}><td><span className={`classification ${item.classification.toLowerCase()}`}>{item.classification}</span></td><td>{item.regressionFlags.join(", ") || "—"}</td><td>{item.finding.title}</td><td>{item.materialChanges.find((v) => v.field === "severity") ? `${item.materialChanges.find((v) => v.field === "severity")?.older} → ${item.materialChanges.find((v) => v.field === "severity")?.newer}` : item.finding.effectiveSeverity}</td><td>{item.finding.confidence}</td><td><strong>{item.finding.module}</strong><small>{item.finding.endpoint}</small></td><td><strong>{item.reasonCode}</strong><small>{item.explanation}</small></td><td><button aria-label={`Explain ${item.finding.title}`} onClick={() => setSelected(item)}>Explain</button></td></tr>)}</tbody></table></div>{visible.length === 0 && <p className="muted">No findings match this filter.</p>}<div className="pagination"><span>{result.findingPage?.total ?? visible.length} results · page {result.findingPage?.page ?? 1} of {result.findingPage?.totalPages ?? 1}</span><label>Page size<select aria-label="Comparison page size" value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value)); setPage(1); }}>{[10,25,50,100].map((value) => <option key={value}>{value}</option>)}</select></label><button disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button><button disabled={page >= (result.findingPage?.totalPages ?? 1)} onClick={() => setPage((value) => value + 1)}>Next</button></div></section>}
    {tab === "plan" && <CoverageTable title="Structured plan changes" rows={result.planDiff} />}
    {tab === "regressions" && <section><h3>Regression intelligence</h3><ComparisonItems items={result.items.filter((item) => item.regressionFlags.length > 0)} onSelect={setSelected} /></section>}
    {tab === "activity" && <section><h3>Immutable comparison metadata</h3><dl className="dense-dl"><dt>Comparison</dt><dd>{result.comparisonId}</dd><dt>State</dt><dd>{result.state}</dd><dt>Engine</dt><dd>{result.engineVersion}</dd></dl></section>}
    {selected && <aside className="comparison-detail" aria-label="Finding comparison detail"><button aria-label="Close comparison detail" onClick={() => setSelected(undefined)}>Close</button><h3>{selected.classification}: {selected.finding.title}</h3><p><strong>{selected.reasonCode}</strong></p><p>{selected.explanation}</p><h4>Coverage proof</h4><p>{selected.coverageState}</p><h4>Older / newer occurrence</h4><div className="side-by-side"><pre>{selected.olderOccurrenceId ?? "Not present"}</pre><pre>{selected.newerOccurrenceId ?? "Not present"}</pre></div><h4>Material changes</h4><pre>{JSON.stringify(selected.materialChanges, null, 2)}</pre><h4>Safe evidence delta</h4><pre>{JSON.stringify(selected.evidenceDelta, null, 2)}</pre></aside>}
  </div>;
}

function ComparisonItems({ items, onSelect }: { items: ComparisonResult["items"]; onSelect(item: ComparisonResult["items"][number]): void }) { return items.length === 0 ? <p className="muted">None</p> : <ul className="safe-object-list">{items.map((item) => <li key={item.id}><button className="link" onClick={() => onSelect(item)}>{item.finding.title}</button><span>{item.regressionFlags.join(", ")} · {item.reasonCode}</span></li>)}</ul>; }
function CoverageTable({ title, rows }: { title: string; rows: unknown[] }) { const records = rows as Array<Record<string, unknown>>; const columns = [...new Set(records.flatMap((row) => Object.keys(row)))]; return <section><h3>{title}</h3>{records.length === 0 ? <p className="muted">No persisted coverage facts.</p> : <div className="comparison-table-wrap"><table className="comparison-table"><thead><tr>{columns.map((column) => <th key={column}>{column.replaceAll(/([A-Z])/g, " $1")}</th>)}</tr></thead><tbody>{records.map((row, index) => <tr key={index}>{columns.map((column) => <td key={column}>{typeof row[column] === "object" ? JSON.stringify(row[column]) : String(row[column] ?? "—")}</td>)}</tr>)}</tbody></table></div>}</section>; }

export function ProofPacks() {
  const [title, setTitle] = useState("Confirmed findings proof pack");
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [result, setResult] = useState("");
  const [packs, setPacks] = useState<any[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const loadPacks = () => void apiGet<{ proofPacks: any[] }>("/api/proof-packs").then((body) => setPacks(body.proofPacks));
  useEffect(() => { void apiGet<{ findings: FindingSummary[] }>("/api/findings?review=CONFIRMED&limit=100").then((body) => setFindings(body.findings)); }, []);
  useEffect(loadPacks, []);
  const generate = async (): Promise<void> => {
    const normalizedTitle = title.trim();
    if (!normalizedTitle) {
      setResult("Enter a proof-pack title.");
      return;
    }
    if (selected.length === 0) {
      setResult("Select at least one confirmed finding.");
      return;
    }
    setSubmitting(true);
    setResult("Generating proof pack...");
    try {
      const body = await apiMutation<{ proofPackId: string }>("/api/proof-packs", "POST", { title: normalizedTitle, findingIds: selected });
      setResult(`Generated proof pack ${body.proofPackId}`);
      setSelected([]);
      loadPacks();
    } catch (cause: unknown) {
      setResult(errorText(cause));
    } finally {
      setSubmitting(false);
    }
  };
  return (
    <section>
      <Header title="Proof Packs" subtitle="Proof packs include confirmed findings only and generate escaped Markdown plus scriptless HTML." />
      <form className="form" onSubmit={(event) => { event.preventDefault(); void generate(); }}>
        <label>Title <span aria-hidden="true">*</span><input required maxLength={160} value={title} onChange={(event) => setTitle(event.target.value)} /></label>
        <div className="selection-list">{findings.length === 0 ? <p className="muted">No confirmed findings are proof-pack eligible yet.</p> : findings.map((finding) => <label key={finding.id}><input type="checkbox" checked={selected.includes(finding.id)} onChange={(event) => setSelected((current) => event.target.checked ? [...current, finding.id] : current.filter((id) => id !== finding.id))} /> <strong>{finding.title}</strong><span>{finding.severity} · {finding.endpoint}</span></label>)}</div>
        <button type="submit" disabled={submitting}>{submitting ? "Generating..." : "Generate Proof Pack"}</button>
      </form>
      {result && <p aria-live="polite">{result}</p>}
      <h3>Generated Proof Packs</h3>
      {packs.length === 0 ? <EmptyState text="No proof packs yet." /> : packs.map((pack) => <article className="finding" key={pack.id}><h2>{pack.title}</h2><p>Version {pack.version} · {pack.status} · {pack.includedFindingCount} findings</p>{pack.artifacts.map((id: string) => <a key={id} href={`/api/artifacts/${id}/download`}>Download artifact</a>)}</article>)}
    </section>
  );
}

function Configurations(props: { onRun(config: Record<string, unknown>): void }) {
  const [data, setData] = useState<any>();
  const [editing, setEditing] = useState<any>();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [profile, setProfile] = useState("quick");
  const [evidenceLevel, setEvidenceLevel] = useState("normal");
  const [modules, setModules] = useState("");
  const [query, setQuery] = useState("");
  const [includeArchived, setIncludeArchived] = useState(false);
  const [message, setMessage] = useState("");
  const [history, setHistory] = useState<any>();
  const [versionDiff, setVersionDiff] = useState<any>();
  const load = () => void apiGet<any>(`/api/configurations?q=${encodeURIComponent(query)}&includeArchived=${includeArchived}`).then(setData).catch((cause: unknown) => setMessage(errorText(cause)));
  useEffect(load, [query, includeArchived]);
  const clear = () => { setEditing(undefined); setName(""); setDescription(""); setProfile("quick"); setEvidenceLevel("normal"); setModules(""); };
  const edit = (config: any) => { setEditing(config); setName(config.name); setDescription(config.description ?? ""); setProfile(config.profile); setEvidenceLevel(config.evidenceLevel); setModules((config.modules ?? []).join(", ")); };
  const payload = () => ({ name, description, profile, evidenceLevel, modules: modules.split(",").map((value) => value.trim()).filter(Boolean), limits: editing?.limits ?? {}, scopeSettings: editing?.scopeSettings ?? {}, browserPolicySettings: editing?.browserPolicySettings ?? {}, workflowRefs: editing?.workflowRefs ?? {}, ...(editing ? { expectedVersion: editing.rowVersion, changeSummary: "Dashboard edit" } : {}) });
  const save = async () => { if (editing) await apiMutation(`/api/configurations/${editing.id}`, "PATCH", payload()); else await apiMutation("/api/configurations", "POST", payload()); setMessage(editing ? "Saved immutable configuration version." : "Configuration created."); clear(); load(); };
  const exportConfig = (config: any) => { const blob = new Blob([JSON.stringify({ format: "routecairn-scan-configuration", version: 1, configuration: config }, null, 2)], { type: "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `${config.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase() || "configuration"}.json`; link.click(); URL.revokeObjectURL(link.href); };
  const inspectVersions = async (config: any) => { const detail = await apiGet<any>(`/api/configurations/${config.id}`); setHistory({ config, versions: detail.history }); setVersionDiff(detail.history.length > 1 ? await apiGet<any>(`/api/configurations/${config.id}/diff?older=${detail.history[detail.history.length - 1].version}&newer=${detail.history[0].version}`) : undefined); };
  const importConfig = async (file: File) => { const parsed = JSON.parse(await file.text()) as any; const config = parsed.configuration ?? parsed; const validated = { name: String(config.name ?? "Imported configuration"), description: String(config.description ?? "Imported in browser"), profile: String(config.profile ?? "quick"), modules: Array.isArray(config.modules) ? config.modules : [], limits: config.limits ?? {}, scopeSettings: config.scopeSettings ?? {}, browserPolicySettings: config.browserPolicySettings ?? {}, evidenceLevel: String(config.evidenceLevel ?? "normal"), workflowRefs: config.workflowRefs ?? {} }; await apiMutation("/api/configurations", "POST", validated); setMessage("Configuration imported and validated by the server schema."); load(); };
  return <section><Header title="Configurations" subtitle="Logical configurations with immutable versions, safe import/export, and Scan Studio reuse." />
    <div className="toolbar"><input aria-label="Search configurations" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search configurations" /><label className="inline-check"><input type="checkbox" checked={includeArchived} onChange={(event) => setIncludeArchived(event.target.checked)} /> Include archived</label><label className="file-button">Import JSON<input type="file" accept="application/json,.json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importConfig(file).catch((cause: unknown) => setMessage(errorText(cause))); }} /></label></div>
    <form className="form" onSubmit={(event) => event.preventDefault()}><label>Name<input value={name} onChange={(event) => setName(event.target.value)} /></label><label>Description<textarea value={description} onChange={(event) => setDescription(event.target.value)} /></label><label>Profile<select value={profile} onChange={(event) => setProfile(event.target.value)}><option>quick</option><option>full</option><option>authenticated</option><option>monitor</option><option>proof</option></select></label><label>Evidence level<select value={evidenceLevel} onChange={(event) => setEvidenceLevel(event.target.value)}><option>minimal</option><option>normal</option><option>strong</option></select></label><label>Module IDs<input value={modules} onChange={(event) => setModules(event.target.value)} placeholder="Leave blank for profile defaults" /></label><div className="actions"><button className="primary" disabled={!name.trim()} onClick={() => void save().catch((cause: unknown) => setMessage(errorText(cause)))}>{editing ? "Save New Version" : "Create Configuration"}</button>{editing && <button onClick={clear}>Cancel Edit</button>}</div></form>
    {message && <p aria-live="polite">{message}</p>}<div className="table compact-table"><div className="row config-row head"><span>Configuration</span><span>Evidence</span><span>Actions</span></div>{(data?.configurations ?? []).map((config: any) => <div className="row config-row" key={config.id}><span><strong>{config.name}</strong>{config.archived && <Badge value="ARCHIVED" />}<small>{config.profile} · version {config.currentVersion} · {config.updatedAt}</small></span><span>{config.evidenceLevel}</span><span className="actions compact">{!config.archived && <button className="primary" onClick={() => props.onRun(config)}>Run</button>}{!config.archived && <button onClick={() => edit(config)}>Edit &amp; Save</button>}<button onClick={() => void inspectVersions(config).catch((cause: unknown) => setMessage(errorText(cause)))}>History / Diff</button><button onClick={() => void apiMutation(`/api/configurations/${config.id}/clone`, "POST", { name: `${config.name} copy` }).then(load).catch((cause: unknown) => setMessage(errorText(cause)))}>Clone</button><button onClick={() => exportConfig(config)}>Export</button><button onClick={() => void apiMutation(`/api/configurations/${config.id}/${config.archived ? "restore" : "archive"}`, "POST", {}).then(load).catch((cause: unknown) => setMessage(errorText(cause)))}>{config.archived ? "Restore" : "Archive"}</button></span></div>)}</div>
    {history && <section className="detail-grid" aria-label="Configuration version history"><section><h3>{history.config.name} history</h3><ul className="timeline">{history.versions.map((version: any) => <li key={version.id}><strong>Version {version.version}</strong><small>{version.changeSummary}</small><time>{version.createdAt}</time></li>)}</ul></section><section><h3>Semantic diff</h3>{versionDiff?.changes?.length ? <ul className="safe-object-list">{versionDiff.changes.map((change: any) => <li key={change.field}><strong>{change.field}</strong><span>{JSON.stringify(change.older)} → {JSON.stringify(change.newer)}</span></li>)}</ul> : <p className="muted">No earlier version to compare.</p>}</section></section>}
    </section>;
}

function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [query, setQuery] = useState("");
  useEffect(() => {
    void apiGet<{ events: AuditEvent[] }>(`/api/audit-events?q=${encodeURIComponent(query)}`).then((body) => setEvents(body.events));
  }, [query]);
  return (
    <section>
      <Header title="Audit" subtitle="Append-only records for sensitive local dashboard actions." />
      <div className="toolbar"><input aria-label="Search audit events" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search audit events" /></div>
      <div className="table compact-table">
        <div className="row audit-row head"><span>Action</span><span>Resource</span><span>Summary</span><span>Time</span></div>
        {events.map((event) => (
          <div className="row audit-row" key={event.id}>
            <span><Badge value={event.action} /><small>{event.actor_label}</small></span>
            <span>{event.resource_type}<small>{event.resource_id ?? "none"}</small></span>
            <span>{event.safe_summary}</span>
            <span>{event.created_at}</span>
          </div>
        ))}
      </div>
      {events.length === 0 && <EmptyState text="No audit events match this view." />}
    </section>
  );
}

function Credentials() {
  const [status, setStatus] = useState<any>();
  const [profiles, setProfiles] = useState<CredentialSummary[]>([]);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [name, setName] = useState("");
  const [editing, setEditing] = useState<CredentialSummary>();
  const [renewing, setRenewing] = useState<CredentialSummary>();
  const [description, setDescription] = useState("");
  const [safeAlias, setSafeAlias] = useState("");
  const [targetId, setTargetId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [authorizationHeader, setAuthorizationHeader] = useState("");
  const [cookieName, setCookieName] = useState("");
  const [cookieValue, setCookieValue] = useState("");
  const [expectedPrincipal, setExpectedPrincipal] = useState("");
  const [expectedTenant, setExpectedTenant] = useState("");
  const [expectedRole, setExpectedRole] = useState("");
  const [expectedAccountState, setExpectedAccountState] = useState("");
  const [identityEndpoint, setIdentityEndpoint] = useState("");
  const [principalFieldPath, setPrincipalFieldPath] = useState("id");
  const [tenantFieldPath, setTenantFieldPath] = useState("");
  const [roleFieldPath, setRoleFieldPath] = useState("");
  const [accountStateFieldPath, setAccountStateFieldPath] = useState("");
  const [browserStartUrl, setBrowserStartUrl] = useState("");
  const [browserSuccessUrl, setBrowserSuccessUrl] = useState("");
  const [browserWritePath, setBrowserWritePath] = useState("");
  const [browserUsernameSelector, setBrowserUsernameSelector] = useState("");
  const [browserUsername, setBrowserUsername] = useState("");
  const [browserPasswordSelector, setBrowserPasswordSelector] = useState("");
  const [browserPassword, setBrowserPassword] = useState("");
  const [browserSubmitSelector, setBrowserSubmitSelector] = useState("");
  const [lifecycleSecretsText, setLifecycleSecretsText] = useState("");
  const [message, setMessage] = useState("");
  const [credentialDetail, setCredentialDetail] = useState<CredentialDetailResponse>();
  const load = () => {
    void apiGet<any>("/api/vault/status").then(setStatus).catch((cause: unknown) => setMessage(errorText(cause)));
    void apiGet<{ profiles: CredentialSummary[] }>("/api/credential-profiles").then((body) => setProfiles(body.profiles)).catch((cause: unknown) => setMessage(errorText(cause)));
    void apiGet<{ targets: TargetSummary[] }>("/api/targets").then((body) => setTargets(body.targets)).catch((cause: unknown) => setMessage(errorText(cause)));
  };
  useEffect(load, []);
  const browserBootstrapStarted = [browserStartUrl, browserSuccessUrl, browserWritePath, browserUsernameSelector, browserUsername, browserPasswordSelector, browserPassword, browserSubmitSelector].some(Boolean);
  const browserBootstrapComplete = [browserStartUrl, browserSuccessUrl, browserWritePath, browserUsernameSelector, browserUsername, browserPasswordSelector, browserPassword, browserSubmitSelector].every(Boolean);
  const browserBootstrap = browserBootstrapComplete ? {
    schemaVersion: 1 as const,
    loginSecrets: { username: browserUsername, password: browserPassword },
    login: {
      startUrl: browserStartUrl,
      allowedWritePaths: [browserWritePath],
      successUrlPrefix: browserSuccessUrl,
      steps: [
        { action: "fill" as const, selector: browserUsernameSelector, valueRef: "username" },
        { action: "fill" as const, selector: browserPasswordSelector, valueRef: "password" },
        { action: "click" as const, selector: browserSubmitSelector },
        { action: "waitForUrl" as const, urlPrefix: browserSuccessUrl }
      ]
    },
    journeys: [],
    proofCases: []
  } : undefined;
  const lifecycleSecrets = useMemo(() => parseLifecycleSecrets(lifecycleSecretsText), [lifecycleSecretsText]);
  const clearBrowserBootstrap = () => { setBrowserStartUrl(""); setBrowserSuccessUrl(""); setBrowserWritePath(""); setBrowserUsernameSelector(""); setBrowserUsername(""); setBrowserPasswordSelector(""); setBrowserPassword(""); setBrowserSubmitSelector(""); };
  const selectedTarget = targets.find((target) => target.id === targetId);
  const safeIdentitySummary = { alias: safeAlias, ...(expectedPrincipal ? { principalId: expectedPrincipal } : {}), ...(expectedTenant ? { tenantId: expectedTenant } : {}), ...(expectedRole ? { role: expectedRole } : {}), ...(expectedAccountState ? { accountState: expectedAccountState } : {}) };
  const identityVerification = identityEndpoint && principalFieldPath ? { endpoint: identityEndpoint, principalFieldPath, ...(tenantFieldPath ? { tenantFieldPath } : {}), ...(roleFieldPath ? { roleFieldPath } : {}), ...(accountStateFieldPath ? { accountStateFieldPath } : {}) } : undefined;
  const secret = {
    ...(authorizationHeader ? { authorizationHeader } : {}),
    ...(cookieName && cookieValue ? { cookies: { [cookieName]: cookieValue } } : {}),
    ...(identityVerification ? { identityVerification } : {}),
    ...(browserBootstrap ? { browserBootstrap } : {}),
    ...(lifecycleSecrets.value ? { lifecycleSecrets: lifecycleSecrets.value } : {})
  };
  const body = {
    name,
    description,
    safeAlias,
    ...(targetId ? { targetId, ...(selectedTarget?.projectId ? { projectId: selectedTarget.projectId } : {}) } : {}),
    ...(expiresAt ? { expiresAt: localDateTimeToIso(expiresAt) } : {}),
    safeIdentitySummary,
    secret
  };
  const clearForm = () => {
    setEditing(undefined); setRenewing(undefined); setName(""); setDescription(""); setSafeAlias(""); setTargetId(""); setExpiresAt("");
    setAuthorizationHeader(""); setCookieName(""); setCookieValue(""); setExpectedPrincipal(""); setExpectedTenant(""); setExpectedRole(""); setExpectedAccountState("");
    setIdentityEndpoint(""); setPrincipalFieldPath("id"); setTenantFieldPath(""); setRoleFieldPath(""); setAccountStateFieldPath(""); setLifecycleSecretsText(""); clearBrowserBootstrap();
  };
  const populateMetadata = (profile: CredentialSummary) => {
    setName(profile.name); setDescription(profile.description ?? ""); setSafeAlias(profile.safeAlias); setTargetId(profile.targetId ?? ""); setExpiresAt(dateTimeInputValue(profile.expiresAt));
    setExpectedPrincipal(String(profile.safeIdentitySummary.principalId ?? "")); setExpectedTenant(String(profile.safeIdentitySummary.tenantId ?? "")); setExpectedRole(String(profile.safeIdentitySummary.role ?? "")); setExpectedAccountState(String(profile.safeIdentitySummary.accountState ?? ""));
  };
  const reviewImpact = async (profile: CredentialSummary): Promise<CredentialDetailResponse> => {
    const detail = await apiGet<CredentialDetailResponse>(`/api/credential-profiles/${profile.id}`);
    setCredentialDetail(detail);
    return detail;
  };
  const submitCredential = async () => {
    if (editing) {
      await apiMutation(`/api/credential-profiles/${editing.id}/metadata`, "PATCH", { name, description, safeAlias, safeIdentitySummary, projectId: selectedTarget?.projectId ?? editing.projectId, targetId: targetId || undefined, expiresAt: expiresAt ? localDateTimeToIso(expiresAt) : undefined });
      setMessage("Credential metadata updated without exposing or replacing its secret.");
    } else if (renewing) {
      if (!credentialDetail || credentialDetail.profile.id !== renewing.id) throw new Error("Review dependency impact before renewal.");
      if (!expiresAt) throw new Error("Renewal requires a future expiry.");
      if (Object.keys(secret).length === 0) throw new Error("Enter replacement secret material before renewal.");
      await apiMutation(`/api/credential-profiles/${renewing.id}/renew`, "POST", { secret, expiresAt: localDateTimeToIso(expiresAt), safeIdentitySummary, preserveUnspecified: true, impactDigest: credentialDetail.dependencies.impactDigest });
      setMessage("Credential renewed. Run the bounded identity health check before scan use.");
    } else {
      await apiMutation<{ profileId: string }>("/api/credential-profiles", "POST", body);
      setMessage("Credential profile created. Configure identity verification and test it before scan use.");
    }
    clearForm(); load();
  };
  const beginRenewal = async (profile: CredentialSummary) => {
    const detail = await reviewImpact(profile);
    setEditing(undefined); setRenewing(profile); populateMetadata(profile); setCredentialDetail(detail);
    setAuthorizationHeader(""); setCookieName(""); setCookieValue(""); setLifecycleSecretsText(""); clearBrowserBootstrap();
    setMessage("Dependency impact loaded. Enter fresh secret material and a future expiry, then confirm renewal.");
  };
  const toggleEnabled = async (profile: CredentialSummary) => {
    const detail = await reviewImpact(profile);
    const impact = detail.dependencies;
    const action = profile.enabled ? "disable" : "enable";
    if (!window.confirm(`${profile.enabled ? "Disable" : "Enable"} ${profile.safeAlias}? Impact: ${impact.targetDefaults} target defaults, ${impact.configurationReferences} saved configurations, ${impact.activeScans} active scans.`)) return;
    await apiMutation(`/api/credential-profiles/${profile.id}/${action}`, "POST", { impactDigest: impact.impactDigest });
    setMessage(profile.enabled ? "Credential disabled; dependent scans will fail closed." : "Credential enabled; a fresh identity health check is required.");
    load();
  };
  const testProfile = async (profile: CredentialSummary) => {
    const result = await apiMutation<{ health: { classification: string; reasonCode: string }; reason?: string }>(`/api/credential-profiles/${profile.id}/test`, "POST", { ...(profile.targetId ? { targetId: profile.targetId } : {}) });
    setMessage(`Credential health: ${result.health.classification} (${result.health.reasonCode}).${result.reason ? ` ${result.reason}` : ""}`);
    await reviewImpact(profile); load();
  };
  return (
    <section>
      <Header title="Credential Vault" subtitle="Encrypted reusable credential summaries. Plaintext is accepted only for create/update and is never returned." />
      <div className="cards"><div className="metric"><strong>{status?.enabled ? "Enabled" : "Disabled"}</strong><span>AES-256-GCM vault</span></div><div className="metric"><strong>{status?.keyVersion ?? "none"}</strong><span>Key version</span></div><div className="metric"><strong>{profiles.filter(credentialUsable).length}</strong><span>Scan-eligible profiles</span></div><div className="metric"><strong>{profiles.filter((profile) => ["EXPIRED", "INVALID", "IDENTITY_MISMATCH"].includes(profile.health?.classification ?? "UNVERIFIED")).length}</strong><span>Blocked profiles</span></div></div>
      {!status?.enabled && <p className="error">{status?.reason ?? "Vault unavailable. Configure ROUTECAIRN_MASTER_KEY."}</p>}
      <form className="form" onSubmit={(event) => event.preventDefault()}>
        <label>Name<input value={name} onChange={(event) => setName(event.target.value)} /></label>
        <label>Description<textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Safe metadata only" /></label>
        <label>Safe alias<input value={safeAlias} onChange={(event) => setSafeAlias(event.target.value)} placeholder="Account A analyst session" /></label>
        <label>Approved target<select value={targetId} onChange={(event) => setTargetId(event.target.value)}><option value="">No target binding</option>{targets.map((target) => <option key={target.id} value={target.id}>{target.displayName} · {target.baseOrigin}</option>)}</select></label>
        <label>Credential expiry<input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
        <label>Authorization header<input type="password" value={authorizationHeader} onChange={(event) => setAuthorizationHeader(event.target.value)} placeholder="Bearer token or approved auth header" /></label>
        <label>Cookie name<input value={cookieName} onChange={(event) => setCookieName(event.target.value)} /></label>
        <label>Cookie value<input type="password" value={cookieValue} onChange={(event) => setCookieValue(event.target.value)} /></label>
        <fieldset><legend>Safe expected identity contract</legend><p className="muted">These expected values are safe metadata. The observed response values are hashed before storage.</p><label>Principal ID<input value={expectedPrincipal} onChange={(event) => setExpectedPrincipal(event.target.value)} /></label><label>Tenant ID<input value={expectedTenant} onChange={(event) => setExpectedTenant(event.target.value)} /></label><label>Role<input value={expectedRole} onChange={(event) => setExpectedRole(event.target.value)} /></label><label>Account state<input value={expectedAccountState} onChange={(event) => setExpectedAccountState(event.target.value)} /></label></fieldset>
        <fieldset><legend>Bounded identity health check</legend><p className="muted">The target must be selected and its approved scope controls the exact GET. Redirects, retries, and unrelated requests are not permitted.</p><label>Identity endpoint<input value={identityEndpoint} onChange={(event) => setIdentityEndpoint(event.target.value)} placeholder="https://app.example.test/api/me" /></label><label>Principal field path<input value={principalFieldPath} onChange={(event) => setPrincipalFieldPath(event.target.value)} placeholder="user.id" /></label><label>Tenant field path<input value={tenantFieldPath} onChange={(event) => setTenantFieldPath(event.target.value)} /></label><label>Role field path<input value={roleFieldPath} onChange={(event) => setRoleFieldPath(event.target.value)} /></label><label>Account-state field path<input value={accountStateFieldPath} onChange={(event) => setAccountStateFieldPath(event.target.value)} /></label></fieldset>
        <fieldset><legend>Optional authenticated browser login</legend><p className="muted">Secrets stay in component memory until encrypted by the credential vault. The login POST is restricted to the exact path below; learned writes never inherit that permission.</p><label>Login URL<input value={browserStartUrl} onChange={(event) => setBrowserStartUrl(event.target.value)} placeholder="https://app.example.test/login" /></label><label>Successful URL prefix<input value={browserSuccessUrl} onChange={(event) => setBrowserSuccessUrl(event.target.value)} placeholder="https://app.example.test/app" /></label><label>Exact login POST path<input value={browserWritePath} onChange={(event) => setBrowserWritePath(event.target.value)} placeholder="/api/session" /></label><label>Username selector<input value={browserUsernameSelector} onChange={(event) => setBrowserUsernameSelector(event.target.value)} placeholder="input[name=email]" /></label><label>Username value<input type="password" autoComplete="off" value={browserUsername} onChange={(event) => setBrowserUsername(event.target.value)} /></label><label>Password selector<input value={browserPasswordSelector} onChange={(event) => setBrowserPasswordSelector(event.target.value)} placeholder="input[name=password]" /></label><label>Password value<input type="password" autoComplete="new-password" value={browserPassword} onChange={(event) => setBrowserPassword(event.target.value)} /></label><label>Submit selector<input value={browserSubmitSelector} onChange={(event) => setBrowserSubmitSelector(event.target.value)} placeholder="button[type=submit]" /></label>{browserBootstrapStarted && !browserBootstrapComplete && <p className="error">Complete every browser-login field or clear the section.</p>}<button type="button" onClick={clearBrowserBootstrap}>Clear browser login</button></fieldset>
        <fieldset><legend>Authentication lifecycle secrets</legend><p className="muted">JSON object of reference names to secret values. Values stay in memory until the vault encrypts them and are never returned by the API.</p><label>Secret reference map<textarea value={lifecycleSecretsText} onChange={(event) => setLifecycleSecretsText(event.target.value)} placeholder={'{"username":"disposable@example.test","password":"..."}'} /></label>{lifecycleSecrets.error && <p className="error">{lifecycleSecrets.error}</p>}</fieldset>
        <div className="actions"><button className="primary" disabled={!status?.enabled || !name || !safeAlias || (renewing && !expiresAt) || (browserBootstrapStarted && !browserBootstrapComplete) || Boolean(lifecycleSecrets.error)} onClick={() => void submitCredential().catch((cause: unknown) => setMessage(errorText(cause)))}>{editing ? "Save Metadata" : renewing ? "Confirm Renewal" : "Create Credential Profile"}</button>{(editing || renewing) && <button onClick={clearForm}>Cancel</button>}</div>
      </form>
      {message && <p>{message}</p>}
      {credentialDetail && <><CredentialImpactPanel detail={credentialDetail} /><CredentialHealthTimeline events={credentialDetail.healthTimeline} /></>}
      <div className="table compact-table">
        <div className="row credential-row head"><span>Profile</span><span>Type</span><span>State</span><span>Identity</span><span>Actions</span></div>
        {profiles.map((profile) => (
          <div className="row credential-row" key={profile.id}>
            <span><strong>{profile.name}</strong><small>{profile.safeAlias} · key {profile.keyVersion}</small></span>
            <span>{profile.credentialTypeSummary}</span>
            <span><CredentialHealthBadge classification={profile.health?.classification ?? (profile.enabled ? "UNVERIFIED" : "DISABLED")} /><small>{profile.health?.reasonCode ?? "CREDENTIAL_NOT_YET_TESTED"}</small><small>{credentialExpiryLabel(profile)}</small><small>secret v{profile.secretVersion ?? 1} · last used {profile.lastUsedAt ?? "never"}</small></span>
            <span>{JSON.stringify(profile.safeIdentitySummary)}</span>
            <span className="actions compact">
              <button disabled={!profile.enabled || profile.health?.classification === "EXPIRED" || !profile.targetId} onClick={() => void testProfile(profile).catch((cause: unknown) => setMessage(errorText(cause)))}>Test Identity</button>
              <button onClick={() => void reviewImpact(profile).catch((cause: unknown) => setMessage(errorText(cause)))}>Impact & Timeline</button>
              <button onClick={() => { setRenewing(undefined); setEditing(profile); populateMetadata(profile); setAuthorizationHeader(""); setCookieName(""); setCookieValue(""); }}>Edit Metadata</button>
              <button disabled={!status?.enabled} onClick={() => void beginRenewal(profile).catch((cause: unknown) => setMessage(errorText(cause)))}>Renew / Replace</button>
              <button onClick={() => void toggleEnabled(profile).catch((cause: unknown) => setMessage(errorText(cause)))}>{profile.enabled ? "Disable" : "Enable"}</button>
              <button onClick={() => window.confirm("Delete this credential profile?") && void apiMutation(`/api/credential-profiles/${profile.id}/delete`, "POST", {}).then(load).catch((cause: unknown) => setMessage(errorText(cause)))}>Delete</button>
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function Users() {
  const [users, setUsers] = useState<any[]>([]);
  const [userQuery, setUserQuery] = useState("");
  const [mode, setMode] = useState("local");
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("ANALYST");
  const [message, setMessage] = useState("");
  const load = () => void apiGet<{ mode: string; users: any[] }>("/api/users").then((body) => { setMode(body.mode); setUsers(body.users); }).catch((cause: unknown) => setMessage(errorText(cause)));
  useEffect(load, []);
  return (
    <section>
      <Header title="Users" subtitle="Owner-only server-mode user administration." />
      {mode === "local" && <p className="notice">User administration becomes active in server mode. The first owner remains an intentional CLI-only bootstrap safety step.</p>}
      <div className="toolbar"><input aria-label="Search users" value={userQuery} onChange={(event) => setUserQuery(event.target.value)} placeholder="Search users" /></div>
      {message && <p className="error">{message}</p>}
      <form className="form" aria-disabled={mode === "local"} onSubmit={(event) => event.preventDefault()}>
        <label>Username or email<input value={login} onChange={(event) => setLogin(event.target.value)} autoComplete="off" /></label>
        <label>Temporary password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /></label>
        <label>Role<select value={role} onChange={(event) => setRole(event.target.value)}><option>OWNER</option><option>ANALYST</option><option>VIEWER</option></select></label>
        <button disabled={mode === "local" || !login || password.length < 12} onClick={() => void apiMutation("/api/users", "POST", { login, password, role }).then(() => { setLogin(""); setPassword(""); load(); }).catch((cause: unknown) => setMessage(errorText(cause)))}>Create User</button>
      </form>
      <div className="table compact-table">
        <div className="row user-row head"><span>User</span><span>Role</span><span>State</span><span>Sessions</span><span>Actions</span></div>
        {users.filter((user) => String(user.login).toLowerCase().includes(userQuery.toLowerCase()) || String(user.role).includes(userQuery.toUpperCase())).map((user) => (
          <div className="row user-row" key={user.id}>
            <span><strong>{user.login}</strong><small>{user.id} · created {user.createdAt}</small></span>
            <span><select aria-label={`Role for ${user.login}`} disabled={mode === "local"} value={user.role} onChange={(event) => window.confirm(`Change ${user.login} to ${event.target.value}?`) && void apiMutation(`/api/users/${user.id}`, "PATCH", { role: event.target.value }).then(load).catch((cause: unknown) => setMessage(errorText(cause)))}><option>OWNER</option><option>ANALYST</option><option>VIEWER</option></select></span>
            <span>{user.enabled ? "Enabled" : "Disabled"}<small>{user.lastLoginAt ?? "never logged in"}</small></span>
            <span>{user.activeSessionCount}</span>
            <span className="actions compact">
              <button disabled={mode === "local"} onClick={() => window.confirm(`${user.enabled ? "Disable" : "Enable"} ${user.login}?`) && void apiMutation(`/api/users/${user.id}`, "PATCH", { enabled: !user.enabled }).then(load).catch((cause: unknown) => setMessage(errorText(cause)))}>{user.enabled ? "Disable" : "Enable"}</button>
              <button onClick={() => {
                const next = window.prompt("New password");
                if (next) void apiMutation(`/api/users/${user.id}`, "PATCH", { password: next }).then(load).catch((cause: unknown) => setMessage(errorText(cause)));
              }} disabled={mode === "local"}>Reset Password</button>
              <button disabled={mode === "local" || user.activeSessionCount === 0} onClick={() => window.confirm(`Revoke all sessions for ${user.login}?`) && void apiMutation(`/api/users/${user.id}/revoke-sessions`, "POST", {}).then(load).catch((cause: unknown) => setMessage(errorText(cause)))}>Revoke Sessions</button>
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function Settings() {
  const [data, setData] = useState<any>();
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [message, setMessage] = useState("");
  const [resetSetting, setResetSetting] = useState("defaultProfile");
  const load = () => void apiGet<any>("/api/settings").then((body) => { setData(body); setDraft(Object.fromEntries(Object.entries(body.mutable ?? {}).map(([key, item]: [string, any]) => [key, String(item.value)]))); });
  useEffect(load, []);
  const save = async () => {
    const values = { defaultProfile: draft.defaultProfile, defaultEvidenceLevel: draft.defaultEvidenceLevel, defaultRateLimitPerSecond: Number(draft.defaultRateLimitPerSecond), defaultConcurrency: Number(draft.defaultConcurrency), retentionDays: Number(draft.retentionDays), queueCapacity: Number(draft.queueCapacity), workerMemoryMb: Number(draft.workerMemoryMb), workerCpuTimeMs: Number(draft.workerCpuTimeMs), workerWallClockMs: Number(draft.workerWallClockMs), workerOutputQuotaMb: Number(draft.workerOutputQuotaMb), workerTempQuotaMb: Number(draft.workerTempQuotaMb), workerHeartbeatTimeoutMs: Number(draft.workerHeartbeatTimeoutMs), workerCleanupGraceMs: Number(draft.workerCleanupGraceMs), workerForceKillGraceMs: Number(draft.workerForceKillGraceMs), workerCrashLoopLimit: Number(draft.workerCrashLoopLimit), workerCrashLoopWindowMs: Number(draft.workerCrashLoopWindowMs) };
    const expectedVersions = Object.fromEntries(Object.entries(data.mutable ?? {}).map(([key, item]: [string, any]) => [key, item.rowVersion]));
    await apiMutation("/api/settings", "PATCH", { values, expectedVersions }); setMessage("Settings saved. Changes are active for subsequent operations."); load();
  };
  return (
    <section>
      <Header title="Settings" subtitle="Authoritative runtime defaults, environment posture, and restart semantics." />
      <div className="cards">
        <div className="metric"><strong>{data?.localOnly ? "Local" : "Server"}</strong><span>Dashboard mode</span></div>
        <div className="metric"><strong>{data?.persistence ?? "sqlite"}</strong><span>Persistence</span></div>
        <div className="metric"><strong>{data?.queue?.maxQueuedScans ?? 0}</strong><span>Queue capacity</span></div>
        <div className="metric"><strong>{data?.liveUpdates ?? "sse"}</strong><span>Progress channel</span></div>
        <div className="metric"><strong>{data?.credentialVault?.enabled ? "Enabled" : "Unavailable"}</strong><span>Credential vault</span></div>
        <div className="metric"><strong>{data?.serverModeAvailable ? "Available" : "Fail closed"}</strong><span>Server mode</span></div>
      </div>
      <h3>Mutable defaults</h3>
      <form className="form" onSubmit={(event) => event.preventDefault()}>
        <label>Default profile<select value={draft.defaultProfile ?? "quick"} onChange={(event) => setDraft((current) => ({ ...current, defaultProfile: event.target.value }))}><option>quick</option><option>full</option><option>authenticated</option><option>monitor</option><option>proof</option></select></label>
        <label>Default evidence level<select value={draft.defaultEvidenceLevel ?? "normal"} onChange={(event) => setDraft((current) => ({ ...current, defaultEvidenceLevel: event.target.value }))}><option>minimal</option><option>normal</option><option>strong</option></select></label>
        {[['defaultRateLimitPerSecond','Default requests / second',1,50],['defaultConcurrency','Default concurrency',1,50],['retentionDays','Retention days',1,3650],['queueCapacity','Queue capacity',1,1000]].map(([key,label,min,max]) => <label key={String(key)}>{String(label)}<input type="number" min={Number(min)} max={Number(max)} value={draft[String(key)] ?? ""} onChange={(event) => setDraft((current) => ({ ...current, [String(key)]: event.target.value }))} /></label>)}
        <label>Reset one setting<select value={resetSetting} onChange={(event) => setResetSetting(event.target.value)}>{Object.keys(data?.mutable ?? {}).map((key) => <option key={key}>{key}</option>)}</select></label>
        <div className="actions"><button className="primary" onClick={() => void save().catch((cause: unknown) => setMessage(errorText(cause)))}>Save Settings</button><button onClick={() => void apiMutation("/api/settings/reset", "POST", { keys: [resetSetting] }).then(() => { setMessage(`${resetSetting} reset to its default.`); load(); }).catch((cause: unknown) => setMessage(errorText(cause)))}>Reset Selected</button><button onClick={() => window.confirm("Reset all mutable settings to defaults?") && void apiMutation("/api/settings/reset", "POST", { keys: [] }).then(() => { setMessage("Mutable settings reset to defaults."); load(); }).catch((cause: unknown) => setMessage(errorText(cause)))}>Reset All</button></div>
      </form>
      <h3>Worker governance defaults</h3>
      <p className="muted">Applied as an immutable policy snapshot to each subsequently launched worker. Cleanup grace cannot be reduced below RouteCairn’s bounded restoration window.</p>
      <form className="form" onSubmit={(event) => event.preventDefault()}>
        {[
          ["workerMemoryMb", "Memory ceiling (MiB)", 128, 4096],
          ["workerCpuTimeMs", "CPU-time ceiling (ms)", 10000, 7200000],
          ["workerWallClockMs", "Wall-clock ceiling (ms)", 30000, 7200000],
          ["workerOutputQuotaMb", "Output quota (MiB)", 16, 4096],
          ["workerTempQuotaMb", "Temporary-disk quota (MiB)", 16, 4096],
          ["workerHeartbeatTimeoutMs", "Heartbeat timeout (ms)", 5000, 120000],
          ["workerCleanupGraceMs", "Graceful cleanup window (ms)", 135000, 600000],
          ["workerForceKillGraceMs", "Terminal-exit grace (ms)", 1000, 60000],
          ["workerCrashLoopLimit", "Crashes before quarantine", 2, 20],
          ["workerCrashLoopWindowMs", "Crash-loop window (ms)", 30000, 3600000]
        ].map(([key, label, min, max]) => <label key={String(key)}>{String(label)}<input type="number" min={Number(min)} max={Number(max)} value={draft[String(key)] ?? ""} onChange={(event) => setDraft((current) => ({ ...current, [String(key)]: event.target.value }))} /></label>)}
      </form>
      {message && <p aria-live="polite">{message}</p>}
      <h3>Environment and offline-sensitive settings</h3>
      <div className="table compact-table">{Object.entries(data?.environment ?? {}).map(([key, value]: [string, any]) => <div className="row settings-row" key={key}><span><strong>{key}</strong><small>{value.classification}</small></span><span>{value.configured === undefined ? String(value.value) : value.configured ? "Configured" : "Not configured"}</span><span><Badge value="ENVIRONMENT" /></span></div>)}</div>
      <p className="muted">Environment and vault-key settings are read-only here and require a controlled restart or offline rotation. {data?.serverModeStatus}</p>
    </section>
  );
}

function Header(props: { title: string; subtitle: string }) {
  return <header className="page-header"><h2>{props.title}</h2><p>{props.subtitle}</p></header>;
}

function EmptyState(props: { text: string }) {
  return <div className="empty">{props.text}</div>;
}

function Badge(props: { value: string }) {
  return <span className={`badge ${props.value.toLowerCase().replace(/_/g, "-")}`}>{props.value}</span>;
}

function errorText(error: unknown): string {
  if (error instanceof DashboardApiError && error.diagnostics.length > 0) {
    return `${error.message} ${error.diagnostics.map((diagnostic) => diagnostic.message).join(" ")}`;
  }
  return error instanceof Error ? error.message : "Request failed.";
}

function localDateTimeToIso(value: string): string {
  const timestamp = new Date(value);
  if (!Number.isFinite(timestamp.getTime())) throw new Error("Enter a valid credential expiry date and time.");
  return timestamp.toISOString();
}

function dateTimeInputValue(value?: string): string {
  if (!value) return "";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "";
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function parseLifecycleSecrets(input: string): { value?: Record<string, string>; error?: string } {
  if (!input.trim()) return {};
  try {
    const parsed = JSON.parse(input) as unknown;
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") return { error: "Lifecycle secrets must be a JSON object." };
    const entries = Object.entries(parsed as Record<string, unknown>);
    if (entries.length === 0) return { error: "Lifecycle secret map cannot be empty." };
    for (const [name, value] of entries) if (!/^[A-Za-z0-9._-]{1,100}$/.test(name) || typeof value !== "string" || value.length < 1 || value.length > 8192) return { error: `Invalid lifecycle secret entry: ${name}` };
    return { value: Object.fromEntries(entries) as Record<string, string> };
  } catch {
    return { error: "Lifecycle secrets must be valid JSON." };
  }
}

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(<App />);
}
