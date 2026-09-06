import React, { useEffect, useMemo, useState } from "react";
import { apiGet, apiMutation } from "./api";

interface Policy {
  memoryBytes: number; cpuTimeMs: number; wallClockMs: number; outputBytes: number; tempBytes: number;
  heartbeatTimeoutMs: number; cleanupGraceMs: number; forceKillGraceMs: number; crashLoopLimit: number; crashLoopWindowMs: number;
}

interface Worker {
  id: string; processId?: number; state: string; currentJobId?: string; startedAt: string; lastHeartbeatAt?: string;
  currentModule?: string; cleanupState: string; processTreePids: number[]; failureCategory?: string; terminationReason?: string;
  gracefulStopRequestedAt?: string; forcedTerminationAt?: string; quarantinedAt?: string; quarantineReason?: string; policy: Policy;
  resources: { rssBytes: number; heapUsedBytes: number; cpuTimeMs: number; outputBytes: number; tempBytes: number };
}

interface Fleet { dispatchState: "NORMAL" | "QUARANTINED"; quarantineReason?: string; crashCount: number; crashWindowStartedAt?: string; workers: Worker[]; policy: Policy; }

export function WorkerDiagnostics(props: { canManage: boolean }) {
  const [fleet, setFleet] = useState<Fleet>();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const load = () => void apiGet<Fleet>("/api/workers/diagnostics").then((value) => { setFleet(value); setError(""); }).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "Worker diagnostics failed."));
  useEffect(() => { load(); const timer = window.setInterval(load, 2_000); return () => window.clearInterval(timer); }, []);
  const active = useMemo(() => fleet?.workers.filter((worker) => ["STARTING", "RUNNING", "STOPPING", "UNHEALTHY"].includes(worker.state)) ?? [], [fleet]);
  const act = async (path: string, body: unknown, message: string) => { await apiMutation(path, "POST", body); setNotice(message); load(); };
  return <section>
    <header className="page-header"><h2>Worker Operations</h2><p>Live job isolation, resource ceilings, cleanup grace, process-tree containment, and crash-loop controls.</p></header>
    {error && <p className="error" role="alert">{error}</p>}
    {notice && <p className="notice" aria-live="polite">{notice}</p>}
    {fleet?.dispatchState === "QUARANTINED" && <div className="cleanup-emergency" role="alert"><div><strong>WORKER DISPATCH QUARANTINED</strong><p>{fleet.quarantineReason}</p></div><span>OPERATOR RELEASE REQUIRED</span></div>}
    <div className="cards">
      <div className={`metric ${fleet?.dispatchState === "QUARANTINED" ? "danger-metric" : ""}`}><strong>{fleet?.dispatchState ?? "Loading"}</strong><span>Dispatch state</span></div>
      <div className="metric"><strong>{active.length}</strong><span>Active workers</span></div>
      <div className="metric"><strong>{fleet?.crashCount ?? 0} / {fleet?.policy.crashLoopLimit ?? 0}</strong><span>Crash-loop window</span></div>
      <div className="metric"><strong>{formatBytes(fleet?.policy.memoryBytes ?? 0)}</strong><span>RSS ceiling / worker</span></div>
      <div className="metric"><strong>{formatDuration(fleet?.policy.wallClockMs ?? 0)}</strong><span>Wall-clock ceiling</span></div>
      <div className="metric"><strong>{formatDuration(fleet?.policy.cleanupGraceMs ?? 0)}</strong><span>Cleanup grace</span></div>
    </div>
    <div className="actions">
      <button disabled={!props.canManage || fleet?.dispatchState === "QUARANTINED"} onClick={() => { const reason = window.prompt("Why should all new worker dispatch be quarantined?"); if (reason) void act("/api/workers/fleet/quarantine", { reason }, "New worker dispatch is quarantined.").catch(show(setError)); }}>Quarantine dispatch</button>
      <button disabled={!props.canManage || fleet?.dispatchState !== "QUARANTINED"} onClick={() => window.confirm("Release worker dispatch and reset the crash-loop counter?") && void act("/api/workers/fleet/release", {}, "Worker dispatch released.").catch(show(setError))}>Release dispatch</button>
    </div>
    <h3>Configured hard limits</h3>
    {fleet && <div className="table compact-table">
      <div className="row worker-policy-row head"><span>Resource</span><span>Ceiling</span><span>Enforcement</span></div>
      {[["Resident memory", formatBytes(fleet.policy.memoryBytes), "V8 heap cap plus RSS heartbeat enforcement"], ["CPU time", formatDuration(fleet.policy.cpuTimeMs), "Cumulative user + system CPU"], ["Wall clock", formatDuration(fleet.policy.wallClockMs), "Manager-owned deadline"], ["Report output", formatBytes(fleet.policy.outputBytes), "Job report directory quota"], ["Temporary disk", formatBytes(fleet.policy.tempBytes), "Isolated worker temp quota"], ["Heartbeat", formatDuration(fleet.policy.heartbeatTimeoutMs), "Stale worker containment"]].map(([resource, ceiling, enforcement]) => <div className="row worker-policy-row" key={resource}><span>{resource}</span><span>{ceiling}</span><span>{enforcement}</span></div>)}
    </div>}
    <h3>Worker history and live state</h3>
    <div className="worker-grid">
      {(fleet?.workers ?? []).map((worker) => <article className={`worker-card ${worker.failureCategory ? "worker-failed" : ""}`} key={worker.id}>
        <div className="worker-card-title"><div><strong>{worker.id.slice(0, 8)}</strong><small>PID {worker.processId ?? "unavailable"} · {worker.state}</small></div><span className={`badge ${worker.cleanupState.toLowerCase()}`}>{worker.cleanupState}</span></div>
        <dl>
          <div><dt>Heartbeat</dt><dd>{heartbeatAge(worker.lastHeartbeatAt)}</dd></div>
          <div><dt>Current module</dt><dd>{worker.currentModule ?? "None"}</dd></div>
          <div><dt>Current scan</dt><dd>{worker.currentJobId?.slice(0, 8) ?? "None"}</dd></div>
          <div><dt>Process tree</dt><dd>{worker.processTreePids.length ? worker.processTreePids.join(", ") : worker.processId ?? "Unavailable"}</dd></div>
        </dl>
        <Resource label="RSS" value={worker.resources.rssBytes} limit={worker.policy.memoryBytes} format={formatBytes} />
        <Resource label="CPU" value={worker.resources.cpuTimeMs} limit={worker.policy.cpuTimeMs} format={formatDuration} />
        <Resource label="Output" value={worker.resources.outputBytes} limit={worker.policy.outputBytes} format={formatBytes} />
        <Resource label="Temp" value={worker.resources.tempBytes} limit={worker.policy.tempBytes} format={formatBytes} />
        {worker.failureCategory && <p className="error"><strong>{worker.failureCategory}</strong><br />{worker.terminationReason}</p>}
        {worker.quarantineReason && <p className="notice"><strong>Quarantined:</strong> {worker.quarantineReason}</p>}
        <div className="actions compact"><button disabled={!props.canManage || !["STARTING", "RUNNING", "UNHEALTHY"].includes(worker.state)} onClick={() => window.confirm("Gracefully stop this job-scoped worker, retain partial evidence, and launch a fresh worker for the next job?") && void act(`/api/workers/${worker.id}/restart`, {}, "Worker restart requested.").catch(show(setError))}>Restart worker</button>{worker.quarantinedAt ? <button disabled={!props.canManage} onClick={() => void act(`/api/workers/${worker.id}/release`, {}, "Worker quarantine record released.").catch(show(setError))}>Release quarantine</button> : <button disabled={!props.canManage} onClick={() => { const reason = window.prompt("Quarantine reason"); if (reason) void act(`/api/workers/${worker.id}/quarantine`, { reason }, "Worker quarantined.").catch(show(setError)); }}>Quarantine</button>}</div>
      </article>)}
    </div>
    {fleet && fleet.workers.length === 0 && <div className="empty">No workers have run yet. Diagnostics will populate with the next dashboard scan or recovery job.</div>}
  </section>;
}

function Resource(props: { label: string; value: number; limit: number; format(value: number): string }) {
  const percent = props.limit ? Math.min(100, Math.round(props.value / props.limit * 100)) : 0;
  return <div className="resource-meter"><span><strong>{props.label}</strong><small>{props.format(props.value)} / {props.format(props.limit)}</small></span><progress max={100} value={percent}>{percent}%</progress></div>;
}

function formatBytes(value: number): string { if (!value) return "0 B"; const units = ["B", "KiB", "MiB", "GiB"]; const unit = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024))); return `${(value / 1024 ** unit).toFixed(unit ? 1 : 0)} ${units[unit]}`; }
function formatDuration(value: number): string { return value >= 60_000 ? `${(value / 60_000).toFixed(1)} min` : `${(value / 1000).toFixed(1)} s`; }
function heartbeatAge(value?: string): string { if (!value) return "Never"; const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(value)) / 1000)); return `${seconds}s ago · ${new Date(value).toLocaleTimeString()}`; }
function show(setter: (value: string) => void) { return (cause: unknown) => setter(cause instanceof Error ? cause.message : "Worker operation failed."); }
