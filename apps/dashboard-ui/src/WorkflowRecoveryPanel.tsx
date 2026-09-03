import { useEffect, useState } from "react";
import { apiGet, apiMutation } from "./api";

interface Obligation { caseId: string; targetOrigin?: string; stage: string; recoveryKind: string; workflow?: string; checkpointDigest?: string; actorSlots?: string[] }
interface RecoveryJob { id: string; case_id: string; status: string; safe_summary: string }
interface Target { id: string; displayName: string; baseOrigin: string }
interface Credential { id: string; name: string; enabled: boolean; targetId?: string }
interface Inventory { cases: Obligation[]; jobs: RecoveryJob[] }

async function readInventory(): Promise<Inventory> {
  const value = await apiGet<Inventory>("/api/workflow-mutations/status");
  if (!value || !Array.isArray(value.cases) || !Array.isArray(value.jobs) || value.cases.some((item) => !item || typeof item.caseId !== "string" || typeof item.recoveryKind !== "string") || value.jobs.some((item) => !item || typeof item.id !== "string" || typeof item.case_id !== "string" || typeof item.status !== "string")) throw new Error("Invalid cleanup inventory");
  return value;
}

export function WorkflowRecoveryPanel() {
  const [inventory, setInventory] = useState<Inventory>({ cases: [], jobs: [] });
  const [targets, setTargets] = useState<Target[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [selected, setSelected] = useState("");
  const [targetId, setTargetId] = useState("");
  const [profiles, setProfiles] = useState<Record<string, string>>({});
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const current = inventory.cases.find((item) => item.caseId === selected && item.recoveryKind === "WORKFLOW");
  useEffect(() => { setConfirmed(false); }, [selected, current?.checkpointDigest]);
  const refresh = async () => { setInventory(await readInventory()); };
  useEffect(() => {
    let active = true;
    const load = () => void readInventory().then((value) => { if (active) setInventory(value); }).catch(() => { if (active) { setInventory({ cases: [], jobs: [] }); setConfirmed(false); setError("Cleanup inventory unavailable. Recovery permission is required; no action was taken."); } });
    load();
    void Promise.all([apiGet<{ targets: Target[] }>("/api/targets"), apiGet<{ profiles: Credential[] }>("/api/credential-profiles")]).then(([a, b]) => { if (!Array.isArray(a?.targets) || !Array.isArray(b?.profiles)) throw new Error("Invalid recovery choices"); if (active) { setTargets(a.targets); setCredentials(b.profiles); } }).catch(() => { if (active) setError("Registered targets or credential profiles could not be loaded."); });
    const timer = window.setInterval(load, 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);
  const recover = async () => {
    if (!current?.checkpointDigest || !confirmed || !targetId || busy) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await apiMutation<{ jobId: string }>("/api/workflow-mutations/recovery", "POST", {
        caseId: current.caseId, checkpointDigest: current.checkpointDigest, targetId,
        ...(profiles.primary ? { credentialProfileId: profiles.primary } : {}),
        ...(profiles.account_a ? { credentialProfileAId: profiles.account_a, credentialProfileBId: profiles.account_b } : {}),
        confirmation: "I_AUTHORIZE_STORED_CLEANUP_ONLY"
      });
      setMessage(`Cleanup-only recovery queued: ${result.jobId}. Follow the result below.`); setConfirmed(false); await refresh();
    } catch { setError("Recovery could not be queued. Refresh the obligation and check target, credentials and permissions."); }
    finally { setBusy(false); }
  };
  const activeJob = inventory.jobs.some((job) => job.case_id === selected && job.status === "RUNNING");
  return <section aria-label="Workflow cleanup recovery">
    <h2>Workflow cleanup recovery</h2>
    <p>Recover authentication, invariant, race, link, operational and billing cases here. Only the encrypted, stored cleanup and verification steps run. Original attack steps are never replayed.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {message && <p role="status">{message}</p>}
    <label>Unresolved workflow<select value={selected} onChange={(event) => { setSelected(event.target.value); setTargetId(""); setProfiles({}); setConfirmed(false); }}><option value="">Select a cleanup obligation</option>{inventory.cases.filter((item) => item.recoveryKind === "WORKFLOW").map((item) => <option key={item.caseId} value={item.caseId}>{item.workflow}: {item.caseId} — {item.stage}</option>)}</select></label>
    {current && <>
      <p>Target: {current.targetOrigin}. Checkpoint: {current.checkpointDigest?.slice(0, 12)}. New mutations remain blocked until restoration is verified.</p>
      <label>Registered target<select value={targetId} onChange={(event) => { setTargetId(event.target.value); setProfiles({}); setConfirmed(false); }}><option value="">Select matching target</option>{targets.filter((target) => target.baseOrigin === current.targetOrigin).map((target) => <option key={target.id} value={target.id}>{target.displayName}</option>)}</select></label>
      {(current.actorSlots ?? []).map((slot) => <label key={slot}>Fresh {slot} credential<select value={profiles[slot] ?? ""} onChange={(event) => { setProfiles({ ...profiles, [slot]: event.target.value }); setConfirmed(false); }}><option value="">Select saved credential</option>{credentials.filter((profile) => profile.enabled && (!profile.targetId || profile.targetId === targetId)).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</select></label>)}
      <label><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I authorize only this checkpoint’s stored cleanup and restoration verification.</label>
      <button type="button" onClick={() => void recover()} disabled={!confirmed || !targetId || busy || activeJob || (current.actorSlots ?? []).some((slot) => !profiles[slot])}>{busy || activeJob ? "Recovery running…" : "Run cleanup recovery"}</button>
    </>}
    <h3>Recovery timeline</h3>
    {inventory.jobs.length === 0 ? <p>No workflow recovery jobs yet.</p> : <ul>{inventory.jobs.map((job) => <li key={job.id}><strong>{job.case_id}: {job.status}</strong> — {job.safe_summary}</li>)}</ul>}
  </section>;
}
