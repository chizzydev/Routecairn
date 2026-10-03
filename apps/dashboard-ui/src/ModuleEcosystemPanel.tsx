import React, { useState } from "react";
import { apiMutation } from "./api";

interface ModuleSummary {
  id: string; moduleId: string; version: string; status: string; packageDigest: string; description: string;
  capabilities?: { requestBroker?: unknown }; permissions?: unknown; inputSchema?: unknown;
  signature?: { signed: boolean; publisher?: string; keyId?: string; expiresAt?: string };
}
export function ModuleEcosystemPanel({ data, organizationId, canManage, run }: { data: { modules?: ModuleSummary[] }; organizationId: string; canManage: boolean; run: (path: string, body: unknown, message: string) => Promise<void> }) {
  const [directory, setDirectory] = useState(""), [bundle, setBundle] = useState(""), [input, setInput] = useState("{}"), [broker, setBroker] = useState(""), [busy, setBusy] = useState(false), [error, setError] = useState(""), [result, setResult] = useState<unknown>();
  const action = async (work: () => Promise<unknown>) => { setBusy(true); setError(""); try { await work(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Module operation failed."); } finally { setBusy(false); } };
  const execute = (module: ModuleSummary) => action(async () => {
    setResult(undefined); const parsed = JSON.parse(input);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Execution input must be a JSON object.");
    const binding = broker.trim() ? JSON.parse(broker) : undefined;
    if (module.capabilities?.requestBroker && !binding) throw new Error("This module requires a reviewed target and digest-bound broker approval.");
    setResult(await apiMutation(`/api/operations/modules/${module.id}/execute`, "POST", { input: parsed, ...(binding ? { broker: binding } : {}) }));
  });
  return <section aria-label="Module ecosystem">
    <h3>Capability-mediated detectors</h3>
    <p>Review the exact package, permissions and request limits before approval. Publisher signatures establish origin; requests also require a fresh target approval.</p>
    {canManage && <>
      <form className="form" onSubmit={(event) => { event.preventDefault(); void action(() => run("/api/operations/modules", { organizationId, packageDirectory: directory, ...(bundle.trim() ? { bundlePath: bundle.trim() } : {}) }, "Module registered for separate package approval.")); }}>
        <label>Installed package directory<input required value={directory} onChange={(event) => setDirectory(event.target.value)} /></label>
        <label>Verified signed bundle path<input value={bundle} onChange={(event) => setBundle(event.target.value)} /></label>
        <p className="muted">Both paths must be inside the configured module root. Strict signing deployments require the bundle.</p>
        <button disabled={busy || !organizationId}>Register package for review</button>
      </form>
      <label>Execution input JSON<textarea className="code-input" value={input} onChange={(event) => setInput(event.target.value)} spellCheck={false} /></label>
      <label>Reviewed broker binding JSON<textarea className="code-input" value={broker} onChange={(event) => setBroker(event.target.value)} spellCheck={false} /></label>
    </>}
    {error && <p role="alert">{error}</p>}
    {(data?.modules ?? []).map((module) => <article key={module.id}>
      <h4>{module.moduleId} · {module.version} · {module.status}</h4><p>{module.description}</p>
      <p>Package digest: <code>{module.packageDigest}</code></p>
      <p>{module.signature?.signed ? `Signed by ${module.signature.publisher}; expires ${module.signature.expiresAt}` : "Unsigned local package"}</p>
      <details><summary>Review permissions and contracts</summary><pre className="json-block">{JSON.stringify({ permissions: module.permissions, capabilities: module.capabilities, inputSchema: module.inputSchema, signature: module.signature }, null, 2)}</pre></details>
      {canManage && <div className="actions">
        {["REGISTERED", "DISABLED"].includes(module.status) && <button disabled={busy} onClick={() => void action(() => run(`/api/operations/modules/${module.id}/approve`, {}, `${module.moduleId} approved.`))}>Approve {module.moduleId}</button>}
        {module.status === "APPROVED" && <button disabled={busy} onClick={() => void execute(module)}>Execute {module.moduleId}</button>}
        {["REGISTERED", "APPROVED"].includes(module.status) && <button disabled={busy} onClick={() => void action(() => run(`/api/operations/modules/${module.id}/disable`, {}, `${module.moduleId} disabled.`))}>Disable {module.moduleId}</button>}
      </div>}
    </article>)}
    {result !== undefined && <section aria-label="Module execution result"><h4>Execution result</h4><pre className="json-block">{JSON.stringify(result, null, 2)}</pre></section>}
  </section>;
}
