import React, { useEffect, useMemo, useRef, useState } from "react";
import { apiGet, apiMutation, DashboardApiError, type TargetSummary } from "./api";

type Assertion = { path: string; operator: "EQUALS" | "NOT_EQUALS" | "PRESENT" | "ABSENT"; expectedValue?: unknown };
type VerificationDraft = { path: string; assertionPath: string; expectedValue: string; attempts: number; delayMs: number };
type ProductionCase = Record<string, unknown>;
type CredentialSummary = { id: string; safeAlias: string; enabled: boolean; targetId?: string };
type Diagnostic = { path: string[]; message: string };
type MutationIntent = "SECURITY_NEGATIVE" | "AUTHORIZED_ACCEPTANCE" | "ROLLBACK_ACCEPTANCE" | "RECOVERY_ACCEPTANCE";
type SecurityCategory = "PRIVILEGE_ESCALATION" | "MASS_ASSIGNMENT" | "CROSS_TENANT_REASSIGNMENT" | "OWNERSHIP_TAKEOVER" | "ADMINISTRATIVE_BOUNDARY";

const emptyVerification = (path: string, assertionPath: string): VerificationDraft => ({ path, assertionPath, expectedValue: "replace-with-exact-value", attempts: 3, delayMs: 250 });

export function ProductionMutationWorkspace() {
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [targetId, setTargetId] = useState("");
  const [credentialId, setCredentialId] = useState("");
  const [caseId, setCaseId] = useState("production-authority-boundary-001");
  const [intent, setIntent] = useState<MutationIntent>("SECURITY_NEGATIVE");
  const [securityCategory, setSecurityCategory] = useState<SecurityCategory>("MASS_ASSIGNMENT");
  const [alias, setAlias] = useState("disposable-test-object");
  const [authorityField, setAuthorityField] = useState("role");
  const [mutationValue, setMutationValue] = useState('"admin"');
  const [rollbackValue, setRollbackValue] = useState('"member"');
  const [allowedValues, setAllowedValues] = useState('"member", "admin"');
  const [identity, setIdentity] = useState(() => emptyVerification("/api/me", "id"));
  const [precondition, setPrecondition] = useState(() => emptyVerification("/api/disposable-object", "id"));
  const [mutationPath, setMutationPath] = useState("/api/disposable-object");
  const [mutationMethod, setMutationMethod] = useState<"POST" | "PATCH" | "PUT">("PATCH");
  const [impact, setImpact] = useState(() => emptyVerification("/api/disposable-object", "role"));
  const [protectedEnabled, setProtectedEnabled] = useState(false);
  const [protectedAction, setProtectedAction] = useState(() => emptyVerification("/api/admin/protected-action", "allowed"));
  const [rollbackPath, setRollbackPath] = useState("/api/disposable-object");
  const [rollbackMethod, setRollbackMethod] = useState<"POST" | "PATCH" | "PUT">("PATCH");
  const [restoration, setRestoration] = useState(() => emptyVerification("/api/disposable-object", "role"));
  const [expiresAt, setExpiresAt] = useState(() => toLocalDateTime(new Date(Date.now() + 60 * 60_000)));
  const [acknowledged, setAcknowledged] = useState(false);
  const [authorization, setAuthorization] = useState("");
  const [mode, setMode] = useState<"guided" | "json">("guided");
  const [jsonText, setJsonText] = useState("{}");
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([]);
  const [preview, setPreview] = useState<Record<string, any>>();
  const [approval, setApproval] = useState<Record<string, any>>();
  const [result, setResult] = useState<Record<string, any>>();
  const [message, setMessage] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  useEffect(() => { void Promise.all([apiGet<{ targets: TargetSummary[] }>("/api/targets"), apiGet<{ profiles: CredentialSummary[] }>("/api/credential-profiles")]).then(([targetBody, credentialBody]) => { setTargets(targetBody.targets.filter((target) => Boolean((target as TargetSummary & { productionEnabled?: boolean }).productionEnabled))); setCredentials(credentialBody.profiles.filter((profile) => profile.enabled)); }); }, []);
  const guidedCase = useMemo(() => buildCase({ targetId, credentialId, caseId, intent, securityCategory, alias, authorityField, mutationValue, rollbackValue, allowedValues, identity, precondition, mutationPath, mutationMethod, impact, protectedEnabled, protectedAction, rollbackPath, rollbackMethod, restoration, expiresAt, acknowledged }), [targetId, credentialId, caseId, intent, securityCategory, alias, authorityField, mutationValue, rollbackValue, allowedValues, identity, precondition, mutationPath, mutationMethod, impact, protectedEnabled, protectedAction, rollbackPath, rollbackMethod, restoration, expiresAt, acknowledged]);
  useEffect(() => { if (mode === "guided") setJsonText(JSON.stringify(guidedCase, null, 2)); }, [guidedCase, mode]);
  const activeCase = (): ProductionCase => {
    if (mode === "guided") return guidedCase;
    const parsed = JSON.parse(jsonText) as unknown;
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object" || containsProhibitedKey(parsed)) throw new Error("Production case JSON must be a safe object.");
    return parsed as ProductionCase;
  };
  const clearBinding = () => { setPreview(undefined); setApproval(undefined); setResult(undefined); setDiagnostics([]); };
  const previewCase = async () => {
    try { const body = await apiMutation<Record<string, any>>("/api/production-mutations/preview", "POST", activeCase()); setPreview(body); setApproval(undefined); setDiagnostics([]); setMessage("Exact production case preview resolved. No mutation was transmitted."); }
    catch (error) { captureError(error, setDiagnostics, setMessage); }
  };
  const approveCase = async () => {
    try { const body = await apiMutation<Record<string, any>>("/api/production-mutations/approvals", "POST", { case: activeCase(), authorizationDeclaration: authorization, confirmation: "I_CONFIRM_PRODUCTION_CONTROLLED_MUTATION_AND_CLEANUP_DUTY" }); const approved = await apiMutation<Record<string, any>>(`/api/controlled-mutations/approvals/${body.approval.id}/approve`, "POST", {}); setApproval(approved.approval); setPreview(body); setDiagnostics([]); setMessage("The exact reviewed case is approved and cryptographically bound. Any edit requires a new preview and approval."); }
    catch (error) { captureError(error, setDiagnostics, setMessage); }
  };
  const executeCase = async () => {
    if (!approval) return;
    try { const body = await apiMutation<Record<string, any>>(`/api/production-mutations/approvals/${approval.id}/execute`, "POST", activeCase()); setResult(body); setMessage("Approved production mutation queued through the isolated worker with mandatory restoration."); }
    catch (error) { captureError(error, setDiagnostics, setMessage); }
  };
  const exportCase = () => { const url = URL.createObjectURL(new Blob([JSON.stringify({ format: "routecairn-production-mutation", version: 1, case: activeCase() }, null, 2)], { type: "application/json" })); const link = document.createElement("a"); link.href = url; link.download = `${caseId || "production-mutation"}.routecairn.json`; link.click(); URL.revokeObjectURL(url); };
  const importCase = async (file: File) => { if (file.size > 256 * 1024) throw new Error("Production case import exceeds 256 KiB."); const parsed = JSON.parse(await file.text()) as any; const value = parsed?.format === "routecairn-production-mutation" ? parsed.case : parsed; if (!value || Array.isArray(value) || typeof value !== "object" || containsProhibitedKey(value)) throw new Error("Imported production case is unsafe or invalid."); setMode("json"); setJsonText(JSON.stringify(value, null, 2)); clearBinding(); setMessage("Imported in the browser. Resolve an exact preview before approval."); };
  const edit = <T,>(setter: React.Dispatch<React.SetStateAction<T>>, value: T) => { setter(value); clearBinding(); };
  const selectedTarget = targets.find((target) => target.id === targetId);
  const eligibleCredentials = credentials.filter((profile) => !profile.targetId || profile.targetId === targetId);
  return <section>
    <div className="page-header"><h2>Production Controlled Mutation</h2><p>Build one exact reversible disposable-object test, review its request contract, approve it, execute it, and verify restoration.</p></div>
    <div className="cleanup-emergency" role="alert"><div><strong>Production safety gate</strong><p>Deletion is unavailable. Credentials stay in the vault. Mutation and rollback bodies are derived from one allowlisted authority field.</p></div><span>EXPLICIT APPROVAL REQUIRED</span></div>
    <div className="cards"><div className="metric"><strong>{targets.length}</strong><span>Production-enabled targets</span></div><div className="metric"><strong>{credentials.length}</strong><span>Enabled actor profiles</span></div><div className="metric"><strong>{preview ? "BOUND" : "DRAFT"}</strong><span>Plan state</span></div></div>
    <div className="workflow-editor-toolbar"><button className={mode === "guided" ? "selected" : ""} onClick={() => { setMode("guided"); clearBinding(); }}>Guided builder</button><button className={mode === "json" ? "selected" : ""} onClick={() => { setJsonText(JSON.stringify(guidedCase, null, 2)); setMode("json"); clearBinding(); }}>JSON alternative</button><button onClick={exportCase}>Export safe JSON</button><button onClick={() => fileRef.current?.click()}>Import JSON</button><input ref={fileRef} hidden type="file" accept="application/json,.json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importCase(file).catch((error: unknown) => setMessage(error instanceof Error ? error.message : "Import failed.")); event.currentTarget.value = ""; }} /></div>
    {mode === "guided" ? <div className="production-mutation-builder form">
      <fieldset><legend>1. Target and actor</legend><label>Registered production target<select value={targetId} onChange={(event) => edit(setTargetId, event.target.value)}><option value="">Select target</option>{targets.map((target) => <option key={target.id} value={target.id}>{target.displayName} · {target.baseOrigin}</option>)}</select></label><label>Vault credential profile<select value={credentialId} onChange={(event) => edit(setCredentialId, event.target.value)}><option value="">Select actor</option>{eligibleCredentials.map((profile) => <option key={profile.id} value={profile.id}>{profile.safeAlias}</option>)}</select></label><label>Case ID<input value={caseId} onChange={(event) => edit(setCaseId, event.target.value)} /></label><label>Disposable object alias<input value={alias} onChange={(event) => edit(setAlias, event.target.value)} /></label></fieldset>
      <fieldset><legend>2. Intent and transition</legend><label>Case intent<select value={intent} onChange={(event) => edit(setIntent, event.target.value as MutationIntent)}><option value="SECURITY_NEGATIVE">Security negative — mutation must be rejected</option><option value="AUTHORIZED_ACCEPTANCE">Authorized acceptance — mutation must succeed and restore</option><option value="ROLLBACK_ACCEPTANCE">Rollback acceptance — exercise and verify restoration</option><option value="RECOVERY_ACCEPTANCE">Recovery acceptance — exercise crash-recovery contract</option></select></label><label>Security category<select value={securityCategory} onChange={(event) => edit(setSecurityCategory, event.target.value as SecurityCategory)}><option value="MASS_ASSIGNMENT">Mass assignment</option><option value="PRIVILEGE_ESCALATION">Privilege escalation</option><option value="CROSS_TENANT_REASSIGNMENT">Cross-tenant reassignment</option><option value="OWNERSHIP_TAKEOVER">Ownership takeover</option><option value="ADMINISTRATIVE_BOUNDARY">Administrative boundary</option></select></label><label>Authority or state field<input value={authorityField} onChange={(event) => edit(setAuthorityField, event.target.value)} /></label><label>Mutation value (JSON scalar)<input value={mutationValue} onChange={(event) => edit(setMutationValue, event.target.value)} /></label><label>Rollback value (JSON scalar)<input value={rollbackValue} onChange={(event) => edit(setRollbackValue, event.target.value)} /></label><label>Explicitly allowed values (comma-separated JSON scalars)<input value={allowedValues} onChange={(event) => edit(setAllowedValues, event.target.value)} /></label><p className="muted">Only security-negative cases can create a privilege-mutation finding. Acceptance and recovery cases record operational success or failure independently.</p></fieldset>
      <VerificationBuilder title="3. Actor identity" value={identity} onChange={(value) => edit(setIdentity, value)} />
      <VerificationBuilder title="4. Disposable-object precondition" value={precondition} onChange={(value) => edit(setPrecondition, value)} />
      <fieldset><legend>5. Mutation request</legend><label>Method<select value={mutationMethod} onChange={(event) => edit(setMutationMethod, event.target.value as typeof mutationMethod)}><option>POST</option><option>PATCH</option><option>PUT</option></select></label><label>Same-origin path<input value={mutationPath} onChange={(event) => edit(setMutationPath, event.target.value)} /></label></fieldset>
      <VerificationBuilder title="6. Impact verification" value={impact} onChange={(value) => edit(setImpact, value)} />
      <fieldset><legend>7. Protected-action proof</legend><label className="inline-check"><input type="checkbox" checked={protectedEnabled} onChange={(event) => edit(setProtectedEnabled, event.target.checked)} /> Require independent protected-action proof</label>{protectedEnabled && <VerificationBuilder title="Protected action" value={protectedAction} onChange={(value) => edit(setProtectedAction, value)} nested />}</fieldset>
      <fieldset><legend>8. Rollback request</legend><label>Method<select value={rollbackMethod} onChange={(event) => edit(setRollbackMethod, event.target.value as typeof rollbackMethod)}><option>POST</option><option>PATCH</option><option>PUT</option></select></label><label>Same-origin path<input value={rollbackPath} onChange={(event) => edit(setRollbackPath, event.target.value)} /></label></fieldset>
      <VerificationBuilder title="9. Restoration verification" value={restoration} onChange={(value) => edit(setRestoration, value)} />
      <fieldset><legend>10. Approval window</legend><label>Authorization expires<input type="datetime-local" value={expiresAt} onChange={(event) => edit(setExpiresAt, event.target.value)} /></label><label className="inline-check"><input type="checkbox" checked={acknowledged} onChange={(event) => edit(setAcknowledged, event.target.checked)} /> I acknowledge this exact production mutation and mandatory cleanup duty</label></fieldset>
    </div> : <label className="advanced-json">Production case JSON<textarea rows={32} value={jsonText} spellCheck={false} onChange={(event) => { setJsonText(event.target.value); clearBinding(); }} /></label>}
    {diagnostics.length > 0 && <div className="workflow-diagnostic-summary" role="alert"><strong>{diagnostics.length} field issue(s)</strong>{diagnostics.map((item, index) => <span key={`${item.path.join(".")}-${index}`}><code>{item.path.join(".") || "root"}</code> — {item.message}</span>)}</div>}
    <label>Authorization declaration<textarea value={authorization} onChange={(event) => { setAuthorization(event.target.value); setApproval(undefined); }} placeholder="I own this production target and authorize this exact reversible disposable-account test." /></label>
    <div className="actions"><button onClick={() => void previewCase()}>Resolve exact preview</button><button className="primary" disabled={authorization.length < 40 || !preview} onClick={() => void approveCase()}>Approve reviewed plan</button><button className="danger" disabled={!approval} onClick={() => window.confirm("Execute this exact production mutation case now? Rollback remains mandatory.") && void executeCase()}>Execute approved case</button></div>
    {message && <p aria-live="polite">{message}</p>}
    {preview?.preview && <div className="panel"><h3>Exact request and recovery preview</h3><dl className="dense-dl"><dt>Target</dt><dd>{preview.preview.targetOrigin}</dd><dt>Intent</dt><dd>{preview.preview.intent} · {preview.preview.expectedOutcome}</dd><dt>Security category</dt><dd>{preview.preview.securityCategory}</dd><dt>Identity</dt><dd><code>{preview.preview.identityEndpoint}</code> · {preview.preview.actorIdentityAssertionPath}</dd><dt>Disposable object</dt><dd><code>{preview.preview.preconditionEndpoint}</code> · {preview.preview.disposableObjectIdentityAssertionPath}</dd><dt>Authority field</dt><dd>{preview.preview.authorityField}</dd><dt>Mutation value</dt><dd><code>{preview.preview.mutationValueHash}</code> (hashed)</dd><dt>Protected proof</dt><dd>{preview.preview.protectedActionConfigured ? "Required" : "Not configured"}</dd><dt>Selected target</dt><dd>{selectedTarget?.displayName}</dd></dl><ol>{preview.preview.endpoints.map((endpoint: string, index: number) => <li key={`${index}:${endpoint}`}><code>{endpoint}</code></li>)}</ol></div>}
    {result && <div className="panel"><h3>Execution and recovery</h3><p>Scan <a href={`/scans/${result.scanId}`}>{result.scanId}</a></p><p>Approval {result.approvalId}</p><strong>{String(result.status)}</strong></div>}
  </section>;
}

function VerificationBuilder({ title, value, onChange, nested = false }: { title: string; value: VerificationDraft; onChange(value: VerificationDraft): void; nested?: boolean }) {
  const content = <><label>GET path<input value={value.path} onChange={(event) => onChange({ ...value, path: event.target.value })} /></label><label>Binding assertion field<input value={value.assertionPath} onChange={(event) => onChange({ ...value, assertionPath: event.target.value })} /></label><label>Expected value (JSON scalar)<input value={value.expectedValue} onChange={(event) => onChange({ ...value, expectedValue: event.target.value })} /></label><label>Attempts<input type="number" min={1} max={10} value={value.attempts} onChange={(event) => onChange({ ...value, attempts: Number(event.target.value) })} /></label><label>Delay (ms)<input type="number" min={0} max={30000} value={value.delayMs} onChange={(event) => onChange({ ...value, delayMs: Number(event.target.value) })} /></label></>;
  return nested ? <div className="nested-builder">{content}</div> : <fieldset><legend>{title}</legend>{content}</fieldset>;
}

function buildCase(input: { targetId: string; credentialId: string; caseId: string; intent: MutationIntent; securityCategory: SecurityCategory; alias: string; authorityField: string; mutationValue: string; rollbackValue: string; allowedValues: string; identity: VerificationDraft; precondition: VerificationDraft; mutationPath: string; mutationMethod: "POST" | "PATCH" | "PUT"; impact: VerificationDraft; protectedEnabled: boolean; protectedAction: VerificationDraft; rollbackPath: string; rollbackMethod: "POST" | "PATCH" | "PUT"; restoration: VerificationDraft; expiresAt: string; acknowledged: boolean }): ProductionCase {
  const mutation = parseScalar(input.mutationValue); const rollback = parseScalar(input.rollbackValue);
  return { schemaVersion: 1, caseId: input.caseId, targetId: input.targetId, environment: "PRODUCTION", productionAcknowledged: input.acknowledged, intent: input.intent, securityCategory: input.securityCategory, actorCredentialProfileId: input.credentialId, disposableTargetAlias: input.alias, authorityField: input.authorityField, mutationValue: mutation, allowedValues: parseScalarList(input.allowedValues), identity: verification(input.identity), actorIdentityAssertionPath: input.identity.assertionPath, precondition: verification(input.precondition), disposableObjectIdentityAssertionPath: input.precondition.assertionPath, mutation: { method: input.mutationMethod, path: input.mutationPath, body: { [input.authorityField]: mutation } }, impactVerification: verification({ ...input.impact, expectedValue: input.impact.expectedValue === "replace-with-exact-value" ? input.mutationValue : input.impact.expectedValue }), ...(input.protectedEnabled ? { protectedAction: verification(input.protectedAction) } : {}), rollback: { method: input.rollbackMethod, path: input.rollbackPath, body: { [input.authorityField]: rollback } }, restorationVerification: verification({ ...input.restoration, expectedValue: input.restoration.expectedValue === "replace-with-exact-value" ? input.rollbackValue : input.restoration.expectedValue }), authorizationExpiresAt: input.expiresAt ? new Date(input.expiresAt).toISOString() : "" };
}
function verification(value: VerificationDraft) { const assertion: Assertion = { path: value.assertionPath, operator: "EQUALS", expectedValue: parseScalar(value.expectedValue) }; return { method: "GET", path: value.path, assertions: [assertion], attempts: value.attempts, delayMs: value.delayMs }; }
function parseScalar(value: string): unknown { try { return JSON.parse(value); } catch { return value; } }
function parseScalarList(value: string): unknown[] { try { const parsed = JSON.parse(`[${value}]`) as unknown; return Array.isArray(parsed) ? parsed : [parsed]; } catch { return value.split(",").map((item) => parseScalar(item.trim())).filter((item) => item !== ""); } }
function toLocalDateTime(value: Date): string { const offset = value.getTimezoneOffset() * 60_000; return new Date(value.getTime() - offset).toISOString().slice(0, 16); }
function containsProhibitedKey(value: unknown): boolean { return Boolean(value) && typeof value === "object" && (Array.isArray(value) ? value.some(containsProhibitedKey) : Object.entries(value as Record<string, unknown>).some(([key, child]) => ["__proto__", "prototype", "constructor"].includes(key) || containsProhibitedKey(child))); }
function captureError(error: unknown, setDiagnostics: (value: Diagnostic[]) => void, setMessage: (value: string) => void) { if (error instanceof DashboardApiError) { setDiagnostics([...error.diagnostics]); setMessage(error.coreCode ? `${error.message} (${error.coreCode})` : error.message); } else setMessage(error instanceof Error ? error.message : "Production mutation operation failed."); }
