import React, { useEffect, useMemo, useRef, useState } from "react";
import { apiGet, apiMutation } from "./api";

export type AdvancedEngineId =
  | "supabase-authorization"
  | "authentication-lifecycle"
  | "authentication-lifecycle-automation"
  | "business-invariant"
  | "controlled-race"
  | "api-graphql-authorization"
  | "link-portal-export-security"
  | "operational-endpoint-security"
  | "billing-entitlement-security"
  | "assisted-review"
  | "pre-handover-assault"
  | "bug-bounty-authorization"
  | "active-vulnerability-validation";

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
type JsonObject = { [key: string]: JsonValue };

export interface AdvancedEngineDraft {
  id: AdvancedEngineId;
  enabled: boolean;
  editorMode: "guided" | "json";
  value: JsonObject;
}

interface CatalogEntry {
  id: AdvancedEngineId;
  displayName: string;
  description: string;
  moduleId?: string;
  requestField: string;
  safety: string;
  requiresApproval: boolean;
  template: JsonObject;
}

interface Diagnostic { path: string[]; message: string }

interface Props {
  target: string;
  initialEngineId?: AdvancedEngineId;
  initialEngineValue?: JsonObject;
  drafts: AdvancedEngineDraft[];
  selectedModules: string[];
  onChange(drafts: AdvancedEngineDraft[]): void;
  onEnableModule(moduleId: string): void;
  onPreview(): Promise<void>;
}

const maxImportBytes = 512 * 1024;
const prohibitedKey = /^(?:__proto__|prototype|constructor)$/;

export function AdvancedEngineStudio(props: Props) {
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [openId, setOpenId] = useState<AdvancedEngineId>();
  const [loadError, setLoadError] = useState("");
  const initialEngineApplied = useRef(false);
  useEffect(() => {
    let active = true;
    const query = props.target ? `?target=${encodeURIComponent(props.target)}` : "";
    void apiGet<{ engines: CatalogEntry[] }>(`/api/advanced-engines/catalog${query}`)
      .then((body) => { if (active) { setCatalog(Array.isArray(body.engines) ? body.engines : []); setLoadError(""); } })
      .catch((error: unknown) => { if (active) setLoadError(error instanceof Error ? error.message : "Advanced engine catalog unavailable."); });
    return () => { active = false; };
  }, [props.target]);
  const activeDraft = props.drafts.find((item) => item.id === openId);
  const activeMetadata = catalog.find((item) => item.id === openId);
  const updateDraft = (next: AdvancedEngineDraft) => props.onChange(props.drafts.map((item) => item.id === next.id ? next : item));
  const enable = (entry: CatalogEntry) => {
    const existing = props.drafts.find((item) => item.id === entry.id);
    const mutuallyExclusive = entry.id === "authentication-lifecycle" ? ["authentication-lifecycle-automation"] : entry.id === "authentication-lifecycle-automation" ? ["authentication-lifecycle"] : entry.id === "pre-handover-assault" ? ["bug-bounty-authorization", "assisted-review"] : entry.id === "bug-bounty-authorization" || entry.id === "assisted-review" ? ["pre-handover-assault"] : [];
    const base = props.drafts.map((item) => mutuallyExclusive.includes(item.id) ? { ...item, enabled: false } : item);
    if (existing) props.onChange(base.map((item) => item.id === existing.id ? { ...existing, enabled: true } : item));
    else props.onChange([...base, { id: entry.id, enabled: true, editorMode: "guided", value: structuredClone(entry.template) }]);
    if (entry.moduleId && !props.selectedModules.includes(entry.moduleId)) props.onEnableModule(entry.moduleId);
    setOpenId(entry.id);
  };
  useEffect(() => {
    if (initialEngineApplied.current || !props.initialEngineId || catalog.length === 0) return;
    const entry = catalog.find((item) => item.id === props.initialEngineId);
    if (!entry) return;
    initialEngineApplied.current = true;
    if (props.initialEngineValue) {
      const existing = props.drafts.find((item) => item.id === entry.id);
      const next = { id: entry.id, enabled: true, editorMode: "guided" as const, value: structuredClone(props.initialEngineValue) };
      props.onChange(existing ? props.drafts.map((item) => item.id === entry.id ? next : item) : [...props.drafts, next]);
      if (entry.moduleId && !props.selectedModules.includes(entry.moduleId)) props.onEnableModule(entry.moduleId);
      setOpenId(entry.id);
    } else enable(entry);
  }, [catalog, props.initialEngineId, props.initialEngineValue]);
  return (
    <section className="advanced-engine-studio" aria-label="Advanced security engines">
      <header>
        <div><h4>Advanced security engines</h4><p>Configure exact executable contracts in the dashboard. Server filesystem paths are not required.</p></div>
        <button type="button" onClick={() => void props.onPreview()}>Preview complete plan</button>
      </header>
      {loadError && <p className="error" role="alert">{loadError}</p>}
      <div className="advanced-engine-catalog">
        {catalog.map((entry) => {
          const draft = props.drafts.find((item) => item.id === entry.id);
          const moduleEnabled = !entry.moduleId || props.selectedModules.includes(entry.moduleId);
          return <article className={`advanced-engine-card ${draft?.enabled ? "enabled" : ""}`} key={entry.id}>
            <header><div><h5>{entry.displayName}</h5><p>{entry.description}</p></div><span className={`badge ${draft?.enabled ? "available" : "neutral"}`}>{draft?.enabled ? "CONFIGURED" : "NOT CONFIGURED"}</span></header>
            <dl className="dense-dl"><dt>Cases</dt><dd>{draft ? countCases(draft.value) : 0}</dd><dt>Module</dt><dd>{entry.moduleId ?? "Orchestration policy"}{moduleEnabled ? "" : " · disabled"}</dd><dt>Approval</dt><dd>{entry.requiresApproval ? "Explicit contract required" : "Read-only / review gate"}</dd></dl>
            <p className="safety-note">{entry.safety}</p>
            <div className="actions">
              {!draft?.enabled && <button type="button" onClick={() => enable(entry)}>Configure</button>}
              {draft?.enabled && <><button type="button" onClick={() => setOpenId(entry.id)}>Edit</button><button type="button" onClick={() => updateDraft({ ...draft, enabled: false })}>Disable</button></>}
              {draft && <button type="button" onClick={() => window.confirm(`Clear ${entry.displayName}?`) && props.onChange(props.drafts.filter((item) => item.id !== entry.id))}>Clear</button>}
              {draft?.enabled && entry.moduleId && !moduleEnabled && <button type="button" onClick={() => props.onEnableModule(entry.moduleId!)}>Enable module</button>}
            </div>
          </article>;
        })}
      </div>
      {activeDraft && activeMetadata && <AdvancedEngineEditor draft={activeDraft} metadata={activeMetadata} onChange={updateDraft} onClose={() => setOpenId(undefined)} onPreview={props.onPreview} />}
    </section>
  );
}

function AdvancedEngineEditor({ draft, metadata, onChange, onClose, onPreview }: { draft: AdvancedEngineDraft; metadata: CatalogEntry; onChange(value: AdvancedEngineDraft): void; onClose(): void; onPreview(): Promise<void> }) {
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([]);
  const [status, setStatus] = useState("Not yet validated.");
  const [json, setJson] = useState(() => JSON.stringify(draft.value, null, 2));
  const fileRef = useRef<HTMLInputElement>(null);
  useEffect(() => setJson(JSON.stringify(draft.value, null, 2)), [draft.value]);
  const validate = async (value = draft.value) => {
    const result = await apiMutation<{ valid: boolean; diagnostics: Diagnostic[]; value?: JsonObject }>("/api/advanced-engines/validate", "POST", { engineId: draft.id, value });
    setDiagnostics(result.diagnostics);
    setStatus(result.valid ? "Schema valid. Resolve the complete plan for scope, actor, budget, and approval checks." : `${result.diagnostics.length} field issue(s) require attention.`);
    if (result.valid && result.value) onChange({ ...draft, value: result.value });
  };
  const exportJson = () => {
    const body = JSON.stringify({ format: "routecairn-advanced-engine", version: 1, engineId: draft.id, value: draft.value }, null, 2);
    const url = URL.createObjectURL(new Blob([body], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `${draft.id}.routecairn.json`; link.click(); URL.revokeObjectURL(url);
  };
  const importJson = async (file: File) => {
    if (file.size > maxImportBytes) throw new Error("Import exceeds 512 KiB.");
    const parsed = parseJson(await file.text());
    const envelope = isObject(parsed) && parsed.format === "routecairn-advanced-engine" ? parsed : undefined;
    if (envelope && envelope.engineId !== draft.id) throw new Error("Imported engine ID does not match this builder.");
    const value = envelope ? envelope.value : parsed;
    if (!isObject(value) || containsProhibitedKey(value)) throw new Error("Import must be a safe JSON object without prototype-related keys.");
    onChange({ ...draft, value });
    await validate(value);
    setStatus("Imported in the browser and validated against the server schema.");
  };
  const updateJson = (text: string) => {
    setJson(text);
    try {
      const value = parseJson(text);
      if (!isObject(value) || containsProhibitedKey(value)) throw new Error("A safe JSON object is required.");
      onChange({ ...draft, value }); setStatus("JSON syntax valid; schema validation is still required.");
    } catch (error) { setStatus(error instanceof Error ? error.message : "Invalid JSON."); }
  };
  return <section className="advanced-engine-editor" aria-label={`${metadata.displayName} builder`}>
    <header><div><h4>{metadata.displayName}</h4><p>{metadata.description}</p></div><button type="button" onClick={onClose}>Close</button></header>
    <div className="workflow-editor-toolbar">
      <button type="button" className={draft.editorMode === "guided" ? "selected" : ""} onClick={() => onChange({ ...draft, editorMode: "guided" })}>Guided builder</button>
      <button type="button" className={draft.editorMode === "json" ? "selected" : ""} onClick={() => onChange({ ...draft, editorMode: "json" })}>JSON alternative</button>
      <button type="button" onClick={() => void validate().catch((error: unknown) => setStatus(error instanceof Error ? error.message : "Validation failed."))}>Validate fields</button>
      <button type="button" onClick={() => void onPreview()}>Plan + budget preview</button>
      <button type="button" onClick={exportJson}>Export safe JSON</button>
      <button type="button" onClick={() => fileRef.current?.click()}>Import JSON</button>
      <input ref={fileRef} hidden type="file" accept="application/json,.json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importJson(file).catch((error: unknown) => setStatus(error instanceof Error ? error.message : "Import failed.")); event.currentTarget.value = ""; }} />
    </div>
    <p className="safety-note">{metadata.safety}</p>
    {diagnostics.length > 0 && <div className="workflow-diagnostic-summary" role="alert"><strong>{diagnostics.length} field issue(s)</strong>{diagnostics.map((item, index) => <button type="button" key={`${item.path.join(".")}-${index}`} onClick={() => document.getElementById(fieldId(draft.id, item.path))?.focus()}><code>{item.path.join(".") || "root"}</code> — {item.message}</button>)}</div>}
    {draft.editorMode === "guided" ? <GuidedValueEditor engineId={draft.id} root={draft.value} value={draft.value} path={[]} diagnostics={diagnostics} onChange={(value) => onChange({ ...draft, value })} /> : <label className="advanced-json">Engine JSON<textarea rows={28} spellCheck={false} value={json} onChange={(event) => updateJson(event.target.value)} /></label>}
    <p role="status">{status}</p>
  </section>;
}

function GuidedValueEditor({ engineId, root, value, path, diagnostics, onChange }: { engineId: AdvancedEngineId; root: JsonObject; value: JsonObject; path: Array<string | number>; diagnostics: Diagnostic[]; onChange(value: JsonObject): void }) {
  return <div className={path.length ? "structured-group" : "structured-root"}>{Object.entries(value).map(([key, child]) => {
    const nextPath = [...path, key];
    const fieldDiagnostics = diagnosticsForPath(diagnostics, nextPath);
    if (Array.isArray(child)) return <fieldset key={key}><legend>{humanize(key)} <small>{child.length} item(s)</small></legend>
      {child.map((entry, index) => <section className="structured-array-item" key={`${key}-${index}`}><header><h5>{itemLabel(entry, key, index)}</h5><div className="row-actions"><button type="button" onClick={() => onChange(updateAtPath(root, nextPath, [...child.slice(0, index + 1), structuredClone(entry), ...child.slice(index + 1)]))}>Duplicate</button><button type="button" disabled={child.length <= minimumArrayLength(key)} onClick={() => onChange(updateAtPath(root, nextPath, child.filter((_, itemIndex) => itemIndex !== index)))}>Remove</button></div></header>
        {isObject(entry) ? <GuidedValueEditor engineId={engineId} root={root} value={entry} path={[...nextPath, index]} diagnostics={diagnostics} onChange={onChange} /> : <ScalarInput engineId={engineId} root={root} path={[...nextPath, index]} fieldName={key} value={entry as JsonPrimitive} diagnostics={diagnostics} onChange={onChange} />}
      </section>)}
      <button type="button" onClick={() => onChange(updateAtPath(root, nextPath, [...child, arraySeed(engineId, root, nextPath, child)]))}>Add {humanize(singular(key))}</button>
      {fieldDiagnostics.map((message) => <small role="alert" key={message}>{message}</small>)}
    </fieldset>;
    if (isObject(child)) {
      const record = isRecordPath(nextPath);
      return <fieldset key={key}><legend>{humanize(key)}</legend>{record
        ? Object.entries(child).map(([entryKey, entryValue]) => <section className="structured-record-item" key={entryKey}><GuidedValueEditor engineId={engineId} root={root} value={{ [entryKey]: entryValue }} path={nextPath} diagnostics={diagnostics} onChange={onChange} /><button type="button" onClick={() => onChange(updateAtPath(root, nextPath, withoutKey(child, entryKey)))}>Remove {humanize(entryKey)}</button></section>)
        : <GuidedValueEditor engineId={engineId} root={root} value={child} path={nextPath} diagnostics={diagnostics} onChange={onChange} />}
        {record && <button type="button" onClick={() => { const name = window.prompt(`New ${humanize(key)} key`); if (!name || prohibitedKey.test(name) || Object.hasOwn(child, name)) return; onChange(updateAtPath(root, nextPath, { ...child, [name]: key === "allowedOperations" ? [] : "" })); }}>Add entry</button>}
      </fieldset>;
    }
    return <ScalarInput key={key} engineId={engineId} root={root} path={nextPath} fieldName={key} value={child} diagnostics={diagnostics} onChange={onChange} />;
  })}</div>;
}

function ScalarInput({ engineId, root, path, fieldName, value, diagnostics, onChange }: { engineId: AdvancedEngineId; root: JsonObject; path: Array<string | number>; fieldName: string; value: JsonPrimitive; diagnostics: Diagnostic[]; onChange(value: JsonObject): void }) {
  const messages = diagnosticsForPath(diagnostics, path);
  const options = enumOptions(engineId, fieldName, path, value);
  const id = fieldId(engineId, path);
  return <label className={messages.length ? "field-invalid" : ""}>{humanize(fieldName)}
    {typeof value === "boolean" ? <input id={id} type="checkbox" checked={value} aria-invalid={messages.length > 0} onChange={(event) => onChange(updateAtPath(root, path, event.target.checked))} />
      : options.length ? <select id={id} value={String(value ?? "")} aria-invalid={messages.length > 0} onChange={(event) => onChange(updateAtPath(root, path, coerce(event.target.value, value)))}>{options.map((option) => <option key={option} value={option}>{option}</option>)}</select>
        : <input id={id} type={typeof value === "number" ? "number" : fieldName.toLowerCase().includes("at") ? "text" : "text"} value={value === null ? "null" : String(value)} aria-invalid={messages.length > 0} onChange={(event) => onChange(updateAtPath(root, path, coerce(event.target.value, value)))} />}
    {messages.map((message) => <small role="alert" key={message}>{message}</small>)}
  </label>;
}

export function advancedEngineRequestValues(drafts: readonly AdvancedEngineDraft[]): Record<string, JsonObject> {
  const fields: Record<AdvancedEngineId, string> = {
    "supabase-authorization": "supabaseAuthorization", "authentication-lifecycle": "authenticationLifecycle", "authentication-lifecycle-automation": "authenticationLifecycleAutomation",
    "business-invariant": "businessInvariant", "controlled-race": "controlledRace", "api-graphql-authorization": "apiGraphql", "link-portal-export-security": "linkPortalSecurity",
    "operational-endpoint-security": "operationalEndpointSecurity", "billing-entitlement-security": "billingEntitlement", "assisted-review": "assistedReview", "pre-handover-assault": "preHandover", "bug-bounty-authorization": "targetAuthorization", "active-vulnerability-validation": "activeVulnerability"
  };
  const result: Record<string, JsonObject> = {};
  for (const item of drafts.filter((candidate) => candidate.enabled)) {
    if (item.id === "pre-handover-assault") {
      if (isObject(item.value.orchestration)) result.preHandover = item.value.orchestration;
      if (isObject(item.value.authorization)) result.targetAuthorization = item.value.authorization;
      continue;
    }
    result[fields[item.id]] = item.value;
  }
  return result;
}

function countCases(value: JsonObject): number {
  if (isObject(value.orchestration)) return countCases(value.orchestration);
  if (Array.isArray(value.cases)) return value.cases.length;
  return ["checks", "criticalCases", "objects"].reduce((count, key) => count + (Array.isArray(value[key]) ? value[key].length : 0), 0);
}
function parseJson(text: string): unknown { if (new TextEncoder().encode(text).byteLength > maxImportBytes) throw new Error("JSON exceeds 512 KiB."); return JSON.parse(text) as unknown; }
function containsProhibitedKey(value: unknown): boolean {
  if (value === null || typeof value !== "object") return false;
  return Array.isArray(value)
    ? value.some(containsProhibitedKey)
    : Object.entries(value).some(([key, child]) => prohibitedKey.test(key) || containsProhibitedKey(child));
}
function isObject(value: unknown): value is JsonObject { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function updateAtPath(root: JsonObject, path: Array<string | number>, value: JsonValue): JsonObject { const copy = structuredClone(root); let cursor: JsonValue = copy; for (const part of path.slice(0, -1)) { cursor = Array.isArray(cursor) && typeof part === "number" ? cursor[part]! : isObject(cursor) && typeof part === "string" ? cursor[part]! : cursor; } const last = path.at(-1)!; if (Array.isArray(cursor) && typeof last === "number") cursor[last] = value; else if (isObject(cursor) && typeof last === "string") cursor[last] = value; return copy; }
function diagnosticsForPath(diagnostics: Diagnostic[], path: Array<string | number>): string[] { const normalized = path.map(String); return diagnostics.filter((item) => item.path.length >= normalized.length && normalized.every((part, index) => item.path[index] === part)).map((item) => item.message); }
function fieldId(engineId: string, path: Array<string | number>): string { return `advanced-${engineId}-${path.map(String).join("-")}`.replace(/[^A-Za-z0-9_-]/g, "-"); }
function itemLabel(value: JsonValue, key: string, index: number): string { if (isObject(value)) for (const candidate of ["label", "safeAlias", "id", "name", "path"]) if (typeof value[candidate] === "string") return String(value[candidate]); return `${humanize(singular(key))} ${index + 1}`; }
function singular(value: string): string { return value.endsWith("ies") ? `${value.slice(0, -3)}y` : value.endsWith("s") ? value.slice(0, -1) : value; }
function minimumArrayLength(key: string): number { return ["cases", "actors", "routes", "checks", "resources", "endpoints", "steps", "groups", "requests", "assertions", "preState", "postState", "cleanup", "cleanupVerification", "cleanupInvariants", "invariants", "focus", "requiredLanes", "criticalCases", "sequence", "inScope", "rules", "prohibitedActions"].includes(key) ? 1 : 0; }
function arraySeed(engineId: AdvancedEngineId, root: JsonObject, path: Array<string | number>, values: JsonValue[]): JsonValue { if (values.length) return structuredClone(values.at(-1)!); const key = String(path.at(-1)); const origin = configuredOrigin(root); const seeds: Record<string, JsonValue> = {
  "supabase-authorization:catalog.functions": { schema: "public", name: "safe_function", exposed: true, securityDefiner: false, executableBy: ["authenticated"], searchPath: ["public"], usesDynamicSql: false },
  "supabase-authorization:catalog.storageBuckets": { name: "private-files", public: false, ownershipEnforced: true, allowedOperations: { authenticated: ["SELECT"] } },
  "supabase-authorization:catalog.relationships": { name: "documents_owner", from: "public.documents", to: "public.profiles", exposed: true },
  "pre-handover-assault:orchestration.races": { workflowId: "controlled-race", caseId: "replace-race-case" },
  "pre-handover-assault:orchestration.regressions": { workflowId: "authentication-lifecycle", caseId: "replace-case", previousFindingId: "replace-finding", fixReference: "replace-fix", comparisonFingerprint: "0".repeat(64) },
  "bug-bounty-authorization:bugBounty.requests": { origin, path: "/", method: "GET", effect: "READ" }
  };
  const generic: Record<string, JsonValue> = {
    captures: { name: "captured_value", source: "JSON", path: "id" },
    identityAssertions: { path: "id", equals: "replace-with-disposable-object-id" },
    forbiddenColumns: "private_field",
    documentedResponseFields: "id",
    fieldRules: { path: "id", classification: "OBJECT_IDENTITY", expectation: "MUST_BE_PRESENT" }
  };
  return structuredClone(seeds[`${engineId}:${path.map(String).join(".")}`] ?? generic[key] ?? (key.toLowerCase().includes("status") ? 200 : "")); }
function configuredOrigin(root: JsonObject): string { const candidate = isObject(root.orchestration) ? root.orchestration.targetOrigin : root.targetOrigin ?? root.projectUrl; return typeof candidate === "string" ? candidate : "https://authorized-target.invalid"; }
function withoutKey(value: JsonObject, key: string): JsonObject { return Object.fromEntries(Object.entries(value).filter(([candidate]) => candidate !== key)); }
function isRecordPath(path: Array<string | number>): boolean { return ["headers", "fields", "variables", "fieldSecretRefs", "allowedOperations"].includes(String(path.at(-1))); }
function coerce(value: string, previous: JsonPrimitive): JsonPrimitive { if (typeof previous === "number") return Number(value); if (previous === null) return value === "null" ? null : value; return value; }
function humanize(value: string): string { return value.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]/g, " ").replace(/^./, (letter) => letter.toUpperCase()); }
function enumOptions(engineId: AdvancedEngineId, key: string, path: Array<string | number>, current: JsonPrimitive): string[] { const common: Record<string, string[]> = {
  method: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"], environment: ["LOCAL", "TEST", "STAGING", "PRODUCTION"], authSlot: ["anonymous", "primary", "account_a", "account_b"], phase: ["SETUP", "PRE_STATE", "CONTROL", "ACTION", "VERIFY", "CLEANUP"], source: ["JSON", "HEADER", "COOKIE", "CAPTURE", "LITERAL"], operator: ["EQ", "NEQ", "LT", "LTE", "GT", "GTE"], expectedDecision: ["ALLOW", "DENY", "OBSERVE", "OBSERVE_ONLY"], operation: ["SELECT", "INSERT", "UPDATE", "DELETE", "INVOKE", "SIGNED_URL", "OBSERVE", "CHECKOUT_VALIDATION", "SYNTHETIC_PAYMENT_EVENT", "CANCEL_FIXTURE", "REFUND_FIXTURE", "DOWNGRADE_FIXTURE", "PREMIUM_ACCESS_PROBE", "SUBSCRIPTION_ACCESS_PROBE", "RESET_FIXTURE"], boundary: ["NONE", "CROSS_USER", "CROSS_TENANT", "SERVICE_ROLE"], surface: ["TABLE", "STORAGE", "RPC", "RELATIONSHIP"], responseShape: ["LIST", "SINGLE", "VOID"], protocol: ["REST", "GRAPHQL"], mode: ["OBSERVE_ONLY", "CONTROLLED_LIFECYCLE", "CONTROLLED_INVARIANT", "CONTROLLED_RACE", "CONTROLLED_LINK_FLOW", "CONTROLLED_OPERATIONAL_FLOW", "CONTROLLED_SYNTHETIC_BILLING", "BUG_BOUNTY_AUTHORIZED", "OWNED_PRODUCTION", "INTERNAL_STAGING", "PRE_HANDOVER_ASSAULT", "ONCE", "SEQUENTIAL_DUPLICATE", "CONCURRENT_DUPLICATE", "SYNCHRONIZED"], expectation: ["MUST_MATCH_CANONICAL", "ALTERNATES_MUST_DENY", "MUST_REJECT", "MUST_ALLOW", "OBSERVE", "MUST_MATCH_AUTHORIZATION", "CANDIDATE_MUST_NOT_EXPOSE_MORE_FIELDS", "MUST_MATCH_FIELD_SET", "MUST_BE_PRESENT", "MUST_BE_ABSENT", "MUST_BE_REDACTED"], effect: ["READ", "AUTHENTICATION", "MUTATION", "DESTRUCTIVE"], reportMode: ["BUG_BOUNTY_SAFE"], synchronization: ["READY_BARRIER"], owner: ["accountA", "accountB"], scope: ["MAIN", "CLEANUP"]
  }; const categories: Partial<Record<AdvancedEngineId, string[]>> = {
    "authentication-lifecycle": ["LOGIN_ENUMERATION_RESISTANCE", "SESSION_ROTATION_AFTER_LOGIN", "SESSION_FIXATION", "LOGOUT_INVALIDATION", "PASSWORD_CHANGE_SESSION_INVALIDATION", "SESSION_REVOCATION", "IDLE_EXPIRATION", "ABSOLUTE_EXPIRATION", "REFRESH_TOKEN_ROTATION", "PASSWORD_RESET_TOKEN_BINDING", "PASSWORD_RESET_TOKEN_REPLAY", "PASSWORD_RESET_ACCOUNT_CONFUSION", "EMAIL_VERIFICATION_BYPASS", "ACCOUNT_LINKING_CONFUSION", "OAUTH_OIDC_STATE_REDIRECT_VALIDATION", "MFA_ENROLLMENT_REMOVAL", "PASSKEY_ENROLLMENT_REMOVAL", "RECOVERY_CODE_LIFECYCLE", "ADMIN_INVITATION_LIFECYCLE", "TENANT_INVITATION_LIFECYCLE", "DISABLED_USER_SESSION_BEHAVIOR"],
    "business-invariant": ["FINANCIAL_LIMIT", "ONE_TIME_ACTION", "STATE_TRANSITION", "ENTITLEMENT", "SEPARATION_OF_DUTIES", "TRANSACTION_ELIGIBILITY", "ORDERING_CONSTRAINT", "IDEMPOTENCY", "CUSTOM"],
    "controlled-race": ["SAME_OBJECT", "DUPLICATE_REDEMPTION", "INVENTORY", "PAYMENT_ENTITLEMENT", "INVITATION", "ONE_TIME_TOKEN", "CUSTOM"],
    "link-portal-export-security": ["SIGNED_LINK_EXPIRY", "SIGNATURE_TAMPERING", "ID_SUBSTITUTION", "CROSS_TENANT_SIGNED_LINK", "SIGNED_LINK_REPLAY", "SIGNED_LINK_REVOCATION", "INVITE_EMAIL_BINDING", "INVITE_REPLAY", "INVITE_EXPIRATION", "PORTAL_TENANT_BINDING", "EXPORT_AUTHORIZATION", "EVIDENCE_ARTIFACT_AUTHORIZATION", "OBJECT_PATH_OWNERSHIP"],
    "operational-endpoint-security": ["WEBHOOK_SIGNATURE_REJECTION", "WEBHOOK_REPLAY_PROTECTION", "WEBHOOK_IDEMPOTENCY", "WEBHOOK_EVENT_ORDERING", "WEBHOOK_PAYLOAD_INTEGRITY", "CRON_AUTHENTICATION", "CRON_REPLAY_PROTECTION", "CRON_SCOPE_WORKLOAD_LIMIT", "JOB_AUTHORIZATION", "INCIDENT_ACCESS_CONTROL", "HEALTH_INFORMATION_EXPOSURE", "ADMIN_WORKER_AUTHORIZATION"],
    "billing-entitlement-security": ["CLIENT_PRICE_MANIPULATION", "PRODUCT_PLAN_SUBSTITUTION", "UNVERIFIED_PAYMENT_ENTITLEMENT", "CANCELLATION_ENTITLEMENT_PERSISTENCE", "DUPLICATE_WEBHOOK_PROCESSING", "REPLAYED_PAYMENT_EVENT", "CROSS_ACCOUNT_PREMIUM_ACCESS", "REFUND_DOWNGRADE_CONSISTENCY", "SUBSCRIPTION_OWNERSHIP_CONFUSION", "PAYMENT_EVENT_RACE"]
    ,"active-vulnerability-validation": ["SQL_INJECTION", "NOSQL_INJECTION", "REFLECTED_XSS", "SSRF", "COMMAND_INJECTION", "TEMPLATE_INJECTION", "PATH_TRAVERSAL", "CSRF", "OPEN_REDIRECT", "CACHE_POISONING", "CACHE_DECEPTION", "UNSAFE_DESERIALIZATION", "XXE", "HTTP_DESYNCHRONIZATION"]
  }; const contextual = key === "category" || key === "vulnerabilityClass" ? categories[engineId] ?? [] : key === "kind" ? (path.map(String).includes("endpoints") ? ["WEBHOOK", "CRON", "JOB", "INCIDENT", "HEALTH", "ADMIN", "WORKER", "CHECKOUT_VALIDATION", "SYNTHETIC_WEBHOOK", "ENTITLEMENT_STATE", "SUBSCRIPTION_STATE", "PREMIUM_ACCESS", "FIXTURE_CONTROL"] : path.map(String).includes("resources") ? ["SIGNED_LINK", "INVITE", "PORTAL", "EXPORT", "EVIDENCE_ARTIFACT", "OBJECT_PATH"] : path.map(String).includes("routes") ? ["OBJECT", "COLLECTION", "FUNCTION", "SCHEMA", "DOCUMENTATION"] : path.map(String).includes("checks") ? ["OBJECT_AUTHORIZATION", "FUNCTION_AUTHORIZATION", "FIELD_AUTHORIZATION", "TENANT_ISOLATION", "METHOD_CONFUSION", "GRAPHQL_INTROSPECTION", "GRAPHQL_ALIAS_LIMIT", "GRAPHQL_BATCH_LIMIT", "VERSION_BOUNDARY"] : []) : common[key] ?? [];
  const value = current === null ? "null" : String(current); return contextual.length && !contextual.includes(value) ? [value, ...contextual] : contextual;
}
