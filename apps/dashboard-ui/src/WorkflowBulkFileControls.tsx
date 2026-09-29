import React from "react";
import type { WorkflowCapability, WorkflowDraft } from "./AuthorizationWorkflowStudio";
import { diagnosticFieldId, type WorkflowValidationDiagnostic } from "./WorkflowDiagnostics";

type BulkDraft = Extract<WorkflowDraft, { workflowId: "bulk-authorization" }>;
type BulkBaseline = NonNullable<BulkDraft["config"]["definitions"][number]["cases"][number]["objects"][number]["baseline"]>;
type BulkPostcondition = BulkDraft["config"]["definitions"][number]["cases"][number]["postconditionChecks"][number];

export const safetyModeHelp: Record<string, string> = {
  GET_ONLY:
    "Only safe GET requests execute; no pre/post state comparison is needed.",
  OPERATOR_ATTESTED_DRY_RUN:
    "The POST executes because the operator attests that the exact endpoint and marker are non-mutating. RouteCairn does not independently prove non-mutation.",
  POSTCONDITION_VERIFIED_DRY_RUN:
    "Configured GETs run before and after POST and compare only named scalar fields. This strengthens the dry-run evidence but cannot exclude unobserved side effects.",
};

export const proofModeHelp: Record<string, string> = {
  HEADERS_ONLY:
    "Requests headers only. HEAD does not prove body access, and names or content types do not prove file identity.",
  METADATA_ONLY:
    "Reads bounded metadata. Identity requires the configured metadata path; metadata access does not prove file-content disclosure.",
  BOUNDED_PREFIX:
    "Reads only the configured byte range. A prefix fingerprint does not prove access to the entire file.",
  FULL_STREAM_FINGERPRINT:
    "Reads the complete stream only within the configured cap and retains a fingerprint, never raw bytes. Oversized streams are inconclusive.",
  SIGNED_URL_ONLY:
    "Reads bounded issuance metadata and the configured signed-URL field. Issuance alone does not prove a successful download.",
};

export function defaultBaseline(objectId: string, actorId: string): BulkBaseline {
  return {
    id: `baseline-${objectId}`,
    source: "SAFE_GET",
    actorId,
    method: "GET",
    url: "/api/records/{{OBJECT_ID}}",
    headers: { Accept: "application/json" },
    expectedDecision: "OBSERVE_ONLY",
    requireVerifiedIdentity: true,
    objectIdentityField: "id",
    maxResponseBytes: 65536,
    maxJsonDepth: 10,
  };
}
export function defaultPostcondition(
  objectId: string,
  actorId: string,
  index: number,
): BulkPostcondition {
  return {
    id: `state-check-${index + 1}`,
    actorId,
    objectId,
    method: "GET",
    url: "/api/records/{{OBJECT_ID}}",
    headers: { Accept: "application/json" },
    objectIdentityField: "id",
    objectStateField: "state",
    fields: [{ path: "state" }],
    requireVerifiedIdentity: true,
    maxResponseBytes: 65536,
    maxJsonDepth: 10,
  };
}
export function opts(capability: WorkflowCapability, key: string): string[] {
  return capability.guidedOptions?.[key] ?? capability.expectationTypes;
}
export function human(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .replace(/^./, (letter) => letter.toUpperCase());
}
export function Section({
  title,
  help,
  children,
}: React.PropsWithChildren<{ title: string; help: string }>) {
  return (
    <section className="editor-section">
      <header>
        <h5>{title}</h5>
        <small>{help}</small>
      </header>
      {children}
    </section>
  );
}
export function Text({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange(value: string): void;
}) {
  return (
    <label>
      {label}
      <input value={value} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}
export function Optional({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string | undefined;
  onChange(value: string): void;
}) {
  return (
    <label>
      {label} <small>optional</small>
      <input
        value={value ?? ""}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}
export function Select({
  label,
  value,
  values,
  onChange,
}: {
  label: string;
  value: string;
  values: readonly string[];
  onChange(value: string): void;
}) {
  return (
    <label>
      {label}
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {values.map((option) => (
          <option value={option} key={option}>
            {option ? human(option) : "None"}
          </option>
        ))}
      </select>
    </label>
  );
}
export function Check({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange(value: boolean): void;
}) {
  return (
    <label className="checkbox">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />{" "}
      {label}
    </label>
  );
}
export function NumberField({
  label,
  value,
  min = 1,
  onChange,
}: {
  label: string;
  value: number;
  min?: number;
  onChange(value: number): void;
}) {
  return (
    <label>
      {label}
      <input
        type="number"
        min={min}
        value={value}
        onChange={(event) => onChange(Number(event.target.value))}
      />
    </label>
  );
}
export function Field({
  workflow,
  diagnostics,
  fieldPath,
  label,
  value,
  onChange,
}: {
  workflow: WorkflowDraft;
  diagnostics: readonly WorkflowValidationDiagnostic[];
  fieldPath: string;
  label: string;
  value: string;
  onChange(value: string): void;
}) {
  const error = diagnostics.find(
    (diagnostic) => diagnostic.fieldPath === fieldPath,
  );
  const id = diagnosticFieldId(workflow.workflowId, fieldPath);
  return (
    <label className={error ? "field-invalid" : ""}>
      {label}
      <input
        id={id}
        value={value}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? `${id}-error` : undefined}
        onChange={(event) => onChange(event.target.value)}
      />
      {error && (
        <small id={`${id}-error`} role="alert">
          {error.safeMessage}
        </small>
      )}
    </label>
  );
}
export function HeaderEditor({
  headers,
  onChange,
}: {
  headers: Record<string, string>;
  onChange(value: Record<string, string>): void;
}) {
  const entries = Object.entries(headers);
  return (
    <fieldset className="record-editor">
      <legend>Non-secret request headers</legend>
      {entries.map(([name, value], index) => (
        <div key={`${name}-${index}`}>
          <input
            aria-label={`Header name ${index + 1}`}
            value={name}
            onChange={(event) =>
              onChange(
                Object.fromEntries(
                  entries.map((entry, item) =>
                    item === index ? [event.target.value, entry[1]] : entry,
                  ),
                ),
              )
            }
          />
          <input
            aria-label={`Header value ${index + 1}`}
            value={value}
            onChange={(event) =>
              onChange({ ...headers, [name]: event.target.value })
            }
          />
          <button
            type="button"
            onClick={() => {
              const next = { ...headers };
              delete next[name];
              onChange(next);
            }}
          >
            Remove
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={() =>
          onChange({ ...headers, [`X-Safe-Header-${entries.length + 1}`]: "" })
        }
      >
        Add header
      </button>
    </fieldset>
  );
}
export function StringList({
  label,
  values,
  onChange,
}: {
  label: string;
  values: string[];
  onChange(value: string[]): void;
}) {
  return (
    <fieldset className="string-list">
      <legend>{label}</legend>
      {values.map((value, index) => (
        <div key={`${index}-${value}`}>
          <input
            aria-label={`${label} ${index + 1}`}
            value={value}
            onChange={(event) => {
              const next = [...values];
              next[index] = event.target.value;
              onChange(next);
            }}
          />
          <button
            type="button"
            aria-label={`Remove ${label} ${index + 1}`}
            onClick={() => onChange(values.filter((_, item) => item !== index))}
          >
            Remove
          </button>
        </div>
      ))}
      <button type="button" onClick={() => onChange([...values, ""])}>
        Add
      </button>
    </fieldset>
  );
}
export function DiagnosticStringList({
  workflow,
  diagnostics,
  basePath,
  label,
  values,
  onChange,
}: {
  workflow: WorkflowDraft;
  diagnostics: readonly WorkflowValidationDiagnostic[];
  basePath: string;
  label: string;
  values: string[];
  onChange(value: string[]): void;
}) {
  return (
    <fieldset className="string-list">
      <legend>{label}</legend>
      {values.map((value, index) => (
        <div key={`${index}-${value}`}>
          <Field
            workflow={workflow}
            diagnostics={diagnostics}
            fieldPath={`${basePath}.${index}`}
            label={`${label} ${index + 1}`}
            value={value}
            onChange={(nextValue) => {
              const next = [...values];
              next[index] = nextValue;
              onChange(next);
            }}
          />
          <button
            type="button"
            aria-label={`Remove ${label} ${index + 1}`}
            onClick={() => onChange(values.filter((_, item) => item !== index))}
          >
            Remove
          </button>
        </div>
      ))}
      <button type="button" onClick={() => onChange([...values, ""])}>
        Add
      </button>
    </fieldset>
  );
}
export function NumberList({
  label,
  values,
  onChange,
}: {
  label: string;
  values: number[];
  onChange(value: number[]): void;
}) {
  return (
    <fieldset className="string-list">
      <legend>{label}</legend>
      {values.map((value, index) => (
        <div key={`${index}-${value}`}>
          <input
            type="number"
            min="100"
            max="599"
            aria-label={`${label} ${index + 1}`}
            value={value}
            onChange={(event) => {
              const next = [...values];
              next[index] = Number(event.target.value);
              onChange(next);
            }}
          />
          <button
            type="button"
            onClick={() => onChange(values.filter((_, item) => item !== index))}
          >
            Remove
          </button>
        </div>
      ))}
      <button type="button" onClick={() => onChange([...values, 400])}>
        Add
      </button>
    </fieldset>
  );
}
export function Limits({
  values,
  onChange,
}: {
  values: Record<string, number>;
  onChange(key: string, value: number): void;
}) {
  return (
    <details className="limit-editor">
      <summary>Workflow limits</summary>
      <div className="grid three">
        {Object.entries(values).map(([key, value]) => (
          <NumberField
            key={key}
            label={human(key)}
            value={value}
            onChange={(next) => onChange(key, next)}
          />
        ))}
      </div>
    </details>
  );
}
export function ScalarEditor({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string | number | boolean | null | undefined;
  onChange(value: string | number | boolean | null | undefined): void;
}) {
  const kind =
    value === undefined ? "unset" : value === null ? "null" : typeof value;
  return (
    <fieldset className="scalar-editor">
      <legend>{label}</legend>
      <select
        aria-label={`${label} type`}
        value={kind}
        onChange={(event) =>
          onChange(
            event.target.value === "unset"
              ? undefined
              : event.target.value === "null"
                ? null
                : event.target.value === "boolean"
                  ? false
                  : event.target.value === "number"
                    ? 0
                    : "",
          )
        }
      >
        <option value="unset">Not configured</option>
        <option value="string">Text</option>
        <option value="number">Number</option>
        <option value="boolean">Boolean</option>
        <option value="null">Null</option>
      </select>
      {kind === "string" && (
        <input
          aria-label={label}
          value={String(value)}
          onChange={(event) => onChange(event.target.value)}
        />
      )}
      {kind === "number" && (
        <input
          aria-label={label}
          type="number"
          value={String(value)}
          onChange={(event) => onChange(Number(event.target.value))}
        />
      )}
      {kind === "boolean" && (
        <select
          aria-label={label}
          value={String(value)}
          onChange={(event) => onChange(event.target.value === "true")}
        >
          <option value="true">True</option>
          <option value="false">False</option>
        </select>
      )}
    </fieldset>
  );
}
export function setOptional<T extends object, K extends keyof T>(
  target: T,
  key: K,
  value: string,
): void {
  if (value.trim()) target[key] = value as T[K];
  else delete target[key];
}
export function setOptionalScalar<T extends object, K extends keyof T>(
  target: T,
  key: K,
  value: string | number | boolean | null | undefined,
): void {
  if (value === undefined) delete target[key];
  else target[key] = value as T[K];
}
export function optionalCopy<T extends object, K extends keyof T>(
  source: T,
  key: K,
  value: string,
  onChange: (value: T) => void,
): void {
  const copy = structuredClone(source);
  setOptional(copy, key, value);
  onChange(copy);
}
