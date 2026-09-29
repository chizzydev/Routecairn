import React from "react";
import type { WorkflowCapability, WorkflowDraft } from "./AuthorizationWorkflowStudio";
import { diagnosticFieldId, type WorkflowValidationDiagnostic } from "./WorkflowDiagnostics";

type Actor = {
  id: string;
  safeAlias?: string | undefined;
  authProfile?: string | undefined;
  tenantId?: string | undefined;
  role?: string | undefined;
  accountState?: string | undefined;
  relationship?: string | undefined;
  type?: string | undefined;
};

export function ObjectAssertion({
  title,
  value,
  onChange,
}: {
  title: string;
  value: Extract<
    WorkflowDraft,
    { workflowId: "object-pair" }
  >["config"]["cases"][number]["accountAObject"];
  onChange(
    value: Extract<
      WorkflowDraft,
      { workflowId: "object-pair" }
    >["config"]["cases"][number]["accountAObject"],
  ): void;
}) {
  const set = <K extends keyof typeof value>(key: K, next: (typeof value)[K]) =>
    onChange({ ...value, [key]: next });
  return (
    <fieldset>
      <legend>{title}</legend>
      <Text
        label="Exact object reference"
        value={value.id}
        onChange={(next) => set("id", next)}
      />
      <Text
        label="Safe source description"
        value={value.source}
        onChange={(next) => set("source", next)}
      />
      <OptionalField
        label="Tenant"
        value={value.tenantId}
        onChange={(next) => {
          const copy = { ...value };
          setOptional(copy, "tenantId", next);
          onChange(copy);
        }}
      />
      <div className="grid two">
        <OptionalField
          label="Object ID path"
          value={value.expectedObjectIdField}
          onChange={(next) => {
            const copy = { ...value };
            setOptional(copy, "expectedObjectIdField", next);
            onChange(copy);
          }}
        />
        <OptionalField
          label="Owner path"
          value={value.expectedOwnerField}
          onChange={(next) => {
            const copy = { ...value };
            setOptional(copy, "expectedOwnerField", next);
            onChange(copy);
          }}
        />
        <OptionalField
          label="Tenant path"
          value={value.expectedTenantField}
          onChange={(next) => {
            const copy = { ...value };
            setOptional(copy, "expectedTenantField", next);
            onChange(copy);
          }}
        />
      </div>
      <StringList
        label="Expected private fields"
        values={value.expectedPrivateFields}
        onChange={(next) => set("expectedPrivateFields", next)}
      />
      <StringList
        label="Expected private headers"
        values={value.expectedPrivateHeaders}
        onChange={(next) => set("expectedPrivateHeaders", next)}
      />
      <StringList
        label="Expected safe markers"
        values={value.expectedSafeMarkers}
        onChange={(next) => set("expectedSafeMarkers", next)}
      />
    </fieldset>
  );
}

export function ActorList({
  actors,
  relationshipKey,
  options: values,
  onChange,
}: {
  actors: Actor[];
  relationshipKey: "relationship" | "type";
  options: readonly string[];
  onChange(actors: Actor[]): void;
}) {
  return (
    <Section
      title="Actors"
      help="Actor IDs bind rows to the existing verified Account A, Account B, or public context."
    >
      <div className="actor-list">
        {actors.map((actor, index) => (
          <fieldset key={`${actor.id}-${index}`}>
            <legend>{actor.safeAlias ?? actor.id}</legend>
            <div className="grid three">
              <Text
                label="Actor ID"
                value={actor.id}
                onChange={(value) => updateActor(index, { id: value })}
              />
              <Select
                label={human(relationshipKey)}
                value={actor[relationshipKey] ?? ""}
                options={values}
                onChange={(value) =>
                  updateActor(index, { [relationshipKey]: value })
                }
              />
              <Select
                label="Authentication"
                value={actor.authProfile ?? ""}
                options={["", "account_a", "account_b"]}
                onChange={(value) =>
                  updateActor(index, { authProfile: value || undefined })
                }
              />
              <OptionalField
                label="Safe alias"
                value={actor.safeAlias}
                onChange={(value) =>
                  updateActor(index, { safeAlias: value || undefined })
                }
              />
              <OptionalField
                label="Tenant"
                value={actor.tenantId}
                onChange={(value) =>
                  updateActor(index, { tenantId: value || undefined })
                }
              />
              <OptionalField
                label="Role"
                value={actor.role}
                onChange={(value) =>
                  updateActor(index, { role: value || undefined })
                }
              />
              <OptionalField
                label="Account state"
                value={actor.accountState}
                onChange={(value) =>
                  updateActor(index, { accountState: value || undefined })
                }
              />
            </div>
          </fieldset>
        ))}
        <button
          type="button"
          onClick={() =>
            onChange([
              ...actors,
              {
                id: `actor-${actors.length + 1}`,
                [relationshipKey]: values[0] ?? "OWNER",
                safeAlias: `Actor ${actors.length + 1}`,
              },
            ])
          }
        >
          Add actor
        </button>
      </div>
    </Section>
  );
  function updateActor(index: number, patch: Partial<Actor>) {
    const next = structuredClone(actors);
    Object.assign(next[index]!, patch);
    for (const [key, value] of Object.entries(next[index]!))
      if (value === undefined || value === "")
        delete next[index]![key as keyof Actor];
    onChange(next);
  }
}

export function Relationship({
  from,
  kind,
  to,
  decision,
}: {
  from: string;
  kind: string;
  to: string;
  decision: string;
}) {
  return (
    <div className="relationship-cell">
      <strong>{from}</strong>
      <span>{kind}</span>
      <b aria-hidden="true">-&gt;</b>
      <strong>{to}</strong>
      <small>{decision}</small>
    </div>
  );
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
  type = "text",
}: {
  label: string;
  value: string;
  onChange(value: string): void;
  type?: "text" | "url";
}) {
  return (
    <label>
      {label}
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}
export function OptionalField({
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
export function FieldText({
  workflow,
  diagnostics,
  path,
  label,
  value,
  onChange,
}: {
  workflow: WorkflowDraft;
  diagnostics: readonly WorkflowValidationDiagnostic[];
  path: string;
  label: string;
  value: string;
  onChange(value: string): void;
}) {
  const error = diagnostics.find((item) => item.fieldPath === path);
  const id = diagnosticFieldId(workflow.workflowId, path);
  return (
    <label className={error ? "field-invalid" : ""}>
      {label}
      <input
        id={id}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? `${id}-error` : undefined}
        value={value}
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
export function Select({
  label,
  value,
  options: values,
  onChange,
}: {
  label: string;
  value: string;
  options: readonly string[];
  onChange(value: string): void;
}) {
  return (
    <label>
      {label}
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {values.map((option) => (
          <option key={option} value={option}>
            {option ? human(option) : "Any"}
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
export function ScalarValue({
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
            onClick={() =>
              onChange(values.filter((_, itemIndex) => itemIndex !== index))
            }
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
export function HeaderEditor({
  value,
  onChange,
}: {
  value: Record<string, string>;
  onChange(value: Record<string, string>): void;
}) {
  const entries = Object.entries(value);
  return (
    <fieldset className="record-editor">
      <legend>Non-secret request headers</legend>
      {entries.map(([name, headerValue], index) => (
        <div key={`${name}-${index}`}>
          <input
            aria-label={`Header name ${index + 1}`}
            value={name}
            onChange={(event) => {
              const next = entries.map((entry, itemIndex) =>
                itemIndex === index ? [event.target.value, entry[1]] : entry,
              );
              onChange(Object.fromEntries(next));
            }}
          />
          <input
            aria-label={`Header value ${index + 1}`}
            value={headerValue}
            onChange={(event) => {
              const next = { ...value, [name]: event.target.value };
              onChange(next);
            }}
          />
          <button
            type="button"
            onClick={() => {
              const next = { ...value };
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
          onChange({ ...value, [`X-Safe-Header-${entries.length + 1}`]: "" })
        }
      >
        Add header
      </button>
    </fieldset>
  );
}
export function RowActions({
  index,
  length,
  label,
  deleteDisabledReason,
  onDuplicate,
  onDelete,
  onMove,
}: {
  index: number;
  length: number;
  label: string;
  deleteDisabledReason?: string | undefined;
  onDuplicate(): void;
  onDelete(): void;
  onMove(direction: -1 | 1): void;
}) {
  return (
    <div className="row-actions">
      <button
        type="button"
        aria-label={`Duplicate ${label} ${index + 1}`}
        onClick={onDuplicate}
      >
        Duplicate
      </button>
      <button
        type="button"
        aria-label={`Move ${label} ${index + 1} up`}
        disabled={index === 0}
        onClick={() => onMove(-1)}
      >
        Up
      </button>
      <button
        type="button"
        aria-label={`Move ${label} ${index + 1} down`}
        disabled={index === length - 1}
        onClick={() => onMove(1)}
      >
        Down
      </button>
      <button
        type="button"
        aria-label={`Delete ${label} ${index + 1}`}
        title={deleteDisabledReason}
        disabled={length === 1 || Boolean(deleteDisabledReason)}
        onClick={onDelete}
      >
        Delete
      </button>
      {deleteDisabledReason && (
        <small role="status">{deleteDisabledReason}</small>
      )}
    </div>
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
          <label key={key}>
            {human(key)}
            <input
              type="number"
              min="1"
              value={value}
              onChange={(event) => onChange(key, Number(event.target.value))}
            />
          </label>
        ))}
      </div>
    </details>
  );
}

export function options(capability: WorkflowCapability, key: string): string[] {
  return capability.guidedOptions?.[key] ?? capability.expectationTypes;
}
export function human(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .replace(/^./, (letter) => letter.toUpperCase());
}
export function setOptional<T extends object, K extends keyof T>(
  value: T,
  key: K,
  next: string,
): void {
  if (next.trim()) value[key] = next as T[K];
  else delete value[key];
}
export function move<T>(values: T[], index: number, direction: -1 | 1): void {
  const target = index + direction;
  if (target < 0 || target >= values.length) return;
  [values[index], values[target]] = [values[target]!, values[index]!];
}
export function uiId(): string {
  return `ui-case-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
}
