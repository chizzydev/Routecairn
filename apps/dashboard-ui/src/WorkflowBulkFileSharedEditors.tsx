import { useEffect, useState } from "react";
import type { WorkflowCapability } from "./AuthorizationWorkflowStudio";

import { Optional, Section, Select, Text, opts, setOptional } from "./WorkflowBulkFileControls";
import { type EditableActor } from "./WorkflowBulkFileTypes";

export function JsonBodyEditor({
  value,
  onValid,
  onInvalid,
}: {
  value: unknown;
  onValid(value: unknown): void;
  onInvalid(): void;
}) {
  const [text, setText] = useState(() =>
    JSON.stringify(
      value ?? { objectIds: "{{OBJECT_IDS_ARRAY}}", dryRun: true },
      null,
      2,
    ),
  );
  const [error, setError] = useState("");
  useEffect(() => {
    try {
      if (JSON.stringify(JSON.parse(text)) !== JSON.stringify(value))
        setText(
          JSON.stringify(
            value ?? { objectIds: "{{OBJECT_IDS_ARRAY}}", dryRun: true },
            null,
            2,
          ),
        );
    } catch {
      /* Preserve invalid in-progress text until the operator fixes it. */
    }
  }, [value]);
  const parse = (next: string, format = false) => {
    setText(next);
    if (new TextEncoder().encode(next).byteLength > 65536) {
      setError("Body exceeds the 64 KiB guided editor limit.");
      onInvalid();
      return;
    }
    if (/(?:__proto__|prototype|constructor)/i.test(next)) {
      setError("Prototype keys are not allowed.");
      onInvalid();
      return;
    }
    if (
      /(?:=>|function\s*\(|eval\s*\(|for\s*\(|while\s*\(|\$\(|<%)/i.test(next)
    ) {
      setError("Executable expressions and generators are not allowed.");
      onInvalid();
      return;
    }
    if (
      /(?:authorization|cookie|session|token|secret|password|api[_-]?key)/i.test(
        next,
      )
    ) {
      setError(
        "Secrets and authentication material are prohibited in stored bodies.",
      );
      onInvalid();
      return;
    }
    try {
      const parsed: unknown = JSON.parse(next);
      setError("");
      onValid(parsed);
      if (format) setText(JSON.stringify(parsed, null, 2));
    } catch {
      setError("Enter valid JSON.");
      onInvalid();
    }
  };
  return (
    <fieldset className="json-body-editor">
      <legend>Fixed JSON body</legend>
      <p>
        Use one literal <code>{"{{OBJECT_IDS_ARRAY}}"}</code> value. JavaScript,
        loops, generators, response placeholders, and secrets are prohibited.
      </p>
      <textarea
        aria-label="Fixed JSON body"
        aria-invalid={Boolean(error)}
        value={text}
        onChange={(event) => parse(event.target.value)}
      />
      {error && <small role="alert">{error}</small>}
      <button type="button" onClick={() => parse(text, true)}>
        Format JSON
      </button>
    </fieldset>
  );
}

export function ActorEditor<T extends EditableActor>({
  actors,
  capability,
  onChange,
}: {
  actors: T[];
  capability: WorkflowCapability;
  onChange(value: T[]): void;
}) {
  return (
    <Section
      title="Actors"
      help="Actors bind only to the controlled public, Account A, or Account B contexts."
    >
      {actors.map((actor, index) => (
        <fieldset key={`${actor.id}-${index}`}>
          <legend>{actor.safeAlias ?? actor.id}</legend>
          <div className="grid three">
            <Text
              label="Actor ID"
              value={actor.id}
              onChange={(value) =>
                change(index, (entry) => {
                  entry.id = value;
                })
              }
            />
            <Select
              label="Relationship"
              value={actor.relationship}
              values={opts(capability, "relationship")}
              onChange={(value) =>
                change(index, (entry) => {
                  entry.relationship = value;
                })
              }
            />
            <Select
              label="Authentication"
              value={actor.authProfile ?? ""}
              values={["", "account_a", "account_b"]}
              onChange={(value) =>
                change(index, (entry) =>
                  setOptional(entry, "authProfile", value),
                )
              }
            />
            <Optional
              label="Safe alias"
              value={actor.safeAlias}
              onChange={(value) =>
                change(index, (entry) => setOptional(entry, "safeAlias", value))
              }
            />
            <Optional
              label="Principal ID"
              value={actor.principalId}
              onChange={(value) =>
                change(index, (entry) =>
                  setOptional(entry, "principalId", value),
                )
              }
            />
            <Optional
              label="Tenant"
              value={actor.tenantId}
              onChange={(value) =>
                change(index, (entry) => setOptional(entry, "tenantId", value))
              }
            />
            <Optional
              label="Role"
              value={actor.role}
              onChange={(value) =>
                change(index, (entry) => setOptional(entry, "role", value))
              }
            />
            <Optional
              label="Account state"
              value={actor.accountState}
              onChange={(value) =>
                change(index, (entry) =>
                  setOptional(entry, "accountState", value),
                )
              }
            />
          </div>
        </fieldset>
      ))}
      <button
        type="button"
        onClick={() => {
          const next = structuredClone(actors);
          const actor = structuredClone(actors[0]!);
          actor.id = `actor-${actors.length + 1}`;
          actor.relationship = "PUBLIC";
          actor.safeAlias = `Actor ${actors.length + 1}`;
          delete actor.authProfile;
          delete actor.principalId;
          next.push(actor);
          onChange(next);
        }}
      >
        Add actor
      </button>
    </Section>
  );
  function change(index: number, mutate: (value: EditableActor) => void) {
    const next = structuredClone(actors);
    mutate(next[index]!);
    onChange(next);
  }
}
