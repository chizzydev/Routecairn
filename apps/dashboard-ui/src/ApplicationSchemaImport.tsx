import React, { useState, useRef, useEffect } from "react";
import { apiMutation } from "./api";
import type { ApplicationSchemaService } from "../../../src/dashboard/execution/ApplicationSchemaService";
import type { ApplicationMappingInput } from "../../../src/dashboard/contracts/ApplicationMappingContracts";
type Schema = ReturnType<ApplicationSchemaService["create"]>;
export function ApplicationSchemaImport({
  target,
  disabled,
  onApply
}: {
  target: string;
  disabled: boolean;
  onApply: (
    routes: ApplicationMappingInput["routes"],
    binding: NonNullable<ApplicationMappingInput["schemaBinding"]>
  ) => void;
}) {
  const [document, setDocument] = useState(""),
    [schema, setSchema] = useState<Schema>(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [choices, setChoices] = useState<
      Record<
        string,
        {
          selected: boolean;
          slots: Record<string, string>;
          identityPath: string;
          tenantPath: string;
          kind: "OBJECT" | "FUNCTION";
        }
      >
    >({});
  const fileGeneration = useRef(0);
  useEffect(
    () => () => {
      fileGeneration.current++;
    },
    []
  );
  const update = (id: string, value: Partial<(typeof choices)[string]>) =>
    setChoices((c) => ({ ...c, [id]: { ...c[id]!, ...value } }));
  return (
    <details>
      <summary>Import local OpenAPI route suggestions</summary>
      <p>
        OpenAPI 3.0/3.1 JSON, 256 KiB maximum. Inline schemas and bounded local component references only. Servers are
        ignored. Import never authorizes a request.
      </p>
      <fieldset disabled={disabled || busy || !target}>
        <legend>Schema-suggested · unverified</legend>
        <label>
          Local OpenAPI JSON
          <input
            aria-label="Local OpenAPI JSON"
            type="file"
            accept=".json,application/json"
            onChange={(e) => {
              setSchema(undefined);
              setDocument("");
              setError("");
              const generation = ++fileGeneration.current;
              const file = e.target.files?.[0];
              if (!file) return;
              if (file.size > 262144) {
                setError("Schema exceeds 256 KiB");
                return;
              }
              void file
                .text()
                .then((text) => {
                  if (fileGeneration.current === generation) setDocument(text);
                })
                .catch(() => {
                  if (fileGeneration.current === generation) setError("Local schema could not be read");
                });
            }}
          />
        </label>
        <button
          disabled={!document}
          onClick={() => {
            setBusy(true);
            setError("");
            void apiMutation<Schema>("/api/authorization-workbench/mapping/schemas", "POST", {
              targetId: target,
              document
            })
              .then((s) => {
                setSchema(s);
                setChoices(
                  Object.fromEntries(
                    s.candidates.map((c) => [
                      c.id,
                      { selected: false, slots: {}, identityPath: "", tenantPath: "", kind: c.kind }
                    ])
                  )
                );
              })
              .catch((e) => setError(e.message))
              .finally(() => setBusy(false));
          }}
        >
          Inspect schema suggestions
        </button>
        {error && <p role="alert">{error}</p>}
        {schema && (
          <>
            <p>
              SCHEMA_SUGGESTED_UNVERIFIED · source SHA-256 {schema.sourceHash}. No network authority. Choose at most
              eight GET routes and complete every slot.
            </p>
            {schema.candidates.map((c) => {
              const v = choices[c.id]!;
              return (
                <fieldset key={c.id}>
                  <legend>
                    {c.method} {c.path}
                  </legend>
                  <label>
                    <input
                      aria-label={"Choose " + c.path}
                      type="checkbox"
                      checked={v.selected}
                      onChange={(e) => update(c.id, { selected: e.target.checked })}
                    />
                    Choose suggestion
                  </label>
                  {c.slots.map((s) => (
                    <label key={s.name}>
                      Concrete {s.name} ({s.type})
                      <input
                        aria-label={c.id + " slot " + s.name}
                        value={v.slots[s.name] ?? ""}
                        onChange={(e) => update(c.id, { slots: { ...v.slots, [s.name]: e.target.value } })}
                      />
                    </label>
                  ))}
                  <label>
                    Reviewed kind
                    <select
                      aria-label={c.id + " reviewed kind"}
                      value={v.kind}
                      onChange={(e) => update(c.id, { kind: e.target.value as "OBJECT" | "FUNCTION" })}
                    >
                      <option value="OBJECT">Object</option>
                      <option value="FUNCTION">Function</option>
                    </select>
                  </label>
                  <label>
                    Reviewed identity marker
                    <select
                      aria-label={c.id + " identity marker"}
                      value={v.identityPath}
                      onChange={(e) => update(c.id, { identityPath: e.target.value })}
                    >
                      <option value="">Select non-secret scalar</option>
                      {c.markers.map((m) => (
                        <option key={m.path} value={m.path}>
                          {m.path} ({m.type})
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Reviewed tenant marker
                    <select
                      aria-label={c.id + " tenant marker"}
                      value={v.tenantPath}
                      onChange={(e) => update(c.id, { tenantPath: e.target.value })}
                    >
                      <option value="">No declared tenant marker</option>
                      {c.markers.map((m) => (
                        <option key={m.path} value={m.path}>
                          {m.path} ({m.type})
                        </option>
                      ))}
                    </select>
                  </label>
                </fieldset>
              );
            })}
            <ul aria-label="Excluded schema operations">
              {schema.excluded.map((x, i) => (
                <li key={i}>
                  {x.method} {x.path}: {x.reason} · zero authority
                </li>
              ))}
            </ul>
            <button
              disabled={!schema.candidates.some((c) => choices[c.id]?.selected)}
              onClick={() => {
                try {
                  const selected = schema.candidates.filter((c) => choices[c.id]!.selected);
                  if (selected.length > 8) throw Error("Select at most eight routes");
                  const routes = selected.map((c) => {
                    const v = choices[c.id]!;
                    if (!v.identityPath || c.slots.some((s) => !v.slots[s.name]))
                      throw Error("Complete selected route slots and identity markers");
                    let path = c.path;
                    for (const s of c.slots) {
                      const value = v.slots[s.name]!;
                      if (
                        !/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,79}$/.test(value) ||
                        (s.type === "integer" && !/^(?:0|[1-9][0-9]{0,14})$/.test(value))
                      )
                        throw Error("Invalid concrete parameter");
                      path = path.replace("{" + s.name + "}", value);
                    }
                    return {
                      id: c.id,
                      kind: v.kind,
                      url: new URL(path, window.location.origin).pathname,
                      pathTemplate: c.template,
                      method: "GET" as const,
                      identityPath: v.identityPath,
                      ...(v.tenantPath ? { tenantPath: v.tenantPath } : {})
                    };
                  });
                  onApply(routes, {
                    revisionId: schema.revisionId,
                    digest: schema.digest,
                    selections: selected.map((c) => ({ routeId: c.id, candidateId: c.id, slots: choices[c.id]!.slots }))
                  });
                  setError("");
                } catch (e) {
                  setError(e instanceof Error ? e.message : "Selection invalid");
                }
              }}
            >
              Use reviewed schema selections
            </button>
          </>
        )}
      </fieldset>
    </details>
  );
}
