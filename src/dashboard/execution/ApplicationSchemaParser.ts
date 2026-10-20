import { createHash } from "node:crypto";
export const SCHEMA_LIMITS = {
  bytes: 262144,
  depth: 24,
  nodes: 20000,
  paths: 128,
  operations: 256,
  markers: 16
} as const;
type Obj = Record<string, unknown>;
const object = (v: unknown): Obj => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const safeName = /^[A-Za-z][A-Za-z0-9_]{0,39}$/;
const markerName = /^[A-Za-z][A-Za-z0-9_]*$/;
const secret = /(?:__proto__|prototype|constructor|password|token|secret|cookie|authorization|session|key)/i;
export interface SchemaCandidate {
  id: string;
  path: string;
  template: string;
  method: "GET";
  kind: "OBJECT" | "FUNCTION";
  slots: { name: string; type: "string" | "integer" }[];
  markers: { path: string; type: "string" | "number" }[];
  provenance: "SCHEMA_SUGGESTED_UNVERIFIED";
}
export function parseApplicationSchema(text: string) {
  if (Buffer.byteLength(text, "utf8") > SCHEMA_LIMITS.bytes) throw Error("WORKBENCH_SCHEMA_SIZE_LIMIT");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw Error("WORKBENCH_SCHEMA_JSON_REQUIRED");
  }
  let nodes = 0;
  const walk = (v: unknown, depth: number) => {
    if (++nodes > SCHEMA_LIMITS.nodes || depth > SCHEMA_LIMITS.depth) throw Error("WORKBENCH_SCHEMA_STRUCTURE_LIMIT");
    if (v && typeof v === "object")
      for (const [k, c] of Object.entries(v)) {
        if (["__proto__", "constructor", "prototype"].includes(k)) throw Error("WORKBENCH_SCHEMA_POISON_KEY");
        if (
          k === "$ref" &&
          (typeof c !== "string" || !/^#\/components\/(schemas|parameters)\/[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(c))
        )
          throw Error("WORKBENCH_SCHEMA_EXTERNAL_OR_UNSAFE_REF");
        walk(c, depth + 1);
      }
  };
  walk(parsed, 0);
  const doc = object(parsed);
  if (typeof doc.openapi !== "string" || !/^3\.(?:0|1)\.\d+$/.test(doc.openapi))
    throw Error("WORKBENCH_SCHEMA_OPENAPI_30_31_REQUIRED");
  const resolve = (v: unknown, seen = new Set<string>()): Obj => {
    const o = object(v);
    if (typeof o.$ref !== "string") return o;
    const ref = o.$ref;
    if (seen.has(ref) || seen.size >= 8) throw Error("WORKBENCH_SCHEMA_CYCLIC_REF");
    const [, , category, name] = ref.split("/");
    const components = object(doc.components);
    const collection = Object.hasOwn(components, category!) ? object(components[category!]) : {};
    const target = Object.hasOwn(collection, name!) ? collection[name!] : undefined;
    if (!target) throw Error("WORKBENCH_SCHEMA_UNRESOLVED_REF");
    return resolve(target, new Set([...seen, ref]));
  };
  const paths = object(doc.paths);
  if (
    !doc.paths ||
    typeof doc.paths !== "object" ||
    Array.isArray(doc.paths) ||
    Object.keys(paths).length > SCHEMA_LIMITS.paths
  )
    throw Error("WORKBENCH_SCHEMA_PATH_LIMIT");
  const candidates: SchemaCandidate[] = [],
    excluded: { path: string; method: string; reason: string }[] = [];
  let operations = 0;
  for (const [path, raw] of Object.entries(paths)) {
    if (
      path.length > 200 ||
      !path.startsWith("/") ||
      path.includes("//") ||
      path
        .split("/")
        .slice(1)
        .some(
          (s) =>
            !s ||
            s === "." ||
            s === ".." ||
            !(/^[A-Za-z0-9_.-]+$/.test(s) || /^\{[A-Za-z][A-Za-z0-9_]{0,39}\}$/.test(s))
        )
    )
      throw Error("WORKBENCH_SCHEMA_UNSAFE_PATH");
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw Error("WORKBENCH_SCHEMA_PATH_ITEM_INVALID");
    const item = object(raw);
    if (item.$ref) throw Error("WORKBENCH_SCHEMA_PATH_REF_UNSUPPORTED");
    for (const method of ["get", "post", "put", "patch", "delete", "head", "options", "trace"])
      if (item[method]) {
        if (++operations > SCHEMA_LIMITS.operations) throw Error("WORKBENCH_SCHEMA_OPERATION_LIMIT");
        const reject = (reason: string) => excluded.push({ path, method: method.toUpperCase(), reason });
        if (method !== "get") {
          reject("NON_GET_EXCLUDED_NO_AUTHORITY");
          continue;
        }
        if (typeof item[method] !== "object" || Array.isArray(item[method]))
          throw Error("WORKBENCH_SCHEMA_OPERATION_INVALID");
        const op = object(item[method]);
        if (op.servers || item.servers || op.callbacks || op.requestBody) {
          reject("OVERRIDE_CALLBACK_OR_BODY_UNSUPPORTED");
          continue;
        }
        const params = new Map<string, Obj>();
        let unsupported = false;
        for (const list of [item.parameters, op.parameters]) {
          if (list !== undefined && !Array.isArray(list)) throw Error("WORKBENCH_SCHEMA_PARAMETERS_INVALID");
          for (const p of (list ?? []) as unknown[]) {
            const v = resolve(p);
            if (typeof v.name !== "string" || typeof v.in !== "string")
              throw Error("WORKBENCH_SCHEMA_PARAMETER_INVALID");
            params.set(v.in + ":" + v.name, v);
          }
        }
        const names = [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]!);
        if (names.length > 4 || new Set(names).size !== names.length) {
          reject("PATH_SLOTS_UNSUPPORTED");
          continue;
        }
        const slots: SchemaCandidate["slots"] = [];
        for (const name of names) {
          const p = params.get("path:" + name),
            s = resolve(p?.schema);
          if (!safeName.test(name) || !p || p.required !== true || !["string", "integer"].includes(String(s.type))) {
            unsupported = true;
            break;
          }
          slots.push({ name, type: s.type as "string" | "integer" });
        }
        for (const p of params.values())
          if ((p.in !== "path" && p.required === true) || (p.in === "path" && !names.includes(String(p.name))))
            unsupported = true;
        if (unsupported) {
          reject("REQUIRED_ARGUMENT_UNSUPPORTED");
          continue;
        }
        const response = resolve(object(op.responses)["200"]),
          schema = object(object(response.content)["application/json"]).schema;
        const markers: SchemaCandidate["markers"] = [];
        const fields = (value: unknown, prefix: string, seen: Set<unknown>, depth: number) => {
          if (depth > 7 || !value || seen.has(value)) return;
          const s = resolve(value);
          if (
            s.writeOnly === true ||
            s["x-sensitive"] === true ||
            ["password", "binary", "byte"].includes(String(s.format))
          )
            return;
          if (s.type === "object" || s.properties) {
            for (const [k, v] of Object.entries(object(s.properties))) {
              const p = prefix ? prefix + "." + k : k;
              if (markerName.test(k) && p.length <= 80 && !secret.test(p))
                fields(v, p, new Set([...seen, value]), depth + 1);
            }
          } else if (
            prefix &&
            ["string", "integer", "number"].includes(String(s.type)) &&
            markers.length < SCHEMA_LIMITS.markers
          )
            markers.push({ path: prefix, type: s.type === "string" ? "string" : "number" });
        };
        fields(schema, "", new Set(), 0);
        candidates.push({
          id: "schema-route-" + (candidates.length + 1),
          path,
          template: path.replace(/\{([^}]+)\}/g, ":$1"),
          method: "GET",
          kind: slots.length ? "OBJECT" : "FUNCTION",
          slots,
          markers,
          provenance: "SCHEMA_SUGGESTED_UNVERIFIED"
        });
      }
  }
  return {
    format: "OPENAPI_JSON_REST_SUBSET_V1" as const,
    openapi: doc.openapi,
    sourceHash: createHash("sha256").update(text).digest("hex"),
    candidates,
    excluded,
    serversIgnored: true,
    remoteFetch: false,
    executionAuthorized: false
  };
}
export function concreteSchemaPath(candidate: SchemaCandidate, slots: Record<string, string>): string {
  if (
    Object.keys(slots).length !== candidate.slots.length ||
    candidate.slots.some((s) => !Object.hasOwn(slots, s.name))
  )
    throw Error("WORKBENCH_SCHEMA_EXACT_SLOTS_REQUIRED");
  let path = candidate.path;
  for (const s of candidate.slots) {
    const v = slots[s.name]!;
    if (
      !/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,79}$/.test(v) ||
      v === "." ||
      v === ".." ||
      (s.type === "integer" && !/^(?:0|[1-9][0-9]{0,14})$/.test(v))
    )
      throw Error("WORKBENCH_SCHEMA_UNSAFE_SLOT");
    path = path.replace("{" + s.name + "}", v);
  }
  return path;
}
