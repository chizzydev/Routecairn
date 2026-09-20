import { createHash, randomUUID } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { thirdPartyModuleManifestSchema, type ThirdPartyModuleManifest } from "../../dashboard/contracts/OperationalScaleSchemas.js";

const outputSchema = z.object({
  observations: z.array(z.object({ kind: z.string().min(1).max(100), summary: z.string().min(1).max(1000), data: z.record(z.union([z.string().max(500), z.number(), z.boolean(), z.null()])).default({}) }).strict()).max(1000),
  findings: z.array(z.object({ title: z.string().min(1).max(200), category: z.string().min(1).max(100), severity: z.enum(["Info", "Low", "Medium", "High", "Critical"]), confidence: z.enum(["Low", "Medium", "High"]), endpoint: z.string().max(1000), description: z.string().min(1).max(4000), remediation: z.string().max(4000).optional() }).strict()).max(1000),
  notes: z.array(z.string().max(500)).max(100)
}).strict().superRefine((value, ctx) => {
  value.observations.forEach((observation, index) => {
    for (const key of Object.keys(observation.data)) if (secretKey(key)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["observations", index, "data", key], message: "Secret-like output fields are not allowed." });
  });
  value.findings.forEach((finding, index) => {
    if (/[?#]/.test(finding.endpoint) || /^https?:\/\/[^/]*@/i.test(finding.endpoint)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["findings", index, "endpoint"], message: "Finding endpoints must not contain query, fragment, or user-info data." });
  });
});

export class SandboxedModuleHost {
  public validatePackage(packageDirectory: string, manifestInput: unknown): { manifest: ThirdPartyModuleManifest; digest: string; entrypoint: string } {
    const manifest = thirdPartyModuleManifestSchema.parse(manifestInput); const root = realpathSync(resolve(packageDirectory)); const entrypoint = realpathSync(resolve(root, manifest.entrypoint));
    if (entrypoint !== root && !entrypoint.startsWith(`${root}\\`) && !entrypoint.startsWith(`${root}/`)) throw new Error("SDK_ENTRYPOINT_OUTSIDE_PACKAGE");
    const stat = statSync(entrypoint); if (!stat.isFile() || stat.size > 2 * 1024 * 1024) throw new Error("SDK_ENTRYPOINT_INVALID");
    validateSchema(manifest.inputSchema);
    const digest = digestPackage(root); return { manifest, digest, entrypoint };
  }

  public async execute(packageDirectory: string, manifestInput: unknown, input: Record<string, unknown>): Promise<z.infer<typeof outputSchema>> {
    const validated = this.validatePackage(packageDirectory, manifestInput); const serialized = JSON.stringify(input); if (Buffer.byteLength(serialized) > 1024 * 1024) throw new Error("SDK_INPUT_LIMIT_EXCEEDED");
    assertNoSecretFields(input, 0);
    assertSchema(input, validated.manifest.inputSchema, "$", 0);
    const runner = fileURLToPath(new URL("./ThirdPartyModuleRunner.mjs", import.meta.url));
    const args = [
      permissionFlag(),
      `--allow-fs-read=${realpathSync(resolve(packageDirectory))}`,
      `--allow-fs-read=${runner}`,
      `--max-old-space-size=${validated.manifest.permissions.maxMemoryMb}`,
      runner,
      validated.entrypoint,
      String(validated.manifest.outputLimit)
    ];
    return new Promise((resolvePromise, reject) => {
      const child = spawn(process.execPath, args, { cwd: packageDirectory, env: { PATH: process.env.PATH ?? "", SystemRoot: process.env.SystemRoot ?? "", TEMP: process.env.TEMP ?? "", TMP: process.env.TMP ?? "" }, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
      let stdout = ""; let stderr = ""; let settled = false;
      const finish = (error?: Error, value?: z.infer<typeof outputSchema>) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolvePromise(value!); };
      const timer = setTimeout(() => { child.kill("SIGKILL"); finish(new Error("SDK_RUNTIME_LIMIT_EXCEEDED")); }, validated.manifest.permissions.maxRuntimeMs); timer.unref();
      child.stdout.on("data", (chunk) => { stdout += String(chunk); if (Buffer.byteLength(stdout) > 2 * 1024 * 1024) { child.kill("SIGKILL"); finish(new Error("SDK_OUTPUT_LIMIT_EXCEEDED")); } });
      child.stderr.on("data", (chunk) => { if (stderr.length < 4000) stderr += String(chunk); });
      child.once("error", (error) => finish(error));
      child.once("exit", (code) => { if (settled) return; if (code !== 0) return finish(new Error(`SDK_PROCESS_FAILED:${safe(stderr)}`)); try { finish(undefined, outputSchema.parse(JSON.parse(stdout))); } catch (error) { finish(error instanceof Error ? error : new Error("SDK_OUTPUT_INVALID")); } });
      child.stdin.end(serialized);
    });
  }
}

export function sandboxExecutionId(): string { return randomUUID(); }
function safe(value: string): string { return value.replace(/https?:\/\/\S+/g, "<url>").replace(/[\r\n]+/g, " ").slice(0, 500); }

function permissionFlag(): string {
  const major = Number(process.versions.node.split(".")[0]);
  return major >= 23 ? "--permission" : "--experimental-permission";
}

function digestPackage(root: string): string {
  const files: string[] = []; let bytes = 0;
  const walk = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      if (["node_modules", ".git"].includes(name)) throw new Error("SDK_PACKAGE_DIRECTORY_REJECTED");
      const path = resolve(directory, name); const stat = lstatSync(path);
      if (stat.isSymbolicLink()) throw new Error("SDK_PACKAGE_SYMLINK_REJECTED");
      if (stat.isDirectory()) walk(path);
      else if (stat.isFile()) { files.push(path); bytes += stat.size; }
      else throw new Error("SDK_PACKAGE_ENTRY_REJECTED");
      if (files.length > 256 || bytes > 10 * 1024 * 1024) throw new Error("SDK_PACKAGE_LIMIT_EXCEEDED");
    }
  };
  walk(root);
  const hash = createHash("sha256");
  for (const path of files) hash.update(relative(root, path).replace(/\\/g, "/")).update("\0").update(readFileSync(path)).update("\0");
  return hash.digest("hex");
}

function validateSchema(schema: Record<string, unknown>, depth = 0): void {
  if (depth > 12) throw new Error("SDK_INPUT_SCHEMA_TOO_DEEP");
  const allowed = new Set(["type", "properties", "required", "additionalProperties", "items", "enum", "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems"]);
  for (const key of Object.keys(schema)) if (!allowed.has(key)) throw new Error(`SDK_INPUT_SCHEMA_KEY_REJECTED:${key}`);
  if (schema.type !== undefined && !["object", "array", "string", "number", "integer", "boolean", "null"].includes(String(schema.type))) throw new Error("SDK_INPUT_SCHEMA_TYPE_REJECTED");
  if (schema.properties !== undefined) {
    if (!plainObject(schema.properties) || Object.keys(schema.properties).length > 100) throw new Error("SDK_INPUT_SCHEMA_PROPERTIES_REJECTED");
    for (const child of Object.values(schema.properties)) { if (!plainObject(child)) throw new Error("SDK_INPUT_SCHEMA_CHILD_REJECTED"); validateSchema(child, depth + 1); }
  }
  if (schema.items !== undefined) { if (!plainObject(schema.items)) throw new Error("SDK_INPUT_SCHEMA_ITEMS_REJECTED"); validateSchema(schema.items, depth + 1); }
  if (schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.some((item) => typeof item !== "string"))) throw new Error("SDK_INPUT_SCHEMA_REQUIRED_REJECTED");
  if (schema.enum !== undefined && (!Array.isArray(schema.enum) || schema.enum.length > 100)) throw new Error("SDK_INPUT_SCHEMA_ENUM_REJECTED");
  if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== "boolean") throw new Error("SDK_INPUT_SCHEMA_ADDITIONAL_PROPERTIES_REJECTED");
  for (const key of ["minLength", "maxLength", "minItems", "maxItems"]) if (schema[key] !== undefined && (!Number.isInteger(schema[key]) || Number(schema[key]) < 0)) throw new Error(`SDK_INPUT_SCHEMA_BOUND_REJECTED:${key}`);
  for (const key of ["minimum", "maximum"]) if (schema[key] !== undefined && (typeof schema[key] !== "number" || !Number.isFinite(schema[key]))) throw new Error(`SDK_INPUT_SCHEMA_BOUND_REJECTED:${key}`);
  if (plainObject(schema.properties)) for (const key of Object.keys(schema.properties)) if (unsafeKey(key)) throw new Error("SDK_INPUT_SCHEMA_PROPERTY_REJECTED");
}

function assertSchema(value: unknown, schema: Record<string, unknown>, path: string, depth: number): void {
  if (depth > 12) throw new Error(`SDK_INPUT_SCHEMA_MISMATCH:${path}`);
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value))) throw new Error(`SDK_INPUT_SCHEMA_MISMATCH:${path}`);
  const type = typeof schema.type === "string" ? schema.type : undefined;
  const valid = !type || (type === "null" ? value === null : type === "array" ? Array.isArray(value) : type === "object" ? plainObject(value) : type === "integer" ? Number.isInteger(value) : type === "number" ? typeof value === "number" && Number.isFinite(value) : typeof value === type);
  if (!valid) throw new Error(`SDK_INPUT_SCHEMA_MISMATCH:${path}`);
  if (typeof value === "string") { if (typeof schema.minLength === "number" && value.length < schema.minLength || typeof schema.maxLength === "number" && value.length > schema.maxLength) throw new Error(`SDK_INPUT_SCHEMA_MISMATCH:${path}`); }
  if (typeof value === "number") { if (typeof schema.minimum === "number" && value < schema.minimum || typeof schema.maximum === "number" && value > schema.maximum) throw new Error(`SDK_INPUT_SCHEMA_MISMATCH:${path}`); }
  if (Array.isArray(value)) {
    if (typeof schema.minItems === "number" && value.length < schema.minItems || typeof schema.maxItems === "number" && value.length > schema.maxItems) throw new Error(`SDK_INPUT_SCHEMA_MISMATCH:${path}`);
    if (plainObject(schema.items)) value.forEach((item, index) => assertSchema(item, schema.items as Record<string, unknown>, `${path}[${index}]`, depth + 1));
  }
  if (plainObject(value)) {
    const properties = plainObject(schema.properties) ? schema.properties as Record<string, Record<string, unknown>> : {};
    for (const required of Array.isArray(schema.required) ? schema.required : []) if (!(String(required) in value)) throw new Error(`SDK_INPUT_SCHEMA_MISMATCH:${path}.${String(required)}`);
    if (schema.additionalProperties === false) for (const key of Object.keys(value)) if (!Object.hasOwn(properties, key)) throw new Error(`SDK_INPUT_SCHEMA_MISMATCH:${path}.${key}`);
    for (const [key, child] of Object.entries(value)) if (Object.hasOwn(properties, key)) assertSchema(child, properties[key]!, `${path}.${key}`, depth + 1);
  }
}

function plainObject(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function secretKey(key: string): boolean { return /(?:password|passwd|secret|token|cookie|authorization|private[_-]?key|api[_-]?key|credential|session|jwt|signature|signed)/i.test(key); }
function unsafeKey(key: string): boolean { return ["__proto__", "prototype", "constructor"].includes(key); }
function assertNoSecretFields(value: unknown, depth: number): void { if (depth > 12) throw new Error("SDK_INPUT_TOO_DEEP"); if (Array.isArray(value)) { value.forEach((item) => assertNoSecretFields(item, depth + 1)); return; } if (plainObject(value)) for (const [key, child] of Object.entries(value)) { if (secretKey(key)) throw new Error("SDK_SECRET_FIELD_REJECTED"); if(unsafeKey(key))throw new Error("SDK_INPUT_KEY_REJECTED"); assertNoSecretFields(child, depth + 1); } }
