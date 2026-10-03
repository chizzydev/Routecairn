import { readBoundedFileSync } from "../files/BoundedFile.js";
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { thirdPartyModuleManifestSchema, type ThirdPartyModuleBrokerBinding, type ThirdPartyModuleManifest } from "../../dashboard/contracts/OperationalScaleSchemas.js";
import { ModuleCapabilityBroker, type ModuleCapabilitySummary } from "./ModuleCapabilityBroker.js";

const outputSchema = z.object({
  observations: z.array(z.object({ kind: z.string().min(1).max(100), summary: z.string().min(1).max(1000), data: z.record(z.union([z.string().max(500), z.number(), z.boolean(), z.null()])).default({}) }).strict()).max(1000),
  findings: z.array(z.object({ title: z.string().min(1).max(200), category: z.string().min(1).max(100), severity: z.enum(["Info", "Low", "Medium", "High", "Critical"]), confidence: z.enum(["Low", "Medium", "High"]), endpoint: z.string().max(1000), description: z.string().min(1).max(4000), remediation: z.string().max(4000).optional() }).strict()).max(1000),
  notes: z.array(z.string().max(500)).max(100)
}).strict().superRefine((value, ctx) => {
  value.observations.forEach((observation, index) => {
    for (const key of Object.keys(observation.data)) { if (secretKey(key)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["observations", index, "data", key], message: "Secret-like output fields are not allowed." }); if (unsafeKey(key)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["observations", index, "data", key], message: "Unsafe output fields are not allowed." }); }
  });
  value.findings.forEach((finding, index) => {
    if (!safeEndpoint(finding.endpoint)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["findings", index, "endpoint"], message: "Finding endpoints must be a safe HTTP(S) URL or canonical path without query, fragment, user-info, traversal, or controls." });
  });
});

export class SandboxedModuleHost {
  public constructor(private readonly containerImage = process.env.ROUTECAIRN_MODULE_CONTAINER_IMAGE) {
    if (containerImage && !/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(containerImage)) throw new Error("SDK_CONTAINER_IMAGE_DIGEST_REQUIRED");
  }
  public validatePackage(packageDirectory: string, manifestInput: unknown): { manifest: ThirdPartyModuleManifest; digest: string; entrypoint: string } {
    const manifest = thirdPartyModuleManifestSchema.parse(manifestInput); const root = realpathSync(resolve(packageDirectory)); const entrypoint = realpathSync(resolve(root, manifest.entrypoint));
    const embeddedPath = resolve(root, "routecairn.module.json");
    if (JSON.stringify(thirdPartyModuleManifestSchema.parse(JSON.parse(readBoundedFileSync(embeddedPath, 256 * 1024).toString("utf8")))) !== JSON.stringify(manifest)) throw new Error("SDK_MANIFEST_MISMATCH");
    if (entrypoint !== root && !entrypoint.startsWith(`${root}\\`) && !entrypoint.startsWith(`${root}/`)) throw new Error("SDK_ENTRYPOINT_OUTSIDE_PACKAGE");
    const stat = statSync(entrypoint); if (!stat.isFile() || stat.size > 2 * 1024 * 1024) throw new Error("SDK_ENTRYPOINT_INVALID");
    validateSchema(manifest.inputSchema);
    const digest = digestPackage(root); return { manifest, digest, entrypoint };
  }

  public async execute(packageDirectory: string, manifestInput: unknown, input: Record<string, unknown>, brokerBinding?: ThirdPartyModuleBrokerBinding, expectedDigest?: string): Promise<z.infer<typeof outputSchema> & { capabilitySummary: ModuleCapabilitySummary }> {
    const validated = this.validatePackage(packageDirectory, manifestInput); const serialized = JSON.stringify(input); if (Buffer.byteLength(serialized) > 1024 * 1024) throw new Error("SDK_INPUT_LIMIT_EXCEEDED");
    if (expectedDigest && validated.digest !== expectedDigest) throw new Error("SDK_PACKAGE_DIGEST_CHANGED");
    assertNoSecretFields(input, 0);
    assertSchema(input, validated.manifest.inputSchema, "$", 0);
    if (brokerBinding && !validated.manifest.capabilities.requestBroker) throw new Error("SDK_REQUEST_BROKER_NOT_DECLARED");
    let capabilityBroker: ModuleCapabilityBroker | undefined; let snapshotDirectory: string | undefined; let containerName: string | undefined;
    try {
    capabilityBroker = brokerBinding && validated.manifest.capabilities.requestBroker ? new ModuleCapabilityBroker(validated.manifest.capabilities.requestBroker, brokerBinding, validated.digest) : undefined;
    snapshotDirectory = snapshotPackage(realpathSync(resolve(packageDirectory)), validated.digest); const snapshotEntrypoint = realpathSync(resolve(snapshotDirectory, validated.manifest.entrypoint));
    if (this.containerImage) { const permissions = (path: string): void => { const stat = lstatSync(path); chmodSync(path, stat.isDirectory() ? 0o755 : 0o444); if (stat.isDirectory()) for (const name of readdirSync(path)) permissions(join(path, name)); }; permissions(snapshotDirectory); }
    const runner = fileURLToPath(new URL("./ThirdPartyModuleRunner.mjs", import.meta.url));
    const args = [
      permissionFlag(),
      `--allow-fs-read=${validated.manifest.permissions.filesystem === "PACKAGE_READ_ONLY" ? snapshotDirectory : snapshotEntrypoint}`,
      `--allow-fs-read=${runner}`,
      `--max-old-space-size=${validated.manifest.permissions.maxMemoryMb}`,
      runner,
      snapshotEntrypoint,
      String(validated.manifest.outputLimit)
    ];
    return await new Promise((resolvePromise, reject) => {
      containerName = this.containerImage ? `routecairn-module-${randomUUID()}` : undefined;
      if (this.containerImage && [snapshotDirectory!, runner].some((path) => /[,\r\n]/.test(path))) throw new Error("SDK_CONTAINER_MOUNT_PATH_INVALID");
      const memory = validated.manifest.permissions.maxMemoryMb + 64;
      const launchArgs = this.containerImage ? ["run", "--rm", "--name", containerName!, "--interactive", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=32", `--memory=${memory}m`, `--memory-swap=${memory}m`, "--cpus=1", "--user=65534:65534", "--mount", `type=bind,source=${snapshotDirectory},target=/package,readonly`, "--mount", `type=bind,source=${runner},target=/runtime/runner.mjs,readonly`, "--workdir=/package", this.containerImage, "node", ...args.slice(0, 1), `--allow-fs-read=${validated.manifest.permissions.filesystem === "PACKAGE_READ_ONLY" ? "/package" : `/package/${validated.manifest.entrypoint}`}`, "--allow-fs-read=/runtime/runner.mjs", `--max-old-space-size=${validated.manifest.permissions.maxMemoryMb}`, "/runtime/runner.mjs", `/package/${validated.manifest.entrypoint}`, String(validated.manifest.outputLimit)] : args;
      const child = spawn(this.containerImage ? "docker" : process.execPath, launchArgs, { cwd: snapshotDirectory, env: { PATH: process.env.PATH ?? "", SystemRoot: process.env.SystemRoot ?? "", TEMP: process.env.TEMP ?? "", TMP: process.env.TMP ?? "" }, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
      let stdout = Buffer.alloc(0); let stdoutBytes = 0; let stderr = ""; let settled = false; let finalResult: unknown; let finalCount = 0; const requestIds = new Set<string>(); const rpcTasks = new Set<Promise<void>>();
      const finish = (error?: Error, value?: z.infer<typeof outputSchema> & { capabilitySummary: ModuleCapabilitySummary }) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolvePromise(value!); };
      const fail = (error: Error) => { capabilityBroker?.cancel(); child.kill("SIGKILL"); finish(error); };
      const timer = setTimeout(() => fail(new Error("SDK_RUNTIME_LIMIT_EXCEEDED")), validated.manifest.permissions.maxRuntimeMs); timer.unref();
      const rpcLimit = Math.min(20 * 1024 * 1024, 2 * 1024 * 1024 + (validated.manifest.capabilities.requestBroker?.maxRequests ?? 0) * ((validated.manifest.capabilities.requestBroker?.maxRequestBytes ?? 0) + 64 * 1024));
      const writeRpc = (value: unknown) => { if (!child.stdin.destroyed && child.stdin.writable) child.stdin.write(`${JSON.stringify(value)}\n`); };
      const processLine = (line: Buffer) => {
        if (line.length > Math.max(1024 * 1024, (validated.manifest.capabilities.requestBroker?.maxRequestBytes ?? 0) + 64 * 1024)) return fail(new Error("SDK_RPC_MESSAGE_LIMIT_EXCEEDED"));
        let message: unknown; try { message = JSON.parse(line.toString("utf8")); } catch { return fail(new Error("SDK_RPC_MESSAGE_INVALID")); }
        if (!message || typeof message !== "object") return fail(new Error("SDK_RPC_MESSAGE_INVALID"));
        const record = message as { protocolVersion?: unknown; type?: unknown; id?: unknown; proposal?: unknown; result?: unknown };
        if (record.protocolVersion !== 1) return fail(new Error("SDK_RPC_VERSION_UNSUPPORTED"));
        if (record.type === "result") { finalCount += 1; if (finalCount > 1) return fail(new Error("SDK_RESULT_DUPLICATED")); finalResult = record.result; return; }
        if (record.type !== "rpc-request" || typeof record.id !== "string" || !/^[1-9][0-9]{0,11}$/.test(record.id) || requestIds.has(record.id) || finalCount) return fail(new Error("SDK_RPC_MESSAGE_INVALID"));
        requestIds.add(record.id); const id = record.id;
        const task = (async () => {
          if (!capabilityBroker) { writeRpc({ protocolVersion: 1, type: "rpc-response", id, ok: false, errorCode: "SDK_REQUEST_BROKER_UNAVAILABLE" }); return; }
          try { const result = await capabilityBroker.execute(record.proposal); writeRpc({ protocolVersion: 1, type: "rpc-response", id, ok: true, result }); }
          catch { writeRpc({ protocolVersion: 1, type: "rpc-response", id, ok: false, errorCode: "SDK_REQUEST_BROKER_FAILURE" }); }
        })();
        rpcTasks.add(task); void task.finally(() => rpcTasks.delete(task));
      };
      child.stdout.on("data", (chunk: Buffer) => { if (settled) return; stdoutBytes += chunk.length; if (stdoutBytes > rpcLimit) return fail(new Error("SDK_OUTPUT_LIMIT_EXCEEDED")); stdout = Buffer.concat([stdout, chunk]); let newline: number; while (!settled && (newline = stdout.indexOf(0x0a)) >= 0) { const line = stdout.subarray(0, newline); stdout = stdout.subarray(newline + 1); if (line.length) processLine(line); } if (stdout.length > Math.max(1024 * 1024, (validated.manifest.capabilities.requestBroker?.maxRequestBytes ?? 0) + 64 * 1024)) fail(new Error("SDK_RPC_MESSAGE_LIMIT_EXCEEDED")); });
      child.stderr.on("data", (chunk) => { if (stderr.length < 4000) stderr += String(chunk); });
      child.stdin.on("error", () => undefined);
      child.once("error", (error) => finish(error));
      child.once("exit", async (code) => { if (settled) return; if (stdout.length) processLine(stdout); await Promise.allSettled([...rpcTasks]); if (settled) return; if (code !== 0) return finish(new Error(`SDK_PROCESS_FAILED:${safe(stderr)}`)); if (finalCount !== 1) return finish(new Error("SDK_OUTPUT_INVALID")); try { const output = outputSchema.parse(finalResult); finish(undefined, { ...output, capabilitySummary: capabilityBroker?.summary() ?? disabledCapabilitySummary() }); } catch (error) { finish(error instanceof Error ? error : new Error("SDK_OUTPUT_INVALID")); } });
      writeRpc({ protocolVersion: 1, type: "init", input: JSON.parse(serialized), capabilities: { requestBroker: Boolean(capabilityBroker) } });
    }); } finally { await capabilityBroker?.close(); if (containerName) await removeModuleContainer(containerName); if (snapshotDirectory) rmSync(snapshotDirectory, { recursive: true, force: true }); }
  }
}

export function sandboxExecutionId(): string { return randomUUID(); }
async function removeModuleContainer(name: string): Promise<void> { await new Promise<void>((done, reject) => { const child = spawn("docker", ["rm", "--force", name], { stdio: ["ignore", "ignore", "pipe"], windowsHide: true }); let stderr = ""; child.stderr.on("data", (chunk) => { if (stderr.length < 2000) stderr += String(chunk); }); const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("SDK_CONTAINER_CLEANUP_FAILED")); }, 5000); child.once("error", () => { clearTimeout(timer); reject(new Error("SDK_CONTAINER_CLEANUP_FAILED")); }); child.once("exit", (code) => { clearTimeout(timer); if (code === 0 || /No such container/i.test(stderr)) done(); else reject(new Error("SDK_CONTAINER_CLEANUP_FAILED")); }); }); }
function safe(value: string): string { return /\b(SDK_[A-Z0-9_]{3,100})\b/.exec(value.toUpperCase())?.[1] ?? "RUNTIME"; }

function permissionFlag(): string {
  const major = Number(process.versions.node.split(".")[0]);
  return major >= 23 ? "--permission" : "--experimental-permission";
}

function digestPackage(root: string): string {
  const files: string[] = []; let bytes = 0; let entries = 0;
  const walk = (directory: string, depth = 0): void => {
    if (depth > 16) throw new Error("SDK_PACKAGE_LIMIT_EXCEEDED");
    for (const name of readdirSync(directory).sort()) {
      if (++entries > 512) throw new Error("SDK_PACKAGE_LIMIT_EXCEEDED");
      if (["node_modules", ".git"].includes(name)) throw new Error("SDK_PACKAGE_DIRECTORY_REJECTED");
      const path = resolve(directory, name); const stat = lstatSync(path);
      if (stat.isSymbolicLink()) throw new Error("SDK_PACKAGE_SYMLINK_REJECTED");
      if (stat.isDirectory()) walk(path, depth + 1);
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

function snapshotPackage(sourceRoot: string, expectedDigest: string): string {
  const destination = mkdtempSync(join(tmpdir(), "routecairn-module-snapshot-"));
  let files = 0; let bytes = 0; let entries = 0;
  try {
    const copy = (directory: string, depth = 0): void => { if (depth > 16) throw new Error("SDK_PACKAGE_LIMIT_EXCEEDED"); for (const name of readdirSync(directory).sort()) { if (++entries > 512) throw new Error("SDK_PACKAGE_LIMIT_EXCEEDED"); if (["node_modules", ".git"].includes(name)) throw new Error("SDK_PACKAGE_DIRECTORY_REJECTED"); const source = resolve(directory, name); const stat = lstatSync(source); const target = resolve(destination, relative(sourceRoot, source)); if (stat.isSymbolicLink()) throw new Error("SDK_PACKAGE_SYMLINK_REJECTED"); if (stat.isDirectory()) { mkdirSync(target, { recursive: true }); copy(source, depth + 1); } else if (stat.isFile()) { if (++files > 256 || (bytes += stat.size) > 10 * 1024 * 1024) throw new Error("SDK_PACKAGE_LIMIT_EXCEEDED"); mkdirSync(dirname(target), { recursive: true }); copyFileSync(source, target); } else throw new Error("SDK_PACKAGE_ENTRY_REJECTED"); } };
    copy(sourceRoot); if (digestPackage(destination) !== expectedDigest) throw new Error("SDK_PACKAGE_CHANGED_DURING_SNAPSHOT"); return destination;
  } catch (error) { rmSync(destination, { recursive: true, force: true }); throw error; }
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
function safeEndpoint(value: string): boolean { if (!value || /[?#\\\r\n\0]/.test(value) || value.split("/").some((part) => part === "." || part === "..")) return false; if (value.startsWith("/")) return true; try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password; } catch { return false; } }
function assertNoSecretFields(value: unknown, depth: number): void { if (depth > 12) throw new Error("SDK_INPUT_TOO_DEEP"); if (Array.isArray(value)) { value.forEach((item) => assertNoSecretFields(item, depth + 1)); return; } if (plainObject(value)) for (const [key, child] of Object.entries(value)) { if (secretKey(key)) throw new Error("SDK_SECRET_FIELD_REJECTED"); if(unsafeKey(key))throw new Error("SDK_INPUT_KEY_REJECTED"); assertNoSecretFields(child, depth + 1); } }
function disabledCapabilitySummary(): ModuleCapabilitySummary { return { enabled: false, proposedRequests: 0, transmittedRequests: 0, policyBlockedRequests: 0, budgetBlockedRequests: 0, maxRequests: 0, auditDigest: createHash("sha256").update("[]").digest("hex") }; }
