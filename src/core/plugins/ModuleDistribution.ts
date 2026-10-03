import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { z } from "zod";
import { SandboxedModuleHost } from "./SandboxedModuleHost.js";
import { thirdPartyModuleManifestSchema } from "../../dashboard/contracts/OperationalScaleSchemas.js";

export const MODULE_BUNDLE_LIMIT = 24 * 1024 * 1024;
export const MODULE_PAYLOAD_TYPE = "application/vnd.routecairn.module.v1+json";
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const publisher = z.string().regex(/^[a-z][a-z0-9.-]{2,79}$/);
const moduleId = z.string().regex(/^[a-z][a-z0-9-]{2,79}$/);
const version = z.string().regex(/^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/).max(100);
const base64 = (max: number) => z.string().max(max).refine((value) => Buffer.from(value, "base64").toString("base64") === value, "Canonical base64 required.");
const fileSchema = z.object({ path: z.string().min(1).max(500), content: base64(3 * 1024 * 1024) }).strict();
export const modulePayloadSchema = z.object({
  schemaVersion: z.literal(1), publisher, moduleId, version, sdkVersion: z.literal(2),
  nodeMajorVersions: z.array(z.number().int()).min(1).max(3).refine((value) => value.every((n) => [20, 22, 24].includes(n)) && new Set(value).size === value.length),
  packageDigest: digest, issuedAt: z.string().datetime(), expiresAt: z.string().datetime(),
  files: z.array(fileSchema).min(2).max(256)
}).strict();
export const moduleEnvelopeSchema = z.object({ payloadType: z.literal(MODULE_PAYLOAD_TYPE), payload: base64(20 * 1024 * 1024), signatures: z.array(z.object({ keyid: digest, sig: base64(100).refine((value) => Buffer.from(value, "base64").length === 64) }).strict()).length(1) }).strict();
export const moduleTrustSchema = z.object({
  schemaVersion: z.literal(1),
  publishers: z.array(z.object({ publisher, modulePrefixes: z.array(moduleId).min(1).max(50), publicKeyPem: z.string().min(100).max(4000), keyId: digest, notBefore: z.string().datetime(), expiresAt: z.string().datetime() }).strict()).min(1).max(100),
  revokedKeyIds: z.array(digest).max(1000).default([]), revokedPackageDigests: z.array(digest).max(10000).default([])
}).strict().superRefine((value, ctx) => {
  if (new Set(value.publishers.map((entry) => entry.keyId)).size !== value.publishers.length) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Duplicate trusted key." });
  for (const entry of value.publishers) if (Date.parse(entry.notBefore) >= Date.parse(entry.expiresAt)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Invalid trusted key validity window." });
  for (let i = 0; i < value.publishers.length; i++) for (let j = i + 1; j < value.publishers.length; j++) {
    const left = value.publishers[i]!, right = value.publishers[j]!;
    if (left.publisher !== right.publisher && left.modulePrefixes.some((a) => right.modulePrefixes.some((b) => a === b || a.startsWith(`${b}-`) || b.startsWith(`${a}-`)))) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Different publishers cannot own overlapping namespaces." });
  }
});
export type ModuleEnvelope = z.infer<typeof moduleEnvelopeSchema>;
export type ModuleTrust = z.infer<typeof moduleTrustSchema>;
export type ModulePayload = z.infer<typeof modulePayloadSchema>;

export function moduleKeyId(key: string | KeyObject): string {
  const publicKey = typeof key === "string" ? createPublicKey(key) : key.type === "public" ? key : createPublicKey(key);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("MODULE_ED25519_KEY_REQUIRED");
  return sha256(publicKey.export({ type: "spki", format: "der" }));
}

/** No install hooks, dependency resolution, compressed archives or executable extraction. */
export function buildModulePayload(directory: string, publisherId: string, expiresAt: string, now = Date.now()): ModulePayload {
  const root = realpathSync(resolve(directory));
  const manifest = readModuleJson(join(root, "routecairn.module.json"), 256 * 1024);
  const validated = new SandboxedModuleHost().validatePackage(root, manifest);
  const files: ModulePayload["files"] = [];
  let bytes = 0;
  const walk = (folder: string, depth: number): void => {
    if (depth > 16) throw new Error("MODULE_FILE_DEPTH_LIMIT");
    for (const name of readdirSync(folder).sort()) {
      const path = join(folder, name); const stat = lstatSync(path);
      if (stat.isSymbolicLink()) throw new Error("MODULE_FILE_SYMLINK_REJECTED");
      const portable = relative(root, path).replaceAll("\\", "/"); assertModulePath(portable);
      if (stat.isDirectory()) walk(path, depth + 1);
      else if (stat.isFile()) {
        if (stat.size > 2 * 1024 * 1024 || files.length >= 256) throw new Error("MODULE_FILE_LIMIT");
        const content = readFileSync(path); bytes += content.length;
        if (content.length > 2 * 1024 * 1024 || bytes > 10 * 1024 * 1024) throw new Error("MODULE_FILE_LIMIT");
        files.push({ path: portable, content: content.toString("base64") });
      } else throw new Error("MODULE_FILE_TYPE_REJECTED");
    }
  };
  walk(root, 0);
  const payload = validateModulePayload({ schemaVersion: 1, publisher: publisherId, moduleId: validated.manifest.moduleId, version: validated.manifest.version, sdkVersion: 2, nodeMajorVersions: [20, 22, 24], packageDigest: validated.digest, issuedAt: new Date(now).toISOString(), expiresAt, files }, now);
  if (new SandboxedModuleHost().validatePackage(root, manifest).digest !== payload.packageDigest) throw new Error("MODULE_PACKAGE_CHANGED");
  return payload;
}

export function signModulePayload(input: unknown, privateKeyPem: string, now = Date.now()): ModuleEnvelope {
  const payload = validateModulePayload(input, now);
  const key = createPrivateKey(privateKeyPem); const keyid = moduleKeyId(key);
  const bytes = Buffer.from(canonicalModuleJson(payload));
  return { payloadType: MODULE_PAYLOAD_TYPE, payload: bytes.toString("base64"), signatures: [{ keyid, sig: sign(null, pae(bytes), key).toString("base64") }] };
}

export function verifyModuleEnvelope(input: unknown, trustInput: unknown, now = Date.now(), nodeMajor = Number(process.versions.node.split(".")[0])): ModulePayload {
  const envelope = moduleEnvelopeSchema.parse(input); const trust = moduleTrustSchema.parse(trustInput);
  if (Buffer.byteLength(JSON.stringify(envelope)) > MODULE_BUNDLE_LIMIT) throw new Error("MODULE_BUNDLE_LIMIT");
  const signature = envelope.signatures[0]!;
  const trusted = trust.publishers.find((entry) => entry.keyId === signature.keyid);
  if (!trusted || trust.revokedKeyIds.includes(signature.keyid)) throw new Error("MODULE_KEY_UNTRUSTED_OR_REVOKED");
  if (now < Date.parse(trusted.notBefore) || now >= Date.parse(trusted.expiresAt)) throw new Error("MODULE_KEY_INACTIVE");
  const key = createPublicKey(trusted.publicKeyPem);
  if (moduleKeyId(key) !== trusted.keyId) throw new Error("MODULE_KEY_ID_MISMATCH");
  const bytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, pae(bytes), key, Buffer.from(signature.sig, "base64"))) throw new Error("MODULE_SIGNATURE_INVALID");
  const payload = validateModulePayload(JSON.parse(bytes.toString("utf8")), now);
  if (canonicalModuleJson(payload) !== bytes.toString("utf8")) throw new Error("MODULE_PAYLOAD_NONCANONICAL");
  if (payload.publisher !== trusted.publisher || !trusted.modulePrefixes.some((prefix) => payload.moduleId === prefix || payload.moduleId.startsWith(`${prefix}-`))) throw new Error("MODULE_PUBLISHER_NAMESPACE_MISMATCH");
  if (trust.revokedPackageDigests.includes(payload.packageDigest)) throw new Error("MODULE_PACKAGE_REVOKED");
  if (!payload.nodeMajorVersions.includes(nodeMajor)) throw new Error("MODULE_RUNTIME_INCOMPATIBLE");
  return payload;
}

export function installModuleEnvelope(input: unknown, trust: unknown, installRoot: string, now = Date.now()): { directory: string; payload: ModulePayload } {
  const payload = verifyModuleEnvelope(input, trust, now);
  mkdirSync(installRoot, { recursive: true }); const root = realpathSync(resolve(installRoot));
  const destination = join(root, `${payload.moduleId}-${payload.version}-${payload.packageDigest}`);
  try { lstatSync(destination); throw new Error("MODULE_INSTALL_ALREADY_EXISTS"); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  const staging = mkdtempSync(join(root, ".module-stage-"));
  try {
    for (const file of payload.files) { const path = join(staging, file.path); mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, Buffer.from(file.content, "base64"), { flag: "wx", mode: 0o600 }); }
    const validated = new SandboxedModuleHost().validatePackage(staging, readModuleJson(join(staging, "routecairn.module.json"), 256 * 1024));
    if (validated.digest !== payload.packageDigest) throw new Error("MODULE_INSTALL_DIGEST_MISMATCH");
    renameSync(staging, destination); return { directory: destination, payload };
  } catch (error) { rmSync(staging, { recursive: true, force: true }); throw error; }
}

export function validateModulePayload(input: unknown, now = Date.now()): ModulePayload {
  const payload = modulePayloadSchema.parse(input);
  if (now < Date.parse(payload.issuedAt) || now >= Date.parse(payload.expiresAt) || Date.parse(payload.expiresAt) - Date.parse(payload.issuedAt) > 90 * 86400_000) throw new Error("MODULE_LEASE_INVALID");
  const names = new Set<string>(); const fileNames = new Set<string>(); let total = 0;
  for (const file of payload.files) {
    assertModulePath(file.path); const lower = file.path.toLowerCase();
    if (names.has(lower)) throw new Error("MODULE_FILE_DUPLICATE"); names.add(lower); fileNames.add(file.path);
    const content = Buffer.from(file.content, "base64"); total += content.length;
    if (content.length > 2 * 1024 * 1024 || total > 10 * 1024 * 1024) throw new Error("MODULE_FILE_LIMIT");
  }
  for (const name of names) { const parts = name.split("/"); for (let i = 1; i < parts.length; i++) if (names.has(parts.slice(0, i).join("/"))) throw new Error("MODULE_FILE_DIRECTORY_COLLISION"); }
  const manifestFile = payload.files.find((file) => file.path === "routecairn.module.json");
  if (!manifestFile || Buffer.from(manifestFile.content, "base64").length > 256 * 1024) throw new Error("MODULE_MANIFEST_REQUIRED");
  // Validate the full host schema, restricted input contract and entrypoint again at install.
  const manifest = thirdPartyModuleManifestSchema.parse(JSON.parse(Buffer.from(manifestFile.content, "base64").toString("utf8")));
  if (manifest.moduleId !== payload.moduleId || manifest.version !== payload.version || !fileNames.has(manifest.entrypoint)) throw new Error("MODULE_MANIFEST_IDENTITY_MISMATCH");
  const hash = createHash("sha256");
  for (const file of [...payload.files].sort((a, b) => compareModulePaths(a.path, b.path))) hash.update(file.path).update("\0").update(Buffer.from(file.content, "base64")).update("\0");
  if (hash.digest("hex") !== payload.packageDigest) throw new Error("MODULE_PAYLOAD_DIGEST_MISMATCH");
  return payload;
}

export function readModuleJson(path: string, limit = MODULE_BUNDLE_LIMIT): unknown {
  const stat = lstatSync(path); if (!stat.isFile() || stat.isSymbolicLink() || stat.size > limit) throw new Error("MODULE_INPUT_FILE_REJECTED");
  const bytes = readFileSync(path); if (bytes.length > limit) throw new Error("MODULE_INPUT_FILE_REJECTED"); return JSON.parse(bytes.toString("utf8"));
}
export function canonicalModuleJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalModuleJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalModuleJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
export function assertModulePath(path: string): void {
  if (path.split("/").length > 16 || !/^[a-zA-Z0-9_.\/-]+$/.test(path) || path.split("/").some((part) => !part || part === "." || part === ".." || part.endsWith(".") || /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part) || ["node_modules", ".git", ".env"].includes(part.toLowerCase())) || /\.(?:pem|key|exe|dll|node)$/i.test(path)) throw new Error("MODULE_FILE_PATH_REJECTED");
}
function compareModulePaths(a: string, b: string): number { const left = a.split("/"), right = b.split("/"); for (let i = 0; i < Math.min(left.length, right.length); i++) if (left[i] !== right[i]) return left[i]! < right[i]! ? -1 : 1; return left.length - right.length; }
function pae(bytes: Buffer): Buffer { return Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(MODULE_PAYLOAD_TYPE)} ${MODULE_PAYLOAD_TYPE} ${bytes.length} `), bytes]); }
function sha256(bytes: Buffer): string { return createHash("sha256").update(bytes).digest("hex"); }
