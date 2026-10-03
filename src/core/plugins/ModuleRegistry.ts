import { createHash, timingSafeEqual } from "node:crypto";
import { appendFileSync, lstatSync, mkdirSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer, type ServerOptions } from "node:https";
import { join, resolve } from "node:path";
import { z } from "zod";
import { MODULE_BUNDLE_LIMIT, canonicalModuleJson, moduleEnvelopeSchema, moduleKeyId, moduleTrustSchema, readModuleJson, signModulePayload, validateModulePayload, verifyModuleEnvelope, type ModulePayload, type ModuleTrust } from "./ModuleDistribution.js";

const routeIdentity = /^\/v1\/packages\/([a-z][a-z0-9-]{2,79})\/(\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?)\/([a-f0-9]{64})$/;
export interface ModuleRegistryOptions {
  directory: string;
  /** Read on every operation: rotations and emergency revocations take effect immediately. */
  trustPath: string;
  publishToken: string;
  maxStoredBytes?: number;
  maxVersions?: number;
  tls?: ServerOptions;
  signing?: { token: string; privateKeyPem: string; publisher: string; approvedDigests: readonly string[] };
}

/** Anonymous, bounded discovery; authenticated immutable publication; optional isolated signing role. */
export class ModuleRegistry {
  public readonly server: Server;
  private readonly root: string;
  private active = 0;
  private readonly rates = new Map<string, { at: number; requests: number }>();
  public constructor(private readonly options: ModuleRegistryOptions) {
    if (options.publishToken.length < 32 || (options.signing && (options.signing.token.length < 32 || options.signing.token === options.publishToken))) throw new Error("MODULE_REGISTRY_DISTINCT_TOKENS_REQUIRED");
    if (options.signing) {
      moduleKeyId(options.signing.privateKeyPem);
      if (!options.signing.approvedDigests.length || options.signing.approvedDigests.length > 1000 || options.signing.approvedDigests.some((value) => !/^[a-f0-9]{64}$/.test(value))) throw new Error("MODULE_SIGNING_APPROVALS_REQUIRED");
    }
    this.trust(); mkdirSync(options.directory, { recursive: true }); this.root = realpathSync(resolve(options.directory));
    this.entries();
    const listener = (request: IncomingMessage, response: ServerResponse) => { void this.handle(request, response); };
    this.server = options.tls ? createHttpsServer(options.tls, listener) : createServer(listener);
    this.server.requestTimeout = 15_000; this.server.headersTimeout = 10_000; this.server.keepAliveTimeout = 2000; this.server.maxConnections = 32; this.server.maxRequestsPerSocket = 20;
  }
  public async close(): Promise<void> { this.server.closeAllConnections(); await new Promise<void>((done) => this.server.close(() => done())); }
  private trust(): ModuleTrust { return moduleTrustSchema.parse(readModuleJson(this.options.trustPath, 1024 * 1024)); }
  private entries(): Array<{ file: string; size: number }> {
    const entries: Array<{ file: string; size: number }> = [];
    for (const file of readdirSync(this.root)) {
      if (file === "audit.jsonl") continue;
      if (!/^[a-z][a-z0-9-]{2,79}--\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?\.json$/.test(file)) throw new Error("MODULE_REGISTRY_STORAGE_INVALID");
      const stat = lstatSync(join(this.root, file)); if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MODULE_BUNDLE_LIMIT) throw new Error("MODULE_REGISTRY_STORAGE_INVALID");
      entries.push({ file, size: stat.size });
    }
    if (entries.length > (this.options.maxVersions ?? 100) || entries.reduce((n, entry) => n + entry.size, 0) > (this.options.maxStoredBytes ?? 256 * 1024 * 1024)) throw new Error("MODULE_REGISTRY_CAPACITY");
    return entries;
  }
  private permit(request: IncomingMessage): boolean {
    const now = Date.now();
    for (const [ip, bucket] of this.rates) if (now - bucket.at >= 60_000) this.rates.delete(ip);
    const ip = request.socket.remoteAddress ?? "unknown"; let bucket = this.rates.get(ip);
    if (!bucket) { if (this.rates.size >= 256) return false; bucket = { at: now, requests: 0 }; this.rates.set(ip, bucket); }
    return ++bucket.requests <= 60 && this.active < 4;
  }
  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    response.setHeader("cache-control", "no-store"); response.setHeader("x-content-type-options", "nosniff");
    if (!this.permit(request)) { this.send(response, 429, { error: "MODULE_REGISTRY_RATE_LIMIT" }); request.resume(); return; }
    this.active++;
    try {
      const path = request.url ?? "";
      if (request.method === "GET" && path === "/health") { this.send(response, 200, { schemaVersion: 1, status: "READY" }); return; }
      if (request.method === "GET" && path === "/v1/index") {
        const trust = this.trust(); const packages = [];
        for (const entry of this.entries()) {
          try { const payload = verifyModuleEnvelope(readModuleJson(join(this.root, entry.file)), trust); packages.push(summary(payload)); }
          catch { /* Revoked, expired or invalid artifacts are never advertised. */ }
        }
        this.send(response, 200, { schemaVersion: 1, packages }); return;
      }
      const match = routeIdentity.exec(path);
      if (request.method === "GET" && match) {
        const envelope = readModuleJson(join(this.root, `${match[1]}--${match[2]}.json`)); const payload = verifyModuleEnvelope(envelope, this.trust());
        if (payload.moduleId !== match[1] || payload.version !== match[2] || payload.packageDigest !== match[3]) throw new Error("MODULE_REGISTRY_DIGEST_MISMATCH");
        this.send(response, 200, envelope); return;
      }
      if (request.method === "POST" && path === "/v1/publish") {
        authorize(request, this.options.publishToken);
        const envelope = moduleEnvelopeSchema.parse(await readBody(request)); const payload = verifyModuleEnvelope(envelope, this.trust());
        const bytes = Buffer.from(canonicalModuleJson(envelope)); const entries = this.entries();
        if (entries.length >= (this.options.maxVersions ?? 100) || entries.reduce((n, entry) => n + entry.size, 0) + bytes.length > (this.options.maxStoredBytes ?? 256 * 1024 * 1024)) throw new Error("MODULE_REGISTRY_CAPACITY");
        this.auditPath();
        writeFileSync(join(this.root, `${payload.moduleId}--${payload.version}.json`), bytes, { flag: "wx", mode: 0o600 });
        this.audit("PUBLISHED", payload); this.send(response, 201, summary(payload)); return;
      }
      if (request.method === "POST" && path === "/v1/sign" && this.options.signing) {
        authorize(request, this.options.signing.token);
        const payload = validateModulePayload(await readBody(request)); const signer = this.options.signing;
        if (payload.publisher !== signer.publisher || !signer.approvedDigests.includes(payload.packageDigest)) throw new Error("MODULE_SIGNING_REVIEW_REQUIRED");
        const envelope = signModulePayload(payload, signer.privateKeyPem); verifyModuleEnvelope(envelope, this.trust());
        this.audit("SIGNED", payload); this.send(response, 200, envelope); return;
      }
      request.resume(); this.send(response, 404, { error: "MODULE_REGISTRY_NOT_FOUND" });
    } catch (error) {
      request.resume();
      const code = error instanceof Error && /^MODULE_[A-Z_]+$/.test(error.message) ? error.message : (error as NodeJS.ErrnoException).code === "EEXIST" ? "MODULE_VERSION_IMMUTABLE" : (error as NodeJS.ErrnoException).code === "ENOENT" ? "MODULE_REGISTRY_NOT_FOUND" : "MODULE_REGISTRY_INPUT_REJECTED";
      this.send(response, code === "MODULE_REGISTRY_UNAUTHORIZED" ? 401 : code === "MODULE_VERSION_IMMUTABLE" ? 409 : code === "MODULE_REGISTRY_NOT_FOUND" ? 404 : 400, { error: code });
    } finally { this.active--; }
  }
  private send(response: ServerResponse, status: number, value: unknown): void { if (response.destroyed || response.headersSent) return; response.setHeader("content-type", "application/json"); response.writeHead(status).end(canonicalModuleJson(value)); }
  private audit(action: string, payload: ModulePayload): void {
    appendFileSync(this.auditPath(), `${canonicalModuleJson({ action, at: new Date().toISOString(), ...summary(payload) })}\n`, { mode: 0o600 });
  }
  private auditPath(): string {
    const path = join(this.root, "audit.jsonl");
    try { const stat = lstatSync(path); if (!stat.isFile() || stat.isSymbolicLink() || stat.size >= 4 * 1024 * 1024) throw new Error("MODULE_AUDIT_CAPACITY"); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    return path;
  }
}

export async function moduleRegistryRequest(origin: string, path: string, body?: unknown, token?: string): Promise<unknown> {
  const url = new URL(origin);
  if (url.origin !== origin || url.username || url.password || !(url.protocol === "https:" || (url.protocol === "http:" && ["127.0.0.1", "[::1]"].includes(url.hostname)))) throw new Error("MODULE_REGISTRY_HTTPS_REQUIRED");
  if (!path.startsWith("/v1/") || path.includes("?") || path.includes("#")) throw new Error("MODULE_REGISTRY_PATH_INVALID");
  const serialized = body === undefined ? undefined : canonicalModuleJson(body);
  if (serialized && Buffer.byteLength(serialized) > MODULE_BUNDLE_LIMIT) throw new Error("MODULE_BUNDLE_LIMIT");
  const response = await fetch(`${origin}${path}`, { method: body === undefined ? "GET" : "POST", redirect: "error", signal: AbortSignal.timeout(15_000), headers: { accept: "application/json", ...(body === undefined ? {} : { "content-type": "application/json" }), ...(token ? { authorization: `Bearer ${token}` } : {}) }, ...(serialized === undefined ? {} : { body: serialized }) });
  if (!response.ok) { await response.body?.cancel(); throw new Error(`MODULE_REGISTRY_HTTP_${response.status}`); }
  if (!response.headers.get("content-type")?.startsWith("application/json")) { await response.body?.cancel(); throw new Error("MODULE_REGISTRY_CONTENT_TYPE_INVALID"); }
  if (Number(response.headers.get("content-length") ?? 0) > MODULE_BUNDLE_LIMIT) { await response.body?.cancel(); throw new Error("MODULE_BUNDLE_LIMIT"); }
  const chunks: Uint8Array[] = []; let bytes = 0;
  if (response.body) for await (const chunk of response.body) { bytes += chunk.length; if (bytes > MODULE_BUNDLE_LIMIT) throw new Error("MODULE_BUNDLE_LIMIT"); chunks.push(chunk); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function summary(payload: ModulePayload) { return { publisher: payload.publisher, moduleId: payload.moduleId, version: payload.version, packageDigest: payload.packageDigest, sdkVersion: payload.sdkVersion, nodeMajorVersions: payload.nodeMajorVersions, expiresAt: payload.expiresAt }; }
function authorize(request: IncomingMessage, token: string): void { const actual = createHash("sha256").update(request.headers.authorization ?? "").digest(); const expected = createHash("sha256").update(`Bearer ${token}`).digest(); if (!timingSafeEqual(actual, expected)) throw new Error("MODULE_REGISTRY_UNAUTHORIZED"); }
async function readBody(request: IncomingMessage): Promise<unknown> {
  if (request.headers["content-encoding"] || !request.headers["content-type"]?.startsWith("application/json") || Number(request.headers["content-length"] ?? 0) > MODULE_BUNDLE_LIMIT) throw new Error("MODULE_REGISTRY_BODY_REJECTED");
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of request) { bytes += chunk.length; if (bytes > MODULE_BUNDLE_LIMIT) throw new Error("MODULE_BUNDLE_LIMIT"); chunks.push(Buffer.from(chunk)); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export const moduleRegistryConfigSchema = z.object({ directory: z.string().min(1), trustPath: z.string().min(1), host: z.enum(["127.0.0.1", "::1", "0.0.0.0", "::"]).default("127.0.0.1"), port: z.number().int().min(1).max(65535).default(8788), publishTokenEnv: z.string().regex(/^[A-Z][A-Z0-9_]{1,126}$/), tls: z.object({ certificatePath: z.string().min(1), privateKeyPath: z.string().min(1) }).strict().optional(), signing: z.object({ tokenEnv: z.string().regex(/^[A-Z][A-Z0-9_]{1,126}$/), privateKeyPath: z.string().min(1), publisher: z.string().regex(/^[a-z][a-z0-9.-]{2,79}$/), approvedDigests: z.array(z.string().regex(/^[a-f0-9]{64}$/)).min(1).max(1000) }).strict().optional() }).strict().superRefine((value, ctx) => { if (!["127.0.0.1", "::1"].includes(value.host) && !value.tls) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Public binding requires TLS." }); });
