import { createHash, createHmac, generateKeyPairSync, randomBytes, sign, timingSafeEqual } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export type TestInboxChannel = "EMAIL" | "SMS";

export interface TestInboxMessage {
  id: string;
  channel: TestInboxChannel;
  recipient: string;
  sender?: string;
  subject?: string;
  text: string;
  html?: string;
  receivedAt: string;
}

export interface TestInboxQuery {
  channel: TestInboxChannel;
  recipient: string;
  after?: string;
}

export interface TestInboxAdapter {
  waitForMessage(query: TestInboxQuery, options?: { timeoutMs?: number; pollIntervalMs?: number; signal?: AbortSignal }): Promise<TestInboxMessage>;
  clear?(query: Pick<TestInboxQuery, "channel" | "recipient">): Promise<void>;
}

/** A deterministic adapter for local applications and provider emulator tests. */
export class InMemoryTestInboxAdapter implements TestInboxAdapter {
  private readonly messages: TestInboxMessage[] = [];
  private readonly waiters = new Set<() => void>();

  public deliver(message: Omit<TestInboxMessage, "id" | "receivedAt"> & Partial<Pick<TestInboxMessage, "id" | "receivedAt">>): TestInboxMessage {
    const stored: TestInboxMessage = {
      ...message,
      id: message.id ?? randomBytes(12).toString("hex"),
      receivedAt: message.receivedAt ?? new Date().toISOString()
    };
    this.messages.push(stored);
    for (const wake of this.waiters) wake();
    this.waiters.clear();
    return stored;
  }

  public async waitForMessage(query: TestInboxQuery, options: { timeoutMs?: number; pollIntervalMs?: number; signal?: AbortSignal } = {}): Promise<TestInboxMessage> {
    const timeoutMs = Math.min(options.timeoutMs ?? 30_000, 300_000);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      if (options.signal?.aborted) throw new Error("TEST_INBOX_ABORTED");
      const after = query.after ? Date.parse(query.after) : Number.NEGATIVE_INFINITY;
      const match = [...this.messages].reverse().find((message) => message.channel === query.channel && message.recipient === query.recipient && Date.parse(message.receivedAt) > after);
      if (match) return match;
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error("TEST_INBOX_TIMEOUT");
      await this.wait(Math.min(remaining, options.pollIntervalMs ?? 250), options.signal);
    }
  }

  public async clear(query: Pick<TestInboxQuery, "channel" | "recipient">): Promise<void> {
    for (let index = this.messages.length - 1; index >= 0; index -= 1) {
      const message = this.messages[index];
      if (message?.channel === query.channel && message.recipient === query.recipient) this.messages.splice(index, 1);
    }
  }

  private wait(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const done = () => { if (settled) return; settled = true; clearTimeout(timer); this.waiters.delete(done); signal?.removeEventListener("abort", abort); resolve(); };
      const abort = () => { if (settled) return; settled = true; clearTimeout(timer); this.waiters.delete(done); reject(new Error("TEST_INBOX_ABORTED")); };
      const timer = setTimeout(done, ms);
      this.waiters.add(done);
      signal?.addEventListener("abort", abort, { once: true });
    });
  }
}

/** Loopback webhook receiver usable as an email or SMS sink by a local test app. */
export class LocalTestInboxHarness implements TestInboxAdapter {
  private readonly inbox = new InMemoryTestInboxAdapter();
  private server: Server | undefined;
  private endpoint: string | undefined;

  public async start(port = 0): Promise<{ endpoint: string }> {
    if (this.server && this.endpoint) return { endpoint: this.endpoint };
    const server = createServer(async (request, response) => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "POST" && url.pathname === "/messages") {
        try {
          const body = await readJsonBody(request, 64 * 1024) as Partial<TestInboxMessage>;
          if ((body.channel !== "EMAIL" && body.channel !== "SMS") || typeof body.recipient !== "string" || typeof body.text !== "string") throw new Error("invalid message");
          const message = this.inbox.deliver({ channel: body.channel, recipient: body.recipient, text: body.text, ...(typeof body.sender === "string" ? { sender: body.sender } : {}), ...(typeof body.subject === "string" ? { subject: body.subject } : {}), ...(typeof body.html === "string" ? { html: body.html } : {}) });
          response.writeHead(202, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify({ accepted: true, id: message.id }));
        } catch {
          response.writeHead(400, { "content-type": "application/json", "cache-control": "no-store" }).end('{"accepted":false}');
        }
        return;
      }
      response.writeHead(404, { "cache-control": "no-store" }).end();
    });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(port, "127.0.0.1", () => { server.off("error", reject); resolve(); }); });
    this.server = server;
    this.endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}/messages`;
    return { endpoint: this.endpoint };
  }

  public waitForMessage(query: TestInboxQuery, options?: { timeoutMs?: number; pollIntervalMs?: number; signal?: AbortSignal }): Promise<TestInboxMessage> { return this.inbox.waitForMessage(query, options); }
  public clear(query: Pick<TestInboxQuery, "channel" | "recipient">): Promise<void> { return this.inbox.clear(query); }
  public async close(): Promise<void> { const server = this.server; this.server = undefined; this.endpoint = undefined; if (server) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
}

abstract class PollingTestInboxAdapter implements TestInboxAdapter {
  public async waitForMessage(query: TestInboxQuery, options: { timeoutMs?: number; pollIntervalMs?: number; signal?: AbortSignal } = {}): Promise<TestInboxMessage> {
    const deadline = Date.now() + Math.min(options.timeoutMs ?? 30_000, 300_000);
    for (;;) {
      if (options.signal?.aborted) throw new Error("TEST_INBOX_ABORTED");
      const messages = await this.list(query, options.signal);
      const after = query.after ? Date.parse(query.after) : Number.NEGATIVE_INFINITY;
      const match = messages.filter((item) => item.channel === query.channel && item.recipient.toLowerCase() === query.recipient.toLowerCase() && Date.parse(item.receivedAt) > after).sort((left, right) => Date.parse(right.receivedAt) - Date.parse(left.receivedAt))[0];
      if (match) return match;
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error("TEST_INBOX_TIMEOUT");
      await delay(Math.min(remaining, options.pollIntervalMs ?? 500), options.signal);
    }
  }

  protected abstract list(query: TestInboxQuery, signal?: AbortSignal): Promise<TestInboxMessage[]>;
}

/** Adapter for Mailpit's test-only HTTP API. */
export class MailpitTestInboxAdapter extends PollingTestInboxAdapter {
  private readonly baseUrl: string;
  public constructor(baseUrl: string, private readonly requestJson: (url: string, signal?: AbortSignal) => Promise<unknown> = boundedFetchJson) { super(); this.baseUrl = safeAdapterBase(baseUrl); }
  protected async list(query: TestInboxQuery, signal?: AbortSignal): Promise<TestInboxMessage[]> {
    if (query.channel !== "EMAIL") return [];
    const search = await this.requestJson(`${this.baseUrl}/api/v1/search?query=${encodeURIComponent(`to:${query.recipient}`)}`, signal) as { messages?: Array<Record<string, unknown>> };
    const values: TestInboxMessage[] = [];
    for (const item of search.messages ?? []) {
      const id = stringValue(item.ID ?? item.id); if (!id) continue;
      const detail = await this.requestJson(`${this.baseUrl}/api/v1/message/${encodeURIComponent(id)}`, signal) as Record<string, unknown>;
      values.push({ id, channel: "EMAIL", recipient: firstAddress(detail.To ?? item.To) ?? query.recipient, ...(stringValue(detail.From ?? item.From) ? { sender: stringValue(detail.From ?? item.From)! } : {}), ...(stringValue(detail.Subject ?? item.Subject) ? { subject: stringValue(detail.Subject ?? item.Subject)! } : {}), text: stringValue(detail.Text) ?? "", ...(stringValue(detail.HTML) ? { html: stringValue(detail.HTML)! } : {}), receivedAt: normalizedDate(detail.Created ?? item.Created) });
    }
    return values;
  }
}

/** Adapter for MailHog's v2 search API. */
export class MailHogTestInboxAdapter extends PollingTestInboxAdapter {
  private readonly baseUrl: string;
  public constructor(baseUrl: string, private readonly requestJson: (url: string, signal?: AbortSignal) => Promise<unknown> = boundedFetchJson) { super(); this.baseUrl = safeAdapterBase(baseUrl); }
  protected async list(query: TestInboxQuery, signal?: AbortSignal): Promise<TestInboxMessage[]> {
    if (query.channel !== "EMAIL") return [];
    const search = await this.requestJson(`${this.baseUrl}/api/v2/search?kind=to&query=${encodeURIComponent(query.recipient)}`, signal) as { items?: Array<Record<string, unknown>> };
    return (search.items ?? []).flatMap((item) => {
      const id = stringValue(item.ID); const content = objectValue(item.Content); const headers = objectValue(content.Headers);
      if (!id) return [];
      return [{ id, channel: "EMAIL" as const, recipient: firstHeader(headers.To) ?? query.recipient, ...(firstHeader(headers.From) ? { sender: firstHeader(headers.From)! } : {}), ...(firstHeader(headers.Subject) ? { subject: firstHeader(headers.Subject)! } : {}), text: stringValue(content.Body) ?? "", receivedAt: normalizedDate(item.Created) }];
    });
  }
}

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface TotpProfile {
  secret: string;
  encoding?: "BASE32" | "HEX" | "UTF8";
  algorithm?: TotpAlgorithm;
  digits?: 6 | 7 | 8;
  periodSeconds?: number;
  epochSeconds?: number;
}

export function generateTotp(profile: TotpProfile, at = new Date()): { code: string; counter: number; validFrom: string; validUntil: string } {
  const period = profile.periodSeconds ?? 30;
  if (!Number.isInteger(period) || period < 5 || period > 300) throw new Error("TOTP_PERIOD_INVALID");
  const epoch = profile.epochSeconds ?? 0;
  const seconds = Math.floor(at.getTime() / 1000);
  const counter = Math.floor((seconds - epoch) / period);
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error("TOTP_TIME_INVALID");
  const digits = profile.digits ?? 6;
  const code = hotp(decodeTotpSecret(profile.secret, profile.encoding ?? "BASE32"), counter, profile.algorithm ?? "SHA1", digits);
  const validFromSeconds = epoch + counter * period;
  return { code, counter, validFrom: new Date(validFromSeconds * 1000).toISOString(), validUntil: new Date((validFromSeconds + period) * 1000).toISOString() };
}

export function verifyTotp(code: string, profile: TotpProfile, at = new Date(), window = 1): { valid: boolean; delta?: number } {
  if (!/^\d{6,8}$/.test(code) || !Number.isInteger(window) || window < 0 || window > 10) return { valid: false };
  const period = profile.periodSeconds ?? 30;
  for (let delta = -window; delta <= window; delta += 1) {
    const candidate = generateTotp(profile, new Date(at.getTime() + delta * period * 1000)).code;
    if (candidate.length === code.length && timingSafeEqual(Buffer.from(candidate), Buffer.from(code))) return { valid: true, delta: delta === 0 ? 0 : delta };
  }
  return { valid: false };
}

function hotp(secret: Buffer, counter: number, algorithm: TotpAlgorithm, digits: number): string {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac(algorithm.toLowerCase().replace("sha", "sha") as "sha1" | "sha256" | "sha512", secret).update(buffer).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const value = (digest.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits);
  return value.toString().padStart(digits, "0");
}

function decodeTotpSecret(secret: string, encoding: NonNullable<TotpProfile["encoding"]>): Buffer {
  if (encoding === "HEX") {
    if (!/^(?:[0-9a-f]{2})+$/i.test(secret)) throw new Error("TOTP_SECRET_INVALID");
    return Buffer.from(secret, "hex");
  }
  if (encoding === "UTF8") return Buffer.from(secret, "utf8");
  const normalized = secret.toUpperCase().replace(/[\s=-]/g, "");
  if (!/^[A-Z2-7]+$/.test(normalized)) throw new Error("TOTP_SECRET_INVALID");
  let bits = "";
  for (const character of normalized) bits += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(character).toString(2).padStart(5, "0");
  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  return Buffer.from(bytes);
}

export interface OidcHarnessOptions {
  clientId: string;
  clientSecret?: string;
  redirectUris: string[];
  subject: string;
  claims?: Record<string, string | number | boolean>;
  port?: number;
  accessTokenLifetimeSeconds?: number;
}

/** A loopback-only OAuth 2.0/OIDC authorization-code IdP and callback receiver. */
export class OidcTestHarness {
  private readonly keyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  private readonly codes = new Map<string, { clientId: string; redirectUri: string; subject: string; nonce?: string; codeChallenge?: string; expiresAt: number }>();
  private readonly callbacks: Array<Record<string, string>> = [];
  private server: Server | undefined;
  private issuer: string | undefined;

  public constructor(private readonly options: OidcHarnessOptions) {
    if (!options.clientId || !options.redirectUris.length || options.redirectUris.some((uri) => !isSafeRedirectUri(uri))) throw new Error("OIDC_HARNESS_CONFIGURATION_INVALID");
  }

  public async start(): Promise<{ issuer: string; authorizationEndpoint: string; tokenEndpoint: string; callbackEndpoint: string }> {
    if (!this.server) {
      const server = createServer((request, response) => { void this.handle(request, response); });
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(this.options.port ?? 0, "127.0.0.1", () => { server.off("error", reject); resolve(); }); });
      this.server = server;
      this.issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    }
    return { issuer: this.issuer!, authorizationEndpoint: `${this.issuer}/authorize`, tokenEndpoint: `${this.issuer}/token`, callbackEndpoint: `${this.issuer}/callback` };
  }

  public async waitForCallback(options: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<Record<string, string>> {
    const deadline = Date.now() + Math.min(options.timeoutMs ?? 30_000, 300_000);
    while (Date.now() < deadline) {
      if (options.signal?.aborted) throw new Error("OIDC_CALLBACK_ABORTED");
      const callback = this.callbacks.shift();
      if (callback) return callback;
      await delay(Math.min(100, deadline - Date.now()), options.signal);
    }
    throw new Error("OIDC_CALLBACK_TIMEOUT");
  }

  public async close(): Promise<void> { const server = this.server; this.server = undefined; this.issuer = undefined; this.codes.clear(); this.callbacks.splice(0); if (server) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }

  private async handle(request: import("node:http").IncomingMessage, response: import("node:http").ServerResponse): Promise<void> {
    const origin = this.issuer ?? "http://127.0.0.1";
    const url = new URL(request.url ?? "/", origin);
    response.setHeader("cache-control", "no-store");
    if (request.method === "GET" && url.pathname === "/.well-known/openid-configuration") return json(response, 200, { issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, jwks_uri: `${origin}/jwks.json`, response_types_supported: ["code"], subject_types_supported: ["public"], id_token_signing_alg_values_supported: ["RS256"], code_challenge_methods_supported: ["S256"] });
    if (request.method === "GET" && url.pathname === "/jwks.json") return json(response, 200, { keys: [{ ...(this.keyPair.publicKey.export({ format: "jwk" }) as Record<string, unknown>), use: "sig", alg: "RS256", kid: "routecairn-fixture" }] });
    if (request.method === "GET" && url.pathname === "/authorize") {
      const clientId = url.searchParams.get("client_id") ?? "";
      const redirectUri = url.searchParams.get("redirect_uri") ?? "";
      const state = url.searchParams.get("state") ?? "";
      if (url.searchParams.get("response_type") !== "code" || clientId !== this.options.clientId || !this.options.redirectUris.includes(redirectUri) || !state) return oauthError(response, 400, "invalid_request");
      const challenge = url.searchParams.get("code_challenge") ?? undefined;
      if (challenge && (url.searchParams.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge))) return oauthError(response, 400, "invalid_request");
      const code = randomUrlToken(32);
      this.codes.set(code, { clientId, redirectUri, subject: this.options.subject, ...(url.searchParams.get("nonce") ? { nonce: url.searchParams.get("nonce")! } : {}), ...(challenge ? { codeChallenge: challenge } : {}), expiresAt: Date.now() + 60_000 });
      const location = new URL(redirectUri); location.searchParams.set("code", code); location.searchParams.set("state", state);
      response.writeHead(302, { location: location.toString() }).end(); return;
    }
    if (request.method === "POST" && url.pathname === "/token") {
      const body = new URLSearchParams(await readTextBody(request, 32 * 1024));
      const code = body.get("code") ?? "";
      const record = this.codes.get(code);
      this.codes.delete(code);
      if (body.get("grant_type") !== "authorization_code" || !record || record.expiresAt <= Date.now() || body.get("client_id") !== record.clientId || body.get("redirect_uri") !== record.redirectUri || (this.options.clientSecret && body.get("client_secret") !== this.options.clientSecret)) return oauthError(response, 400, "invalid_grant");
      if (record.codeChallenge && base64Url(createHash("sha256").update(body.get("code_verifier") ?? "").digest()) !== record.codeChallenge) return oauthError(response, 400, "invalid_grant");
      const now = Math.floor(Date.now() / 1000); const expiresIn = this.options.accessTokenLifetimeSeconds ?? 300;
      const idToken = this.signJwt({ iss: origin, aud: record.clientId, sub: record.subject, iat: now, exp: now + expiresIn, ...(record.nonce ? { nonce: record.nonce } : {}), ...this.options.claims });
      return json(response, 200, { token_type: "Bearer", access_token: randomUrlToken(32), id_token: idToken, expires_in: expiresIn });
    }
    if (request.method === "GET" && url.pathname === "/callback") {
      const values = Object.fromEntries(url.searchParams.entries()); this.callbacks.push(values);
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end("<!doctype html><title>Authentication callback received</title><p>You can close this window.</p>"); return;
    }
    response.writeHead(404).end();
  }

  private signJwt(payload: Record<string, unknown>): string {
    const header = base64Url(Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "routecairn-fixture" })));
    const body = base64Url(Buffer.from(JSON.stringify(payload)));
    return `${header}.${body}.${base64Url(sign("RSA-SHA256", Buffer.from(`${header}.${body}`), this.keyPair.privateKey))}`;
  }
}

function isSafeRedirectUri(value: string): boolean { try { const url = new URL(value); return url.protocol === "https:" || (url.protocol === "http:" && ["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname)); } catch { return false; } }
function safeAdapterBase(value: string): string { const url = new URL(value); if (url.username || url.password || url.search || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname)))) throw new Error("TEST_INBOX_BASE_URL_INVALID"); return url.toString().replace(/\/$/, ""); }
async function boundedFetchJson(url: string, signal?: AbortSignal): Promise<unknown> { const response = await fetch(url, { redirect: "error", headers: { accept: "application/json" }, ...(signal ? { signal } : {}) }); if (!response.ok) throw new Error(`TEST_INBOX_HTTP_${response.status}`); const declared = Number(response.headers.get("content-length") ?? "0"); if (declared > 1024 * 1024) throw new Error("TEST_INBOX_RESPONSE_LIMIT"); const body = await response.text(); if (Buffer.byteLength(body, "utf8") > 1024 * 1024) throw new Error("TEST_INBOX_RESPONSE_LIMIT"); return JSON.parse(body); }
function objectValue(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function stringValue(value: unknown): string | undefined { return typeof value === "string" && value.length > 0 ? value : undefined; }
function firstAddress(value: unknown): string | undefined { if (Array.isArray(value)) { const first = value[0]; if (typeof first === "string") return first; if (first && typeof first === "object") return stringValue((first as Record<string, unknown>).Address ?? (first as Record<string, unknown>).address); } return stringValue(value); }
function firstHeader(value: unknown): string | undefined { return Array.isArray(value) ? stringValue(value[0]) : stringValue(value); }
function normalizedDate(value: unknown): string { const parsed = typeof value === "string" ? new Date(value) : new Date(); return Number.isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString(); }
function randomUrlToken(bytes: number): string { return base64Url(randomBytes(bytes)); }
function base64Url(value: Buffer): string { return value.toString("base64url"); }
function json(response: import("node:http").ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(value)); }
function oauthError(response: import("node:http").ServerResponse, status: number, error: string): void { json(response, status, { error }); }
async function readTextBody(request: import("node:http").IncomingMessage, limit: number): Promise<string> { const chunks: Buffer[] = []; let length = 0; for await (const chunk of request) { const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); length += buffer.length; if (length > limit) throw new Error("BODY_LIMIT_EXCEEDED"); chunks.push(buffer); } return Buffer.concat(chunks).toString("utf8"); }
async function readJsonBody(request: import("node:http").IncomingMessage, limit: number): Promise<unknown> { return JSON.parse(await readTextBody(request, limit)); }
function delay(ms: number, signal?: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { if (signal?.aborted) return reject(new Error("ABORTED")); const timer = setTimeout(resolve, Math.max(0, ms)); signal?.addEventListener("abort", () => { clearTimeout(timer); reject(new Error("ABORTED")); }, { once: true }); }); }
