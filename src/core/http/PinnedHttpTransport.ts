import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP, type Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import { buildConnector as createUndiciConnector } from "undici";
import { isProhibitedAddress } from "../net/AddressClassifier.js";
import type { DnsAddress, DnsResolver } from "./HttpTypes.js";

export interface DestinationPolicyOptions {
  allowedPrivateOrigins: readonly string[];
  dnsResolver?: DnsResolver;
  dnsTimeoutMs: number;
  maxDnsAnswers: number;
}

export interface PinnedDestination {
  origin: string;
  hostname: string;
  port: string;
  protocol: "http:" | "https:";
  address: DnsAddress;
  addressFingerprint: string;
  privateOriginExceptionUsed: boolean;
  answerCount: number;
}

interface ConnectorOptions {
  hostname: string;
  host?: string;
  protocol: string;
  port: string;
  servername?: string;
  localAddress?: string | null;
  socketPath?: string | null;
  httpSocket?: Socket;
}

interface ConnectorCallback {
  (error: null, socket: Socket | TLSSocket): void;
  (error: Error, socket: null): void;
}
type Connector = (options: ConnectorOptions, callback: ConnectorCallback) => void;

const defaultDnsTimeoutMs = 3000;
const defaultMaxDnsAnswers = 16;

export function createPinnedConnector(options: Partial<DestinationPolicyOptions> = {}): Connector {
  const policy: DestinationPolicyOptions = {
    allowedPrivateOrigins: options.allowedPrivateOrigins ?? [],
    dnsTimeoutMs: options.dnsTimeoutMs ?? defaultDnsTimeoutMs,
    maxDnsAnswers: options.maxDnsAnswers ?? defaultMaxDnsAnswers,
    ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {})
  };
  const baseConnector = createUndiciConnector({ keepAlive: false, maxCachedSessions: 0, allowH2: false, timeout: policy.dnsTimeoutMs });

  return (connectOptions, callback) => {
    resolvePinnedDestination(connectOptions, policy)
      .then((pin) => {
        baseConnector(
          {
            ...connectOptions,
            hostname: pin.address.address,
            host: pin.address.address,
            ...(connectOptions.protocol === "https:" && !isIpLiteral(pin.hostname) ? { servername: pin.hostname } : connectOptions.servername ? { servername: connectOptions.servername } : {})
          },
          (error, socket) => {
            if (error || !socket) {
              callback(error ?? new PinnedConnectionError("Pinned connection failed.", "PINNED_CONNECTION_FAILED"), null);
              return;
            }
            const remoteAddress = socket.remoteAddress;
            if (!remoteAddress || !sameIp(remoteAddress, pin.address.address)) {
              socket.destroy();
              callback(new PinnedConnectionError("Pinned socket remote address did not match the selected destination.", "PINNED_REMOTE_ADDRESS_MISMATCH"), null);
              return;
            }
            callback(null, socket);
          }
        );
      })
      .catch((error: unknown) => {
        callback(normalizePinnedError(error), null);
      });
  };
}

/** A connector permanently bound to one already-validated origin/address pair.
 * It is safe to reuse only for that exact origin. The remote socket is checked
 * again after connect and TLS continues to authenticate the original hostname. */
export function createBoundPinnedConnector(pin: PinnedDestination, options: { allowHttp2: boolean; timeoutMs: number; onConnect?: (protocol: "http/1.1" | "h2") => void }): Connector {
  const baseConnector = createUndiciConnector({ keepAlive: true, keepAliveInitialDelay: 1000, maxCachedSessions: 100, allowH2: options.allowHttp2, timeout: options.timeoutMs });
  return (connectOptions, callback) => {
    let requested: PinnedDestination;
    try {
      const protocol = protocolFor(connectOptions.protocol);
      const hostname = canonicalHostname(connectOptions.hostname);
      const port = connectOptions.port || (protocol === "https:" ? "443" : "80");
      requested = { ...pin, protocol, hostname, port, origin: `${protocol}//${hostForOrigin(hostname, port, protocol)}` };
      if (requested.origin !== pin.origin || hostname !== pin.hostname || port !== pin.port || protocol !== pin.protocol) throw new PinnedConnectionError("Origin-isolated pool rejected a cross-origin connection.", "PINNED_POOL_ORIGIN_MISMATCH");
    } catch (error) { callback(normalizePinnedError(error), null); return; }
    baseConnector({ ...connectOptions, hostname: pin.address.address, host: pin.address.address, ...(pin.protocol === "https:" && !isIpLiteral(pin.hostname) ? { servername: pin.hostname } : connectOptions.servername ? { servername: connectOptions.servername } : {}) }, (error, socket) => {
      if (error || !socket) { callback(error ?? new PinnedConnectionError("Pinned connection failed.", "PINNED_CONNECTION_FAILED"), null); return; }
      if (!socket.remoteAddress || !sameIp(socket.remoteAddress, pin.address.address)) { socket.destroy(); callback(new PinnedConnectionError("Pinned socket remote address did not match the selected destination.", "PINNED_REMOTE_ADDRESS_MISMATCH"), null); return; }
      const alpn = "alpnProtocol" in socket ? (socket as TLSSocket).alpnProtocol : undefined;
      if (alpn === "h2" && (!options.allowHttp2 || pin.protocol !== "https:")) { socket.destroy(); callback(new PinnedConnectionError("HTTP/2 negotiation was not permitted for this pool.", "PINNED_HTTP2_POLICY_MISMATCH"), null); return; }
      options.onConnect?.(alpn === "h2" ? "h2" : "http/1.1");
      callback(null, socket);
    });
  };
}

export function connectorOptionsForUrl(url: URL): ConnectorOptions {
  return { hostname: url.hostname, protocol: url.protocol, port: url.port || (url.protocol === "https:" ? "443" : "80") };
}

export async function resolvePinnedDestination(connectOptions: ConnectorOptions, policy: DestinationPolicyOptions): Promise<PinnedDestination> {
  const protocol = protocolFor(connectOptions.protocol);
  const hostname = canonicalHostname(connectOptions.hostname);
  const port = connectOptions.port || (protocol === "https:" ? "443" : "80");
  const origin = `${protocol}//${hostForOrigin(hostname, port, protocol)}`;
  const privateOriginAllowed = policy.allowedPrivateOrigins.includes(origin);
  const answers = await resolveAddresses(hostname, policy);
  if (answers.length === 0) throw new PinnedConnectionError("DNS resolution returned no addresses.", "DNS_NO_ADDRESSES");
  if (answers.length > policy.maxDnsAnswers) throw new PinnedConnectionError("DNS resolution returned too many addresses.", "DNS_TOO_MANY_ADDRESSES");

  const unique = dedupeAddresses(answers);
  const classes = unique.map((address) => addressClass(address.address, privateOriginAllowed));
  const blocked = classes.find((item) => !item.allowed);
  if (blocked) throw new PinnedConnectionError(blocked.message, blocked.code);
  const classNames = new Set(classes.map((item) => item.networkClass));
  if (classNames.size > 1) throw new PinnedConnectionError("DNS answer set mixed incompatible destination classes.", "DNS_MIXED_DESTINATION_CLASSES");

  const selected = [...unique].sort(compareAddress)[0];
  if (!selected) throw new PinnedConnectionError("DNS resolution returned no usable addresses.", "DNS_NO_ADDRESSES");
  return Object.freeze({
    origin,
    hostname,
    port,
    protocol,
    address: selected,
    addressFingerprint: fingerprintAddress(selected.address),
    privateOriginExceptionUsed: privateOriginAllowed && classes[0]?.networkClass === "private",
    answerCount: unique.length
  });
}

export class PinnedConnectionError extends Error {
  public constructor(message: string, public readonly code: string) {
    super(message);
    this.name = code;
  }
}

async function resolveAddresses(hostname: string, policy: DestinationPolicyOptions): Promise<readonly DnsAddress[]> {
  const literal = normalizeIp(hostname);
  if (literal) return [{ address: literal.address, family: literal.family }];
  if (isInternalHostname(hostname)) throw new PinnedConnectionError("Internal hostname was blocked by destination policy.", "DNS_PROHIBITED_ADDRESS");

  const resolver = policy.dnsResolver ?? defaultResolver;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new PinnedConnectionError("DNS resolution timed out.", "DNS_TIMEOUT")), policy.dnsTimeoutMs); timer.unref(); });
  const raw = await Promise.race([resolver(hostname), timeout]).catch((error: unknown) => {
    if (error instanceof PinnedConnectionError) throw error;
    throw new PinnedConnectionError("DNS resolution failed.", "DNS_RESOLUTION_FAILED");
  }).finally(() => { if (timer) clearTimeout(timer); });
  return raw.map(normalizeDnsAnswer);
}

async function defaultResolver(hostname: string): Promise<readonly DnsAddress[]> {
  const results = await lookup(hostname, { all: true, verbatim: false });
  return results.map((result) => ({ address: result.address, family: result.family === 6 ? 6 : 4 }));
}

function normalizeDnsAnswer(answer: string | DnsAddress): DnsAddress {
  const value = typeof answer === "string" ? answer : answer.address;
  const normalized = normalizeIp(value);
  if (!normalized) throw new PinnedConnectionError("DNS returned an unsupported address.", "DNS_PROHIBITED_ADDRESS");
  return normalized;
}

function addressClass(address: string, privateOriginAllowed: boolean): { allowed: true; networkClass: "public" | "private" } | { allowed: false; networkClass: "private"; code: string; message: string } {
  if (isCloudMetadataAddress(address)) return { allowed: false, networkClass: "private", code: "DNS_PROHIBITED_ADDRESS", message: "Cloud metadata destination was blocked." };
  if (isMulticastOrReserved(address)) return { allowed: false, networkClass: "private", code: "DNS_PROHIBITED_ADDRESS", message: "Reserved destination address was blocked." };
  if (isProhibitedAddress(address)) {
    return privateOriginAllowed
      ? { allowed: true, networkClass: "private" }
      : { allowed: false, networkClass: "private", code: "DNS_PRIVATE_ORIGIN_NOT_ALLOWED", message: "Private destination requires an exact private-origin exception." };
  }
  return { allowed: true, networkClass: "public" };
}

function protocolFor(value: string): "http:" | "https:" {
  if (value === "http:" || value === "https:") return value;
  throw new PinnedConnectionError("Unsupported protocol for pinned HTTP transport.", "DESTINATION_POLICY_BLOCKED");
}

function canonicalHostname(value: string): string {
  const hostname = value.replace(/\.$/, "").toLowerCase();
  if (!hostname || hostname.includes("%")) throw new PinnedConnectionError("Invalid hostname for pinned HTTP transport.", "DESTINATION_POLICY_BLOCKED");
  return hostname;
}

function hostForOrigin(hostname: string, port: string, protocol: "http:" | "https:"): string {
  const bracketed = hostname.includes(":") && !hostname.startsWith("[") ? `[${hostname}]` : hostname;
  const defaultPort = protocol === "https:" ? "443" : "80";
  return port === defaultPort ? bracketed : `${bracketed}:${port}`;
}

function normalizeIp(value: string): DnsAddress | undefined {
  const unbracketed = value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
  if (isIP(unbracketed) === 4) return { address: unbracketed, family: 4 };
  if (isIP(unbracketed) === 6) return { address: unbracketed.toLowerCase(), family: 6 };
  return undefined;
}

function isIpLiteral(value: string): boolean {
  return Boolean(normalizeIp(value));
}

function sameIp(left: string, right: string): boolean {
  const normalizedLeft = normalizeIp(left);
  const normalizedRight = normalizeIp(right);
  if (!normalizedLeft || !normalizedRight) return false;
  if (normalizedLeft.address === normalizedRight.address) return true;
  if (normalizedLeft.family === 6 && normalizedRight.family === 4 && normalizedLeft.address.toLowerCase() === `::ffff:${normalizedRight.address}`) return true;
  if (normalizedLeft.family === 4 && normalizedRight.family === 6 && normalizedRight.address.toLowerCase() === `::ffff:${normalizedLeft.address}`) return true;
  return false;
}

function dedupeAddresses(addresses: readonly DnsAddress[]): DnsAddress[] {
  const seen = new Set<string>();
  const unique: DnsAddress[] = [];
  for (const address of addresses) {
    const key = `${address.family}:${address.address.toLowerCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(address);
    }
  }
  return unique;
}

function compareAddress(left: DnsAddress, right: DnsAddress): number {
  if (left.family !== right.family) return left.family - right.family;
  return left.address.localeCompare(right.address);
}

function fingerprintAddress(address: string): string {
  return createHash("sha256").update("routecairn-pinned-address-v1").update("\0").update(address).digest("hex").slice(0, 16);
}

function isInternalHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal") || !hostname.includes(".");
}

function isCloudMetadataAddress(address: string): boolean {
  const normalized = normalizeIp(address)?.address.toLowerCase() ?? address.toLowerCase();
  return normalized === "169.254.169.254" || normalized === "fd00:ec2::254";
}

function isMulticastOrReserved(address: string): boolean {
  const normalized = normalizeIp(address);
  if (!normalized) return true;
  if (normalized.family === 6) {
    const value = normalized.address.toLowerCase();
    return value.startsWith("ff") || value === "::";
  }
  const [first, second] = normalized.address.split(".").map((part) => Number.parseInt(part, 10)) as [number, number, number, number];
  return first >= 224 || (first === 192 && second === 0);
}

function normalizePinnedError(error: unknown): Error {
  if (error instanceof Error) return error;
  return new PinnedConnectionError("Pinned connection failed.", "PINNED_CONNECTION_FAILED");
}
