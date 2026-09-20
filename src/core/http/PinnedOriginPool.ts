import { Pool } from "undici";
import type { Dispatcher } from "undici";
import { createBoundPinnedConnector, type PinnedDestination } from "./PinnedHttpTransport.js";

export interface PinnedTransportSettings {
  poolingEnabled: boolean;
  http2Enabled: boolean;
  maxOrigins: number;
  maxConnectionsPerOrigin: number;
  maxConcurrentHttp2Streams: number;
  maxHeaderSizeBytes: number;
  keepAliveTimeoutMs: number;
  keepAliveMaxTimeoutMs: number;
  maxConnectionLifetimeMs: number;
  maxRequestsPerConnection: number;
  dnsCacheTtlMs: number;
}

export interface PinnedTransportDiagnostics extends PinnedTransportSettings {
  requestsDispatched: number;
  poolHits: number;
  poolMisses: number;
  pinRotations: number;
  originEvictions: number;
  connectionsCreated: number;
  estimatedConnectionReuses: number;
  http1Connections: number;
  http2Connections: number;
  dnsResolutions: number;
  dnsCacheHits: number;
  blockedResolutions: number;
  activeOriginPools: number;
  peakOriginPools: number;
}

export const defaultPinnedTransportSettings: PinnedTransportSettings = {
  poolingEnabled: true,
  http2Enabled: false,
  maxOrigins: 64,
  maxConnectionsPerOrigin: 4,
  maxConcurrentHttp2Streams: 32,
  maxHeaderSizeBytes: 16384,
  keepAliveTimeoutMs: 10_000,
  keepAliveMaxTimeoutMs: 30_000,
  maxConnectionLifetimeMs: 120_000,
  maxRequestsPerConnection: 1000,
  dnsCacheTtlMs: 0
};

interface Entry { pin: PinnedDestination; pool: Pool; lastUsedAt: number }
export interface PinnedDispatcherLease { dispatcher: Dispatcher; release(): Promise<void> }

/** One physical pool per exact origin and selected IP. A pool can never receive
 * another origin, which prevents HTTP/2 certificate-based coalescing. */
export class PinnedOriginPool {
  private readonly entries = new Map<string, Entry>();
  private readonly retiring = new Set<Promise<void>>();
  private closed = false;
  private closePromise: Promise<void> | undefined;
  private readonly counters = { requestsDispatched: 0, poolHits: 0, poolMisses: 0, pinRotations: 0, originEvictions: 0, connectionsCreated: 0, http1Connections: 0, http2Connections: 0, dnsResolutions: 0, dnsCacheHits: 0, blockedResolutions: 0, peakOriginPools: 0 };
  public readonly settings: PinnedTransportSettings;

  public constructor(settings: Partial<PinnedTransportSettings> = {}) { this.settings = validateSettings({ ...defaultPinnedTransportSettings, ...settings }); }

  public acquire(pin: PinnedDestination): PinnedDispatcherLease {
    if (this.closed) throw new Error("PINNED_ORIGIN_POOL_CLOSED");
    this.counters.requestsDispatched += 1;
    if (!this.settings.poolingEnabled) { this.counters.poolMisses += 1; const pool = this.createPool(pin, false); return { dispatcher: pool, release: async () => { await pool.close(); } }; }
    const existing = this.entries.get(pin.origin);
    if (existing && samePin(existing.pin, pin) && !existing.pool.closed && !existing.pool.destroyed) { existing.lastUsedAt = Date.now(); this.counters.poolHits += 1; return { dispatcher: existing.pool, release: async () => undefined }; }
    if (existing) { this.entries.delete(pin.origin); this.counters.pinRotations += 1; this.retire(existing.pool); }
    this.evictIfRequired();
    const pool = this.createPool(pin, true); this.entries.set(pin.origin, { pin, pool, lastUsedAt: Date.now() }); this.counters.poolMisses += 1; this.counters.peakOriginPools = Math.max(this.counters.peakOriginPools, this.entries.size); return { dispatcher: pool, release: async () => undefined };
  }

  public recordDnsResolution(): void { this.counters.dnsResolutions += 1; }
  public recordDnsCacheHit(): void { this.counters.dnsCacheHits += 1; }
  public recordBlockedResolution(): void { this.counters.blockedResolutions += 1; }

  public diagnostics(): PinnedTransportDiagnostics {
    return { ...this.settings, ...this.counters, estimatedConnectionReuses: Math.max(0, this.counters.requestsDispatched - this.counters.connectionsCreated), activeOriginPools: this.entries.size };
  }

  public close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    const active = [...this.entries.values()].map((entry) => entry.pool.close());
    this.entries.clear();
    this.closePromise = Promise.allSettled([...active, ...this.retiring]).then(() => undefined);
    return this.closePromise;
  }

  private createPool(pin: PinnedDestination, persistent: boolean): Pool {
    const allowHttp2 = this.settings.http2Enabled && pin.protocol === "https:";
    return new Pool(pin.origin, {
      connect: createBoundPinnedConnector(pin, { allowHttp2, timeoutMs: this.settings.keepAliveMaxTimeoutMs, onConnect: (protocol) => { this.counters.connectionsCreated += 1; if (protocol === "h2") this.counters.http2Connections += 1; else this.counters.http1Connections += 1; } }),
      connections: persistent ? this.settings.maxConnectionsPerOrigin : 1,
      pipelining: 1,
      allowH2: allowHttp2,
      maxConcurrentStreams: this.settings.maxConcurrentHttp2Streams,
      maxHeaderSize: this.settings.maxHeaderSizeBytes,
      keepAliveTimeout: persistent ? this.settings.keepAliveTimeoutMs : 1,
      keepAliveMaxTimeout: persistent ? this.settings.keepAliveMaxTimeoutMs : 1,
      maxRequestsPerClient: persistent ? this.settings.maxRequestsPerConnection : 1,
      clientTtl: persistent ? this.settings.maxConnectionLifetimeMs : 1
    });
  }

  private evictIfRequired(): void {
    if (this.entries.size < this.settings.maxOrigins) return;
    const oldest = [...this.entries.entries()].sort((left, right) => left[1].lastUsedAt - right[1].lastUsedAt)[0];
    if (!oldest) return; this.entries.delete(oldest[0]); this.counters.originEvictions += 1; this.retire(oldest[1].pool);
  }
  private retire(pool: Pool): void { const pending = pool.close().then(() => undefined).catch(() => pool.destroy().then(() => undefined)).finally(() => this.retiring.delete(pending)); this.retiring.add(pending); }
}
function samePin(left: PinnedDestination, right: PinnedDestination): boolean { return left.origin === right.origin && left.address.family === right.address.family && left.address.address.toLowerCase() === right.address.address.toLowerCase(); }
function validateSettings(value: PinnedTransportSettings): PinnedTransportSettings {
  const bounded: Array<[keyof PinnedTransportSettings, number, number]> = [
    ["maxOrigins", 1, 1024], ["maxConnectionsPerOrigin", 1, 32], ["maxConcurrentHttp2Streams", 1, 256], ["maxHeaderSizeBytes", 4096, 65536],
    ["keepAliveTimeoutMs", 100, 120000], ["keepAliveMaxTimeoutMs", 100, 300000], ["maxConnectionLifetimeMs", 1000, 900000],
    ["maxRequestsPerConnection", 1, 10000], ["dnsCacheTtlMs", 0, 60000]
  ];
  for (const [key, minimum, maximum] of bounded) { const candidate = value[key]; if (typeof candidate !== "number" || !Number.isInteger(candidate) || candidate < minimum || candidate > maximum) throw new Error(`PINNED_TRANSPORT_SETTING_INVALID:${key}`); }
  if (value.keepAliveMaxTimeoutMs < value.keepAliveTimeoutMs) throw new Error("PINNED_TRANSPORT_SETTING_INVALID:keepAliveMaxTimeoutMs");
  return Object.freeze({ ...value });
}
