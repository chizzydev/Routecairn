import Database from "better-sqlite3";
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { OastEvidenceSummary, OastLeaseIdentity, OastLeaseRequest, OastPollResponse, OastProtocol } from "./OastTypes.js";

interface LeaseRow { id: string; signature: string; expires_at: string; poll_token_hash: string; binding_fingerprint: string; status: "ACTIVE" | "REVOKED"; protocols_json: string; created_at: string }

export class OastStore {
  private readonly db: Database.Database;
  public constructor(path: string, private readonly signingKey: Buffer, private readonly baseDomain: string, private readonly publicHttpBaseUrl: string | undefined, private readonly publicHttpsBaseUrl: string | undefined, private readonly maxLeaseSeconds: number, private readonly maxEventsPerLease: number, private readonly now: () => number = Date.now) {
    mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL"); this.db.pragma("busy_timeout = 5000"); this.db.pragma("foreign_keys = ON");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS oast_leases (id TEXT PRIMARY KEY, signature TEXT NOT NULL, expires_at TEXT NOT NULL, poll_token_hash TEXT NOT NULL, binding_fingerprint TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('ACTIVE','REVOKED')), protocols_json TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS oast_events (id TEXT PRIMARY KEY, lease_id TEXT NOT NULL REFERENCES oast_leases(id) ON DELETE CASCADE, protocol TEXT NOT NULL, observed_at TEXT NOT NULL, delay_ms INTEGER NOT NULL, source_fingerprint TEXT NOT NULL, request_fingerprint TEXT NOT NULL, replay_rejected INTEGER NOT NULL DEFAULT 0, UNIQUE(lease_id, request_fingerprint));
      CREATE INDEX IF NOT EXISTS idx_oast_events_lease ON oast_events(lease_id, observed_at);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_oast_events_lease_protocol ON oast_events(lease_id, protocol);
      CREATE INDEX IF NOT EXISTS idx_oast_leases_expiry ON oast_leases(expires_at);
    `);
  }

  public createLease(request: OastLeaseRequest): OastLeaseIdentity {
    const ttl = Math.min(this.maxLeaseSeconds, Math.max(30, request.ttlSeconds));
    const leaseId = randomBytes(16).toString("hex");
    const expiresAt = new Date(this.now() + ttl * 1000).toISOString();
    const dnsSignature = this.signature(leaseId, expiresAt, "DNS");
    const httpSignature = this.signature(leaseId, expiresAt, "HTTP");
    const httpsSignature = this.signature(leaseId, expiresAt, "HTTPS");
    const pollToken = randomBytes(32).toString("base64url");
    const bindingFingerprint = this.keyedHash([request.tenantId, request.workerId, request.jobId, request.caseId].join("\0"));
    this.db.prepare("INSERT INTO oast_leases(id,signature,expires_at,poll_token_hash,binding_fingerprint,status,protocols_json,created_at) VALUES(?,?,?,?,?,'ACTIVE',?,?)")
      .run(leaseId, dnsSignature, expiresAt, hash(pollToken), bindingFingerprint, JSON.stringify([...new Set(request.protocols)]), new Date(this.now()).toISOString());
    const dnsName = `${leaseId}.${dnsSignature}.${this.baseDomain}`;
    return { leaseId, expiresAt, dnsName, ...(this.publicHttpBaseUrl ? { httpUrl: new URL(`/c/${leaseId}/${httpSignature}`, this.publicHttpBaseUrl).toString() } : {}), ...(this.publicHttpsBaseUrl ? { httpsUrl: new URL(`/c/${leaseId}/${httpsSignature}`, this.publicHttpsBaseUrl).toString() } : {}), pollUrl: `/v1/leases/${leaseId}/events`, pollToken, bindingFingerprint };
  }

  public validateIdentity(leaseId: string, signature: string, protocol: OastProtocol): LeaseRow | undefined {
    const row = this.db.prepare("SELECT * FROM oast_leases WHERE id=?").get(leaseId) as LeaseRow | undefined;
    if (!row || row.status !== "ACTIVE" || Date.parse(row.expires_at) <= this.now() || !safeEqual(signature, this.signature(leaseId, row.expires_at, protocol))) return;
    const protocols = JSON.parse(row.protocols_json) as OastProtocol[];
    return protocols.includes(protocol) ? row : undefined;
  }

  public record(row: LeaseRow, protocol: OastProtocol, source: string, requestMaterial: string): { accepted: boolean; replay: boolean } {
    const current = this.db.prepare("SELECT status,expires_at FROM oast_leases WHERE id=?").get(row.id) as Pick<LeaseRow, "status" | "expires_at"> | undefined;
    if (!current || current.status !== "ACTIVE" || Date.parse(current.expires_at) <= this.now()) return { accepted: false, replay: false };
    const requestFingerprint = this.keyedHash(`${protocol}\0${requestMaterial}`);
    const existing = this.db.prepare("SELECT 1 FROM oast_events WHERE lease_id=? AND protocol=?").get(row.id, protocol);
    if (existing) {
      this.db.prepare("UPDATE oast_events SET replay_rejected=1 WHERE lease_id=? AND protocol=?").run(row.id, protocol);
      return { accepted: false, replay: true };
    }
    const count = (this.db.prepare("SELECT COUNT(*) AS count FROM oast_events WHERE lease_id=?").get(row.id) as { count: number }).count;
    if (count >= this.maxEventsPerLease) return { accepted: false, replay: false };
    const observedAt = new Date(this.now()).toISOString();
    const result = this.db.prepare("INSERT OR IGNORE INTO oast_events(id,lease_id,protocol,observed_at,delay_ms,source_fingerprint,request_fingerprint,replay_rejected) VALUES(?,?,?,?,?,?,?,0)")
      .run(randomUUID(), row.id, protocol, observedAt, Math.max(0, this.now() - Date.parse(row.created_at)), this.keyedHash(source), requestFingerprint);
    if (result.changes === 0) this.db.prepare("UPDATE oast_events SET replay_rejected=1 WHERE lease_id=? AND protocol=?").run(row.id, protocol);
    return { accepted: result.changes === 1, replay: result.changes === 0 };
  }

  public poll(leaseId: string, pollToken: string): OastPollResponse | undefined {
    const row = this.db.prepare("SELECT * FROM oast_leases WHERE id=?").get(leaseId) as LeaseRow | undefined;
    if (!row || !safeEqual(hash(pollToken), row.poll_token_hash)) return;
    const status = row.status === "REVOKED" ? "REVOKED" : Date.parse(row.expires_at) <= this.now() ? "EXPIRED" : "ACTIVE";
    const rows = this.db.prepare("SELECT id,protocol,observed_at,delay_ms,source_fingerprint,request_fingerprint,replay_rejected FROM oast_events WHERE lease_id=? ORDER BY observed_at,id LIMIT ?").all(leaseId, this.maxEventsPerLease) as Array<{ id: string; protocol: OastProtocol; observed_at: string; delay_ms: number; source_fingerprint: string; request_fingerprint: string; replay_rejected: number }>;
    const events: OastEvidenceSummary[] = rows.map((event) => ({ eventId: event.id, protocol: event.protocol, observedAt: event.observed_at, delayMs: event.delay_ms, sourceFingerprint: event.source_fingerprint, requestFingerprint: event.request_fingerprint, bindingFingerprint: row.binding_fingerprint, replayRejected: event.replay_rejected === 1 }));
    return { leaseId, status, expiresAt: row.expires_at, events };
  }

  public revoke(leaseId: string, pollToken: string): boolean {
    const row = this.db.prepare("SELECT poll_token_hash FROM oast_leases WHERE id=?").get(leaseId) as { poll_token_hash: string } | undefined;
    if (!row || !safeEqual(hash(pollToken), row.poll_token_hash)) return false;
    this.db.prepare("UPDATE oast_leases SET status='REVOKED' WHERE id=?").run(leaseId); return true;
  }

  public close(): void { this.db.close(); }
  private signature(leaseId: string, expiresAt: string, protocol: OastProtocol): string { return createHmac("sha256", this.signingKey).update(leaseId).update("\0").update(expiresAt).update("\0").update(protocol).digest("hex").slice(0, 32); }
  private keyedHash(value: string): string { return createHmac("sha256", this.signingKey).update(value).digest("hex"); }
}

function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function safeEqual(left: string, right: string): boolean { const a = Buffer.from(left); const b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }
