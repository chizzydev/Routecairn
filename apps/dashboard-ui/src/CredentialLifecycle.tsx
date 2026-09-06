import React from "react";

export type CredentialHealthClassification = "HEALTHY" | "NEAR_EXPIRY" | "EXPIRED" | "DISABLED" | "INVALID" | "IDENTITY_MISMATCH" | "UNVERIFIED";

export interface CredentialSummary {
  id: string;
  name: string;
  description?: string;
  safeAlias: string;
  enabled: boolean;
  projectId?: string;
  targetId?: string;
  credentialTypeSummary: string;
  safeIdentitySummary: Record<string, unknown>;
  expiresAt?: string;
  lastUsedAt?: string;
  secretVersion: number;
  secretReplacedAt?: string;
  keyVersion: string;
  health: { classification: CredentialHealthClassification; reasonCode: string; checkedAt?: string; principalFingerprint?: string; expiresInMs?: number };
  createdAt: string;
  updatedAt: string;
}

export interface CredentialDependencyImpact {
  targetDefaults: number;
  configurationReferences: number;
  activeScans: number;
  canDelete: boolean;
  impactDigest: string;
  targetIds: string[];
  configurationIds: string[];
  activeScanIds: string[];
}

export interface CredentialHealthEvent {
  id: string;
  classification: CredentialHealthClassification;
  source: string;
  reasonCode: string;
  safeSummary: string;
  principalFingerprint?: string;
  createdAt: string;
}

export interface CredentialDetailResponse {
  profile: CredentialSummary;
  dependencies: CredentialDependencyImpact;
  healthTimeline: CredentialHealthEvent[];
}

const blocked = new Set<CredentialHealthClassification>(["DISABLED", "EXPIRED", "INVALID", "IDENTITY_MISMATCH"]);

export function credentialUsable(profile: { enabled: boolean; health?: { classification: CredentialHealthClassification } }): boolean {
  return profile.enabled && !blocked.has(profile.health?.classification ?? "UNVERIFIED");
}

export function credentialExpiryLabel(profile: Pick<CredentialSummary, "expiresAt">, nowMs = Date.now()): string {
  if (!profile.expiresAt) return "No expiry supplied";
  const delta = Date.parse(profile.expiresAt) - nowMs;
  const absolute = new Date(profile.expiresAt).toLocaleString();
  if (!Number.isFinite(delta)) return "Invalid expiry";
  if (delta <= 0) return `Expired ${absolute}`;
  const minutes = Math.ceil(delta / 60_000);
  if (minutes < 60) return `Expires in ${minutes} minute${minutes === 1 ? "" : "s"}`;
  const hours = Math.ceil(minutes / 60);
  if (hours < 48) return `Expires in ${hours} hour${hours === 1 ? "" : "s"}`;
  const days = Math.ceil(hours / 24);
  return `Expires in ${days} days · ${absolute}`;
}

export function accountPairIdentityWarnings(a?: CredentialSummary, b?: CredentialSummary): string[] {
  if (!a || !b) return [];
  const warnings: string[] = [];
  const principalA = typeof a.safeIdentitySummary?.principalId === "string" ? a.safeIdentitySummary.principalId : undefined;
  const principalB = typeof b.safeIdentitySummary?.principalId === "string" ? b.safeIdentitySummary.principalId : undefined;
  if (principalA && principalA === principalB) warnings.push("Account A and Account B declare the same principal.");
  if (a.health?.principalFingerprint && a.health.principalFingerprint === b.health?.principalFingerprint) warnings.push("Account A and Account B most recently resolved to the same verified principal fingerprint.");
  if (a.health?.classification === "IDENTITY_MISMATCH" || b.health?.classification === "IDENTITY_MISMATCH") warnings.push("One or both accounts have identity drift and cannot be used until renewed or revalidated.");
  return warnings;
}

export function CredentialHealthBadge({ classification }: { classification: CredentialHealthClassification }) {
  return <span className={`badge credential-health ${classification.toLowerCase().replace(/_/g, "-")}`}>{classification.replace(/_/g, " ")}</span>;
}

export function CredentialImpactPanel({ detail }: { detail: CredentialDetailResponse }) {
  const impact = detail.dependencies;
  return (
    <section className="notice credential-impact" aria-label="Credential dependency impact">
      <strong>Impact review · {detail.profile.safeAlias}</strong>
      <span>Target defaults: {impact.targetDefaults} · saved configurations: {impact.configurationReferences} · active scans: {impact.activeScans}</span>
      {impact.activeScans > 0 && <span className="error">Disabling or replacing this profile can invalidate {impact.activeScans} active scan binding(s).</span>}
      <small>Impact binding {impact.impactDigest.slice(0, 12)}… · deletion {impact.canDelete ? "allowed" : "blocked"}</small>
    </section>
  );
}

export function CredentialHealthTimeline({ events }: { events: CredentialHealthEvent[] }) {
  return (
    <section className="credential-timeline" aria-label="Credential health timeline">
      <h3>Health timeline</h3>
      {events.length === 0 ? <p className="muted">No lifecycle observations yet.</p> : events.map((event) => (
        <div className="timeline-item" key={event.id}>
          <CredentialHealthBadge classification={event.classification} />
          <span><strong>{event.reasonCode}</strong><small>{event.safeSummary} · {new Date(event.createdAt).toLocaleString()}</small></span>
        </div>
      ))}
    </section>
  );
}
