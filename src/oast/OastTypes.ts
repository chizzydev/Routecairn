export type OastProtocol = "DNS" | "HTTP" | "HTTPS";

export interface OastLeaseBinding {
  tenantId: string;
  workerId: string;
  jobId: string;
  caseId: string;
}

export interface OastLeaseRequest extends OastLeaseBinding {
  ttlSeconds: number;
  protocols: readonly OastProtocol[];
}

export interface OastLeaseIdentity {
  leaseId: string;
  expiresAt: string;
  dnsName: string;
  httpUrl?: string;
  httpsUrl?: string;
  pollUrl: string;
  pollToken: string;
  bindingFingerprint: string;
}

export interface OastEvidenceSummary {
  eventId: string;
  protocol: OastProtocol;
  observedAt: string;
  delayMs: number;
  sourceFingerprint: string;
  requestFingerprint: string;
  bindingFingerprint: string;
  replayRejected: boolean;
}

export interface OastPollResponse {
  leaseId: string;
  status: "ACTIVE" | "EXPIRED" | "REVOKED";
  expiresAt: string;
  events: readonly OastEvidenceSummary[];
}
