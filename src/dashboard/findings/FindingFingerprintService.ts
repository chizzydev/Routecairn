import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Finding } from "../../core/findings/Finding.js";

export class FindingFingerprintService {
  private readonly key: Buffer;

  public constructor(keyPath: string) {
    this.key = loadOrCreateKey(keyPath);
  }

  public fingerprint(targetOrigin: string, finding: Finding): string {
    const parts = [
      normalizeOrigin(targetOrigin),
      finding.sourceModule ?? "unknown-module",
      finding.type,
      finding.method ?? "GET",
      routeIdentity(finding.url),
      boundaryIdentity(finding.tags ?? []),
      ...(finding.workflow ? [finding.workflow.caseId, finding.workflow.comparisonFingerprint ?? ""] : [])
    ];
    return createHmac("sha256", this.key).update(parts.join("\n")).digest("hex");
  }

  public routeIdentity(rawUrl: string): string {
    return routeIdentity(rawUrl);
  }
}

function loadOrCreateKey(keyPath: string): Buffer {
  mkdirSync(dirname(keyPath), { recursive: true });
  if (existsSync(keyPath)) {
    return Buffer.from(readFileSync(keyPath, "utf8"), "hex");
  }
  const key = randomBytes(32);
  writeFileSync(keyPath, key.toString("hex"), { mode: 0o600 });
  return key;
}

function normalizeOrigin(origin: string): string {
  const parsed = new URL(origin);
  parsed.hostname = parsed.hostname.toLowerCase();
  return parsed.origin;
}

function routeIdentity(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol === "redacted:") return rawUrl.replace(/[?#].*$/, "");
    parsed.hash = "";
    parsed.username = "";
    parsed.password = "";
    parsed.hostname = parsed.hostname.toLowerCase();
    const normalizedNextPath = parsed.pathname
      .replace(/^(\/_next\/data\/)[^/]+\//, "$1:build/")
      .replace(/^(\/_next\/static\/)[^/]+\//, "$1:build/")
      .replace(/([._-])[a-f0-9]{6,}(?=\.(?:js|css|map)|[._-])/gi, "$1:asset-hash");
    const safePath = normalizedNextPath
      .split("/")
      .map((segment) => {
        if (/^[0-9a-f]{16,}$/i.test(segment)) return ":hex";
        if (/^[0-9]+$/.test(segment)) return ":number";
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(segment)) return ":uuid";
        return segment;
      })
      .join("/");
    const sensitive = /(?:token|secret|session|cookie|auth|password|pass|key|jwt|sig|signature|credential|expires|policy|x-amz-|x-goog-)/i;
    const params: string[] = [];
    parsed.searchParams.forEach((value, key) => {
      params.push(sensitive.test(key) ? `${key}=<redacted>` : `${key}=${value.length > 80 ? "<opaque>" : value}`);
    });
    return `${parsed.origin}${safePath}${params.length > 0 ? `?${params.join("&")}` : ""}`;
  } catch {
    return rawUrl.replace(/[0-9a-f]{16,}/gi, ":hex").replace(/\b\d+\b/g, ":number");
  }
}

function boundaryIdentity(tags: readonly string[]): string {
  return tags.filter((tag) => /auth|role|tenant|object|collection|file|bulk|state|workflow/i.test(tag)).sort().join("|") || "general";
}
