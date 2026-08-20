import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";

let server: Server | undefined;
const tempDirs: string[] = [];

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve, reject) => server?.close((error) => (error ? reject(error) : resolve())));
    server = undefined;
  }
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("file authorization testing integration", () => {
  it("classifies exact metadata, bounded content, public, and signed-url file authorization without raw bytes or discovery", async () => {
    const seen: string[] = [];
    let publicHadAuth = false;
    const privateBytes = Buffer.from("private-file-content-secret-marker-".repeat(20));
    server = createServer((request, response) => {
      const cookie = String(request.headers.cookie ?? "");
      const actor = cookie.includes("account-a") ? "owner" : cookie.includes("account-b") ? "viewer" : "public";
      if (actor === "public") publicHadAuth = Boolean(request.headers.cookie || request.headers.authorization || request.headers["x-csrf-token"] || request.headers["x-tenant-id"]);
      seen.push(`${actor}:${request.method}:${request.url}:${request.headers.range ?? ""}`);
      if (request.url === "/") return json(response, { ok: true });
      if (request.url === "/identity-a") return json(response, { id: "principal-a", tenant: "tenant-a", role: "member", state: "active" });
      if (request.url === "/identity-b") return json(response, { id: "principal-b", tenant: "tenant-b", role: "member", state: "active" });
      if (request.url === "/api/files/private-a") return json(response, { file: { id: "private-a", tenant: "tenant-a", state: "active", name: "secret.pdf" } });
      if (request.url === "/api/files/secure/private-a") {
        response.writeHead(403, { "content-type": "application/json" }).end('{"error":"denied"}');
        return;
      }
      if (request.url === "/download/private-a") {
        response.writeHead(200, { "content-type": "application/pdf", "content-length": String(privateBytes.length), "content-disposition": "attachment; filename=secret.pdf" });
        response.end(privateBytes);
        return;
      }
      if (request.url === "/download/secure/private-a") {
        response.writeHead(403, { "content-type": "application/json" }).end('{"error":"denied"}');
        return;
      }
      if (request.url === "/api/files/public") return json(response, { file: { id: "public-file", tenant: "tenant-a", state: "active" } });
      if (request.url === "/signed/private-a") return json(response, { download: { url: "https://storage.example.test/private-a?signature=signed-secret" } });
      response.writeHead(404).end();
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-file-auth-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-a", "/identity-a")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-b", "/identity-b")),
      fileAuthorization: await writeJson(tempDir, "files.json", fileInput(target))
    });

    const jsonText = await readFile(result.reportPath, "utf8");
    const markdownText = await readFile(result.markdownReportPath, "utf8");
    const report = JSON.parse(jsonText) as {
      scanPlan: { modules: Array<{ id: string }>; fileAuthorizationTesting?: { requestMatrix: Array<{ fileRef: string; url: string }> } };
      identityVerification?: { accountA?: { verified: boolean }; accountB?: { verified: boolean } };
      fileAuthorization?: {
        plannedRequests: number;
        executedRequests: number;
        confirmedIssues: number;
        observations: Array<{ caseId: string; observedDecision: string; findingCategory?: string; identityConfirmed: boolean; bytesObserved: number; rangeIgnored: boolean; signedUrlObserved: boolean; signedUrlFollowed: boolean }>;
      };
      findings: Array<{ type: string; evidence: { source: string; curlCommand: string } }>;
      requestAudit: Array<{ requestedUrl: string; requestHeaders: Record<string, string> }>;
    };

    expect(report.scanPlan.modules.map((module) => module.id)).toEqual(["file-authorization-testing"]);
    expect(report.identityVerification?.accountA?.verified).toBe(true);
    expect(report.identityVerification?.accountB?.verified).toBe(true);
    expect(report.fileAuthorization?.plannedRequests).toBe(6);
    expect(report.fileAuthorization?.executedRequests).toBe(6);
    expect(publicHadAuth).toBe(false);
    expect(seen.some((entry) => entry.includes("page=") || entry.includes("list") || entry.includes("signed-secret"))).toBe(false);
    expect(seen.filter((entry) => entry.includes("/download/private-a"))[0]).toContain("bytes=0-31");
    expect(seen.some((entry) => entry.includes("storage.example.test"))).toBe(false);

    const secureMetadata = report.fileAuthorization?.observations.find((observation) => observation.caseId === "secure-metadata-denied");
    const vulnerableMetadata = report.fileAuthorization?.observations.find((observation) => observation.caseId === "vulnerable-metadata");
    const secureDownload = report.fileAuthorization?.observations.find((observation) => observation.caseId === "secure-download-denied");
    const vulnerableDownload = report.fileAuthorization?.observations.find((observation) => observation.caseId === "vulnerable-download-prefix");
    const publicFile = report.fileAuthorization?.observations.find((observation) => observation.caseId === "public-allowed");
    const signed = report.fileAuthorization?.observations.find((observation) => observation.caseId === "signed-url-issued");
    expect(secureMetadata?.observedDecision).toBe("ACCESS_DENIED_CONFIRMED");
    expect(secureMetadata?.findingCategory).toBeUndefined();
    expect(vulnerableMetadata?.findingCategory).toBe("UNAUTHORIZED_FILE_METADATA_ACCESS");
    expect(vulnerableMetadata?.identityConfirmed).toBe(true);
    expect(secureDownload?.observedDecision).toBe("ACCESS_DENIED_CONFIRMED");
    expect(vulnerableDownload?.findingCategory).toBe("CROSS_TENANT_FILE_ACCESS");
    expect(vulnerableDownload?.bytesObserved).toBe(32);
    expect(vulnerableDownload?.rangeIgnored).toBe(true);
    expect(publicFile?.findingCategory).toBeUndefined();
    expect(signed?.findingCategory).toBe("UNAUTHORIZED_SIGNED_URL_ISSUANCE");
    expect(signed?.signedUrlObserved).toBe(true);
    expect(signed?.signedUrlFollowed).toBe(false);
    expect(signed?.observedDecision).toBe("SIGNED_URL_FOLLOW_NOT_CONFIGURED");
    expect(report.fileAuthorization?.confirmedIssues).toBe(3);
    expect(report.findings.filter((finding) => finding.type === "File Authorization Issue")).toHaveLength(3);

    for (const serialized of [jsonText, markdownText]) {
      expect(serialized).not.toContain("private-a");
      expect(serialized).not.toContain("secret.pdf");
      expect(serialized).not.toContain("private-file-content-secret-marker");
      expect(serialized).not.toContain("signed-secret");
      expect(serialized).not.toContain("session=account-a");
      expect(serialized).not.toContain("session=account-b");
    }
    expect(JSON.stringify(report.scanPlan.fileAuthorizationTesting)).toContain("<file:");
    expect(report.scanPlan.fileAuthorizationTesting?.requestMatrix.every((testCase) => testCase.fileRef === "<redacted>" && testCase.url.includes("<file:"))).toBe(true);
    expect(report.requestAudit.every((entry) => Object.values(entry.requestHeaders).every((value) => value !== "session=account-a" && value !== "session=account-b"))).toBe(true);
  });

  it("separates signed-url issuance/download and enforces bounded streaming, range, HEAD, cache, and redaction policy", async () => {
    const seen: string[] = [];
    let storageAuthSeen = false;
    const storageBytes = Buffer.from("signed-storage-file-content".repeat(4));
    const differentBytes = Buffer.from("different-file-content");
    const fullBytes = Buffer.from("full-stream-file-content");
    const oversizedBytes = Buffer.from("oversized-stream-content".repeat(20));
    server = createServer((request, response) => {
      seen.push(`${request.method}:${request.url}:${request.headers.range ?? ""}`);
      if (request.url === "/") return json(response, { ok: true });
      if (request.url === "/identity-a") return json(response, { id: "principal-a", tenant: "tenant-a", role: "member", state: "active" });
      if (request.url === "/identity-b") return json(response, { id: "principal-b", tenant: "tenant-b", role: "member", state: "active" });
      if (request.url === "/signed/private-a") return json(response, { download: { url: `${originFromRequest(request)}/storage/private-a?signature=signed-secret&expires=999&x=1&x=2` }, other: { url: `${originFromRequest(request)}/storage/other?signature=discarded` } });
      if (request.url === "/signed-mismatch/private-a") return json(response, { download: { url: `${originFromRequest(request)}/storage/different?signature=signed-secret` } });
      if (request.url === "/signed-unapproved/private-a") return json(response, { download: { url: "https://storage.example.com.attacker.test/private-a?signature=signed-secret" } });
      if (request.url?.startsWith("/storage/private-a")) {
        storageAuthSeen = Boolean(request.headers.cookie || request.headers.authorization || request.headers["x-csrf-token"] || request.headers["x-tenant-id"]);
        response.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(storageBytes.length) });
        response.end(storageBytes);
        return;
      }
      if (request.url?.startsWith("/storage/different")) {
        response.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(differentBytes.length) });
        response.end(differentBytes);
        return;
      }
      if (request.url === "/full/private-a") {
        response.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(fullBytes.length) });
        response.end(fullBytes);
        return;
      }
      if (request.url === "/full-too-large/private-a") {
        response.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(oversizedBytes.length) });
        response.end(oversizedBytes);
        return;
      }
      if (request.url === "/head/private-a") {
        response.writeHead(200, { "content-type": "application/pdf", "content-length": String(fullBytes.length), "content-disposition": "attachment; filename=secret.pdf" });
        response.end();
        return;
      }
      if (request.url === "/slice-valid/private-a") {
        response.writeHead(206, { "content-type": "application/octet-stream", "content-range": "bytes 0-7/24", "content-length": "8" });
        response.end(fullBytes.subarray(0, 8));
        return;
      }
      if (request.url === "/slice-invalid/private-a") {
        response.writeHead(206, { "content-type": "application/octet-stream", "content-range": "bytes 4-11/24", "content-length": "8" });
        response.end(fullBytes.subarray(4, 12));
        return;
      }
      if (request.url === "/slice-unsat/private-a") {
        response.writeHead(416, { "content-range": "bytes */24" });
        response.end();
        return;
      }
      response.writeHead(404).end();
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-file-auth-closure-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-a", "/identity-a")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-b", "/identity-b")),
      fileAuthorization: await writeJson(tempDir, "files.json", closureInput(target, hash(storageBytes), hash(fullBytes), hash(fullBytes.subarray(0, 8))))
    });

    const jsonText = await readFile(result.reportPath, "utf8");
    const report = JSON.parse(jsonText) as {
      fileAuthorization?: { executedRequests: number; observations: Array<{ caseId: string; observedDecision: string; findingCategory?: string; identityConfirmed: boolean; signedUrlFollowed: boolean; bytesObserved: number; rangeIgnored: boolean }> };
      requestAudit: Array<{ requestedUrl: string; outcome: string; requestHeaders: Record<string, string> }>;
    };

    const observation = (id: string) => report.fileAuthorization?.observations.find((item) => item.caseId === id);
    expect(observation("signed-follow")?.observedDecision).toBe("SIGNED_URL_DOWNLOAD_ALLOWED");
    expect(observation("signed-follow")?.findingCategory).toBe("UNAUTHORIZED_SIGNED_URL_DOWNLOAD");
    expect(observation("signed-follow")?.signedUrlFollowed).toBe(true);
    expect(observation("signed-mismatch")?.observedDecision).toBe("SIGNED_URL_FILE_IDENTITY_MISMATCH");
    expect(observation("signed-unapproved")?.observedDecision).toBe("SIGNED_URL_ORIGIN_BLOCKED");
    expect(observation("full-ok")?.observedDecision).toBe("CONTENT_ACCESS_CONFIRMED");
    expect(observation("full-too-large")?.observedDecision).toBe("DECLARED_CONTENT_LENGTH_EXCEEDS_LIMIT");
    expect(observation("head-only")?.observedDecision).toBe("HEADERS_ONLY_OBSERVATION");
    expect(observation("head-only")?.findingCategory).toBeUndefined();
    expect(observation("range-valid")?.observedDecision).toBe("CONTENT_ACCESS_CONFIRMED");
    expect(observation("range-invalid")?.observedDecision).toBe("INVALID_CONTENT_RANGE");
    expect(observation("range-unsat")?.observedDecision).toBe("RANGE_NOT_SATISFIABLE");
    expect(storageAuthSeen).toBe(false);
    expect(seen.filter((entry) => entry.includes("/storage/private-a"))).toHaveLength(1);
    expect(seen.some((entry) => entry.includes("/storage/other"))).toBe(false);
    expect(seen.filter((entry) => entry.includes("/slice-valid/private-a"))).toHaveLength(1);
    expect(seen.find((entry) => entry.includes("/slice-valid/private-a"))).toContain("bytes=0-7");
    expect(report.requestAudit.filter((entry) => entry.requestedUrl.includes("/signed/private-a")).every((entry) => entry.outcome === "sent")).toBe(true);
    expect(report.requestAudit.every((entry) => entry.outcome !== "duplicate-skipped")).toBe(true);
    expect(report.requestAudit.every((entry) => Object.values(entry.requestHeaders).every((value) => !value.includes("session=account-")))).toBe(true);
    expect(jsonText).not.toContain("signed-secret");
    expect(jsonText).not.toContain("expires=999");
    expect(jsonText).not.toContain("secret.pdf");
    expect(jsonText).not.toContain("signed-storage-file-content");
    expect(jsonText).not.toContain("full-stream-file-content");
  });
});

function fileInput(target: string) {
  return {
    schemaVersion: 1,
    maxDefinitions: 1,
    maxCasesPerDefinition: 8,
    maxFilesPerDefinition: 2,
    maxRequests: 8,
    maxRetainedObservations: 8,
    definitions: [
      {
        id: "files",
        label: "Files",
        actors: [
          { id: "owner", relationship: "OWNER", authProfile: "account_a", safeAlias: "Owner", principalId: "principal-a", tenantId: "tenant-a", role: "member", accountState: "active" },
          { id: "viewer", relationship: "CROSS_TENANT_MEMBER", authProfile: "account_b", safeAlias: "Viewer", principalId: "principal-b", tenantId: "tenant-b", role: "member", accountState: "active" },
          { id: "public", relationship: "PUBLIC", safeAlias: "Public" }
        ],
        files: [
          { id: "private", fileRef: "private-a", safeAlias: "Private file", fileType: "pdf", ownerActorId: "owner", tenantId: "tenant-a", state: "active", expectedPublic: false },
          { id: "public-file", fileRef: "public", safeAlias: "Public file", fileType: "txt", tenantId: "tenant-a", state: "active", expectedPublic: true }
        ],
        cases: [
          metadataCase(target, "secure-metadata-denied", "viewer", "private", "/api/files/secure/{{FILE_ID}}", "MUST_DENY_METADATA"),
          metadataCase(target, "vulnerable-metadata", "viewer", "private", "/api/files/{{FILE_ID}}", "MUST_DENY_METADATA"),
          { ...contentCase(target, "secure-download-denied", "viewer", "private", "/download/secure/{{FILE_ID}}"), contentProofMode: "HEADERS_ONLY", method: "HEAD" },
          contentCase(target, "vulnerable-download-prefix", "viewer", "private", "/download/{{FILE_ID}}"),
          metadataCase(target, "public-allowed", "public", "public-file", "/api/files/{{FILE_ID}}", "MUST_ALLOW_METADATA", false),
          signedCase(target)
        ]
      }
    ]
  };
}

function metadataCase(target: string, id: string, actorId: string, fileRefId: string, path: string, expectedDecision: string, requireVerifiedIdentity = true) {
  return {
    id,
    label: id,
    category: "FILE_METADATA",
    actorId,
    fileRefId,
    method: "GET",
    url: `${target}${path.replace(/^\//, "")}`,
    headers: { Accept: "application/json" },
    expectedDecision,
    requireVerifiedIdentity,
    expectedTenantId: actorId === "viewer" ? "tenant-b" : actorId === "owner" ? "tenant-a" : undefined,
    expectedRole: actorId === "public" ? undefined : "member",
    expectedAccountState: actorId === "public" ? undefined : "active",
    expectedFileState: "active",
    identityStrategy: "METADATA_FIELD_MATCH",
    identityField: "file.id",
    stateField: "file.state",
    contentProofMode: "METADATA_ONLY",
    maxMetadataBytes: 65536
  };
}

function contentCase(target: string, id: string, actorId: string, fileRefId: string, path: string) {
  return {
    id,
    label: id,
    category: "DIRECT_DOWNLOAD",
    actorId,
    fileRefId,
    method: "GET",
    url: `${target}${path.replace(/^\//, "")}`,
    headers: {},
    expectedDecision: "MUST_DENY_CONTENT",
    requireVerifiedIdentity: true,
    expectedTenantId: "tenant-b",
    expectedRole: "member",
    expectedAccountState: "active",
    identityStrategy: "OPERATOR_SUPPLIED_FINGERPRINT",
    expectedFingerprint: "ad9869135b8cdf1f0d59c414d5872a0472164e00240eb907965dded1d667e394",
    contentProofMode: "BOUNDED_PREFIX",
    rangeStart: 0,
    rangeLength: 32,
    maxProbeBytes: 32,
    maxFullStreamBytes: 64
  };
}

function signedCase(target: string) {
  return {
    id: "signed-url-issued",
    label: "signed-url-issued",
    category: "SIGNED_URL_ISSUANCE",
    actorId: "viewer",
    fileRefId: "private",
    method: "GET",
    url: `${target}signed/{{FILE_ID}}`,
    headers: { Accept: "application/json" },
    expectedDecision: "MUST_NOT_RECEIVE_SIGNED_URL",
    requireVerifiedIdentity: true,
    expectedTenantId: "tenant-b",
    expectedRole: "member",
    expectedAccountState: "active",
    identityStrategy: "SIGNED_URL_FIELD_MATCH",
    signedUrlField: "download.url",
    contentProofMode: "SIGNED_URL_ONLY",
    allowedSignedUrlOrigins: ["https://storage.example.test"],
    followSignedUrl: false
  };
}

function closureInput(target: string, signedHash: string, fullHash: string, rangeHash: string) {
  const origin = new URL(target).origin;
  const base = fileInput(target);
  return {
    ...base,
    maxCasesPerDefinition: 10,
    maxRequests: 20,
    maxRetainedObservations: 20,
    definitions: [
      {
        ...base.definitions[0],
        files: [{ id: "private", fileRef: "private-a", safeAlias: "Private file", fileType: "pdf", ownerActorId: "owner", tenantId: "tenant-a", state: "active", expectedPublic: false }],
        cases: [
          signedFollowCase(target, "signed-follow", "/signed/{{FILE_ID}}", signedHash, [origin]),
          signedFollowCase(target, "signed-mismatch", "/signed-mismatch/{{FILE_ID}}", signedHash, [origin]),
          signedFollowCase(target, "signed-unapproved", "/signed-unapproved/{{FILE_ID}}", signedHash, [origin]),
          fullCase(target, "full-ok", "/full/{{FILE_ID}}", fullHash, 64),
          fullCase(target, "full-too-large", "/full-too-large/{{FILE_ID}}", fullHash, 16),
          { ...fullCase(target, "head-only", "/head/{{FILE_ID}}", fullHash, 64), method: "HEAD", contentProofMode: "HEADERS_ONLY" },
          rangeCase(target, "range-valid", "/slice-valid/{{FILE_ID}}", rangeHash),
          rangeCase(target, "range-invalid", "/slice-invalid/{{FILE_ID}}", rangeHash),
          rangeCase(target, "range-unsat", "/slice-unsat/{{FILE_ID}}", rangeHash)
        ]
      }
    ]
  };
}

function signedFollowCase(target: string, id: string, path: string, expectedFingerprint: string, allowedSignedUrlOrigins: string[]) {
  return {
    id,
    label: id,
    category: "SIGNED_URL_DOWNLOAD",
    actorId: "viewer",
    fileRefId: "private",
    method: "GET",
    url: `${target}${path.replace(/^\//, "")}`,
    headers: { Accept: "application/json" },
    expectedDecision: "MUST_DENY_CONTENT",
    requireVerifiedIdentity: true,
    expectedTenantId: "tenant-b",
    expectedRole: "member",
    expectedAccountState: "active",
    identityStrategy: "OPERATOR_SUPPLIED_FINGERPRINT",
    signedUrlField: "download.url",
    expectedFingerprint,
    contentProofMode: "SIGNED_URL_ONLY",
    maxProbeBytes: 128,
    maxFullStreamBytes: 128,
    allowedSignedUrlOrigins,
    followSignedUrl: true
  };
}

function fullCase(target: string, id: string, path: string, expectedFingerprint: string, maxFullStreamBytes: number) {
  return {
    id,
    label: id,
    category: "DIRECT_DOWNLOAD",
    actorId: "viewer",
    fileRefId: "private",
    method: "GET",
    url: `${target}${path.replace(/^\//, "")}`,
    headers: {},
    expectedDecision: "MUST_DENY_CONTENT",
    requireVerifiedIdentity: true,
    expectedTenantId: "tenant-b",
    expectedRole: "member",
    expectedAccountState: "active",
    identityStrategy: "OPERATOR_SUPPLIED_FINGERPRINT",
    expectedFingerprint,
    contentProofMode: "FULL_STREAM_FINGERPRINT",
    maxProbeBytes: 8,
    maxFullStreamBytes
  };
}

function rangeCase(target: string, id: string, path: string, expectedFingerprint: string) {
  return {
    id,
    label: id,
    category: "DIRECT_DOWNLOAD",
    actorId: "viewer",
    fileRefId: "private",
    method: "GET",
    url: `${target}${path.replace(/^\//, "")}`,
    headers: {},
    expectedDecision: "MUST_DENY_CONTENT",
    requireVerifiedIdentity: true,
    expectedTenantId: "tenant-b",
    expectedRole: "member",
    expectedAccountState: "active",
    identityStrategy: "OPERATOR_SUPPLIED_FINGERPRINT",
    expectedFingerprint,
    contentProofMode: "BOUNDED_PREFIX",
    rangeStart: 0,
    rangeLength: 8,
    maxProbeBytes: 8,
    maxFullStreamBytes: 64
  };
}

function authProfile(label: string, principalId: string, tenantId: string, endpoint: string) {
  return {
    label,
    safeAlias: label,
    principalId,
    tenantId,
    role: "member",
    accountState: "active",
    headers: { Cookie: `session=${label}` },
    identityVerification: {
      mode: "required",
      endpoint,
      method: "GET",
      principalIdField: "id",
      tenantIdField: "tenant",
      roleField: "role",
      accountStateField: "state"
    }
  };
}

function json(response: Parameters<NonNullable<Parameters<typeof createServer>[0]>>[1], value: unknown): void {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

function hash(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function originFromRequest(request: Parameters<NonNullable<Parameters<typeof createServer>[0]>>[0]): string {
  return `http://${request.headers.host}`;
}

async function writeScope(tempDir: string): Promise<string> {
  return writeJson(tempDir, "scope.json", {
    ...exampleScope,
    allowedDomains: ["127.0.0.1"],
    allowedMethods: ["GET", "HEAD"],
    disallowedPaths: [],
    rateLimitPerSecond: 50,
    concurrency: 2,
    userAgent: "RouteCairn/Test"
  });
}

async function writeJson(tempDir: string, name: string, value: unknown): Promise<string> {
  const path = join(tempDir, name);
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  return path;
}

function listen(targetServer: Server): Promise<void> {
  return new Promise((resolve) => targetServer.listen(0, "127.0.0.1", resolve));
}
