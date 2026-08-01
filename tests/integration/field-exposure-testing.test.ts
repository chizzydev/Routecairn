import { afterEach, describe, expect, it } from "vitest";
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
    await new Promise<void>((resolve, reject) => {
      server?.close((error) => (error ? reject(error) : resolve()));
    });
    server = undefined;
  }
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("field exposure testing integration", () => {
  it("executes a fixed actor matrix, detects configured field exposure, and redacts secrets", async () => {
    const seen: string[] = [];
    let publicRequestHadAuthMaterial = false;
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("ok");
        return;
      }
      const match = request.url?.match(/^\/api\/documents\/([^/?]+)/);
      if (!match) {
        response.writeHead(404).end();
        return;
      }
      const cookie = String(request.headers.cookie ?? "");
      const actor = cookie.includes("account-a") ? "owner" : cookie.includes("account-b") ? "non_owner" : "public";
      if (actor === "public") {
        publicRequestHadAuthMaterial = Boolean(request.headers.cookie || request.headers.authorization || request.headers["x-csrf-token"] || request.headers["x-tenant-id"]);
      }
      seen.push(`${actor}:${request.url}`);
      const objectId = decodeURIComponent(match[1] ?? "");
      const ownerEmail = actor === "public" ? undefined : "private-owner@example.test";
      const billingLast4 = actor === "owner" ? "4242" : actor === "non_owner" ? "4242" : undefined;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          id: objectId,
          owner: "principal-a-secret",
          marker: "document-marker",
          ownerProfile: { email: ownerEmail, phone: "555-0100", internalId: "internal-owner-child-secret" },
          billing: billingLast4 ? { last4: billingLast4 } : {},
          members: [{ role: "reader" }],
          unrelatedSecret: "password=NeverSerializeThis"
        })
      );
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-field-exposure-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-one", "member")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-one", "viewer")),
      fieldExposure: await writeJson(tempDir, "field-exposure.json", fieldExposureInput(target, false))
    });

    const jsonText = await readFile(result.reportPath, "utf8");
    const markdownText = await readFile(result.markdownReportPath, "utf8");
    const report = JSON.parse(jsonText) as {
      scanPlan: { modules: Array<{ id: string }>; fieldExposureTesting?: { cases: Array<{ objectId: string; fieldExpectations: Array<{ path: string }> }> } };
      fieldExposureTesting?: {
        plannedRequests: number;
        executedRequests: number;
        confirmedIssues: number;
        cases: Array<{ actors: Array<{ actorId: string; objectConfirmed: boolean; observations: Array<{ fieldPathRef: string; classification: string; preview?: string; valueFingerprint?: string }> }> }>;
      };
      findings: Array<{ type: string; sourceModule: string; evidence: { source: string; curlCommand: string } }>;
      requestAudit: Array<{ requestedUrl: string; outcome: string; requestHeaders: Record<string, string> }>;
    };

    expect(report.scanPlan.modules.map((module) => module.id)).toEqual(["field-exposure-testing"]);
    expect(report.fieldExposureTesting?.plannedRequests).toBe(3);
    expect(report.fieldExposureTesting?.executedRequests).toBe(3);
    expect(seen).toEqual(["owner:/api/documents/doc-a-001", "non_owner:/api/documents/doc-a-001", "public:/api/documents/doc-a-001"]);
    expect(publicRequestHadAuthMaterial).toBe(false);
    expect(report.requestAudit.filter((entry) => entry.outcome === "sent").map((entry) => entry.requestHeaders.Cookie ?? "")).toEqual(["", "<redacted>", "<redacted>", ""]);

    const nonOwner = report.fieldExposureTesting?.cases[0]?.actors.find((actor) => actor.actorId === "non_owner");
    expect(nonOwner?.objectConfirmed).toBe(true);
    expect(nonOwner?.observations.some((observation) => observation.classification === "UNAUTHORIZED_PRIVATE_VALUE_EXPOSED")).toBe(true);
    expect(nonOwner?.observations.some((observation) => observation.classification === "EXPECTED_REDACTION_MISSING")).toBe(true);
    expect(report.fieldExposureTesting?.confirmedIssues).toBe(2);
    expect(report.findings.filter((finding) => finding.type === "Field Exposure Issue")).toHaveLength(2);
    expect(report.findings.every((finding) => finding.sourceModule === "field-exposure-testing")).toBe(true);

    for (const serialized of [jsonText, markdownText]) {
      expect(serialized).not.toContain("doc-a-001");
      expect(serialized).not.toContain("principal-a-secret");
      expect(serialized).not.toContain("principal-b-secret");
      expect(serialized).not.toContain("private-owner@example.test");
      expect(serialized).not.toContain("internal-owner-child-secret");
      expect(serialized).not.toContain("NeverSerializeThis");
      expect(serialized).not.toContain("session=account-a");
      expect(serialized).not.toContain("session=account-b");
    }
  });

  it("does not compare fields or create findings when a successful response is a different object", async () => {
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200).end("ok");
        return;
      }
      const cookie = String(request.headers.cookie ?? "");
      const objectId = cookie.includes("account-a") ? "doc-a-001" : "doc-b-foreign";
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: objectId, ownerProfile: { email: "private-owner@example.test" }, billing: { last4: "4242" } }));
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-field-exposure-mismatch-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-one", "member")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-one", "viewer")),
      fieldExposure: await writeJson(tempDir, "field-exposure.json", fieldExposureInput(target, false))
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as {
      fieldExposureTesting?: { confirmedIssues: number; cases: Array<{ actors: Array<{ actorId: string; objectConfirmed: boolean; objectIdentity: string; observations: Array<{ classification: string }> }> }> };
      findings: Array<{ type: string }>;
    };

    const nonOwner = report.fieldExposureTesting?.cases[0]?.actors.find((actor) => actor.actorId === "non_owner");
    expect(nonOwner?.objectConfirmed).toBe(false);
    expect(nonOwner?.objectIdentity).toBe("OBJECT_MISMATCH");
    expect(nonOwner?.observations.every((observation) => observation.classification === "OBJECT_MISMATCH")).toBe(true);
    expect(report.fieldExposureTesting?.confirmedIssues).toBe(0);
    expect(report.findings.some((finding) => finding.type === "Field Exposure Issue")).toBe(false);
  });

  it("blocks verified-identity-required cases before field requests when verification is missing", async () => {
    const seen: string[] = [];
    server = createServer((request, response) => {
      seen.push(request.url ?? "");
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"id":"doc-a-001"}');
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-field-exposure-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-one", "member")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-one", "viewer")),
      fieldExposure: await writeJson(tempDir, "field-exposure.json", fieldExposureInput(target, true))
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { fieldExposureTesting?: { plannedRequests: number; executedRequests: number; cases: Array<{ notes: string[] }> } };

    expect(report.fieldExposureTesting?.plannedRequests).toBe(3);
    expect(report.fieldExposureTesting?.executedRequests).toBe(0);
    expect(seen).toEqual(["/"]);
    expect(report.fieldExposureTesting?.cases[0]?.notes.join(" ")).toContain("required verified identity");
  });

  it("keeps duplicate caching isolated by authenticated actor context", async () => {
    let documentRequests = 0;
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200).end("ok");
        return;
      }
      documentRequests += 1;
      const cookie = String(request.headers.cookie ?? "");
      const actor = cookie.includes("account-a") ? "owner" : cookie.includes("account-b") ? "non_owner" : "public";
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: "doc-a-001", marker: "document-marker", ownerProfile: { email: actor }, billing: { last4: actor } }));
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-field-exposure-cache-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-one", "member")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-one", "viewer")),
      fieldExposure: await writeJson(tempDir, "field-exposure.json", fieldExposureInput(target, false))
    });

    expect(documentRequests).toBe(3);
  });

  it("applies evidence policy to field previews", async () => {
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200).end("ok");
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: "doc-a-001", marker: "document-marker", ownerProfile: {}, billing: {}, members: [{ role: "reader" }] }));
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-field-exposure-evidence-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const scope = await writeScope(tempDir);
    const authA = await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-one", "member"));
    const authB = await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-one", "viewer"));
    const fieldExposure = await writeJson(tempDir, "field-exposure.json", fieldExposureInput(target, false));

    const minimal = await runScanCommand(target, { scope, output: join(tempDir, "minimal"), authA, authB, fieldExposure, profile: "quick" });
    const normal = await runScanCommand(target, { scope, output: join(tempDir, "normal"), authA, authB, fieldExposure, profile: "full" });
    const minimalReport = JSON.parse(await readFile(minimal.reportPath, "utf8")) as { fieldExposureTesting?: { cases: Array<{ actors: Array<{ observations: Array<{ fieldPathRef: string; preview?: string }> }> }> } };
    const normalReport = JSON.parse(await readFile(normal.reportPath, "utf8")) as { fieldExposureTesting?: { cases: Array<{ actors: Array<{ observations: Array<{ fieldPathRef: string; preview?: string }> }> }> } };

    const minimalRole = minimalReport.fieldExposureTesting?.cases[0]?.actors[0]?.observations.find((observation) => observation.fieldPathRef === "members[0].role");
    const normalRole = normalReport.fieldExposureTesting?.cases[0]?.actors[0]?.observations.find((observation) => observation.fieldPathRef === "members[0].role");
    expect(minimalRole?.preview).toBeUndefined();
    expect(normalRole?.preview).toBe("reader");
  });

  it("distinguishes supported expectation outcomes without turning consistency observations into findings", async () => {
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200).end("ok");
        return;
      }
      const cookie = String(request.headers.cookie ?? "");
      const actor = cookie.includes("account-a") ? "owner" : cookie.includes("account-b") ? "non_owner" : "public";
      const body =
        actor === "public"
          ? { id: "doc-a-001", publicSummary: "public", sameAsPublic: "public", absentAllowed: undefined }
          : actor === "owner"
            ? { id: "doc-a-001", nullable: null, empty: "", masked: "******42", ownerSecret: "owner-private", sameAsPublic: "owner-private", mustPresent: "yes", parent: { childSecret: "do-not-serialize" } }
            : { id: "doc-a-001", absentAllowed: "leaked", nullable: "not-null", redacted: "raw", masked: "424242", ownerSecret: "owner-private", sameAsOwner: "owner-private", sameAsPublic: "different", mustPresent: undefined, parent: { childSecret: "do-not-serialize" } };
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(body));
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-field-exposure-expectations-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-one", "member")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-one", "viewer")),
      fieldExposure: await writeJson(tempDir, "field-exposure.json", expectationMatrixInput(target))
    });
    const jsonText = await readFile(result.reportPath, "utf8");
    const report = JSON.parse(jsonText) as {
      fieldExposureTesting?: { cases: Array<{ confirmedIssues: Array<{ classification: string }>; actors: Array<{ actorId: string; observations: Array<{ fieldId: string; presence: string; classification: string; valueFingerprint?: string }> }> }> };
      findings: Array<{ type: string }>;
    };

    const nonOwner = report.fieldExposureTesting?.cases[0]?.actors.find((actor) => actor.actorId === "non_owner");
    const owner = report.fieldExposureTesting?.cases[0]?.actors.find((actor) => actor.actorId === "owner");
    const byId = Object.fromEntries(nonOwner?.observations.map((observation) => [observation.fieldId, observation]) ?? []);
    expect(byId.absent.classification).toBe("UNAUTHORIZED_FIELD_PRESENT");
    expect(byId.nullable.classification).toBe("UNAUTHORIZED_FIELD_PRESENT");
    expect(byId.redacted.classification).toBe("EXPECTED_REDACTION_MISSING");
    expect(byId.masked.classification).toBe("MASKING_POLICY_VIOLATION");
    expect(byId.diffOwner.classification).toBe("UNAUTHORIZED_PRIVATE_VALUE_EXPOSED");
    expect(byId.matchPublic.classification).toBe("PUBLIC_BASELINE_MISMATCH");
    expect(byId.mayPresent.classification).toBe("FIELD_POLICY_SATISFIED");
    expect(byId.mustPresent.classification).toBe("FIELD_UNEXPECTEDLY_ABSENT");
    expect(byId.parent.presence).toBe("PRESENT_VALUE");
    expect(owner?.observations.find((observation) => observation.fieldId === "empty")?.presence).toBe("PRESENT_EMPTY_STRING");
    expect(owner?.observations.find((observation) => observation.fieldId === "nullable")?.presence).toBe("PRESENT_NULL");
    expect(owner?.observations.find((observation) => observation.fieldId === "masked")?.presence).toBe("PRESENT_VALUE");
    expect(byId.diffOwner.valueFingerprint).toBe(owner?.observations.find((observation) => observation.fieldId === "diffOwner")?.valueFingerprint);
    expect(report.findings.filter((finding) => finding.type === "Field Exposure Issue")).toHaveLength(5);
    expect(jsonText).not.toContain("do-not-serialize");
  });
});

function fieldExposureInput(target: string, requireVerifiedIdentity: boolean) {
  return {
    schemaVersion: 1,
    maxCases: 1,
    maxResponseBytes: 65536,
    maxPreviewLength: 80,
    cases: [
      {
        id: "document-fields",
        objectType: "document",
        objectId: "doc-a-001",
        declaredOwnerActor: "owner",
        expectedVisibility: "PUBLIC_SUMMARY",
        requireVerifiedIdentity,
        template: { id: "document-read", method: "GET", url: new URL("/api/documents/{{OBJECT_ID}}", target).toString() },
        objectConfirmation: { expectedObjectIdField: "id", expectedOwnerField: "owner" },
        actors: [
          { id: "owner", type: "OWNER", authProfile: "account_a", safeAlias: "Owner", principalId: "principal-a-secret" },
          { id: "non_owner", type: "NON_OWNER", authProfile: "account_b", safeAlias: "Non Owner", principalId: "principal-b-secret" },
          { id: "public", type: "PUBLIC", safeAlias: "Public" }
        ],
        fieldExpectations: [
          { path: "ownerProfile.email", label: "Owner email", sensitivity: "OWNER_ONLY", expectation: "OWNER_ONLY_VALUE", allowedActors: ["owner"], prohibitedActors: ["non_owner", "public"], allowPreview: false },
          { path: "billing.last4", label: "Billing last four", sensitivity: "PRIVATE", expectation: "MUST_BE_REDACTED", allowedActors: ["owner"], prohibitedActors: ["non_owner"], redactionPattern: "^\\*{2,}\\d{2,4}$", allowPreview: false },
          { path: "members[0].role", label: "First member role", sensitivity: "PUBLIC", expectation: "MAY_BE_PRESENT", allowedActors: ["owner", "non_owner", "public"], prohibitedActors: [], allowPreview: true }
        ]
      }
    ]
  };
}

function expectationMatrixInput(target: string) {
  return {
    schemaVersion: 1,
    maxCases: 1,
    cases: [
      {
        id: "expectation-matrix",
        objectType: "document",
        objectId: "doc-a-001",
        declaredOwnerActor: "owner",
        expectedVisibility: "PUBLIC_SUMMARY",
        requireVerifiedIdentity: false,
        template: { id: "document-read", method: "GET", url: new URL("/api/documents/{{OBJECT_ID}}", target).toString() },
        objectConfirmation: { expectedObjectIdField: "id" },
        actors: [
          { id: "owner", type: "OWNER", authProfile: "account_a", principalId: "principal-a-secret" },
          { id: "non_owner", type: "NON_OWNER", authProfile: "account_b", principalId: "principal-b-secret" },
          { id: "public", type: "PUBLIC" }
        ],
        fieldExpectations: [
          { id: "absent", path: "absentAllowed", label: "Absent", expectation: "MUST_BE_ABSENT", allowedActors: ["owner", "public"], prohibitedActors: ["non_owner"] },
          { id: "nullable", path: "nullable", label: "Nullable", expectation: "MUST_BE_NULL", allowedActors: ["owner"], prohibitedActors: ["non_owner"] },
          { id: "empty", path: "empty", label: "Empty", expectation: "MAY_BE_PRESENT", allowedActors: ["owner"], prohibitedActors: [] },
          { id: "redacted", path: "redacted", label: "Redacted", expectation: "MUST_BE_REDACTED", allowedActors: ["owner"], prohibitedActors: ["non_owner"], redactionPattern: "^REDACTED$" },
          { id: "masked", path: "masked", label: "Masked", expectation: "MASKED_VALUE", allowedActors: ["owner"], prohibitedActors: ["non_owner"], redactionPattern: "^\\*{2,}\\d{2}$" },
          { id: "diffOwner", path: "ownerSecret", label: "Owner Secret", expectation: "MUST_DIFFER_FROM_OWNER", allowedActors: ["owner"], prohibitedActors: ["non_owner"] },
          { id: "matchPublic", path: "sameAsPublic", label: "Public Match", expectation: "MUST_MATCH_PUBLIC_BASELINE", allowedActors: ["public"], prohibitedActors: ["non_owner"] },
          { id: "mayPresent", path: "publicSummary", label: "Public Summary", sensitivity: "PUBLIC", expectation: "MAY_BE_PRESENT", allowedActors: ["owner", "non_owner", "public"], prohibitedActors: [] },
          { id: "mustPresent", path: "mustPresent", label: "Required Display", expectation: "MUST_BE_PRESENT", allowedActors: ["owner", "non_owner"], prohibitedActors: [] },
          { id: "parent", path: "parent", label: "Parent", expectation: "MAY_BE_PRESENT", allowedActors: ["owner", "non_owner"], prohibitedActors: [] }
        ]
      }
    ]
  };
}

function authProfile(label: string, principalId: string, tenantId: string, role: string) {
  return {
    label,
    safeAlias: label,
    principalId,
    tenantId,
    role,
    headers: { Cookie: `session=${label}` }
  };
}

async function writeScope(tempDir: string): Promise<string> {
  return writeJson(tempDir, "scope.json", {
    ...exampleScope,
    allowedDomains: ["127.0.0.1"],
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
  return new Promise((resolve) => {
    targetServer.listen(0, "127.0.0.1", resolve);
  });
}
