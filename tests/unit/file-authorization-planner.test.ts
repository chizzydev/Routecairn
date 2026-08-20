import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import type { AuthProfileSet } from "../../src/core/auth/AuthProfileSet.js";
import { planFileAuthorizationTesting, type FileAuthorizationInput } from "../../src/modules/fileAuthorization/FileAuthorizationPlanner.js";

describe("file authorization planner", () => {
  it("resolves metadata, bounded content, and signed-url cases into an immutable fixed matrix", () => {
    const plan = planFileAuthorizationTesting(validInput("https://app.example.com/"), { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() });
    expect(plan.requestMatrix).toHaveLength(3);
    expect(plan.requestMatrix[0]?.url).toContain("file-private-a");
    expect(plan.requestMatrix[1]?.headers.Range).toBe("bytes=0-31");
    expect(plan.requestMatrix[2]?.contentProofMode).toBe("SIGNED_URL_ONLY");
    expect(Object.isFrozen(plan.requestMatrix[0])).toBe(true);
    expect(JSON.stringify(plan)).not.toContain("session=account-a");
  });

  it.each([
    ["unsafe method", (input: FileAuthorizationInput) => (input.definitions[0].cases[0].method = "POST" as "GET")],
    ["wildcard file reference", (input: FileAuthorizationInput) => (input.definitions[0].files[0].fileRef = "file-*")],
    ["path traversal file reference", (input: FileAuthorizationInput) => (input.definitions[0].files[0].fileRef = "../secret.pdf")],
    ["missing actor", (input: FileAuthorizationInput) => (input.definitions[0].cases[0].actorId = "ghost")],
    ["unknown placeholder", (input: FileAuthorizationInput) => (input.definitions[0].cases[0].url = "https://app.example.com/api/files/{{UNKNOWN}}")],
    ["out of scope", (input: FileAuthorizationInput) => (input.definitions[0].cases[0].url = "https://evil.example.com/api/files/{{FILE_ID}}")],
    ["range missing length", (input: FileAuthorizationInput) => delete input.definitions[0].cases[1].rangeLength],
    ["signed URL missing field", (input: FileAuthorizationInput) => delete input.definitions[0].cases[2].signedUrlField],
    ["signed URL follow without approved origin", (input: FileAuthorizationInput) => {
      input.definitions[0].cases[2].followSignedUrl = true;
      input.definitions[0].cases[2].identityStrategy = "OPERATOR_SUPPLIED_FINGERPRINT";
      input.definitions[0].cases[2].expectedFingerprint = "b".repeat(64);
      input.definitions[0].cases[2].allowedSignedUrlOrigins = [];
    }],
    ["signed URL follow without operator fingerprint", (input: FileAuthorizationInput) => {
      input.definitions[0].cases[2].followSignedUrl = true;
      input.definitions[0].cases[2].identityStrategy = "SIGNED_URL_FIELD_MATCH";
    }],
    ["public actor with auth", (input: FileAuthorizationInput) => (input.definitions[0].actors[2].authProfile = "account_a")]
  ])("rejects %s", (_label, mutate) => {
    const input = validInput("https://app.example.com/");
    mutate(input);
    expect(() => planFileAuthorizationTesting(input, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow();
  });

  it("rejects missing auth pair, same principal, and reused authentication material", () => {
    expect(() => planFileAuthorizationTesting(validInput("https://app.example.com/"), { target: "https://app.example.com/", scope: exampleScope })).toThrow(/requires --auth-a and --auth-b/);
    const samePrincipal = profileSet();
    samePrincipal.accountB.principalId = samePrincipal.accountA.principalId;
    const samePrincipalInput = validInput("https://app.example.com/");
    samePrincipalInput.definitions[0].actors[1].principalId = "principal-a";
    expect(() => planFileAuthorizationTesting(samePrincipalInput, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: samePrincipal })).toThrow(/same principal/);
    const reused = profileSet();
    reused.accountB.headers = { ...reused.accountA.headers };
    expect(() => planFileAuthorizationTesting(validInput("https://app.example.com/"), { target: "https://app.example.com/", scope: exampleScope, authProfileSet: reused })).toThrow(/reused authentication material/);
  });
});

function validInput(origin: string): FileAuthorizationInput {
  return {
    schemaVersion: 1,
    maxDefinitions: 1,
    maxCasesPerDefinition: 5,
    maxFilesPerDefinition: 3,
    maxRequests: 5,
    maxRetainedObservations: 5,
    definitions: [
      {
        id: "files",
        label: "Files",
        actors: [
          { id: "owner", relationship: "OWNER", authProfile: "account_a", principalId: "principal-a", tenantId: "tenant-a", role: "member", accountState: "active" },
          { id: "viewer", relationship: "CROSS_TENANT_MEMBER", authProfile: "account_b", principalId: "principal-b", tenantId: "tenant-b", role: "member", accountState: "active" },
          { id: "public", relationship: "PUBLIC" }
        ],
        files: [{ id: "private-a", fileRef: "file-private-a", safeAlias: "Private A", fileType: "pdf", ownerActorId: "owner", tenantId: "tenant-a", state: "active", expectedPublic: false }],
        cases: [
          fileCase(origin, "metadata", "viewer", "MUST_DENY_METADATA", "METADATA_ONLY", "METADATA_FIELD_MATCH"),
          { ...fileCase(origin, "download", "viewer", "MUST_DENY_CONTENT", "BOUNDED_PREFIX", "OPERATOR_SUPPLIED_FINGERPRINT"), category: "DIRECT_DOWNLOAD", url: `${origin}download/{{FILE_ID}}`, rangeLength: 32, expectedFingerprint: "a".repeat(64) },
          { ...fileCase(origin, "signed", "viewer", "MUST_NOT_RECEIVE_SIGNED_URL", "SIGNED_URL_ONLY", "SIGNED_URL_FIELD_MATCH"), category: "SIGNED_URL_ISSUANCE", url: `${origin}signed/{{FILE_ID}}`, signedUrlField: "download.url", allowedSignedUrlOrigins: ["https://storage.example.com"] }
        ]
      }
    ]
  };
}

function fileCase(origin: string, id: string, actorId: string, expectedDecision: string, contentProofMode: string, identityStrategy: string) {
  return {
    id,
    label: id,
    category: "FILE_METADATA",
    actorId,
    fileRefId: "private-a",
    method: "GET",
    url: `${origin}api/files/{{FILE_ID}}`,
    headers: { Accept: "application/json" },
    expectedDecision,
    requireVerifiedIdentity: true,
    expectedTenantId: actorId === "owner" ? "tenant-a" : "tenant-b",
    expectedRole: "member",
    expectedAccountState: "active",
    identityStrategy,
    identityField: identityStrategy === "METADATA_FIELD_MATCH" ? "file.id" : undefined,
    contentProofMode,
    maxMetadataBytes: 65536,
    maxProbeBytes: 64
  } as FileAuthorizationInput["definitions"][number]["cases"][number];
}

function profileSet(): AuthProfileSet {
  return {
    accountA: { label: "account-a", safeAlias: "Account A", principalId: "principal-a", tenantId: "tenant-a", role: "member", accountState: "active", headers: { Cookie: "session=account-a" }, cookies: [], notes: [] },
    accountB: { label: "account-b", safeAlias: "Account B", principalId: "principal-b", tenantId: "tenant-b", role: "member", accountState: "active", headers: { Cookie: "session=account-b" }, cookies: [], notes: [] }
  };
}
