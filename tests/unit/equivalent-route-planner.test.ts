import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { exampleScope } from "../../src/config/defaults.js";
import type { AuthProfileSet } from "../../src/core/auth/AuthProfileSet.js";
import { loadEquivalentRouteInput, planEquivalentRouteTesting, type EquivalentRouteInput } from "../../src/modules/equivalentRouteTesting/EquivalentRoutePlanner.js";

describe("equivalent route planner", () => {
  it("resolves a fixed actor-route matrix and deeply freezes the plan", () => {
    const plan = planEquivalentRouteTesting(validInput("https://app.example.com"), {
      target: "https://app.example.com/",
      scope: exampleScope,
      authProfileSet: profileSet()
    });

    expect(plan.requestMatrix).toHaveLength(9);
    expect(plan.routeSets[0]?.routes.map((route) => route.id)).toEqual(["canonical", "legacy-secure", "legacy-vuln"]);
    expect(plan.requestMatrix.map((cell) => `${cell.actorId}:${cell.routeId}`)).toContain("viewer:legacy-vuln");
    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.routeSets[0]?.cells)).toBe(true);
    expect(JSON.stringify(plan)).not.toContain("session=account-a-secret");
    expect(JSON.stringify(plan)).not.toContain("session=account-b-secret");
  });

  it.each([
    ["missing canonical route", (input: EquivalentRouteInput) => (input.routeSets[0].canonicalRouteId = "missing")],
    ["multiple canonical flags", (input: EquivalentRouteInput) => {
      input.routeSets[0].routes[0].isCanonical = true;
      input.routeSets[0].routes[1].isCanonical = true;
    }],
    ["duplicate route", (input: EquivalentRouteInput) => (input.routeSets[0].routes[1].id = "canonical")],
    ["missing expectation", (input: EquivalentRouteInput) => delete input.routeSets[0].routes[1].expectations.viewer],
    ["unknown actor expectation", (input: EquivalentRouteInput) => (input.routeSets[0].routes[1].expectations.ghost = "MUST_DENY")],
    ["unsafe method", (input: EquivalentRouteInput) => (input.routeSets[0].routes[1].template.method = "HEAD" as "GET")],
    ["unsafe route", (input: EquivalentRouteInput) => (input.routeSets[0].routes[1].template.url = "https://app.example.com/delete/{{OBJECT_ID}}")],
    ["secret query", (input: EquivalentRouteInput) => (input.routeSets[0].routes[1].template.url = "https://app.example.com/legacy/{{OBJECT_ID}}?access_token=secret")],
    ["reference cycle", (input: EquivalentRouteInput) => {
      input.routeSets[0].routes[1].referenceRouteId = "legacy-vuln";
      input.routeSets[0].routes[2].referenceRouteId = "legacy-secure";
    }],
    ["state without field", (input: EquivalentRouteInput) => {
      delete input.routeSets[0].objectStateField;
      input.routeSets[0].expectedObjectState = "published";
    }]
  ])("rejects %s", (_label, mutate) => {
    const input = validInput("https://app.example.com");
    mutate(input);
    expect(() => planEquivalentRouteTesting(input, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow();
  });

  it("rejects missing account pair, same declared principal, reused auth material, and public auth", () => {
    expect(() => planEquivalentRouteTesting(validInput("https://app.example.com"), { target: "https://app.example.com/", scope: exampleScope })).toThrow(/requires --auth-a and --auth-b/);

    const samePrincipal = profileSet();
    samePrincipal.accountB.principalId = samePrincipal.accountA.principalId;
    const samePrincipalInput = validInput("https://app.example.com");
    samePrincipalInput.routeSets[0].actors[1].principalId = "principal-a";
    expect(() => planEquivalentRouteTesting(samePrincipalInput, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: samePrincipal })).toThrow(/same declared principal/);

    const reusedMaterial = profileSet();
    reusedMaterial.accountB.headers = { ...reusedMaterial.accountA.headers };
    expect(() => planEquivalentRouteTesting(validInput("https://app.example.com"), { target: "https://app.example.com/", scope: exampleScope, authProfileSet: reusedMaterial })).toThrow(/reused authentication material/);

    const publicAuth = validInput("https://app.example.com");
    publicAuth.routeSets[0].actors[2].authProfile = "account_a";
    expect(() => planEquivalentRouteTesting(publicAuth, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/Public equivalent-route actor/);
  });

  it("fails closed for malformed, oversized, and non-strict input files", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-equivalent-route-file-"));
    const malformed = join(tempDir, "malformed.json");
    await writeFile(malformed, "{no", "utf8");
    await expect(loadEquivalentRouteInput(malformed)).rejects.toThrow(/not valid JSON/);

    const oversized = join(tempDir, "oversized.json");
    await writeFile(oversized, " ".repeat(257 * 1024), "utf8");
    await expect(loadEquivalentRouteInput(oversized)).rejects.toThrow(/maximum size/);

    const nonStrict = join(tempDir, "non-strict.json");
    await writeFile(nonStrict, JSON.stringify({ ...validInput("https://app.example.com"), extra: true }), "utf8");
    await expect(loadEquivalentRouteInput(nonStrict)).rejects.toThrow();
  });
});

function validInput(origin: string): EquivalentRouteInput {
  return {
    schemaVersion: 1,
    maxRouteSets: 1,
    maxRoutesPerSet: 4,
    maxActorsPerSet: 3,
    maxCells: 20,
    maxResponseBytes: 65536,
    maxPreviewLength: 80,
    routeSets: [
      {
        id: "document-equivalent-routes",
        name: "Document equivalent routes",
        objectType: "document",
        objectId: "doc-a-001",
        canonicalRouteId: "canonical",
        equivalencePolicy: "SAME_OWNER_BOUNDARY",
        objectIdentityField: "id",
        objectStateField: "state",
        expectedObjectState: "published",
        requireVerifiedIdentity: false,
        actors: [
          { id: "owner", relationship: "OWNER", authProfile: "account_a", principalId: "principal-a", tenantId: "tenant-one", role: "member", accountState: "active" },
          { id: "viewer", relationship: "NON_OWNER", authProfile: "account_b", principalId: "principal-b", tenantId: "tenant-one", role: "viewer", accountState: "active" },
          { id: "public", relationship: "PUBLIC", safeAlias: "Public" }
        ],
        routes: [
          route("canonical", "Canonical", "CANONICAL", `${origin}/api/documents/{{OBJECT_ID}}`, { owner: "MUST_ALLOW", viewer: "MUST_DENY", public: "MUST_REQUIRE_AUTHENTICATION" }),
          route("legacy-secure", "Legacy Secure", "LEGACY", `${origin}/legacy/documents/{{OBJECT_ID}}`, { owner: "MUST_ALLOW", viewer: "MUST_DENY", public: "MUST_REQUIRE_AUTHENTICATION" }, "canonical"),
          route("legacy-vuln", "Legacy Vulnerable", "LEGACY", `${origin}/legacy-open/documents/{{OBJECT_ID}}`, { owner: "MUST_ALLOW", viewer: "MUST_DENY", public: "MUST_REQUIRE_AUTHENTICATION" }, "canonical")
        ]
      }
    ]
  };
}

function route(id: string, label: string, category: EquivalentRouteInput["routeSets"][number]["routes"][number]["category"], url: string, expectations: Record<string, EquivalentRouteInput["routeSets"][number]["routes"][number]["expectations"][string]>, referenceRouteId?: string) {
  return {
    id,
    label,
    category,
    isCanonical: id === "canonical",
    template: { id: `${id}-get`, method: "GET" as const, url, headers: { Accept: "application/json" } },
    expectedContentType: "application/json",
    representationType: "json",
    ...(referenceRouteId ? { referenceRouteId } : {}),
    expectations
  };
}

function profileSet(): AuthProfileSet {
  return {
    accountA: { label: "account-a", safeAlias: "Account A", principalId: "principal-a", tenantId: "tenant-one", role: "member", accountState: "active", headers: { Cookie: "session=account-a-secret" }, cookies: [], notes: [] },
    accountB: { label: "account-b", safeAlias: "Account B", principalId: "principal-b", tenantId: "tenant-one", role: "viewer", accountState: "active", headers: { Cookie: "session=account-b-secret" }, cookies: [], notes: [] }
  };
}
