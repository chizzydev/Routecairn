import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { projectAdaptiveSecurityCases } from "../../src/dashboard/execution/AdaptiveSecurityCaseProjection.js";
import { adaptiveExecutionFingerprint } from "../../src/dashboard/execution/AdaptiveCanonical.js";
import { parseSecurityCaseV1, securityCaseV1Schema, securityCaseIdPurpose, securityCaseIdV1, securityCaseIdentityPreimage, projectionDiagnosticSchema, type SecurityCaseV1 } from "../../src/dashboard/execution/AdaptiveSecurityCaseIR.js";
import { buildAdaptiveInventory, synthesizeAdaptiveRecommendations, type AdaptiveInventory, type AdaptiveRecommendation } from "../../src/dashboard/execution/AdaptiveSynthesisCore.js";
import { ng2Corpus, ng2Report, ng2Origin, ng2Canary } from "../helpers/adaptive-ng2-fixture.js";

const fixture = ng2Corpus();
const projection = projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, fixture.recommendations);
const automation = (item: AdaptiveRecommendation) => item.draft.automation as Record<string, unknown>;
const binding = (item: AdaptiveRecommendation) => item.draft.attackGraphBinding as { graphFingerprint: string; graphPathIds: string[] };
function recommendation(category: string): AdaptiveRecommendation { const item = fixture.recommendations.find((value) => value.category === category); if (!item) throw new Error("Missing production-generated fixture category"); return structuredClone(item); }
function caseFor(category: string): SecurityCaseV1 { const item = projection.cases.find((value) => value.source.category === category); if (!item) throw new Error("Missing projected fixture category"); return structuredClone(item); }
afterEach(() => vi.restoreAllMocks());

describe("RC-NG2 primary target origin binding", () => {
  const secondaryOrigin = "https://secondary.test";
  const exactCategories = ["EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION", "EXACT_CONTRACT_REPLAY_BUSINESS_INVARIANT"];
  for (const category of exactCategories) {
    it(`rejects genuinely observed secondary origin for ${category}`, () => {
      const report = ng2Report();
      report.apiMapper!.endpoints.push({ endpoint: `${secondaryOrigin}/health`, method: "GET", source: "html" });
      const inventory = buildAdaptiveInventory(report, []);
      expect(inventory.origins).toEqual([ng2Origin, secondaryOrigin]);
      expect(inventory.routes).toContainEqual(expect.objectContaining({ origin: secondaryOrigin, pathTemplate: "/health", method: "GET" }));
      const item = synthesizeAdaptiveRecommendations(report, inventory, []).find((value) => value.category === category)!;
      expect(item).toBeDefined();
      const primary = projectAdaptiveSecurityCases(new URL(report.target).origin, inventory, [item]);
      expect(primary.diagnostics).toEqual([]);
      expect(primary.cases).toHaveLength(1);
      expect(primary.cases[0]).toMatchObject({ targetOrigin: ng2Origin, readiness: { kind: category.includes("BUSINESS_INVARIANT") ? "READY_APPROVAL_GATED" : "READY_READ_ONLY" }, executable: false, safety: { executionAuthority: "NONE" } });
      expect(projectAdaptiveSecurityCases(secondaryOrigin, inventory, [item])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_TARGET" }] });
    });
    it(`does not confer target authority by adding inventory.origins for ${category}`, () => {
      const inventory = structuredClone(fixture.inventory);
      inventory.origins.push(secondaryOrigin);
      const item = recommendation(category);
      expect(projectAdaptiveSecurityCases(ng2Origin, inventory, [item]).diagnostics).toEqual([]);
      expect(projectAdaptiveSecurityCases(secondaryOrigin, inventory, [item])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_TARGET" }] });
    });
  }
  const witnessNegatives: Array<{ name: string; mutate: (inventory: AdaptiveInventory) => void }> = [
    { name: "absent v2 graph", mutate: (inventory) => { delete inventory.attackGraph; } },
    { name: "absent public scan actor", mutate: (inventory) => { inventory.attackGraph!.nodes = inventory.attackGraph!.nodes.filter((node) => node.semanticKey !== "actor:public"); } },
    { name: "absent scan evidence", mutate: (inventory) => { inventory.attackGraph!.nodes.find((node) => node.semanticKey === "actor:public")!.evidence = []; } },
    { name: "corrupted scan digest", mutate: (inventory) => { const node = inventory.attackGraph!.nodes.find((node) => node.semanticKey === "actor:public")!; node.evidence = node.evidence.map((entry) => ({ ...entry, fingerprint: "f".repeat(64) })); } },
    { name: "wrong scan strength", mutate: (inventory) => { const node = inventory.attackGraph!.nodes.find((node) => node.semanticKey === "actor:public")!; node.evidence = node.evidence.map((entry) => ({ ...entry, strength: "DECLARED_CONTRACT" })); } },
    { name: "wrong public actor identity", mutate: (inventory) => { inventory.attackGraph!.nodes.find((node) => node.semanticKey === "actor:public")!.id = "f".repeat(64); } },
    { name: "ambiguous public actors", mutate: (inventory) => { inventory.attackGraph!.nodes = [...inventory.attackGraph!.nodes, structuredClone(inventory.attackGraph!.nodes.find((node) => node.semanticKey === "actor:public")!)]; } },
    { name: "contradictory scan witnesses", mutate: (inventory) => { const node = inventory.attackGraph!.nodes.find((node) => node.semanticKey === "actor:public")!; node.evidence = [...node.evidence, { producer: "scan", strength: "OBSERVED", fingerprint: "f".repeat(64) }]; } }
  ];
  it.each(witnessNegatives)("fails closed on $name", ({ mutate }) => {
    const inventory = structuredClone(fixture.inventory);
    mutate(inventory);
    const sources = exactCategories.map(recommendation);
    expect(projectAdaptiveSecurityCases(ng2Origin, inventory, sources)).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_TARGET" }, { inputIndex: 1, code: "INVALID_TARGET" }] });
  });
  it("preserves unambiguous graph-free legacy metadata but rejects multi-origin legacy attribution", () => {
    const inventory = structuredClone(fixture.inventory);
    inventory.schemaVersion = 1;
    delete inventory.attackGraph;
    const item = recommendation("DRIFT_NEW_ROUTE");
    const single = projectAdaptiveSecurityCases(ng2Origin, inventory, [item]);
    expect(single.diagnostics).toEqual([]);
    expect(single.cases[0]).toMatchObject({ actors: "UNKNOWN", subject: { kind: "UNRESOLVED", reason: "DRIFT_REVIEW" }, readiness: { kind: "REQUIRES_BINDINGS" }, executable: false });
    inventory.origins.push(secondaryOrigin);
    for (const origin of [ng2Origin, secondaryOrigin]) expect(projectAdaptiveSecurityCases(origin, inventory, [item])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_TARGET" }] });
  });
});

describe("RC-NG2 source-audit counterexamples", () => {
  for (const category of ["API_READ_ONLY_REGRESSION", "EXACT_CONTRACT_REPLAY_BUSINESS_INVARIANT"]) {
    for (const field of ["executionFingerprint", "engineConfiguration", "evidenceFingerprint"]) {
      it(`A rejects changed ${field} on ${category}`, () => {
        const item = recommendation(category);
        if (field === "executionFingerprint") item.draft.executionFingerprint = "f".repeat(64);
        else if (field === "evidenceFingerprint") automation(item).evidenceFingerprint = "f".repeat(64);
        else item.draft.engineConfiguration = { ...(item.draft.engineConfiguration as Record<string, unknown>), maxRequests: 999 };
        expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [item])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_PROVENANCE" }] });
      });
    }
  }
  it("B rejects reassignment to another existing same-origin GET route", () => {
    const item = structuredClone(fixture.recommendations.find((value) => value.category === "API_READ_ONLY_REGRESSION" && value.draft.pathTemplate === "/api/public-profile")!);
    expect(fixture.inventory.routes.some((route) => route.pathTemplate === "/health" && route.method === "GET")).toBe(true);
    item.draft.pathTemplate = "/health";
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [item])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_SUBJECT" }] });
  });
  for (const category of ["EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION", "EXACT_CONTRACT_REPLAY_BUSINESS_INVARIANT"]) {
    it(`C rejects foreign target context for ${category}`, () => {
      expect(projectAdaptiveSecurityCases("https://foreign.test", fixture.inventory, [recommendation(category)])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_TARGET" }] });
    });
  }
  for (const slot of ["primary", "account_a"] as const) {
    it(`D rejects anonymous relabeling of a compiled ${slot} actor`, () => {
      const corpus = ng2Corpus(slot);
      const item = structuredClone(corpus.recommendations.find((value) => value.category === "EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION")!);
      expect(automation(item).authentication).toBe(slot === "primary" ? "primary" : "account-pair");
      automation(item).authentication = "public";
      expect(projectAdaptiveSecurityCases(ng2Origin, corpus.inventory, [item])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_READINESS" }] });
    });
  }
  it("B checks the legacy route source even after configuration and digest are rebound", () => {
    const item = recommendation("API_READ_ONLY_REGRESSION");
    const health = structuredClone(fixture.recommendations.find((value) => value.category === item.category && value.draft.pathTemplate === "/health")!);
    item.draft.pathTemplate = "/health";
    item.draft.engineConfiguration = health.draft.engineConfiguration;
    delete item.draft.attackGraphBinding;
    item.draft.executionFingerprint = adaptiveExecutionFingerprint(item.engineId, item.sourceFingerprint, String(automation(item).evidenceFingerprint), item.draft.engineConfiguration, 1);
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [item])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_PROVENANCE" }] });
  });
  it("B rejects contradictory graph operation metadata", () => {
    const item = recommendation("API_READ_ONLY_REGRESSION");
    const inventory = structuredClone(fixture.inventory);
    const path = inventory.attackGraph!.paths.find((value) => value.id === binding(item).graphPathIds[0])!;
    const node = inventory.attackGraph!.nodes.find((value) => path.nodeIds.includes(value.id) && value.kind === "OPERATION")!;
    node.attributes = { ...node.attributes, pathTemplate: "/health" };
    expect(projectAdaptiveSecurityCases(ng2Origin, inventory, [item])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_GRAPH_BINDING" }] });
  });
  it("B leaves unknown ready route families unresolved", () => {
    const item = recommendation("API_READ_ONLY_REGRESSION");
    item.category = "FUTURE_READ_ONLY_REVIEW";
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [item]).cases[0]).toMatchObject({ subject: { kind: "UNRESOLVED", reason: "NO_SUBJECT_EVIDENCE" }, executable: false });
  });
  it("C accounts for all inputs when observed origins are missing", () => {
    const inventory = { ...fixture.inventory, origins: [] };
    expect(projectAdaptiveSecurityCases(ng2Origin, inventory, fixture.recommendations.slice(0, 2))).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_TARGET" }, { inputIndex: 1, code: "INVALID_TARGET" }] });
  });
  it("D rejects relabeling nested secret-slot requirements", () => {
    const item = recommendation("EXACT_CONTRACT_REPLAY_BUSINESS_INVARIANT");
    const configuration = structuredClone(item.draft.engineConfiguration) as { cases: Array<{ actions: Array<{ request: Record<string, unknown> }> }> };
    configuration.cases[0]!.actions[0]!.request.secretSource = "account_b";
    item.draft.engineConfiguration = configuration;
    item.draft.executionFingerprint = adaptiveExecutionFingerprint(item.engineId, item.sourceFingerprint, String(automation(item).evidenceFingerprint), configuration, 2);
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [item])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_READINESS" }] });
  });
});

describe("RC-NG2 SecurityCase v1 shadow representation", () => {
  it("round-trips every production-generated family through the strict schema", () => {
    expect(projection.diagnostics).toEqual([]);
    expect(projection.cases).toHaveLength(fixture.recommendations.length);
    for (const value of projection.cases) expect(parseSecurityCaseV1(JSON.parse(JSON.stringify(value)))).toEqual(value);
    expect(new Set(projection.cases.map((value) => value.proposition.kind))).toEqual(new Set(["AUTHORIZATION", "LIFECYCLE", "CAPABILITY", "BUSINESS_INVARIANT", "BILLING", "OPERATIONAL", "GRAPH_TRANSITION", "DRIFT"]));
    expect(caseFor("EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION")).toMatchObject({ subject: { kind: "EXACT_SOURCE_CONTRACT" }, actors: "PRIMARY_FIXTURE_REQUIRED", readiness: { kind: "READY_READ_ONLY", compilerVersion: 2 } });
    expect(caseFor("EXACT_CONTRACT_REPLAY_BUSINESS_INVARIANT")).toMatchObject({ subject: { kind: "EXACT_SOURCE_CONTRACT" }, readiness: { kind: "READY_APPROVAL_GATED", cleanupRequestCount: 2 } });
    expect(caseFor("API_READ_ONLY_REGRESSION")).toMatchObject({ subject: { kind: "ROUTE", protocol: "REST", methods: ["GET"] }, actors: "ANONYMOUS" });
    expect(caseFor("GRAPHQL_INTROSPECTION_READ_ONLY")).toMatchObject({ subject: { kind: "ROUTE", protocol: "GRAPHQL" }, readiness: { kind: "READY_READ_ONLY" } });
    for (const category of ["LIFECYCLE_LOGOUT_INVALIDATION", "CAPABILITY_LINK_REVIEW", "OPERATIONAL_ENDPOINT_REVIEW", "SYNTHETIC_BILLING_REVIEW"]) expect(caseFor(category)).toMatchObject({ subject: { kind: "ROUTE" }, actors: "UNKNOWN", readiness: { kind: "REQUIRES_BINDINGS" }, observation: { kind: "HYPOTHESIZED" } });
    expect(caseFor("ATTACK_GRAPH_STATE_TRANSITION")).toMatchObject({ subject: { kind: "GRAPH_PATH", mutability: "STATE_CHANGING" }, actors: "UNKNOWN", readiness: { kind: "REQUIRES_BINDINGS" } });
    expect(caseFor("DRIFT_NEW_ROUTE")).toMatchObject({ subject: { kind: "UNRESOLVED", reason: "DRIFT_REVIEW" }, actors: "UNKNOWN", observation: { kind: "OBSERVED" } });
  });

  it("uses actor requirements only from exact compiler metadata, including account pairs", () => {
    const pair = ng2Corpus("account_a");
    const result = projectAdaptiveSecurityCases(ng2Origin, pair.inventory, pair.recommendations);
    expect(result.diagnostics).toEqual([]);
    expect(result.cases.find((value) => value.source.category === "EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION")?.actors).toBe("ACCOUNT_PAIR_REQUIRED");
    for (const value of result.cases.filter((item) => item.readiness.kind === "REQUIRES_BINDINGS")) expect(value.actors).toBe("UNKNOWN");
    expect(JSON.stringify(result)).not.toMatch(/tenantAlias|principalId|credentialProfileId|expectedDecision|ownerActorId/);
  });

  it("never treats observed readiness or completed PASS/FAIL evidence as execution authority or proof", () => {
    for (const value of projection.cases) {
      expect(value).toMatchObject({ executable: false, safety: { executionAuthority: "NONE", approval: "NOT_GRANTED", cleanup: "NOT_ASSESSED" }, observation: { vulnerabilityConclusion: "NOT_ASSESSED" } });
      expect(JSON.stringify(value)).not.toMatch(/engineConfiguration|safeDraft|requestBody|responseBody|authorizedAt|expiresAt|operatorRationale/);
    }
    expect(securityCaseV1Schema.safeParse({ ...caseFor("API_READ_ONLY_REGRESSION"), executable: true }).success).toBe(false);
  });

  it("keeps an exact anonymous data observation unresolved when the draft supplies no route", () => {
    const report = ng2Report();
    report.supabaseAuthorization = { projectOrigin: "https://project.supabase.co", observations: [{ caseId: "public-rows", comparisonFingerprint: "b".repeat(64), surface: "TABLE", resource: "public_articles", operation: "SELECT", actor: "ANONYMOUS", boundary: "NONE", method: "GET", url: "/rest/v1/public_articles?select=id&limit=1", expectedDecision: "ALLOW", observedDecision: "ALLOW", statusCode: 200, evidenceIds: [], safeSummary: "Fixture anonymous list read" }], resourceCoverage: [{ surface: "TABLE", resource: "public_articles", operations: ["SELECT"], actors: ["ANONYMOUS"] }] } as unknown as NonNullable<typeof report.supabaseAuthorization>;
    const inventory = buildAdaptiveInventory(report, []);
    const result = projectAdaptiveSecurityCases(ng2Origin, inventory, synthesizeAdaptiveRecommendations(report, inventory, []));
    expect(result.diagnostics).toEqual([]);
    expect(result.cases.find((value) => value.source.category === "SUPABASE_ANONYMOUS_READ_REGRESSION")).toMatchObject({ actors: "ANONYMOUS", subject: { kind: "UNRESOLVED", reason: "NO_SUBJECT_EVIDENCE" }, readiness: { kind: "READY_READ_ONLY", evidenceStrength: "EXACT_ENGINE_OBSERVATION" }, executable: false });
    expect(JSON.stringify(result)).not.toMatch(/SUPABASE_ANON_KEY|select=id|project\.supabase\.co/);
  });

  it("does not use a read-only label to justify an arbitrary observed REST POST", () => {
    const item = recommendation("API_READ_ONLY_REGRESSION");
    delete item.draft.attackGraphBinding;
    item.draft.pathTemplate = "/webhook";
    item.draft.documentedMethods = ["POST"];
    const result = projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [item]);
    expect(result).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_READINESS" }] });
  });

  it("rejects version, discriminant, identity, unknown field and array-bound violations", () => {
    const base = caseFor("API_READ_ONLY_REGRESSION");
    const invalid = [
      { ...base, schemaVersion: 2 }, { ...base, caseId: "not-a-hash" }, { ...base, caseId: "f".repeat(64) },
      { ...base, subject: { kind: "ENGINE_CONFIGURATION" } }, { ...base, targetOrigin: ng2Origin + "/private" },
      { ...base, actors: "saved-profile-uuid" }, { ...base, engineConfiguration: {} },
      { ...base, source: { ...base.source, sourceFingerprint: "invalid" } },
      { ...base, subject: { kind: "ROUTE", pathTemplate: "/" + "x".repeat(501) } },
      { ...base, subject: { kind: "ROUTE", pathTemplate: "/objects/12345" } },
      { ...base, subject: { kind: "ROUTE", pathTemplate: "/objects", methods: Array(17).fill("GET") } },
      { ...base, unresolvedBindings: Array(33).fill("UNCLASSIFIED_BINDING") },
      { ...base, provenance: { ...base.provenance, graph: { fingerprint: "a".repeat(64), pathIds: Array(33).fill("b".repeat(64)) } } },
      { ...base, readiness: { kind: "APPROVED" } }, { ...base, safety: { ...base.safety, approval: "APPROVED" } }
    ];
    for (const value of invalid) expect(securityCaseV1Schema.safeParse(value).success).toBe(false);
  });

  it("checks actual graph paths and genuine source-case fingerprints", () => {
    for (const value of projection.cases) {
      if (value.provenance.graph) {
        expect(value.provenance.graph.fingerprint).toBe(fixture.inventory.attackGraph!.graphFingerprint);
        for (const id of value.provenance.graph.pathIds) expect(fixture.inventory.attackGraph!.paths.some((path) => path.id === id)).toBe(true);
      }
      for (const id of value.provenance.sourceCaseFingerprints ?? []) expect(fixture.inventory.workflowCases.some((entry) => entry.fingerprint === id) || fixture.inventory.attackGraph!.paths.some((path) => path.sourceCaseFingerprints.includes(id))).toBe(true);
    }
    const exact = recommendation("EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION");
    exact.draft.sourceCaseFingerprints = ["f".repeat(64)];
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [exact])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_PROVENANCE" }] });
  });

  it("domain separates identities, preserves array order and omits mutable review metadata", () => {
    const value = caseFor("API_READ_ONLY_REGRESSION");
    const identity = { targetOrigin: value.targetOrigin, source: value.source, subject: value.subject };
    const preimage = securityCaseIdentityPreimage(identity);
    expect(JSON.parse(preimage).purpose).toBe(securityCaseIdPurpose);
    expect(createHash("sha256").update(preimage).digest("hex")).toBe(value.caseId);
    expect(value.caseId).not.toBe(value.source.sourceFingerprint);
    expect(value.caseId).not.toBe(value.provenance.evidenceFingerprint);
    expect(value.caseId).not.toBe(value.provenance.graph?.fingerprint);
    expect(securityCaseIdV1({ subject: identity.subject, source: identity.source, targetOrigin: identity.targetOrigin })).toBe(value.caseId);
    const route = { kind: "ROUTE" as const, pathTemplate: "/api/public-profile", methods: ["GET", "HEAD"] as ["GET", "HEAD"] };
    expect(securityCaseIdV1({ ...identity, subject: route })).not.toBe(securityCaseIdV1({ ...identity, subject: { ...route, methods: ["HEAD", "GET"] } }));
  });

  it("preserves inputs and produces equal output with the clock and network forbidden", () => {
    const inventory = structuredClone(fixture.inventory);
    const sources = structuredClone(fixture.recommendations);
    const before = structuredClone({ inventory, sources });
    vi.spyOn(Date, "now").mockImplementation(() => { throw new Error("Projection must not read clock"); });
    vi.spyOn(globalThis, "fetch").mockImplementation(() => { throw new Error("Projection must not transmit"); });
    const left = projectAdaptiveSecurityCases(ng2Origin, inventory, sources);
    const right = projectAdaptiveSecurityCases(ng2Origin, structuredClone(inventory), structuredClone(sources));
    expect(left).toEqual(right);
    expect({ inventory, sources }).toEqual(before);
    expect(Date.now).not.toHaveBeenCalled();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("accounts for all inputs without deduplication and preserves case and diagnostic order", () => {
    const first = recommendation("API_READ_ONLY_REGRESSION");
    const invalid = structuredClone(first); invalid.sourceFingerprint = "bad";
    const second = structuredClone(fixture.recommendations.find((value) => value.category === "API_READ_ONLY_REGRESSION" && value.sourceFingerprint !== first.sourceFingerprint)!);
    const result = projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [first, invalid, first, second, invalid]);
    expect(result.cases).toHaveLength(3);
    expect(result.diagnostics).toEqual([{ inputIndex: 1, code: "INVALID_SOURCE" }, { inputIndex: 4, code: "INVALID_SOURCE" }]);
    expect(result.cases.map((value) => value.source.sourceFingerprint)).toEqual([first.sourceFingerprint, first.sourceFingerprint, second.sourceFingerprint]);
    expect(result.cases[0]!.caseId).toBe(result.cases[1]!.caseId);
    expect(result.cases[0]!.caseId).not.toBe(result.cases[2]!.caseId);
    expect(result.cases.length + result.diagnostics.length).toBe(5);
  });

  it("accounts for sparse slots and does not confuse prototype names with known engines", () => {
    const source = recommendation("DRIFT_NEW_ROUTE");
    const sparse = new Array<AdaptiveRecommendation>(2); sparse[1] = source;
    const result = projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, sparse);
    expect(result.diagnostics).toEqual([{ inputIndex: 0, code: "INVALID_SOURCE" }]);
    expect(result.cases).toHaveLength(1);
    const unknown = { ...source, category: "FUTURE_REVIEW", engineId: "constructor" };
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [unknown]).cases[0]?.proposition.kind).toBe("OTHER");
  });

  it("requires source-grounded drift evidence rather than inferring observation from a category", () => {
    const drift = recommendation("DRIFT_NEW_ROUTE");
    delete drift.draft.semanticKey; delete drift.draft.safeSummary;
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [drift]).cases[0]).toMatchObject({ proposition: { kind: "DRIFT" }, observation: { kind: "DECLARED" } });
    const broken = recommendation("DRIFT_NEW_ROUTE"); broken.draft.safeSummary = "Unbound fabricated evidence";
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [broken])).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_PROVENANCE" }] });
  });

  it("supports empty and legacy graph-free inventory without inventing evidence or actors", () => {
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [])).toEqual({ cases: [], diagnostics: [] });
    const item = recommendation("DRIFT_NEW_ROUTE");
    const legacy = structuredClone(fixture.inventory); legacy.schemaVersion = 1; delete legacy.attackGraph; legacy.routes = [];
    expect(projectAdaptiveSecurityCases(ng2Origin, legacy, [item]).cases[0]).toMatchObject({ subject: { kind: "UNRESOLVED" }, actors: "UNKNOWN", readiness: { kind: "REQUIRES_BINDINGS" } });
    const route = recommendation("API_AUTHORIZATION_MATRIX"); delete route.draft.attackGraphBinding;
    legacy.routes = fixture.inventory.routes.map(({ origin: _origin, ...value }) => value);
    expect(projectAdaptiveSecurityCases(ng2Origin, legacy, [route]).cases[0]).toMatchObject({ subject: { kind: "UNRESOLVED", reason: "ROUTE_ORIGIN_UNKNOWN" }, actors: "UNKNOWN" });
    const future = { ...item, category: "FUTURE_REVIEW", engineId: "future-engine" };
    expect(projectAdaptiveSecurityCases(ng2Origin, legacy, [future]).cases[0]?.proposition.kind).toBe("OTHER");
  });

  it("keeps secrets out of JSON, diagnostics and the case-ID preimage", () => {
    const item = recommendation("EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION");
    const canaries = [ng2Canary, "ng2-private-body-canary", "ng2-private-ticket-canary", "Bearer ng2-private-bearer", "eyJprivate.eyJprivate.private", "8e776563-531a-4978-a873-fd6d0867e20f"];
    item.draft.operatorRationale = canaries[2];
    item.draft.credentialProfileId = canaries[5];
    item.draft.engineConfiguration = { ...item.draft.engineConfiguration as object, privateBody: canaries[1], headers: { Authorization: canaries[3] }, signedUrl: `https://private.test/secret?value=${canaries[0]}#${canaries[4]}` };
    // Rebind synthetic canaries so this still tests output redaction, independently of tamper rejection.
    item.draft.executionFingerprint = adaptiveExecutionFingerprint(item.engineId, item.sourceFingerprint, String(automation(item).evidenceFingerprint), item.draft.engineConfiguration, 2);
    const result = projectAdaptiveSecurityCases(`${ng2Origin}/private?value=${ng2Canary}#private`, fixture.inventory, [item]);
    expect(result.diagnostics).toEqual([]);
    expect(result.cases[0]!.caseId).toBe(caseFor(item.category).caseId);
    const value = result.cases[0]!;
    const preimage = securityCaseIdentityPreimage({ targetOrigin: value.targetOrigin, source: value.source, subject: value.subject });
    for (const canary of canaries) { expect(JSON.stringify(result)).not.toContain(canary); expect(preimage).not.toContain(canary); }
    const labels = structuredClone(fixture.inventory);
    labels.attackGraph!.nodes = labels.attackGraph!.nodes.map((node) => ({ ...node, label: canaries[1]!, attributes: { privateValue: canaries[3]! } }));
    labels.attackGraph!.paths = labels.attackGraph!.paths.map((path) => ({ ...path, label: canaries[2]! }));
    expect(projectAdaptiveSecurityCases(ng2Origin, labels, [item])).toEqual(result);
    const drift = recommendation("DRIFT_NEW_ROUTE");
    drift.requiredBindings = [canaries[1]!]; automation(drift).unresolvedBindings = [...drift.requiredBindings];
    expect(projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [drift]).cases[0]!.unresolvedBindings).toEqual(["UNCLASSIFIED_BINDING"]);
    const malformed = structuredClone(item); malformed.draft.pathTemplate = canaries[3]; malformed.draft.exactExecutedContract = false;
    const diagnostic = projectAdaptiveSecurityCases(ng2Origin, fixture.inventory, [malformed]).diagnostics;
    for (const canary of canaries) expect(JSON.stringify(diagnostic)).not.toContain(canary);
  });

  const negatives: Array<{ name: string; category?: string; mutate: (item: AdaptiveRecommendation, inventory: AdaptiveInventory) => void }> = [
    { name: "false executable metadata", mutate: (item) => { item.draft.executable = false; } },
    { name: "unsupported compiler version", mutate: (item) => { automation(item).compilerVersion = 3; } },
    { name: "malformed evidence fingerprint", mutate: (item) => { automation(item).evidenceFingerprint = "Bearer private-canary"; } },
    { name: "missing execution fingerprint", mutate: (item) => { delete item.draft.executionFingerprint; } },
    { name: "fabricated execution status", mutate: (item) => { automation(item).state = "EXECUTED"; } },
    { name: "claimed approval", mutate: (item) => { automation(item).approved = true; } },
    { name: "inconsistent mutation state", mutate: (item) => { item.mutationHypothesis = true; } },
    { name: "wrong graph fingerprint", mutate: (item) => { binding(item).graphFingerprint = "f".repeat(64); } },
    { name: "missing graph path", mutate: (item) => { binding(item).graphPathIds = ["f".repeat(64)]; } },
    { name: "duplicate graph paths", mutate: (item) => { binding(item).graphPathIds.push(binding(item).graphPathIds[0]!); } },
    { name: "graph mutation differs", mutate: (item, inventory) => { const path = inventory.attackGraph!.paths.find((value) => value.id === binding(item).graphPathIds[0])!; path.mutability = "STATE_CHANGING"; } },
    { name: "incomplete bound compiler path", mutate: (item, inventory) => { inventory.attackGraph!.paths.find((value) => value.id === binding(item).graphPathIds[0])!.contractReadiness = "REQUIRES_BINDINGS"; } },
    { name: "unbounded graph", mutate: (_item, inventory) => { inventory.attackGraph!.bounds.maxPaths = 501; } },
    { name: "unsupported evidence strength", mutate: (item) => { automation(item).evidenceStrength = "PASS"; } },
    { name: "unresolved advertised executable", category: "LIFECYCLE_LOGOUT_INVALIDATION", mutate: (item) => { item.draft.executable = true; } },
    { name: "binding list disagreement", category: "LIFECYCLE_LOGOUT_INVALIDATION", mutate: (item) => { item.requiredBindings = []; } },
    { name: "overlong route identity", category: "API_READ_ONLY_REGRESSION", mutate: (item) => { item.draft.pathTemplate = "/" + "x".repeat(501); } },
    { name: "unsafe route query", category: "API_READ_ONLY_REGRESSION", mutate: (item) => { item.draft.pathTemplate = `/api/public-profile?secret=${ng2Canary}`; } },
    { name: "missing inventory subject", category: "API_READ_ONLY_REGRESSION", mutate: (item) => { item.draft.pathTemplate = "/not-observed"; } },
    { name: "legacy missing readiness", mutate: (item) => { delete item.draft.automation; } },
    { name: "too many bindings", category: "LIFECYCLE_LOGOUT_INVALIDATION", mutate: (item) => { item.requiredBindings = Array(33).fill("cleanup"); automation(item).unresolvedBindings = [...item.requiredBindings]; } },
    { name: "too many methods", category: "API_READ_ONLY_REGRESSION", mutate: (item) => { item.draft.documentedMethods = Array(17).fill("GET"); } },
    { name: "unsafe category identity", mutate: (item) => { item.category = "CREDENTIAL=" + ng2Canary; } },
    { name: "unsafe authentication requirement", mutate: (item) => { automation(item).authentication = "saved-profile-private-id"; } },
    { name: "negative cleanup count", mutate: (item) => { automation(item).cleanupRequestCount = -1; } }
  ];
  it.each(negatives)("diagnoses $name without a permissive fallback or source echo", ({ category, mutate }) => {
    const item = recommendation(category ?? "EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION");
    const inventory = structuredClone(fixture.inventory);
    mutate(item, inventory);
    const result = projectAdaptiveSecurityCases(ng2Origin, inventory, [item]);
    expect(result.cases).toEqual([]);
    expect(result.diagnostics).toHaveLength(1);
    expect(projectionDiagnosticSchema.safeParse(result.diagnostics[0]).success).toBe(true);
    expect(result.diagnostics[0]!.inputIndex).toBe(0);
    expect(JSON.stringify(result.diagnostics)).not.toMatch(/private|Bearer|eyJ|secret=/);
  });

  it("diagnoses invalid targets once per input without exposing credentials", () => {
    const sources = fixture.recommendations.slice(0, 2);
    for (const target of ["file:///private", "https://owner:private@app.test", "invalid", "https://" + "a".repeat(2100)]) expect(projectAdaptiveSecurityCases(target, fixture.inventory, sources)).toEqual({ cases: [], diagnostics: [{ inputIndex: 0, code: "INVALID_TARGET" }, { inputIndex: 1, code: "INVALID_TARGET" }] });
  });
});
