import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { synthesizeAdaptiveAuthorizationReview, validateAdaptiveAuthorizationReviewQuestion } from "../../src/dashboard/execution/AdaptiveAuthorizationSynthesis.js";
import { authorizationReviewQuestionV1Schema, authorizationReviewQuestionId, authorizationReviewIdentityPreimage, authorizationReviewPurpose } from "../../src/dashboard/execution/AdaptiveAuthorizationReviewIR.js";
import { projectAdaptiveSecurityCases } from "../../src/dashboard/execution/AdaptiveSecurityCaseProjection.js";
import { adaptiveDigest } from "../../src/dashboard/execution/AdaptiveCanonical.js";
import { buildAdaptiveInventory, synthesizeAdaptiveRecommendations, type AdaptiveInventory, type AdaptiveRecommendation } from "../../src/dashboard/execution/AdaptiveSynthesisCore.js";
import { apiGraphqlInputSchema, planApiGraphqlReview } from "../../src/modules/apiGraphql/ApiGraphqlPlanner.js";
import { ng2Corpus, ng2Origin, ng2Report, ng2Scope } from "../helpers/adaptive-ng2-fixture.js";

const corpus = ng2Corpus();
const run = (inventory = corpus.inventory, recommendations = corpus.recommendations) => synthesizeAdaptiveAuthorizationReview(ng2Origin, inventory, recommendations);
const source = (category: string) => structuredClone(corpus.recommendations.find((item) => item.category === category)!);
const exact = "EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION";
const identity = (question: ReturnType<typeof run>["questions"][number]) => ({ targetOrigin: question.targetOrigin, sourceCaseId: question.sourceCaseId, questionKind: question.questionKind, references: question.references });
function rebind(inventory: AdaptiveInventory, recommendations: AdaptiveRecommendation[]) {
  const { graphFingerprint: _old, ...payload } = inventory.attackGraph!;
  inventory.attackGraph!.graphFingerprint = adaptiveDigest(payload);
  for (const item of recommendations) if (item.draft.attackGraphBinding) (item.draft.attackGraphBinding as { graphFingerprint: string }).graphFingerprint = inventory.attackGraph!.graphFingerprint;
}
/** Original planners/builders create all relationships; this is source metadata, never transmitted. */
function relationshipFixture(owner = "owner", resourceCount = 1) {
  const report = ng2Report();
  const profile = { label: "Fixture slot", headers: {}, cookies: [] } as NonNullable<Parameters<typeof planApiGraphqlReview>[1]["authProfile"]>;
  const plan = planApiGraphqlReview(apiGraphqlInputSchema.parse({ schemaVersion: 1, maxRequests: 1,
    actors: [{ id: "owner", safeAlias: "Fixture owner", authSlot: "primary", relationship: "OWNER", tenantId: "ng3-private-tenant" }],
    routes: [{ id: "object", safeAlias: "Disposable object", protocol: "REST", kind: "OBJECT", objectType: "invoice", url: `${ng2Origin}/api/invoices/inv_fixture`, pathTemplate: "/api/invoices/:id", documentedMethods: ["GET"] }],
    checks: [{ id: "owner-read", matrixId: "invoice-owner", label: "Exact owner read", kind: "OBJECT_AUTHORIZATION", routeId: "object", actorId: "owner", requireVerifiedIdentity: false, request: { method: "GET" }, response: { expectedDecision: "ALLOW" } }]
  }), { target: ng2Origin, scope: ng2Scope, authProfile: profile });
  report.scanPlan.apiGraphql = plan;
  report.apiGraphql!.checks[0]!.comparisonFingerprint = plan.checks[0]!.comparisonFingerprint;
  // Declarative link-resource metadata is consumed by addObjectOwnership, not an execution fixture.
  report.scanPlan.linkPortalSecurity = { actors: [{ id: owner, safeAlias: "Fixture owner", authSlot: "primary" }], resources: Array.from({ length: resourceCount }, (_, index) => ({ id: `export-${index}`, kind: "EXPORT", safeAlias: "ng3-private-object", ownerActorId: owner })) } as unknown as NonNullable<typeof report.scanPlan.linkPortalSecurity>;
  const inventory = buildAdaptiveInventory(report, []);
  const recommendations = synthesizeAdaptiveRecommendations(report, inventory, []).filter((item) => item.category === exact);
  expect(recommendations).toHaveLength(1);
  return { report, inventory, recommendations };
}
afterEach(() => vi.restoreAllMocks());

describe("RC-NG3 authorization review shadow synthesis", () => {
  it("freezes the first correct ordered semantic golden independent of timestamps and saved IDs", () => {
    const result=run();
    expect(createHash("sha256").update(JSON.stringify(result)).digest("hex")).toBe("7a5bf87fb2f590a4c1f0a80b7fdd5f9e6dd2b26fd8d71abffe4d997e0d382b9f");
    const report=ng2Report();
    const left=structuredClone(report) as typeof report & {scanId:string;createdAt:string;savedProfileId:string};
    const right=structuredClone(left);
    left.scanId="8e776563-531a-4978-a873-fd6d0867e20f";left.createdAt="2026-10-13T10:00:00Z";left.savedProfileId="profile-left";
    right.scanId="bd7c4938-53dc-4a5d-a8b0-93a365b13c30";right.createdAt="2030-01-01T10:00:00Z";right.savedProfileId="profile-right";
    const derive=(value:typeof report)=>{const inventory=buildAdaptiveInventory(value,[]);return synthesizeAdaptiveAuthorizationReview(ng2Origin,inventory,synthesizeAdaptiveRecommendations(value,inventory,[]));};
    expect(derive(left)).toEqual(derive(right));expect(JSON.stringify(derive(left))).not.toMatch(/profile-left|8e776563|2026-10-13T10/);
  });
  it("accounts for all genuine cases with questions or safe explicit omissions", () => {
    const upstream = projectAdaptiveSecurityCases(ng2Origin, corpus.inventory, corpus.recommendations);
    const result = run();
    expect(result.accountedCases).toBe(99); expect(result.upstreamDiagnostics).toEqual([]);
    expect(result.questions).toHaveLength(33);
    expect(result.diagnostics.every((item) => item.code === "NO_ELIGIBLE_RELATIONSHIP")).toBe(true);
    for (const [inputIndex, item] of upstream.cases.entries()) expect(result.questions.some((q) => q.sourceCaseId === item.caseId) || result.diagnostics.some((d) => d.inputIndex === inputIndex && d.sourceCaseId === item.caseId)).toBe(true);
    for (const question of result.questions) expect(authorizationReviewQuestionV1Schema.safeParse(question).success).toBe(true);
  });
  it("binds each actor/operation edge and global role to the actual same actor and retained path", () => {
    const upstream = projectAdaptiveSecurityCases(ng2Origin, corpus.inventory, corpus.recommendations);
    for (const q of run().questions.filter((item) => item.evidenceBasis !== "UNRESOLVED")) {
      const c = upstream.cases.find((item) => item.caseId === q.sourceCaseId)!;
      expect(c.provenance.graph!.pathIds).toContain(q.references.graphPathId);
      const path = corpus.inventory.attackGraph!.paths.find((item) => item.id === q.references.graphPathId)!;
      const links = q.references.relationshipEdgeIds!.map((id) => corpus.inventory.attackGraph!.edges.find((item) => item.id === id)!);
      const performed = links.find((item) => item.kind === "PERFORMS")!;
      expect(performed.from).toBe(q.references.actorNodeId); expect(performed.to).toBe(q.references.operationNodeId);
      expect(path.edgeIds).toContain(performed.id); expect(path.nodeIds).toContain(performed.from); expect(path.nodeIds).toContain(performed.to);
      if (q.questionKind === "ROLE_BOUNDARY") expect(links.find((item) => item.kind === "HAS_ROLE")).toMatchObject({ from: performed.from, to: q.references.roleNodeId });
    }
  });
  it("derives all relationship families from real source-backed builders without claiming ownership", () => {
    const f = relationshipFixture();
    const r = synthesizeAdaptiveAuthorizationReview(ng2Origin, f.inventory, f.recommendations);
    expect(r.diagnostics).toEqual([]); expect(r.questions).toHaveLength(4);
    expect(new Set(r.questions.map((q) => q.questionKind))).toEqual(new Set(["ACTOR_OPERATION_BOUNDARY", "ROLE_BOUNDARY", "TENANT_BOUNDARY", "OBJECT_OWNERSHIP_BOUNDARY"]));
    for (const q of r.questions) expect(q).toMatchObject({ expectedDecision: "UNKNOWN", expectedOwnership: "UNKNOWN", executable: false, executionAuthority: "NONE", operatorApproval: "NOT_GRANTED", cleanup: "NOT_ASSESSED", vulnerabilityConclusion: "NOT_ASSESSED" });
    expect(r.questions.find((q) => q.questionKind === "OBJECT_OWNERSHIP_BOUNDARY")!.evidenceBasis).toBe("MIXED");
  });
  it("never joins a different actor through equal labels or aliases", () => {
    const f = relationshipFixture("other");
    expect(f.inventory.attackGraph!.edges.some((item) => item.kind === "OWNS")).toBe(true);
    const r = synthesizeAdaptiveAuthorizationReview(ng2Origin, f.inventory, f.recommendations);
    expect(r.questions.some((q) => q.questionKind === "OBJECT_OWNERSHIP_BOUNDARY")).toBe(false);
    expect(r.questions.some((q) => q.questionKind === "TENANT_BOUNDARY")).toBe(true);
  });
  it("retains legitimate scoped capabilities without inventing object ownership", () => {
    const f = relationshipFixture();
    const metadata = f.report.scanPlan.linkPortalSecurity as unknown as { resources:Array<Record<string,unknown>> };
    metadata.resources[0]!.kind="SIGNED_LINK"; metadata.resources[0]!.tenantFingerprint="a".repeat(64);
    const inventory=buildAdaptiveInventory(f.report,[]), recommendations=synthesizeAdaptiveRecommendations(f.report,inventory,[]).filter(item=>item.category===exact);
    expect(inventory.attackGraph!.edges.some(e=>e.kind==="SCOPED_TO" && inventory.attackGraph!.nodes.find(n=>n.id===e.from)?.kind==="CAPABILITY")).toBe(true);
    const r=synthesizeAdaptiveAuthorizationReview(ng2Origin,inventory,recommendations);
    expect(r.diagnostics).toEqual([]);expect(r.questions.some(q=>q.questionKind==="ACTOR_OPERATION_BOUNDARY")).toBe(true);
    expect(r.questions.some(q=>q.questionKind==="OBJECT_OWNERSHIP_BOUNDARY")).toBe(false);
  });
  it("keeps exact, mixed, observed and unresolved strengths distinct and outcomes unknown", () => {
    const r = run();
    expect(new Set(r.questions.map((q) => q.evidenceBasis))).toEqual(new Set(["EXACT_EXECUTED_CONTRACT", "MIXED", "OBSERVED", "UNRESOLVED"]));
    for (const q of r.questions) expect(q).toMatchObject({ status: "REQUIRES_OPERATOR_CASE", expectedDecision: "UNKNOWN", expectedOwnership: "UNKNOWN" });
    for (const q of r.questions.filter((q) => q.missingRequirements.includes("MUTATION_APPROVAL"))) expect(q.missingRequirements).toEqual(expect.arrayContaining(["VERIFIED_CLEANUP", "POST_STATE_ASSERTIONS"]));
    const report = ng2Report();
    for (const observation of report.businessInvariant!.observations) observation.outcome = "INCONCLUSIVE";
    const inventory = buildAdaptiveInventory(report, []);
    const recommendations = synthesizeAdaptiveRecommendations(report, inventory, []).filter(item=>item.category === "ATTACK_GRAPH_STATE_TRANSITION");
    expect(recommendations.length).toBeGreaterThan(0);
    const pending = synthesizeAdaptiveAuthorizationReview(ng2Origin, inventory, recommendations);
    expect(pending.questions.some(q=>q.evidenceBasis === "DECLARED_CONTRACT")).toBe(true);
    expect(pending.questions.every(q=>q.executable===false && q.expectedDecision==="UNKNOWN" && q.cleanup==="NOT_ASSESSED")).toBe(true);
  });
  it("does not collapse mixed observed and exact-response evidence into a stronger single grade", () => {
    const report=ng2Report();
    const audit=report.requestAudit!.find(item=>new URL(item.requestedUrl).pathname==="/api/public-profile")!;
    const response=report.responses.find(item=>new URL(item.requestedUrl).pathname==="/api/public-profile")!;
    audit.requestId="observed-exact-response";response.requestId=audit.requestId;
    report.requestAudit!.push({...audit,requestId:"observed-no-response"});
    const inventory=buildAdaptiveInventory(report,[]),recommendations=synthesizeAdaptiveRecommendations(report,inventory,[]).filter(item=>item.category==="API_READ_ONLY_REGRESSION"&&item.draft.pathTemplate==="/api/public-profile");
    expect(recommendations).toHaveLength(1);
    const r=synthesizeAdaptiveAuthorizationReview(ng2Origin,inventory,recommendations);
    expect(r.diagnostics).toEqual([]);expect(r.questions[0]!.evidenceBasis).toBe("MIXED");
    expect(r.questions[0]!.expectedDecision).toBe("UNKNOWN");
  });
  it("returns unresolved questions only for genuine authorization/capability purposes", () => {
    const r = run();
    const unresolved = r.questions.filter(q=>q.questionKind==="UNRESOLVED_AUTHORIZATION_BOUNDARY");
    expect(unresolved.length).toBeGreaterThan(0);
    for (const q of unresolved) { expect(q.references).toEqual({}); expect(q.evidenceBasis).toBe("UNRESOLVED"); expect(q.missingRequirements).toEqual(expect.arrayContaining(["ACTOR_FIXTURE", "OWNERSHIP_VERIFICATION", "TENANT_VERIFICATION", "EXPECTED_ALLOW_DENY", "EXACT_REQUEST_CONTRACT"])); }
    expect(run(corpus.inventory, [source("DRIFT_NEW_ROUTE")]).diagnostics[0]!.code).toBe("NO_ELIGIBLE_RELATIONSHIP");
  });
  it("preserves upstream target/source errors and sparse input indices without invented cases", () => {
    const bad = source(exact); bad.sourceFingerprint = "f".repeat(64);
    const sparse = new Array<AdaptiveRecommendation>(4); sparse[1] = source(exact); sparse[2] = bad; sparse[3] = source("DRIFT_NEW_ROUTE");
    const r = run(corpus.inventory, sparse);
    expect(r.upstreamDiagnostics).toEqual(projectAdaptiveSecurityCases(ng2Origin, corpus.inventory, sparse).diagnostics);
    expect(r.upstreamDiagnostics.map(item=>item.inputIndex)).toEqual([0,2]); expect(r.accountedCases).toBe(2);
    const inventory = structuredClone(corpus.inventory); inventory.origins.push("https://secondary.test");
    const other = synthesizeAdaptiveAuthorizationReview("https://secondary.test", inventory, [source(exact)]);
    expect(other.questions).toEqual([]); expect(other.upstreamDiagnostics).toEqual([{ inputIndex:0,code:"INVALID_TARGET" }]);
  });
  const negatives: Array<{ name:string; mutate:(inventory:AdaptiveInventory)=>void }> = [
    {name:"stale graph payload",mutate:i=>{i.attackGraph!.nodes[0]!.label="changed";}},
    {name:"duplicate node",mutate:i=>{i.attackGraph!.nodes=[...i.attackGraph!.nodes,i.attackGraph!.nodes[0]!];}},
    {name:"duplicate edge",mutate:i=>{i.attackGraph!.edges=[...i.attackGraph!.edges,i.attackGraph!.edges[0]!];}},
    {name:"dangling endpoint",mutate:i=>{i.attackGraph!.edges[0]!.to="f".repeat(64);}},
    {name:"wrong edge orientation",mutate:i=>{const e=i.attackGraph!.edges.find(e=>e.kind==="PERFORMS")!;[e.from,e.to]=[e.to,e.from];}},
    {name:"unsupported node",mutate:i=>{i.attackGraph!.nodes[0]!.kind="UNSUPPORTED" as never;}},
    {name:"unsupported edge",mutate:i=>{i.attackGraph!.edges[0]!.kind="UNSUPPORTED" as never;}},
    {name:"malformed evidence",mutate:i=>{i.attackGraph!.edges[0]!.evidence=[{producer:"Bearer private",strength:"OBSERVED",fingerprint:"f".repeat(64)}];}},
    {name:"truncated graph",mutate:i=>{i.attackGraph!.bounds.truncated=true;}},
    {name:"oversized attributes",mutate:i=>{i.attackGraph!.nodes[0]!.attributes={ label:"x".repeat(161) };}},
    {name:"oversized graph",mutate:i=>{i.attackGraph!.edges=Array(3001).fill(i.attackGraph!.edges[0]);}},
    {name:"cyclic attributes",mutate:i=>{const value:Record<string,unknown>={};value.loop=value;i.attackGraph!.nodes[0]!.attributes=value as never;}},
    {name:"deep attributes",mutate:i=>{let value:unknown="x";for(let n=0;n<80;n++)value={nested:value};i.attackGraph!.nodes[0]!.attributes={value} as never;}}
  ];
  it.each(negatives)("fails closed on $name with no raw error echo", ({mutate}) => {
    const inventory=structuredClone(corpus.inventory), recommendations=[source(exact)]; mutate(inventory);
    // Keep the old fingerprint deliberately: malformed source may fail in NG2 or NG3, both are safe.
    const r=run(inventory,recommendations); expect(r.questions).toEqual([]);
    expect(r.diagnostics.length+r.upstreamDiagnostics.length).toBe(1);
    expect(JSON.stringify([...r.diagnostics,...r.upstreamDiagnostics])).not.toMatch(/Bearer|private|changed|nested/);
  });
  it("checks typed endpoint integrity even when the graph digest is recomputed", () => {
    const inventory=structuredClone(corpus.inventory), recommendations=[source(exact)];
    const e=inventory.attackGraph!.edges.find(e=>e.kind==="PERFORMS")!; [e.from,e.to]=[e.to,e.from];
    rebind(inventory,recommendations);
    expect(run(inventory,recommendations).diagnostics).toEqual([{inputIndex:0,sourceCaseId:projectAdaptiveSecurityCases(ng2Origin,inventory,recommendations).cases[0]!.caseId,code:"INVALID_GRAPH"}]);
  });
  it("rejects stale case-bound paths and graph fingerprints through original NG2 checks", () => {
    for(const key of ["graphFingerprint","graphPathIds"]) {
      const item=source(exact),binding=item.draft.attackGraphBinding as {graphFingerprint:string;graphPathIds:string[]};
      if(key==="graphFingerprint")binding.graphFingerprint="f".repeat(64);else binding.graphPathIds=["f".repeat(64)];
      const r=run(corpus.inventory,[item]);expect(r.questions).toEqual([]);expect(r.upstreamDiagnostics).toEqual([{inputIndex:0,code:"INVALID_GRAPH_BINDING"}]);
    }
  });
  it("rejects dangling path membership despite a rebound graph digest", () => {
    const inventory=structuredClone(corpus.inventory),recommendations=[source(exact)];
    const binding=recommendations[0]!.draft.attackGraphBinding as {graphPathIds:string[]};
    const path=inventory.attackGraph!.paths.find(p=>p.id===binding.graphPathIds[0])!;
    const performed=inventory.attackGraph!.edges.find(e=>path.edgeIds.includes(e.id)&&e.kind==="PERFORMS")!;
    path.nodeIds=path.nodeIds.filter(id=>id!==performed.from);
    rebind(inventory,recommendations);
    const r=run(inventory,recommendations);expect(r.questions).toEqual([]);expect(r.diagnostics[0]!.code).toBe("INVALID_GRAPH");
  });
  it("preserves every real operation in a multi-step case instead of selecting a best operation", () => {
    const item=source("EXACT_CONTRACT_REPLAY_BUSINESS_INVARIANT"),r=run(corpus.inventory,[item]);
    const q=r.questions.filter(q=>q.questionKind==="ACTOR_OPERATION_BOUNDARY");expect(q).toHaveLength(5);expect(new Set(q.map(q=>q.references.operationNodeId)).size).toBe(5);
    expect(r.questions.every(q=>q.missingRequirements.includes("VERIFIED_CLEANUP"))).toBe(true);
  });
  it("keeps secrets and transport/configuration fields out of outputs and public ID preimages", () => {
    const canaries=["Bearer ng3-private", "eyJprivate.eyJprivate.private", "ng3-private-object", "ng3-private-tenant", "8e776563-531a-4978-a873-fd6d0867e20f", "ng3-private-query", "ng3-private-rationale"];
    const inventory=structuredClone(corpus.inventory), recommendations=structuredClone(corpus.recommendations);
    for(const q of recommendations){q.draft.operatorRationale=canaries[6];q.draft.credentialProfileId=canaries[4];}
    for(const node of inventory.attackGraph!.nodes){node.label=canaries[0]+" "+canaries[1];node.attributes={...node.attributes,privateBearer:canaries[0]!,privateJWT:canaries[1]!,privateObject:canaries[2]!,privateTenant:canaries[3]!,privateProfile:canaries[4]!,privateURL:`https://private.test/resource?secret=${canaries[5]}#private`};}
    rebind(inventory,recommendations);
    const r=run(inventory,recommendations);
    expect(r.questions).toHaveLength(33);expect(r.upstreamDiagnostics).toEqual([]);
    const f=relationshipFixture(); const focused=synthesizeAdaptiveAuthorizationReview(ng2Origin,f.inventory,f.recommendations);
    for(const q of [...r.questions,...focused.questions]) {const preimage=authorizationReviewIdentityPreimage(identity(q));for(const c of canaries){expect(JSON.stringify(q)).not.toContain(c);expect(preimage).not.toContain(c);}expect(JSON.stringify(q)).not.toMatch(/engineConfiguration|semanticKey|label|safeAlias|headers|cookies/);}
    expect(()=>authorizationReviewIdentityPreimage({...identity(r.questions[0]!),references:{actorNodeId:canaries[0]} as never})).toThrow("INVALID_AUTHORIZATION_REVIEW_IDENTITY");
  });
  it("preserves cloned inputs, upstream cases and deterministic outputs without clock/network access", () => {
    const inventory=structuredClone(corpus.inventory), recommendations=structuredClone(corpus.recommendations);
    const before=structuredClone({inventory,recommendations,upstream:projectAdaptiveSecurityCases(ng2Origin,inventory,recommendations)});
    vi.spyOn(Date,"now").mockImplementation(()=>{throw Error("clock forbidden");});
    vi.spyOn(globalThis,"fetch").mockImplementation(()=>{throw Error("network forbidden");});
    const a=run(inventory,recommendations),b=run(structuredClone(inventory),structuredClone(recommendations));
    expect(a).toEqual(b);expect({inventory,recommendations,upstream:projectAdaptiveSecurityCases(ng2Origin,inventory,recommendations)}).toEqual(before);
    expect(Date.now).not.toHaveBeenCalled();expect(fetch).not.toHaveBeenCalled();
  });
  it("does not deduplicate repeated inputs or distinct same-category source cases", () => {
    const same=source(exact); const alternatives=corpus.recommendations.filter(item=>item.category==="API_READ_ONLY_REGRESSION").slice(0,2);
    const r=run(corpus.inventory,[same,same,...alternatives]);expect(r.accountedCases).toBe(4);expect(r.diagnostics).toEqual([]);
    const one=run(corpus.inventory,[same]);expect(r.questions.slice(0,one.questions.length)).toEqual(r.questions.slice(one.questions.length,one.questions.length*2));
    expect(new Set(r.questions.map(q=>q.sourceCaseId)).size).toBe(3);
  });
  it("enforces input, relationship and total-output budgets atomically", () => {
    const item=source(exact);const over=run(corpus.inventory,Array(501).fill(item));expect(over.questions).toEqual([]);expect(over.diagnostics).toHaveLength(501);expect(over.diagnostics.every(d=>d.code==="INPUT_LIMIT")).toBe(true);
    const crowded=relationshipFixture("owner",31);const blocked=synthesizeAdaptiveAuthorizationReview(ng2Origin,crowded.inventory,crowded.recommendations);expect(blocked.questions).toEqual([]);expect(blocked.diagnostics[0]!.code).toBe("RELATIONSHIP_LIMIT");
    const many=relationshipFixture("owner",19);const all=synthesizeAdaptiveAuthorizationReview(ng2Origin,many.inventory,Array(500).fill(many.recommendations[0]!));expect(all.questions).toEqual([]);expect(all.diagnostics).toHaveLength(500);expect(all.diagnostics.every(d=>d.code==="OUTPUT_LIMIT")).toBe(true);
  });
  it("uses a separate binary-canonical identity and rejects spoofed authority or refs", () => {
    const q=run().questions[0]!, base=identity(q), preimage=authorizationReviewIdentityPreimage(base);
    expect(JSON.parse(preimage).purpose).toBe(authorizationReviewPurpose);expect(createHash("sha256").update(preimage).digest("hex")).toBe(q.questionId);
    expect(q.questionId).not.toBe(q.sourceCaseId);expect(authorizationReviewQuestionId({references:base.references,questionKind:base.questionKind,sourceCaseId:base.sourceCaseId,targetOrigin:base.targetOrigin})).toBe(q.questionId);
    for(const bad of [{...q,executable:true},{...q,executionAuthority:"HTTP"},{...q,expectedDecision:"ALLOW"},{...q,expectedOwnership:"OWNER"},{...q,sourceCaseId:"f".repeat(64)},{...q,references:{...q.references,actorNodeId:"f".repeat(64)}},{...q,secret:"Bearer private"}])expect(authorizationReviewQuestionV1Schema.safeParse(bad).success).toBe(false);
    const forged={...q,references:{...q.references,actorNodeId:"f".repeat(64)}};forged.questionId=authorizationReviewQuestionId(identity(forged));
    expect(authorizationReviewQuestionV1Schema.safeParse(forged).success).toBe(true);expect(validateAdaptiveAuthorizationReviewQuestion(forged,ng2Origin,corpus.inventory,corpus.recommendations)).toBe(false);
    expect(validateAdaptiveAuthorizationReviewQuestion(q,ng2Origin,corpus.inventory,corpus.recommendations)).toBe(true);
  });
});
