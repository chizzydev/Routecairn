import { createHash } from "node:crypto";
import { z } from "zod";
import type { AdaptiveInventory, AdaptiveRecommendation } from "./AdaptiveSynthesisCore.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { projectAdaptiveSecurityCases } from "./AdaptiveSecurityCaseProjection.js";
import { securityCaseFingerprintSchema as fp, type ProjectionDiagnostic, type SecurityCaseV1 } from "./AdaptiveSecurityCaseIR.js";
import { authorizationReviewBounds as bounds, authorizationReviewQuestionId, authorizationReviewQuestionV1Schema, type AuthorizationRequirement, type AuthorizationReviewDiagnostic, type AuthorizationReviewQuestionV1 } from "./AdaptiveAuthorizationReviewIR.js";

const evidence = z.object({ producer: z.string().regex(/^[a-z][a-z0-9-]{0,79}$/), strength: z.enum(["OBSERVED", "EXACT_RESPONSE", "EXACT_EXECUTED_CONTRACT", "DECLARED_CONTRACT"]), fingerprint: fp }).strict();
const evidences = z.array(evidence).min(1).max(6);
const nodeKinds = ["ACTOR", "ROLE", "TENANT", "OBJECT", "ROUTE", "PARAMETER", "OPERATION", "BROWSER_STATE", "CAPABILITY", "PRECONDITION", "EFFECT", "CLEANUP"] as const;
const edgeKinds = ["HAS_ROLE", "MEMBER_OF", "SCOPED_TO", "OWNS", "EXPOSES", "ACCEPTS", "PERFORMS", "TRANSITIONS_TO", "ISSUES", "CONSUMES", "REQUIRES", "PRODUCES", "EFFECTS", "CLEANED_BY", "VERIFIES", "NAVIGATES_TO"] as const;
const node = z.object({ id: fp, kind: z.enum(nodeKinds), label: z.string().max(160), semanticKey: z.string().max(500), attributes: z.record(z.union([z.string().max(160), z.number().finite(), z.boolean()])).refine((value) => Object.keys(value).length <= 30), evidence: evidences }).strict();
const edge = z.object({ id: fp, kind: z.enum(edgeKinds), from: fp, to: fp, stateChanging: z.boolean(), evidence: evidences }).strict();
const path = z.object({ id: fp, label: z.string().max(200), nodeIds: z.array(fp).min(1).max(100), edgeIds: z.array(fp).max(150), mutability: z.enum(["READ_ONLY", "STATE_CHANGING"]), automationState: z.enum(["READ_ONLY_AUTO_COMPILE_CANDIDATE", "STATE_CHANGE_PROPOSED", "EVIDENCE_ONLY"]), contractReadiness: z.enum(["COMPLETE", "REQUIRES_BINDINGS"]), engineId: z.string().max(160), sourceCaseFingerprints: z.array(fp).max(32), requiredBindings: z.array(z.string().max(160)).max(100), evidence: evidences }).strict();
const graphSchema = z.object({ schemaVersion: z.literal(1), bounds: z.object({ maxNodes: z.number().int().min(1).max(1200), maxEdges: z.number().int().min(1).max(3000), maxPaths: z.number().int().min(1).max(500), truncated: z.literal(false) }).strict(), nodes: z.array(node).max(1200), edges: z.array(edge).max(3000), paths: z.array(path).max(500), coverage: z.record(z.number().int().nonnegative()).refine((value) => Object.keys(value).length <= 16), producers: z.array(z.string().max(160)).max(100), graphFingerprint: fp }).strict();
type Graph = z.infer<typeof graphSchema>;
type Edge = z.infer<typeof edge>;
interface PathIndex { value: Graph["paths"][number]; nodes: Set<string>; edges: Set<string>; performs: Edge[] }
interface GraphIndex { fingerprint: string; nodes: Map<string, Graph["nodes"][number]>; edges: Map<string, Edge>; paths: Map<string, PathIndex>; actorRelations: Map<string, Edge[]> }
type Code = AuthorizationReviewDiagnostic["code"];
class ReviewFailure extends Error { public constructor(public readonly code: Code) { super(code); } }
function fail(code: Code): never { throw new ReviewFailure(code); }
const ordered = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const hash = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
const intersects = (a: readonly z.infer<typeof evidence>[], b: readonly z.infer<typeof evidence>[]) => a.some((left) => b.some((right) => left.fingerprint === right.fingerprint && left.producer === right.producer && left.strength === right.strength));

/** Once per call. Raw graph metadata stays internal; only validated opaque references reach questions. */
function indexGraph(value: unknown): GraphIndex {
  const parsed = graphSchema.safeParse(value);
  if (!parsed.success) fail("INVALID_GRAPH");
  const graph = parsed.data;
  if (graph.nodes.length > graph.bounds.maxNodes || graph.edges.length > graph.bounds.maxEdges || graph.paths.length > graph.bounds.maxPaths) fail("INVALID_GRAPH");
  const { graphFingerprint, ...payload } = graph;
  // Check the existing graph payload binding; this is not a new public question-ID preimage.
  if (adaptiveDigest(payload) !== graphFingerprint) fail("INVALID_GRAPH");
  const nodes = new Map(graph.nodes.map((item) => [item.id, item]));
  const edges = new Map(graph.edges.map((item) => [item.id, item]));
  if (nodes.size !== graph.nodes.length || edges.size !== graph.edges.length) fail("INVALID_GRAPH");
  const actorRelations = new Map<string, Edge[]>();
  for (const item of [...edges.values()].sort((a, b) => ordered(a.id, b.id))) {
    const from = nodes.get(item.from), to = nodes.get(item.to);
    if (!from || !to || item.id !== hash(`edge\0${item.kind}\0${item.from}\0${item.to}`)) fail("INVALID_GRAPH");
    const expected = item.kind === "PERFORMS" ? ["ACTOR", "OPERATION"] : item.kind === "HAS_ROLE" ? ["ACTOR", "ROLE"] : item.kind === "MEMBER_OF" ? ["ACTOR", "TENANT"] : item.kind === "SCOPED_TO" ? ["OBJECT", "TENANT"] : item.kind === "OWNS" ? ["ACTOR", "OBJECT", "CAPABILITY"] : undefined;
    if (expected && ((from.kind !== expected[0] && !(item.kind === "SCOPED_TO" && from.kind === "CAPABILITY")) || !expected.slice(1).includes(to.kind))) fail("INVALID_GRAPH");
    if (["HAS_ROLE", "MEMBER_OF", "OWNS"].includes(item.kind)) actorRelations.set(item.from, [...(actorRelations.get(item.from) ?? []), item]);
  }
  const paths = new Map<string, PathIndex>();
  for (const item of graph.paths) {
    const members = new Set(item.nodeIds), links = new Set(item.edgeIds);
    if (paths.has(item.id) || members.size !== item.nodeIds.length || links.size !== item.edgeIds.length || item.nodeIds.some((id) => !nodes.has(id))) fail("INVALID_GRAPH");
    const selected = item.edgeIds.map((id) => edges.get(id));
    if (selected.some((link) => !link || !members.has(link.from) || !members.has(link.to))) fail("INVALID_GRAPH");
    const semantics = { label: item.label, retainedNodes: [...item.nodeIds].sort(), mutability: item.mutability, engineId: item.engineId, sourceCaseFingerprints: [...item.sourceCaseFingerprints].sort() };
    if (item.id !== hash(`path\0${JSON.stringify(semantics)}`)) fail("INVALID_GRAPH");
    paths.set(item.id, { value: item, nodes: members, edges: links, performs: (selected as Edge[]).filter((link) => link.kind === "PERFORMS").sort((a, b) => ordered(a.id, b.id)) });
  }
  return { fingerprint: graphFingerprint, nodes, edges, paths, actorRelations };
}

function basis(links: readonly Edge[]): AuthorizationReviewQuestionV1["evidenceBasis"] {
  const strengths = new Set(links.flatMap((link) => link.evidence.map((item) => item.strength)));
  if (strengths.size !== 1) return "MIXED";
  const strength = [...strengths][0]!;
  return strength === "EXACT_RESPONSE" ? "OBSERVED" : strength;
}
function question(source: SecurityCaseV1, kind: AuthorizationReviewQuestionV1["questionKind"], references: AuthorizationReviewQuestionV1["references"], links: Edge[]): AuthorizationReviewQuestionV1 {
  const missing: AuthorizationRequirement[] = ["ACTOR_FIXTURE", "EXACT_TARGET_RESOURCE", "EXPECTED_ALLOW_DENY", "EXACT_REQUEST_CONTRACT", "AUTHORIZATION_SCOPE"];
  if (kind !== "ACTOR_OPERATION_BOUNDARY") missing.push("COMPARISON_PAIR");
  if (kind === "ROLE_BOUNDARY") missing.push("ROLE_EXPECTATION");
  if (kind === "TENANT_BOUNDARY" || kind === "UNRESOLVED_AUTHORIZATION_BOUNDARY") missing.push("TENANT_VERIFICATION");
  if (kind === "OBJECT_OWNERSHIP_BOUNDARY" || kind === "UNRESOLVED_AUTHORIZATION_BOUNDARY") missing.push("OWNERSHIP_VERIFICATION");
  if (source.safety.mutationHypothesis) missing.push("MUTATION_APPROVAL", "POST_STATE_ASSERTIONS", "VERIFIED_CLEANUP");
  const identity = { targetOrigin: source.targetOrigin, sourceCaseId: source.caseId, questionKind: kind, references };
  return authorizationReviewQuestionV1Schema.parse({ schemaVersion: 1, questionId: authorizationReviewQuestionId(identity), ...identity, evidenceBasis: links.length ? basis(links) : "UNRESOLVED", expectedDecision: "UNKNOWN", expectedOwnership: "UNKNOWN", vulnerabilityConclusion: "NOT_ASSESSED", status: "REQUIRES_OPERATOR_CASE", missingRequirements: missing.sort(), executable: false, executionAuthority: "NONE", operatorApproval: "NOT_GRANTED", cleanup: "NOT_ASSESSED" });
}
function questionsFor(source: SecurityCaseV1, graph: GraphIndex | undefined): AuthorizationReviewQuestionV1[] {
  const result: AuthorizationReviewQuestionV1[] = [];
  let considered = 0;
  const count = () => { if (++considered > bounds.relationshipsPerCase) fail("RELATIONSHIP_LIMIT"); };
  if (source.provenance.graph) {
    if (!graph || graph.fingerprint !== source.provenance.graph.fingerprint) fail("INVALID_GRAPH");
    // Path and relationship collections are sets: binary-sort once; case input order remains intact.
    for (const id of [...source.provenance.graph.pathIds].sort(ordered)) {
      const path = graph.paths.get(id);
      if (!path || path.value.engineId !== source.source.engineId) fail("INVALID_RELATIONSHIP");
      for (const performed of path.performs) {
        count();
        if (!intersects(performed.evidence, path.value.evidence)) fail("INVALID_RELATIONSHIP");
        const refs = { graphFingerprint: graph.fingerprint, graphPathId: id, actorNodeId: performed.from, operationNodeId: performed.to, relationshipEdgeIds: [performed.id] };
        result.push(question(source, "ACTOR_OPERATION_BOUNDARY", refs, [performed]));
        for (const link of graph.actorRelations.get(performed.from) ?? []) {
          if (link.kind === "OWNS" && graph.nodes.get(link.to)?.kind !== "OBJECT") continue;
          count();
          // Global relationships join only by this validated canonical actor ID. Node evidence
          // is capped by GraphBuilder and need not retain each global relationship's evidence.
          const kind = link.kind === "HAS_ROLE" ? "ROLE_BOUNDARY" : link.kind === "MEMBER_OF" ? "TENANT_BOUNDARY" : "OBJECT_OWNERSHIP_BOUNDARY";
          const extra = link.kind === "HAS_ROLE" ? { roleNodeId: link.to } : link.kind === "MEMBER_OF" ? { tenantNodeId: link.to } : { objectNodeId: link.to };
          result.push(question(source, kind, { ...refs, ...extra, relationshipEdgeIds: [performed.id, link.id].sort(ordered) }, [performed, link]));
        }
      }
    }
  }
  if (result.length > bounds.questionsPerCase) fail("RELATIONSHIP_LIMIT");
  if (!result.length && ["AUTHORIZATION", "CAPABILITY"].includes(source.proposition.kind)) return [question(source, "UNRESOLVED_AUTHORIZATION_BOUNDARY", {}, [])];
  return result;
}

export interface AdaptiveAuthorizationReviewResult { questions: AuthorizationReviewQuestionV1[]; diagnostics: AuthorizationReviewDiagnostic[]; upstreamDiagnostics: ProjectionDiagnostic[]; accountedCases: number }
/** Shadow value pipeline only. Committed NG2 source/target checks always precede synthesis. */
export function synthesizeAdaptiveAuthorizationReview(targetOrigin: string, inventory: AdaptiveInventory, recommendations: readonly AdaptiveRecommendation[]): AdaptiveAuthorizationReviewResult {
  const upstream = projectAdaptiveSecurityCases(targetOrigin, inventory, recommendations);
  const questions: AuthorizationReviewQuestionV1[] = [], diagnostics: AuthorizationReviewDiagnostic[] = [];
  const invalid = new Set(upstream.diagnostics.map((item) => item.inputIndex));
  const inputs: Array<{ inputIndex: number; source: SecurityCaseV1 }> = [];
  let next = 0;
  for (let inputIndex = 0; inputIndex < recommendations.length; inputIndex++) if (!invalid.has(inputIndex)) inputs.push({ inputIndex, source: upstream.cases[next++]! });
  let graph: GraphIndex | undefined, failure: Code | undefined;
  if (recommendations.length > bounds.cases) failure = "INPUT_LIMIT";
  else if (inputs.length && inventory.attackGraph !== undefined) {
    try { graph = indexGraph(inventory.attackGraph); } catch { failure = "INVALID_GRAPH"; }
  }
  for (const { inputIndex, source } of inputs) {
    try {
      if (failure) fail(failure);
      const values = questionsFor(source, graph);
      if (!values.length) diagnostics.push({ inputIndex, sourceCaseId: source.caseId, code: "NO_ELIGIBLE_RELATIONSHIP" });
      else questions.push(...values);
    } catch (error) { diagnostics.push({ inputIndex, sourceCaseId: source.caseId, code: error instanceof ReviewFailure ? error.code : "INVALID_QUESTION" }); }
  }
  if (questions.length > bounds.totalQuestions) {
    questions.length = 0; diagnostics.length = 0;
    for (const { inputIndex, source } of inputs) diagnostics.push({ inputIndex, sourceCaseId: source.caseId, code: "OUTPUT_LIMIT" });
  }
  return { questions, diagnostics, upstreamDiagnostics: upstream.diagnostics, accountedCases: upstream.cases.length };
}

/** Context validation, not authorization: a shape-valid forged ref/case must match fresh NG2->NG3 derivation. */
export function validateAdaptiveAuthorizationReviewQuestion(input: unknown, targetOrigin: string, inventory: AdaptiveInventory, recommendations: readonly AdaptiveRecommendation[]): boolean {
  const parsed = authorizationReviewQuestionV1Schema.safeParse(input);
  if (!parsed.success) return false;
  const result = synthesizeAdaptiveAuthorizationReview(targetOrigin, inventory, recommendations);
  const expected = result.questions.find((item) => item.questionId === parsed.data.questionId);
  return expected !== undefined && JSON.stringify(expected) === JSON.stringify(parsed.data);
}
