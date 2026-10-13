import { createHash } from "node:crypto";
import type { AdaptiveAttackPath } from "./AdaptiveAttackStateGraph.js";
import type { AdaptiveInventory, AdaptiveRecommendation } from "./AdaptiveSynthesisCore.js";
import { adaptiveDigest, adaptiveExecutionFingerprint } from "./AdaptiveCanonical.js";
import {
  securityCaseBounds, securityCaseFingerprintSchema, securityCaseOriginSchema, securityCaseSourceSchema, securityCaseSubjectSchema,
  securityCaseReadinessSchema, securityCaseIdV1, securityCaseV1Schema,
  type ProjectionDiagnostic, type SecurityCaseV1
} from "./AdaptiveSecurityCaseIR.js";

type Code = ProjectionDiagnostic["code"];
class ProjectionFailure extends Error { public constructor(public readonly code: Code) { super(code); } }
function fail(code: Code): never { throw new ProjectionFailure(code); }
function record(value: unknown): Record<string, unknown> | undefined { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function fingerprint(value: unknown): string { const result = securityCaseFingerprintSchema.safeParse(value); return result.success ? result.data : fail("INVALID_PROVENANCE"); }
function fingerprintList(value: unknown, allowEmpty = false): string[] {
  if (!Array.isArray(value) || (!allowEmpty && !value.length) || value.length > securityCaseBounds.sourceCases) fail("INVALID_PROVENANCE");
  return value.map(fingerprint);
}
function bindingList(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > securityCaseBounds.bindings || value.some((item) => typeof item !== "string" || !item.length || item.length > 500)) fail("INVALID_BOUNDS");
  return value as string[];
}
const bindingNames: Readonly<Record<string, SecurityCaseV1["unresolvedBindings"][number]>> = Object.freeze({
  "disposable actor": "DISPOSABLE_ACTOR", "exact actor": "ACTOR_BINDING", "exact assertions": "EXACT_ASSERTIONS", "expiring authorization": "EXPIRING_AUTHORIZATION", "verified cleanup": "VERIFIED_CLEANUP", "cleanup": "CLEANUP_BINDING", "cleanup for writes": "CLEANUP_BINDING", "verified cleanup evidence": "VERIFIED_CLEANUP", "cleanup transition": "CLEANUP_BINDING", "cleanup transition or disposable fixture proof": "CLEANUP_OR_DISPOSABLE_PROOF",
  "single-use token/fixture binding": "TOKEN_FIXTURE", "bounded wait contract": "BOUNDED_WAIT", "Account A/B object identities": "ACTOR_OBJECT_IDENTITIES", "Account A/B and tenant identities": "ACTOR_TENANT_IDENTITIES", "exact object bindings": "OBJECT_IDENTITIES", "expected decisions": "EXPECTED_DECISIONS", "response field rules": "RESPONSE_FIELD_RULES", "sensitive columns": "SENSITIVE_COLUMNS",
  "pre-state": "PRE_STATE", "bounded action sequence": "BOUNDED_ACTIONS", "expected invariant": "EXPECTED_INVARIANT", "authoritative post-state": "POST_STATE", "resource owner": "RESOURCE_OWNER", "tenant": "TENANT_BINDING", "expiry": "EXPIRY", "tamper/replay assertions": "TAMPER_REPLAY_ASSERTIONS", "endpoint kind": "ENDPOINT_KIND", "authorized actor": "AUTHORIZED_ACTOR", "signature/auth expectation": "AUTH_EXPECTATION", "replay/workload bounds": "WORKLOAD_BOUNDS",
  "test-provider fixture": "TEST_PROVIDER_FIXTURE", "synthetic event": "SYNTHETIC_EVENT", "account ownership": "ACCOUNT_OWNERSHIP", "authoritative entitlement verification": "ENTITLEMENT_VERIFICATION", "named operation": "NAMED_OPERATION", "actor matrix": "ACTOR_MATRIX", "field expectations": "FIELD_EXPECTATIONS", "tenant expectation": "TENANT_EXPECTATION", "compiler-valid exact execution contract": "EXACT_EXECUTION_CONTRACT", "explicit operator review": "OPERATOR_REVIEW", "operator review": "OPERATOR_REVIEW", "exact regression case": "EXACT_REGRESSION_CASE", "authoritative expected outcome": "AUTHORITATIVE_OUTCOME",
  "conclusive executed contract": "CONCLUSIVE_EVIDENCE", "conclusive executed response contract": "CONCLUSIVE_EVIDENCE", "exact anonymous response contract": "ANONYMOUS_RESPONSE_CONTRACT", "exact response contract": "RESPONSE_CONTRACT", "exact precondition": "EXACT_PRECONDITION", "precondition": "EXACT_PRECONDITION", "authoritative effect verification": "VERIFIED_EFFECT", "expected effect": "EXPECTED_EFFECT", "complete bounded graph path": "COMPLETE_GRAPH_PATH"
});
function bindingName(value: string): SecurityCaseV1["unresolvedBindings"][number] {
  if (Object.prototype.hasOwnProperty.call(bindingNames, value)) return bindingNames[value]!;
  if (/^(?:prior producer for capture |producer for capture |unique capture producer )/.test(value)) return "CAPTURE_PRODUCER";
  return "UNCLASSIFIED_BINDING";
}

const publicActorNodeId = createHash("sha256").update("node\0ACTOR\0actor:public").digest("hex");
/** Scan-origin evidence is an internal NG1 attribution witness, not external authenticity proof. */
function isPrimaryTarget(origin: string, inventory: AdaptiveInventory): boolean {
  if (![1, 2].includes(inventory.schemaVersion) || !Array.isArray(inventory.origins) || !inventory.origins.includes(origin) || inventory.origins.some((value) => !securityCaseOriginSchema.safeParse(value).success)) return false;
  if (inventory.attackGraph === undefined) return inventory.schemaVersion === 1 && new Set(inventory.origins).size === 1;
  const graph = record(inventory.attackGraph);
  if (!graph || graph.schemaVersion !== 1 || !Array.isArray(graph.nodes) || graph.nodes.length > 1200) return false;
  const anchors = graph.nodes.map(record).filter((node) => node?.semanticKey === "actor:public" || node?.id === publicActorNodeId);
  if (anchors.length !== 1) return false;
  const actor = anchors[0]!;
  if (actor.kind !== "ACTOR" || actor.semanticKey !== "actor:public" || actor.id !== publicActorNodeId || !Array.isArray(actor.evidence) || actor.evidence.length > 6) return false;
  const witnesses = actor.evidence.map(record).filter((entry) => entry?.producer === "scan");
  if (witnesses.length !== 1) return false;
  const witness = witnesses[0]!;
  if (Object.keys(witness).some((key) => !["producer", "fingerprint", "strength"].includes(key)) || witness.strength !== "OBSERVED" || !securityCaseFingerprintSchema.safeParse(witness.fingerprint).success) return false;
  // Preserve GraphBuilder.evidence's original locale-sorted canonical digest exactly.
  return witness.fingerprint === adaptiveDigest({ producer: "scan", semantics: { target: origin }, strength: "OBSERVED" });
}

/** Metadata inspection only. No request configuration, credential lookup or execution permission is returned. */
export function projectAdaptiveSecurityCases(targetOrigin: string, inventory: AdaptiveInventory, recommendations: readonly AdaptiveRecommendation[]): { cases: SecurityCaseV1[]; diagnostics: ProjectionDiagnostic[] } {
  const cases: SecurityCaseV1[] = [];
  const diagnostics: ProjectionDiagnostic[] = [];
  let origin: string | undefined;
  let primaryTarget = false;
  try {
    if (typeof targetOrigin === "string" && targetOrigin.length <= 2048) {
      const url = new URL(targetOrigin);
      if (["http:", "https:"].includes(url.protocol) && !url.username && !url.password && url.origin.length <= 300) origin = url.origin;
      if (origin) primaryTarget = isPrimaryTarget(origin, inventory);
    }
  } catch { /* invalid target is diagnosed separately for each source */ }
  for (let inputIndex = 0; inputIndex < recommendations.length; inputIndex++) {
    try {
      if (!origin || !primaryTarget) fail("INVALID_TARGET");
      const recommendation = recommendations[inputIndex];
      if (!recommendation) fail("INVALID_SOURCE");
      cases.push(projectOne(origin, inventory, recommendation));
    } catch (error) {
      // Never expose parser messages, source labels, URLs or a failed hash preimage.
      diagnostics.push({ inputIndex, code: error instanceof ProjectionFailure ? error.code : "INVALID_CASE" });
    }
  }
  return { cases, diagnostics };
}

function projectOne(origin: string, inventory: AdaptiveInventory, recommendation: AdaptiveRecommendation): SecurityCaseV1 {
  const item = record(recommendation);
  if (!item || typeof item.mutationHypothesis !== "boolean" || typeof item.operatorApprovalRequired !== "boolean") fail("INVALID_SOURCE");
  const parsedSource = securityCaseSourceSchema.safeParse({ category: item.category, engineId: item.engineId, laneKind: item.laneKind, sourceFingerprint: item.sourceFingerprint });
  if (!parsedSource.success) fail("INVALID_SOURCE");
  const source = parsedSource.data;
  const draft = record(item.draft);
  const automation = record(draft?.automation);
  if (!draft || !automation) fail("INVALID_READINESS");
  const requiredBindings = bindingList(item.requiredBindings);
  const readiness = projectReadiness(draft, automation, item.mutationHypothesis, item.operatorApprovalRequired, requiredBindings);
  if (readiness.kind !== "REQUIRES_BINDINGS") {
    // The legacy digest proves internal consistency only, never publisher authenticity or approval.
    if (configurationAuthentication(draft.engineConfiguration) !== automation.authentication) fail("INVALID_READINESS");
    if (adaptiveExecutionFingerprint(source.engineId, source.sourceFingerprint, readiness.evidenceFingerprint, draft.engineConfiguration, readiness.compilerVersion) !== draft.executionFingerprint) fail("INVALID_PROVENANCE");
  }
  const paths = boundPaths(inventory, draft, item.mutationHypothesis);
  if (readiness.kind !== "REQUIRES_BINDINGS" && paths.some((path) => path.contractReadiness !== "COMPLETE")) fail("INVALID_GRAPH_BINDING");

  let sourceCases: string[] | undefined;
  if (draft.sourceCaseFingerprints !== undefined) {
    sourceCases = fingerprintList(draft.sourceCaseFingerprints);
    const observed = new Set((inventory.workflowCases ?? []).map((entry) => entry.fingerprint));
    const bound = new Set(paths.flatMap((path) => path.sourceCaseFingerprints));
    if (sourceCases.some((id) => !observed.has(id) && !bound.has(id))) fail("INVALID_PROVENANCE");
    if (draft.exactExecutedContract === true && (paths.length === 0 || sourceCases.some((id) => !bound.has(id)) || paths.some((path) => path.engineId !== source.engineId))) fail("INVALID_PROVENANCE");
  } else {
    const fromPaths = paths.flatMap((path) => path.sourceCaseFingerprints);
    if (fromPaths.length) sourceCases = fingerprintList(fromPaths);
  }
  if (readiness.kind !== "REQUIRES_BINDINGS" && readiness.compilerVersion === 2 && (draft.exactExecutedContract !== true || !sourceCases?.length)) fail("INVALID_PROVENANCE");
  if (readiness.kind === "REQUIRES_BINDINGS" && draft.exactExecutedContract === true) fail("INVALID_READINESS");
  const proposition = purpose(source.category, source.engineId);
  const subject = projectSubject(origin, inventory, draft, proposition, sourceCases, paths, source, readiness);
  if (readiness.kind !== "REQUIRES_BINDINGS" && readiness.compilerVersion === 1 && subject.kind === "ROUTE" && subject.protocol !== "GRAPHQL" && subject.methods?.some((method) => !["GET", "HEAD", "OPTIONS"].includes(method))) fail("INVALID_READINESS");
  const actors: SecurityCaseV1["actors"] = readiness.kind === "REQUIRES_BINDINGS" ? "UNKNOWN" : automation.authentication === "public" ? "ANONYMOUS" : automation.authentication === "primary" ? "PRIMARY_FIXTURE_REQUIRED" : "ACCOUNT_PAIR_REQUIRED";
  const graph = paths.length ? { fingerprint: inventory.attackGraph!.graphFingerprint, pathIds: paths.map((path) => path.id) } : undefined;
  const observation: SecurityCaseV1["observation"] = readiness.kind !== "REQUIRES_BINDINGS"
    ? { kind: "EXACT_COMPILER_EVIDENCE", evidenceStrength: readiness.evidenceStrength, vulnerabilityConclusion: "NOT_ASSESSED" }
    : { kind: uncompiledObservation(source.category, source.sourceFingerprint, draft, item.mutationHypothesis), vulnerabilityConclusion: "NOT_ASSESSED" };
  const identity = { targetOrigin: origin, source, subject };
  const result = securityCaseV1Schema.safeParse({
    schemaVersion: 1, caseId: securityCaseIdV1(identity), targetOrigin: origin, source, proposition: { kind: proposition }, subject, actors, observation,
    provenance: { sourceFingerprint: source.sourceFingerprint, ...(readiness.kind !== "REQUIRES_BINDINGS" ? { evidenceFingerprint: readiness.evidenceFingerprint } : {}), ...(graph ? { graph } : {}), ...(sourceCases ? { sourceCaseFingerprints: sourceCases } : {}) },
    readiness, safety: { mutationHypothesis: item.mutationHypothesis, operatorApprovalRequired: item.operatorApprovalRequired, executionAuthority: "NONE", approval: "NOT_GRANTED", cleanup: "NOT_ASSESSED" },
    executable: false, unresolvedBindings: requiredBindings.map(bindingName)
  });
  return result.success ? result.data : fail("INVALID_CASE");
}

function projectReadiness(draft: Record<string, unknown>, automation: Record<string, unknown>, mutation: boolean, approval: boolean, bindings: string[]): SecurityCaseV1["readiness"] {
  const allowed = new Set(["state", "compilerVersion", "mutationApprovalRequired", "unresolvedBindings", "evidenceStrength", "evidenceFingerprint", "requestCount", "cleanupRequestCount", "authentication", "summary"]);
  if (Object.keys(automation).some((key) => !allowed.has(key)) || automation.mutationApprovalRequired !== mutation || (draft.state !== undefined && draft.state !== "DRAFT_REQUIRES_OPERATOR_CASE")) fail("INVALID_READINESS");
  if (draft.exactExecutedContract !== undefined && typeof draft.exactExecutedContract !== "boolean") fail("INVALID_READINESS");
  if (automation.state === "REQUIRES_BINDINGS") {
    if (draft.executable !== undefined && draft.executable !== false) fail("INVALID_READINESS");
    if (!approval || automation.compilerVersion !== 1 || ["evidenceStrength", "evidenceFingerprint", "requestCount", "cleanupRequestCount", "authentication"].some((key) => automation[key] !== undefined) || draft.engineConfiguration !== undefined || draft.executionFingerprint !== undefined) fail("INVALID_READINESS");
    const unresolved = bindingList(automation.unresolvedBindings);
    if (unresolved.length !== bindings.length || unresolved.some((name, index) => name !== bindings[index])) fail("INVALID_READINESS");
    return { kind: "REQUIRES_BINDINGS", metadataOnly: true, compilerVersion: 1 };
  }
  if (!["READY_READ_ONLY", "READY_APPROVAL_GATED"].includes(String(automation.state)) || draft.executable !== true || !record(draft.engineConfiguration) || !securityCaseFingerprintSchema.safeParse(draft.executionFingerprint).success || bindings.length || automation.unresolvedBindings !== undefined) fail("INVALID_READINESS");
  if (!["public", "primary", "account-pair"].includes(String(automation.authentication))) fail("INVALID_READINESS");
  const parsed = securityCaseReadinessSchema.safeParse({ kind: automation.state, metadataOnly: true, compilerVersion: automation.compilerVersion, evidenceStrength: automation.evidenceStrength, evidenceFingerprint: automation.evidenceFingerprint, requestCount: automation.requestCount, cleanupRequestCount: automation.cleanupRequestCount });
  if (!parsed.success || parsed.data.kind === "REQUIRES_BINDINGS") fail("INVALID_READINESS");
  const value = parsed.data;
  const gated = value.kind === "READY_APPROVAL_GATED";
  if (mutation !== gated || approval !== gated || value.cleanupRequestCount > value.requestCount || (!gated && value.cleanupRequestCount !== 0)) fail("INVALID_READINESS");
  if (value.compilerVersion === 1 && (value.evidenceStrength === "EXACT_EXECUTED_CONTRACT" || automation.authentication !== "public" || draft.exactExecutedContract === true)) fail("INVALID_READINESS");
  if (value.compilerVersion === 2 && value.evidenceStrength !== "EXACT_EXECUTED_CONTRACT") fail("INVALID_READINESS");
  return value;
}

function boundPaths(inventory: AdaptiveInventory, draft: Record<string, unknown>, mutation: boolean): AdaptiveAttackPath[] {
  if (draft.attackGraphBinding === undefined) {
    if (draft.graphPathId !== undefined) fail("INVALID_GRAPH_BINDING");
    return [];
  }
  const binding = record(draft.attackGraphBinding);
  const graph = inventory.attackGraph;
  if (!binding || Object.keys(binding).some((key) => !["graphFingerprint", "graphPathIds"].includes(key)) || !graph || !securityCaseFingerprintSchema.safeParse(binding.graphFingerprint).success || binding.graphFingerprint !== graph.graphFingerprint) fail("INVALID_GRAPH_BINDING");
  const ids = binding.graphPathIds;
  if (!Array.isArray(ids) || !ids.length || ids.length > securityCaseBounds.graphPaths || ids.some((id) => !securityCaseFingerprintSchema.safeParse(id).success) || new Set(ids).size !== ids.length) fail("INVALID_GRAPH_BINDING");
  const limits = graph.bounds;
  if (graph.schemaVersion !== 1 || !limits || !Number.isInteger(limits.maxPaths) || limits.maxPaths < 1 || limits.maxPaths > 500 || !Number.isInteger(limits.maxNodes) || limits.maxNodes < 1 || limits.maxNodes > 1200 || !Number.isInteger(limits.maxEdges) || limits.maxEdges < 1 || limits.maxEdges > 3000 || !Array.isArray(graph.paths) || graph.paths.length > limits.maxPaths || !Array.isArray(graph.nodes) || graph.nodes.length > limits.maxNodes || !Array.isArray(graph.edges) || graph.edges.length > limits.maxEdges) fail("INVALID_GRAPH_BINDING");
  if (graph.paths.some((path) => !securityCaseFingerprintSchema.safeParse(path?.id).success) || new Set(graph.paths.map((path) => path.id)).size !== graph.paths.length) fail("INVALID_GRAPH_BINDING");
  return ids.map((id) => {
    const path = graph.paths.find((entry) => entry.id === id);
    if (!path || !["READ_ONLY", "STATE_CHANGING"].includes(path.mutability) || (path.mutability === "STATE_CHANGING") !== mutation || !["COMPLETE", "REQUIRES_BINDINGS"].includes(path.contractReadiness) || !Array.isArray(path.nodeIds) || path.nodeIds.length > 100 || !Array.isArray(path.edgeIds) || path.edgeIds.length > 150) fail("INVALID_GRAPH_BINDING");
    fingerprintList(path.sourceCaseFingerprints, true);
    return path;
  });
}

function projectSubject(origin: string, inventory: AdaptiveInventory, draft: Record<string, unknown>, proposition: SecurityCaseV1["proposition"]["kind"], sourceCases: string[] | undefined, paths: AdaptiveAttackPath[], source: SecurityCaseV1["source"], readiness: SecurityCaseV1["readiness"]): SecurityCaseV1["subject"] {
  if (draft.exactExecutedContract === true) return sourceCases?.length ? { kind: "EXACT_SOURCE_CONTRACT", sourceCaseFingerprints: sourceCases } : fail("INVALID_PROVENANCE");
  if (draft.graphPathId !== undefined) {
    const path = paths.find((entry) => entry.id === draft.graphPathId);
    return path ? { kind: "GRAPH_PATH", pathId: path.id, mutability: path.mutability } : fail("INVALID_GRAPH_BINDING");
  }
  if (draft.pathTemplate === undefined) return { kind: "UNRESOLVED", reason: proposition === "DRIFT" ? "DRIFT_REVIEW" : "NO_SUBJECT_EVIDENCE" };
  const methods = draft.documentedMethods !== undefined ? draft.documentedMethods : draft.method !== undefined ? [draft.method] : undefined;
  const parsed = securityCaseSubjectSchema.safeParse({ kind: "ROUTE", pathTemplate: draft.pathTemplate, ...(draft.protocol !== undefined ? { protocol: draft.protocol } : {}), ...(methods !== undefined ? { methods } : {}) });
  if (!parsed.success || parsed.data.kind !== "ROUTE") fail("INVALID_SUBJECT");
  const subject = parsed.data;
  const matches = (inventory.routes ?? []).filter((route) => route.pathTemplate === subject.pathTemplate && (!subject.protocol || route.protocol === subject.protocol) && (!subject.methods || subject.methods.includes(route.method as NonNullable<typeof subject.methods>[number])));
  if (!matches.length) fail("INVALID_SUBJECT");
  if (!matches.some((route) => route.origin === origin)) {
    if (inventory.schemaVersion === 1 && matches.some((route) => route.origin === undefined)) return { kind: "UNRESOLVED", reason: "ROUTE_ORIGIN_UNKNOWN" };
    fail("INVALID_SUBJECT");
  }
  if (subject.methods?.some((method) => !matches.some((route) => route.origin === origin && route.method === method))) fail("INVALID_SUBJECT");
  if (readiness.kind !== "REQUIRES_BINDINGS") {
    if (readiness.compilerVersion === 1 && subject.protocol !== "GRAPHQL" && subject.methods?.some((method) => !["GET", "HEAD", "OPTIONS"].includes(method))) fail("INVALID_READINESS");
    if (!groundReadyRoute(origin, inventory, draft, subject, source, paths)) return { kind: "UNRESOLVED", reason: "NO_SUBJECT_EVIDENCE" };
  }
  return subject;
}

/** Same slot precedence as the committed exact compiler; bounded inspection, no credential resolution. */
function configurationAuthentication(configuration: unknown): "public" | "primary" | "account-pair" {
  const slots = new Set<string>();
  let visited = 0;
  const ancestors = new Set<object>();
  const walk = (value: unknown, depth: number): void => {
    if (++visited > 100_000 || depth > 64) fail("INVALID_BOUNDS");
    if (!value || typeof value !== "object") return;
    if (ancestors.has(value)) fail("INVALID_READINESS");
    ancestors.add(value);
    if (Array.isArray(value)) value.forEach((child) => walk(child, depth + 1));
    else {
      const item = record(value)!;
      for (const key of ["authSlot", "secretSource"]) {
        if (item[key] !== undefined) {
          if (typeof item[key] !== "string" || !["anonymous", "primary", "account_a", "account_b"].includes(item[key])) fail("INVALID_READINESS");
          slots.add(item[key]);
        }
      }
      if (typeof item.actor === "string") slots.add(item.actor === "ACCOUNT_A" ? "account_a" : item.actor === "ACCOUNT_B" ? "account_b" : item.actor === "SERVICE_ROLE" ? "primary" : "anonymous");
      Object.values(item).forEach((child) => walk(child, depth + 1));
    }
    ancestors.delete(value);
  };
  walk(configuration, 0);
  return slots.has("account_a") || slots.has("account_b") ? "account-pair" : slots.has("primary") ? "primary" : "public";
}

type RouteSubject = Extract<SecurityCaseV1["subject"], { kind: "ROUTE" }>;
function rows(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value) || value.length > securityCaseBounds.requests || value.some((item) => !record(item))) fail("INVALID_SUBJECT");
  return value as Record<string, unknown>[];
}

/** Verify a declared subject, never infer a different route from a compatible method. */
function groundReadyRoute(origin: string, inventory: AdaptiveInventory, draft: Record<string, unknown>, subject: RouteSubject, source: SecurityCaseV1["source"], paths: AdaptiveAttackPath[]): boolean {
  const configuration = record(draft.engineConfiguration)!;
  const operations: Array<{ method: string; protocol: string }> = [];
  const checkRequest = (rawUrl: unknown, method: unknown, protocol: unknown): void => {
    if (typeof rawUrl !== "string" || rawUrl.length > 4096 || typeof method !== "string" || !["REST", "GRAPHQL"].includes(String(protocol))) fail("INVALID_SUBJECT");
    let url: URL;
    try { url = new URL(rawUrl); } catch { return fail("INVALID_SUBJECT"); }
    if (url.origin !== origin || url.pathname !== subject.pathTemplate || (subject.protocol && protocol !== subject.protocol) || (subject.methods && !subject.methods.includes(method as NonNullable<RouteSubject["methods"]>[number]))) fail("INVALID_SUBJECT");
    operations.push({ method, protocol: String(protocol) });
  };
  if (source.engineId === "api-graphql-authorization") {
    const routes = rows(configuration.routes);
    for (const check of rows(configuration.checks)) {
      const selected = routes.filter((route) => route.id === check.routeId);
      if (selected.length !== 1) fail("INVALID_SUBJECT");
      const route = selected[0]!;
      if (route.pathTemplate !== subject.pathTemplate) fail("INVALID_SUBJECT");
      checkRequest(route.url, record(check.request)?.method ?? (check.kind === "GRAPHQL_INTROSPECTION" ? "POST" : undefined), route.protocol);
    }
  } else if (["operational-endpoint-security", "billing-entitlement-security", "business-invariant"].includes(source.engineId)) {
    for (const item of rows(configuration.cases)) {
      const steps = source.engineId === "business-invariant" ? [...rows(item.preState), ...rows(item.actions), ...rows(item.postState), ...rows(item.cleanup), ...rows(item.cleanupVerification)] : rows(item.steps);
      for (const step of steps) {
        const request = record(step.request);
        if (!request) fail("INVALID_SUBJECT");
        if (source.engineId !== "business-invariant") {
          const endpoints = rows(configuration.endpoints).filter((endpoint) => endpoint.id === step.endpointId);
          if (endpoints.length !== 1 || endpoints[0]!.pathTemplate !== subject.pathTemplate) fail("INVALID_SUBJECT");
        }
        checkRequest(request.url ?? request.urlTemplate, request.method, "REST");
      }
    }
  } else return false;
  if (!operations.length || subject.methods?.some((method) => !operations.some((operation) => operation.method === method))) fail("INVALID_SUBJECT");
  for (const path of paths) {
    const nodes = inventory.attackGraph!.nodes.filter((node) => path.nodeIds.includes(node.id) && node.kind === "OPERATION");
    if (!nodes.length || nodes.some((node) => node.attributes.pathTemplate !== subject.pathTemplate || (node.attributes.origin !== undefined && node.attributes.origin !== origin) || !operations.some((operation) => operation.method === node.attributes.method && operation.protocol === node.attributes.protocol))) fail("INVALID_GRAPH_BINDING");
  }
  const graphPathIds = paths.map((path) => path.id);
  const digest = (evidence: unknown): string => adaptiveDigest(graphPathIds.length ? { evidence, graphPathIds } : evidence);
  const matches = inventory.routes.filter((route) => route.pathTemplate === subject.pathTemplate && (!route.origin || route.origin === origin));
  if (source.category === "API_READ_ONLY_REGRESSION" || (source.category === "GRAPHQL_INTROSPECTION_READ_ONLY" && draft.documentedMethods !== undefined)) {
    if (!matches.some((route) => operations.some((operation) => operation.method === route.method && operation.protocol === route.protocol) && digest(route) === source.sourceFingerprint)) fail("INVALID_PROVENANCE");
  } else if (source.category === "GRAPHQL_INTROSPECTION_READ_ONLY" && draft.operation === "GENERATED_INTROSPECTION") {
    if (digest({ protocol: "GRAPHQL", path: subject.pathTemplate, kind: "generated-introspection" }) !== source.sourceFingerprint) fail("INVALID_PROVENANCE");
  } else if (source.category === "BUSINESS_INVARIANT_READ_ONLY") {
    const key = draft.sourceCandidateId === undefined ? "pathTemplate" : "path";
    if (!operations.some(({ method }) => digest({ method, [key]: subject.pathTemplate, kind: "stable-observation" }) === source.sourceFingerprint)) fail("INVALID_PROVENANCE");
  } else if (["OPERATIONAL_HEALTH_READ_ONLY", "SYNTHETIC_BILLING_READ_ONLY"].includes(source.category) && draft.sourceCandidateId === undefined) {
    if (!operations.some(({ method }) => digest({ method, pathTemplate: subject.pathTemplate }) === source.sourceFingerprint)) fail("INVALID_PROVENANCE");
  } else return false; // Browser field preimages and unknown families are not recoverable from this API.
  return true;
}

function purpose(category: string, engine: string): SecurityCaseV1["proposition"]["kind"] {
  // This labels review purpose only; it never supplies actors, assertions or execution authority.
  if (category.startsWith("DRIFT_")) return "DRIFT";
  if (category === "ATTACK_GRAPH_STATE_TRANSITION") return "GRAPH_TRANSITION";
  const kinds: Readonly<Record<string, SecurityCaseV1["proposition"]["kind"]>> = { "api-graphql-authorization": "AUTHORIZATION", "supabase-authorization": "AUTHORIZATION", "authentication-lifecycle": "LIFECYCLE", "authentication-lifecycle-automation": "LIFECYCLE", "link-portal-export-security": "CAPABILITY", "business-invariant": "BUSINESS_INVARIANT", "billing-entitlement-security": "BILLING", "operational-endpoint-security": "OPERATIONAL" };
  return Object.prototype.hasOwnProperty.call(kinds, engine) ? kinds[engine]! : "OTHER";
}

function uncompiledObservation(category: string, sourceFingerprint: string, draft: Record<string, unknown>, mutation: boolean): "OBSERVED" | "DECLARED" | "HYPOTHESIZED" {
  if (category.startsWith("DRIFT_") && draft.semanticKey !== undefined && draft.safeSummary !== undefined) {
    if (typeof draft.semanticKey !== "string" || draft.semanticKey.length > 1000 || typeof draft.safeSummary !== "string" || draft.safeSummary.length > 500) fail("INVALID_BOUNDS");
    // NG1 synthesizes drift recommendations only from HIGH entries. Verify that actual source value;
    // the category alone labels purpose and cannot establish an observation.
    const source = { type: category.slice(6), severity: "HIGH", semanticKey: draft.semanticKey, summary: draft.safeSummary };
    if (adaptiveDigest(source) !== sourceFingerprint) fail("INVALID_PROVENANCE");
    return "OBSERVED";
  }
  return mutation ? "HYPOTHESIZED" : "DECLARED";
}
