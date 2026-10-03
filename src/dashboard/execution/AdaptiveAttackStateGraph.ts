import { createHash } from "node:crypto";
import { adaptiveCredentialHeaderNames, adaptiveHttpUrl, adaptiveRequestIdentity, createAdaptiveResponseMatcher, isAnonymousAdaptiveRequest, isConclusiveAdaptiveOutcome, isVerifiedAdaptiveCleanup, isReadOnlyAdaptiveApiOperation } from "./AdaptiveEvidenceSafety.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";

export type AdaptiveAttackNodeKind = "ACTOR" | "ROLE" | "TENANT" | "OBJECT" | "ROUTE" | "PARAMETER" | "OPERATION" | "BROWSER_STATE" | "CAPABILITY" | "PRECONDITION" | "EFFECT" | "CLEANUP";
export type AdaptiveAttackEdgeKind = "HAS_ROLE" | "MEMBER_OF" | "SCOPED_TO" | "OWNS" | "EXPOSES" | "ACCEPTS" | "PERFORMS" | "TRANSITIONS_TO" | "ISSUES" | "CONSUMES" | "REQUIRES" | "PRODUCES" | "EFFECTS" | "CLEANED_BY" | "VERIFIES" | "NAVIGATES_TO";

export interface AdaptiveGraphEvidence {
  producer: string;
  fingerprint: string;
  strength: "OBSERVED" | "EXACT_RESPONSE" | "EXACT_EXECUTED_CONTRACT" | "DECLARED_CONTRACT";
}

export interface AdaptiveAttackNode {
  id: string;
  kind: AdaptiveAttackNodeKind;
  label: string;
  semanticKey: string;
  attributes: Readonly<Record<string, string | number | boolean>>;
  evidence: readonly AdaptiveGraphEvidence[];
}

export interface AdaptiveAttackEdge {
  id: string;
  kind: AdaptiveAttackEdgeKind;
  from: string;
  to: string;
  stateChanging: boolean;
  evidence: readonly AdaptiveGraphEvidence[];
}

export interface AdaptiveAttackPath {
  id: string;
  label: string;
  nodeIds: readonly string[];
  edgeIds: readonly string[];
  mutability: "READ_ONLY" | "STATE_CHANGING";
  automationState: "READ_ONLY_AUTO_COMPILE_CANDIDATE" | "STATE_CHANGE_PROPOSED" | "EVIDENCE_ONLY";
  contractReadiness: "COMPLETE" | "REQUIRES_BINDINGS";
  engineId: string;
  sourceCaseFingerprints: readonly string[];
  requiredBindings: readonly string[];
  evidence: readonly AdaptiveGraphEvidence[];
}

export interface AdaptiveAttackStateGraph {
  schemaVersion: 1;
  bounds: { maxNodes: number; maxEdges: number; maxPaths: number; truncated: boolean };
  nodes: readonly AdaptiveAttackNode[];
  edges: readonly AdaptiveAttackEdge[];
  paths: readonly AdaptiveAttackPath[];
  coverage: Record<AdaptiveAttackNodeKind | "EDGES" | "PATHS" | "READ_ONLY_PATHS" | "STATE_CHANGING_PATHS", number>;
  producers: readonly string[];
  graphFingerprint: string;
}

const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);


export function buildAdaptiveAttackStateGraph(report: RouteCairnReport): AdaptiveAttackStateGraph {
  const graph = new GraphBuilder();
  const credentialHeaderNames = adaptiveCredentialHeaderNames(report);
  const matchResponse = createAdaptiveResponseMatcher(report.requestAudit ?? [], report.responses ?? [], report.target);
  const publicActor = graph.node("ACTOR", "actor:public", "Public actor", { authSlot: "anonymous" }, evidence("scan", { target: safeOrigin(report.target) }, "OBSERVED"));
  const routes = new Map<string, { routeId: string; operationId: string }>();

  const addRoute = (rawUrl: string, method: string, producer: string, strength: AdaptiveGraphEvidence["strength"] = "OBSERVED", exact = false): { routeId: string; operationId: string; path: string; method: string } | undefined => {
    if (!rawUrl) return;
    const url = adaptiveHttpUrl(rawUrl, report.target); if (!url) return;
    const normalizedMethod = normalizeMethod(method);
    const path = safePath(url.pathname);
    const routeKey = `${url.origin}${path}`;
    const routeEvidence = evidence(producer, { origin: url.origin, path, method: normalizedMethod }, strength);
    const routeId = graph.node("ROUTE", `route:${routeKey}`, path, { origin: safeOrigin(url.origin), pathTemplate: path }, routeEvidence);
    const operationKey = `operation:${normalizedMethod}:${routeKey}`;
    const operationId = graph.node("OPERATION", operationKey, `${normalizedMethod} ${path}`, { method: normalizedMethod, pathTemplate: path, origin: safeOrigin(url.origin), protocol: path.toLowerCase().includes("graphql") ? "GRAPHQL" : "REST", stateChanging: !safeMethods.has(normalizedMethod), exactEvidence: exact }, routeEvidence);
    graph.edge("EXPOSES", routeId, operationId, !safeMethods.has(normalizedMethod), routeEvidence);
    for (const name of [...url.searchParams.keys()].map(safeName).filter(Boolean).slice(0, 40)) {
      const parameterId = graph.node("PARAMETER", `parameter:query:${routeKey}:${name}`, name, { location: "QUERY" }, routeEvidence);
      graph.edge("ACCEPTS", operationId, parameterId, !safeMethods.has(normalizedMethod), routeEvidence);
    }
    for (const segment of path.split("/").filter((value) => value.startsWith(":"))) {
      const name = safeName(segment.slice(1));
      const parameterId = graph.node("PARAMETER", `parameter:path:${routeKey}:${name}`, name, { location: "PATH" }, routeEvidence);
      graph.edge("ACCEPTS", operationId, parameterId, !safeMethods.has(normalizedMethod), routeEvidence);
    }
    routes.set(`${normalizedMethod}:${url.origin}${path}`, { routeId, operationId });
    return { routeId, operationId, path, method: normalizedMethod };
  };

  for (const item of report.apiMapper?.endpoints ?? []) addRoute(item.endpoint, item.method, "api-mapper");
  for (const item of report.apiGraphql?.inventory ?? []) for (const method of item.documentedMethods) addRoute(item.path, method, "api-graphql-inventory", "DECLARED_CONTRACT");
  for (const item of records(record(report.scanPlan?.apiGraphql)?.routes)) for (const method of Array.isArray(item.documentedMethods) ? item.documentedMethods : []) addRoute(String(item.path ?? item.url ?? ""), String(method), "api-graphql-plan", "DECLARED_CONTRACT");
  for (const item of report.browserCrawl?.networkRequests ?? []) addRoute(item.url, item.method, "browser-network", "OBSERVED", item.transmitted === true);
  for (const item of report.browserCrawl?.authentication?.learnedTestCases ?? []) addRoute(item.endpoint, item.method, "browser-learning", "OBSERVED", item.transmitted);

  for (const item of report.requestAudit ?? []) {
    if (item.outcome !== "sent") continue;
    const response = matchResponse(item);
    const exactRead = Boolean(response && isAnonymousAdaptiveRequest(item, credentialHeaderNames));
    const route = addRoute(item.requestedUrl, item.method, "request-audit", response ? "EXACT_RESPONSE" : "OBSERVED", Boolean(response));
    if (!route) continue;
    const ev = evidence("request-audit", { requestFingerprint: hash(requestKey(item.requestedUrl, item.method, report.target)), statusCode: item.statusCode ?? 0 }, response ? "EXACT_RESPONSE" : "OBSERVED");
    const actor = isAnonymousAdaptiveRequest(item, credentialHeaderNames) ? publicActor : graph.node("ACTOR", "actor:unbound-request", "Unbound request actor", { authSlot: "unknown" }, ev);
    const performed = graph.edge("PERFORMS", actor, route.operationId, !safeMethods.has(route.method), ev);
    graph.path(`${route.method} ${route.path}`, [actor, route.routeId, route.operationId], [performed], safeMethods.has(route.method) && exactRead ? "READ_ONLY_AUTO_COMPILE_CANDIDATE" : safeMethods.has(route.method) ? "EVIDENCE_ONLY" : "STATE_CHANGE_PROPOSED", safeMethods.has(route.method) ? "api-graphql-authorization" : "business-invariant", [], safeMethods.has(route.method) ? exactRead ? [] : ["exact anonymous response contract"] : ["exact precondition", "expected effect", "verified cleanup"], [ev]);
  }
  const graphqlEndpoints = [...new Set([...(report.apiMapper?.graphQlEndpoints ?? []), ...(report.apiProbe?.graphQlEndpoints ?? []), ...(report.apiGraphql?.inventory?.filter((item) => item.protocol === "GRAPHQL").map((item) => item.path) ?? [])])];
  for (const raw of graphqlEndpoints) {
    const url = adaptiveHttpUrl(raw, report.target); if (!url) continue;
    const path = safePath(url.pathname);
    const audit = (report.requestAudit ?? []).find((item) => isAnonymousAdaptiveRequest(item, credentialHeaderNames) && requestKey(item.requestedUrl, item.method, report.target) === requestKey(url.toString(), "POST", report.target) && matchResponse(item));
    if (!audit) continue;
    const ev = evidence("graphql-read-compiler", { origin: url.origin, path, operation: "GENERATED_INTROSPECTION" }, "EXACT_RESPONSE");
    const route = graph.node("ROUTE", `route:${url.origin}${path}`, path, { origin: safeOrigin(url.origin), pathTemplate: path }, ev);
    const operation = graph.node("OPERATION", `operation:GRAPHQL_QUERY:${url.origin}${path}`, `GraphQL query ${path}`, { method: "POST", pathTemplate: path, protocol: "GRAPHQL", semanticOperation: "GENERATED_INTROSPECTION", stateChanging: false, exactEvidence: true }, ev);
    const exposed = graph.edge("EXPOSES", route, operation, false, ev);
    const performed = graph.edge("PERFORMS", publicActor, operation, false, ev);
    graph.path(`GraphQL introspection ${path}`, [publicActor, route, operation], [exposed, performed], "READ_ONLY_AUTO_COMPILE_CANDIDATE", "api-graphql-authorization", [], [], [ev]);
  }
  for (const item of report.supabaseAuthorization?.observations ?? []) {
    const exact = isConclusiveAdaptiveOutcome(item.observedDecision) && Boolean(validFingerprint(item.comparisonFingerprint)) && Boolean(item.statusCode);
    const ev = evidence("supabase-authorization", { fingerprint: validFingerprint(item.comparisonFingerprint), surface: item.surface, resource: safeName(item.resource), operation: item.operation, actor: item.actor, boundary: item.boundary, decision: item.observedDecision }, exact ? "EXACT_EXECUTED_CONTRACT" : "OBSERVED");
    const url = adaptiveHttpUrl(item.url, report.supabaseAuthorization?.projectOrigin ?? report.target); if (!url) continue;
    const route = addRoute(url.toString(), item.method, "supabase-authorization", exact ? "EXACT_EXECUTED_CONTRACT" : "OBSERVED", exact); if (!route) continue;
    const actor = graph.node("ACTOR", `actor:supabase:${safeName(item.actor)}`, safeName(item.actor), { authSlot: safeName(item.actor) }, ev);
    const role = graph.node("ROLE", `role:supabase:${safeName(item.boundary)}`, safeName(item.boundary), {}, ev);
    const object = graph.node("OBJECT", `data:${item.surface}:${safeName(item.resource)}`, safeName(item.resource), { objectType: item.surface }, ev);
    const performed = graph.edge("PERFORMS", actor, route.operationId, item.operation !== "SELECT" || !safeMethods.has(route.method), ev);
    const consumed = graph.edge("CONSUMES", route.operationId, object, item.operation !== "SELECT", ev);
    graph.edge("HAS_ROLE", actor, role, false, ev);
    const stateChanging = item.operation !== "SELECT" || !safeMethods.has(route.method);
    graph.path(`Supabase ${item.operation} ${safeName(item.resource)}`, [actor, route.operationId, object], [performed, consumed], stateChanging ? "STATE_CHANGE_PROPOSED" : exact ? "READ_ONLY_AUTO_COMPILE_CANDIDATE" : "EVIDENCE_ONLY", "supabase-authorization", [validFingerprint(item.comparisonFingerprint)], stateChanging ? ["exact ownership expectation", "authoritative post-state", "verified cleanup"] : exact ? [] : ["conclusive executed response contract"], [ev]);
  }

  addActorModels(report, graph);
  addObjectOwnership(report, graph);
  const browserActor = report.browserCrawl?.authentication ? graph.node("ACTOR", "actor:browser-session", "Observed browser actor", { authSlot: "browser-session" }, evidence("browser-crawler", { origin: safeOrigin(report.target) }, "OBSERVED")) : publicActor;
  addBrowserStates(report, graph, browserActor, routes);
  addCapabilities(report, graph, browserActor);
  addGraphqlContracts(report, graph, routes);
  addWorkflowContracts(report, graph);

  return graph.finish();
}

function addActorModels(report: RouteCairnReport, graph: GraphBuilder): void {
  const observations = [
    ...(report.authenticationLifecycle?.observations ?? []),
    ...(report.businessInvariant?.observations ?? [])
  ];
  for (const observation of observations) {
    const comparisonFingerprint = validFingerprint(observation.comparisonFingerprint);
    const ev = evidence("executed-workflow", { comparisonFingerprint, outcome: observation.outcome }, comparisonFingerprint && isConclusiveAdaptiveOutcome(observation.outcome) ? "EXACT_EXECUTED_CONTRACT" : "DECLARED_CONTRACT");
    for (const actor of observation.actorModel ?? []) {
      const actorId = graph.node("ACTOR", `actor:${actor.authSlot}:${safeName(actor.safeAlias)}`, safeName(actor.safeAlias), { authSlot: safeName(actor.authSlot), declaredState: safeName(actor.declaredState) }, ev);
      const roleId = graph.node("ROLE", `role:${safeName(actor.relationship)}`, safeName(actor.relationship), {}, ev);
      graph.edge("HAS_ROLE", actorId, roleId, false, ev);
      if (actor.tenantAlias) {
        const tenantId = graph.node("TENANT", `tenant:${safeName(actor.tenantAlias)}`, safeName(actor.tenantAlias), {}, ev);
        graph.edge("MEMBER_OF", actorId, tenantId, false, ev);
      }
    }
  }
  for (const matrix of report.apiGraphql?.authorizationMatrices ?? []) for (const cell of matrix.cells) {
    const ev = evidence("api-graphql-authorization", { matrix: matrix.matrixId, actor: cell.actorAlias, relationship: cell.relationship }, isConclusiveAdaptiveOutcome(cell.outcome) ? "EXACT_EXECUTED_CONTRACT" : "DECLARED_CONTRACT");
    const actorId = graph.node("ACTOR", `actor:${safeName(cell.actorAlias)}`, safeName(cell.actorAlias), {}, ev);
    const roleId = graph.node("ROLE", `role:${safeName(cell.relationship)}`, safeName(cell.relationship), {}, ev);
    graph.edge("HAS_ROLE", actorId, roleId, false, ev);
  }
}

function addObjectOwnership(report: RouteCairnReport, graph: GraphBuilder): void {
  for (const testCase of report.objectPairTesting?.cases ?? []) {
    const ev = evidence("object-pair-testing", { caseId: safeName(testCase.caseId), objectType: safeName(testCase.objectType), visibility: safeName(testCase.expectedVisibility) }, "DECLARED_CONTRACT");
    for (const [slot, request] of [["account_a", testCase.baselineA], ["account_b", testCase.baselineB]] as const) {
      const actorId = graph.node("ACTOR", `actor:${slot}`, slot === "account_a" ? "Account A" : "Account B", { authSlot: slot }, ev);
      const objectId = graph.node("OBJECT", `object:${safeName(testCase.objectType)}:${validFingerprint(request.objectIdHash) || hash(String(request.objectIdHash))}`, safeName(testCase.objectType), { objectType: safeName(testCase.objectType), expectedVisibility: safeName(testCase.expectedVisibility), identityEvidence: true }, ev);
      graph.edge("OWNS", actorId, objectId, false, ev);
    }
  }
  for (const item of report.supabaseAuthorization?.resourceCoverage ?? []) {
    const ev = evidence("supabase-authorization", { surface: item.surface, resource: safeName(item.resource), operations: [...item.operations].sort() }, "OBSERVED");
    graph.node("OBJECT", `data:${item.surface}:${safeName(item.resource)}`, safeName(item.resource), { objectType: item.surface }, ev);
  }
  const plan = record(report.scanPlan?.linkPortalSecurity);
  const actors = new Map(records(plan?.actors).map((item) => [String(item.id), item]));
  for (const resource of records(plan?.resources)) {
    const resourceId = String(resource.id ?? ""); if (!resourceId) continue;
    const ev = evidence("link-portal-export-security", { resourceId: safeName(resourceId), kind: safeName(String(resource.kind ?? "RESOURCE")) }, "DECLARED_CONTRACT");
    const resourceKind = safeName(String(resource.kind ?? "RESOURCE"));
    const resourceNode = graph.node(["SIGNED_LINK", "INVITE"].includes(resourceKind) ? "CAPABILITY" : "OBJECT", `link-resource:${safeName(resourceId)}`, safeName(String(resource.safeAlias ?? resource.kind ?? "Resource")), { ...(["SIGNED_LINK", "INVITE"].includes(resourceKind) ? { capabilityType: resourceKind === "INVITE" ? "INVITATION" : "SIGNED_CAPABILITY" } : { objectType: resourceKind }), ownerDeclared: Boolean(resource.ownerActorId), tenantDeclared: Boolean(resource.tenantFingerprint) }, ev);
    if (typeof resource.ownerActorId === "string") {
      const actor = actors.get(resource.ownerActorId);
      const actorId = graph.node("ACTOR", `actor:${safeName(resource.ownerActorId)}`, safeName(String(actor?.safeAlias ?? resource.ownerActorId)), { authSlot: safeName(String(actor?.authSlot ?? "unknown")) }, ev);
      graph.edge("OWNS", actorId, resourceNode, false, ev);
    }
    if (typeof resource.tenantFingerprint === "string") {
      const tenantId = graph.node("TENANT", `tenant-fingerprint:${validFingerprint(resource.tenantFingerprint) || hash(String(resource.tenantFingerprint))}`, "Bound tenant", { fingerprintBound: true }, ev);
      graph.edge("SCOPED_TO", resourceNode, tenantId, false, ev);
    }
  }
}

function addBrowserStates(report: RouteCairnReport, graph: GraphBuilder, actorId: string, routes: Map<string, { routeId: string; operationId: string }>): void {
  const crawl = report.browserCrawl; if (!crawl) return;
  const startUrl = adaptiveHttpUrl(crawl.startUrl, report.target); if (!startUrl) return;
  const startPath = safePath(startUrl.pathname);
  const ev = evidence("browser-crawler", { startPath }, "OBSERVED");
  const start = graph.node("BROWSER_STATE", `browser-state:${startUrl.origin}${startPath}`, startPath, { depth: 0 }, ev);
  const entryEdge = graph.edge("NAVIGATES_TO", actorId, start, false, ev);
  for (const page of (crawl.visitedPages ?? []).slice(0, 400)) {
    const pageUrl = adaptiveHttpUrl(page.url, report.target); if (!pageUrl) continue;
    const path = safePath(pageUrl.pathname);
    const pageEvidence = evidence("browser-crawler", { path, depth: page.depth }, "OBSERVED");
    const state = graph.node("BROWSER_STATE", `browser-state:${pageUrl.origin}${path}`, path, { depth: page.depth }, pageEvidence);
    if (state !== start) graph.edge("NAVIGATES_TO", actorId, state, false, pageEvidence);
  }
  for (const candidate of crawl.authentication?.learnedTestCases ?? []) {
    const candidateUrl = adaptiveHttpUrl(candidate.endpoint, report.target); if (!candidateUrl) continue;
    const path = safePath(candidateUrl.pathname);
    const operation = routes.get(`${normalizeMethod(candidate.method)}:${candidateUrl.origin}${path}`)?.operationId;
    if (!operation) continue;
    const candidateEvidence = evidence("browser-learning", { candidateId: safeName(candidate.id), method: normalizeMethod(candidate.method), path, classification: candidate.classification }, "OBSERVED");
    for (const name of candidate.observedFieldNames.map(safeName).filter(Boolean).slice(0, 40)) {
      const parameter = graph.node("PARAMETER", `parameter:learned:${operation}:${name}`, name, { location: candidate.requestBodyFormat ?? "UNKNOWN" }, candidateEvidence);
      graph.edge("ACCEPTS", operation, parameter, (candidate.classification === "MUTATION_HYPOTHESIS" || !safeMethods.has(normalizeMethod(candidate.method))), candidateEvidence);
    }
    const transitionEdge = graph.edge("TRANSITIONS_TO", start, operation, (candidate.classification === "MUTATION_HYPOTHESIS" || !safeMethods.has(normalizeMethod(candidate.method))), candidateEvidence);
    graph.path(`Browser ${normalizeMethod(candidate.method)} ${path}`, [actorId, start, operation], [entryEdge, transitionEdge], (candidate.classification === "MUTATION_HYPOTHESIS" || !safeMethods.has(normalizeMethod(candidate.method))) ? "STATE_CHANGE_PROPOSED" : "EVIDENCE_ONLY", candidate.suggestedLifecycleCategories.length ? "authentication-lifecycle" : (candidate.classification === "MUTATION_HYPOTHESIS" || !safeMethods.has(normalizeMethod(candidate.method))) ? "business-invariant" : "api-graphql-authorization", [], (candidate.classification === "MUTATION_HYPOTHESIS" || !safeMethods.has(normalizeMethod(candidate.method))) ? ["exact actor", "precondition", "expected effect", "cleanup transition"] : ["exact response contract"], [candidateEvidence]);
  }
}

function addCapabilities(report: RouteCairnReport, graph: GraphBuilder, actorId: string): void {
  for (const item of report.browserCrawl?.authentication?.storage ?? []) {
    if (!['authentication', 'csrf'].includes(item.classification)) continue;
    const ev = evidence("browser-storage", { origin: safeOrigin(item.origin), storage: item.storage, name: safeName(item.name), classification: item.classification, valueDigest: item.valueDigest }, "OBSERVED");
    const capability = graph.node("CAPABILITY", `storage:${safeOrigin(item.origin)}:${item.storage}:${safeName(item.name)}:${validFingerprint(item.valueDigest) || hash(String(item.valueDigest))}`, item.classification === "csrf" ? "CSRF capability" : "Session capability", { capabilityType: item.classification === "csrf" ? "CSRF_TOKEN" : "SESSION", storage: item.storage, httpOnly: item.httpOnly ?? false, secure: item.secure ?? false }, ev);
    graph.edge("CONSUMES", actorId, capability, false, ev);
  }
}

function addGraphqlContracts(report: RouteCairnReport, graph: GraphBuilder, routes: Map<string, { routeId: string; operationId: string }>): void {
  const plan = record(report.scanPlan?.apiGraphql); if (!plan) return;
  const routePlans = new Map(records(plan.routes).map((item) => [String(item.id), item]));
  const actorPlans = new Map(records(plan.actors).map((item) => [String(item.id), item]));
  const observations = new Map((report.apiGraphql?.checks ?? []).map((item) => [item.comparisonFingerprint, item]));
  for (const check of records(plan.checks)) {
    const fingerprint = validFingerprint(check.comparisonFingerprint); if (!fingerprint) continue;
    const routePlan = routePlans.get(String(check.routeId ?? check.candidateRouteId ?? check.baselineRouteId ?? "")); if (!routePlan) continue;
    const documentedMethods = Array.isArray(routePlan.documentedMethods) ? routePlan.documentedMethods : [];
    const method = normalizeMethod(String(record(check.request)?.method ?? documentedMethods[0] ?? "GET"));
    const raw = String(routePlan.path ?? routePlan.url ?? ""); if (!raw) continue;
    const routeUrl = adaptiveHttpUrl(String(routePlan.url ?? raw), report.target); if (!routeUrl) continue;
    const displayUrl = adaptiveHttpUrl(raw, routeUrl.origin); if (!displayUrl) continue;
    const path = safePath(displayUrl.pathname);
    const requestPlan = record(check.request);
    const readOnlyOperation = isReadOnlyAdaptiveApiOperation(check, routePlan, requestPlan, method);
    const mappedRoute = routes.get(`${method}:${routeUrl.origin}${path}`);
    const operation = readOnlyOperation && !safeMethods.has(method)
      ? graph.node("OPERATION", `operation:READ_ONLY_CONTRACT:${method}:${safeOrigin(routeUrl.origin)}${path}:${fingerprint}`, `${method} ${path}`, { method, pathTemplate: path, protocol: String(routePlan.protocol ?? "REST"), semanticOperation: "CONTRACT_READ", stateChanging: false }, evidence("api-graphql-authorization", { fingerprint }, "DECLARED_CONTRACT"))
      : mappedRoute?.operationId ?? graph.node("OPERATION", `operation:${method}:${safeOrigin(routeUrl.origin)}${path}`, `${method} ${path}`, { method, pathTemplate: path, protocol: String(routePlan.protocol ?? "REST"), stateChanging: !readOnlyOperation }, evidence("api-graphql-authorization", { fingerprint }, "DECLARED_CONTRACT"));
    const actorAlias = safeName(String(check.actorId ?? "anonymous"));
    const actorPlan = actorPlans.get(String(check.actorId ?? ""));
    const actor = graph.node("ACTOR", `actor:${actorAlias}`, safeName(String(actorPlan?.safeAlias ?? actorAlias)), { authSlot: safeName(String(actorPlan?.authSlot ?? "unknown")) }, evidence("api-graphql-authorization", { fingerprint }, "DECLARED_CONTRACT"));
    if (actorPlan?.relationship) { const role = graph.node("ROLE", `role:${safeName(String(actorPlan.relationship))}`, safeName(String(actorPlan.relationship)), {}, evidence("api-graphql-authorization", { fingerprint }, "DECLARED_CONTRACT")); graph.edge("HAS_ROLE", actor, role, false, evidence("api-graphql-authorization", { fingerprint }, "DECLARED_CONTRACT")); }
    if (actorPlan?.tenantFingerprint) { const tenant = graph.node("TENANT", `tenant-fingerprint:${validFingerprint(actorPlan.tenantFingerprint) || hash(String(actorPlan.tenantFingerprint))}`, "Bound tenant", { fingerprintBound: true }, evidence("api-graphql-authorization", { fingerprint }, "DECLARED_CONTRACT")); graph.edge("MEMBER_OF", actor, tenant, false, evidence("api-graphql-authorization", { fingerprint }, "DECLARED_CONTRACT")); }
    const ev = evidence("api-graphql-authorization", { fingerprint, outcome: observations.get(fingerprint)?.outcome ?? "NOT_OBSERVED" }, isConclusiveAdaptiveOutcome(observations.get(fingerprint)?.outcome) ? "EXACT_EXECUTED_CONTRACT" : "DECLARED_CONTRACT");
    const performed = graph.edge("PERFORMS", actor, operation, !readOnlyOperation, ev);
    const exposed = mappedRoute && mappedRoute.operationId !== operation ? graph.edge("EXPOSES", mappedRoute.routeId, operation, false, ev) : undefined;
    const complete = isConclusiveAdaptiveOutcome(observations.get(fingerprint)?.outcome);
    graph.path(`API contract ${path}`, [actor, ...(mappedRoute ? [mappedRoute.routeId] : []), operation], [performed, ...(exposed ? [exposed] : [])], readOnlyOperation && complete ? "READ_ONLY_AUTO_COMPILE_CANDIDATE" : !readOnlyOperation ? "STATE_CHANGE_PROPOSED" : "EVIDENCE_ONLY", "api-graphql-authorization", [fingerprint], complete ? [] : ["conclusive executed response contract"], [ev]);
  }
}

function addWorkflowContracts(report: RouteCairnReport, graph: GraphBuilder): void {
  const sources: Array<{ engineId: string; plan: unknown; observations: readonly unknown[] }> = [
    { engineId: "authentication-lifecycle", plan: report.scanPlan?.authenticationLifecycle, observations: report.authenticationLifecycle?.observations ?? [] },
    { engineId: "business-invariant", plan: report.scanPlan?.businessInvariant, observations: report.businessInvariant?.observations ?? [] },
    { engineId: "link-portal-export-security", plan: report.scanPlan?.linkPortalSecurity, observations: report.linkPortalSecurity?.observations ?? [] },
    { engineId: "operational-endpoint-security", plan: report.scanPlan?.operationalEndpointSecurity, observations: report.operationalEndpointSecurity?.observations ?? [] },
    { engineId: "billing-entitlement-security", plan: report.scanPlan?.billingEntitlement, observations: report.billingEntitlement?.observations ?? [] }
  ];
  for (const source of sources) {
    const plan = record(source.plan); if (!plan) continue;
    const observationByFingerprint = new Map(records(source.observations).map((item) => [validFingerprint(item.comparisonFingerprint), item]));
    for (const testCase of records(plan.cases)) addWorkflowCase(report, graph, source.engineId, testCase, records(plan.actors), validFingerprint(testCase.comparisonFingerprint) ? observationByFingerprint.get(validFingerprint(testCase.comparisonFingerprint)) : undefined);
  }
}

function addWorkflowCase(report: RouteCairnReport, graph: GraphBuilder, engineId: string, testCase: Record<string, unknown>, planActors: Record<string, unknown>[], observation?: Record<string, unknown>): void {
  const caseId = safeName(String(testCase.id ?? "case"));
  const fingerprint = validFingerprint(testCase.comparisonFingerprint);
  const outcome = String(observation?.outcome ?? observation?.observedDecision ?? "NOT_OBSERVED");
  const exact = Boolean(fingerprint && observation && isConclusiveAdaptiveOutcome(outcome));
  const ev = evidence(engineId, { caseId, fingerprint, outcome }, exact ? "EXACT_EXECUTED_CONTRACT" : "DECLARED_CONTRACT");
  const actorPlans = [...records(testCase.actors), ...planActors];
  const actors = new Map<string, string>();
  for (const actor of actorPlans) {
    const id = String(actor.id ?? actor.actorId ?? ""); if (!id) continue;
    const actorId = graph.node("ACTOR", `actor:${engineId}:${safeName(id)}`, safeName(String(actor.safeAlias ?? id)), { authSlot: safeName(String(actor.authSlot ?? actor.secretSource ?? "unknown")), declaredState: safeName(String(actor.declaredState ?? "unknown")) }, ev);
    actors.set(id, actorId);
    if (actor.relationship) { const role = graph.node("ROLE", `role:${safeName(String(actor.relationship))}`, safeName(String(actor.relationship)), {}, ev); graph.edge("HAS_ROLE", actorId, role, false, ev); }
    if (actor.tenantAlias) { const tenant = graph.node("TENANT", `tenant:${safeName(String(actor.tenantAlias))}`, safeName(String(actor.tenantAlias)), {}, ev); graph.edge("MEMBER_OF", actorId, tenant, false, ev); }
    else if (actor.tenantFingerprint) { const tenant = graph.node("TENANT", `tenant-fingerprint:${validFingerprint(actor.tenantFingerprint) || hash(String(actor.tenantFingerprint))}`, "Bound tenant", { fingerprintBound: true }, ev); graph.edge("MEMBER_OF", actorId, tenant, false, ev); }
  }
  const steps = records(testCase.steps);
  const groups: Array<{ phase: string; values: Record<string, unknown>[] }> = [
    { phase: "PRECONDITION", values: [...records(testCase.preState), ...steps.filter((item) => ["SETUP", "CONTROL", "PRE_STATE"].includes(String(item.phase)))] },
    { phase: "ACTION", values: [...records(testCase.actions), ...steps.filter((item) => item.phase === "ACTION")] },
    { phase: "STEP", values: steps.filter((item) => !["SETUP", "CONTROL", "PRE_STATE", "ACTION", "VERIFY", "CLEANUP"].includes(String(item.phase))) },
    { phase: "EFFECT", values: records(testCase.postState) },
    { phase: "VERIFY", values: steps.filter((item) => item.phase === "VERIFY") },
    { phase: "CLEANUP", values: [...records(testCase.cleanup), ...steps.filter((item) => item.phase === "CLEANUP")] },
    { phase: "CLEANUP_VERIFY", values: records(testCase.cleanupVerification) }
  ];
  const ordered = steps.length ? steps.map((item) => ({ phase: ["SETUP", "CONTROL", "PRE_STATE"].includes(String(item.phase)) ? "PRECONDITION" : ["ACTION", "VERIFY", "CLEANUP"].includes(String(item.phase)) ? String(item.phase) : "STEP", item })) : groups.flatMap((group) => group.values.map((item) => ({ phase: group.phase, item })));
  const namespace = `${engineId}:${caseId}:${fingerprint || digest(testCase)}`;
  const unresolved = new Set<string>();
  const nodeIds: string[] = []; const edgeIds: string[] = []; const captureProducers = new Map<string, string>();
  let previous: string | undefined; let stateChanging = false; let cleanupSeen = false;
  for (const [index, entry] of ordered.entries()) {
    const request = record(entry.item.request); const rawUrl = String(request?.urlTemplate ?? request?.url ?? "");
    if (!rawUrl) continue;
    const method = normalizeMethod(String(request?.method ?? "GET")); stateChanging ||= request?.stateChanging === true || !safeMethods.has(method); cleanupSeen ||= entry.phase === "CLEANUP";
    const requestUrl = adaptiveHttpUrl(rawUrl, report.target);
    if (!requestUrl) { unresolved.add("valid HTTP request URL"); continue; }
    const path = safePath(requestUrl.pathname);
    const route = graph.node("ROUTE", `route:${requestUrl.origin}${path}`, path, { origin: safeOrigin(requestUrl.origin), pathTemplate: path }, ev);
    const operation = graph.node("OPERATION", `workflow-operation:${namespace}:${safeName(String(entry.item.id ?? index))}`, `${method} ${path}`, { method, pathTemplate: path, phase: entry.phase, stateChanging: request?.stateChanging === true || !safeMethods.has(method) }, ev);
    edgeIds.push(graph.edge("EXPOSES", route, operation, request?.stateChanging === true || !safeMethods.has(method), ev)); nodeIds.push(route);
    for (const name of [...requestUrl.searchParams.keys()].map(safeName).filter(Boolean).slice(0, 40)) { const parameter = graph.node("PARAMETER", `parameter:query:${operation}:${name}`, name, { location: "QUERY" }, ev); edgeIds.push(graph.edge("ACCEPTS", operation, parameter, request?.stateChanging === true || !safeMethods.has(method), ev)); }
    for (const segment of path.split("/").filter((value) => value.startsWith(":"))) { const name = safeName(segment.slice(1)); const parameter = graph.node("PARAMETER", `parameter:path:${operation}:${name}`, name, { location: "PATH" }, ev); edgeIds.push(graph.edge("ACCEPTS", operation, parameter, request?.stateChanging === true || !safeMethods.has(method), ev)); }
    for (const name of Object.keys(record(request?.fields) ?? {}).map(safeName).filter(Boolean).slice(0, 40)) { const parameter = graph.node("PARAMETER", `parameter:body:${operation}:${name}`, name, { location: "BODY" }, ev); edgeIds.push(graph.edge("ACCEPTS", operation, parameter, request?.stateChanging === true || !safeMethods.has(method), ev)); }
    for (const name of Object.keys(record(request?.headers) ?? {}).map(safeName).filter(Boolean).slice(0, 40)) { const parameter = graph.node("PARAMETER", `parameter:header:${operation}:${name.toLowerCase()}`, name, { location: "HEADER" }, ev); edgeIds.push(graph.edge("ACCEPTS", operation, parameter, request?.stateChanging === true || !safeMethods.has(method), ev)); }
    const actor = actors.get(String(entry.item.actorId ?? "")); if (actor) edgeIds.push(graph.edge("PERFORMS", actor, operation, request?.stateChanging === true || !safeMethods.has(method), ev));
    if (previous) edgeIds.push(graph.edge("TRANSITIONS_TO", previous, operation, request?.stateChanging === true || !safeMethods.has(method), ev));
    previous = operation; nodeIds.push(operation);
    const stateKind = entry.phase.startsWith("CLEANUP") ? "CLEANUP" : ["EFFECT", "VERIFY"].includes(entry.phase) ? "EFFECT" : entry.phase === "PRECONDITION" ? "PRECONDITION" : undefined;
    if (stateKind) {
      const state = graph.node(stateKind, `${stateKind.toLowerCase()}:${namespace}:${index}`, `${stateKind.toLowerCase()} ${index + 1}`, { phase: entry.phase }, ev);
      const stateEdge = entry.phase === "VERIFY" || entry.phase === "CLEANUP_VERIFY" ? "VERIFIES" : stateKind === "CLEANUP" ? "CLEANED_BY" : stateKind === "EFFECT" ? "EFFECTS" : "REQUIRES";
      edgeIds.push(graph.edge(stateEdge, operation, state, request?.stateChanging === true || !safeMethods.has(method), ev)); nodeIds.push(state);
    }
    for (const ref of captureReferences(request)) {
      const capability = captureProducers.get(ref);
      if (capability) edgeIds.push(graph.edge("CONSUMES", operation, capability, request?.stateChanging === true || !safeMethods.has(method), ev));
      else unresolved.add(`prior producer for capture ${ref}`);
    }
    for (const capture of records(entry.item.captures)) {
      const name = safeName(String(capture.name ?? "capture"));
      if (captureProducers.has(name)) unresolved.add(`unique capture producer ${name}`);
      const capability = graph.node("CAPABILITY", `capability:${namespace}:${index}:${name}`, capabilityLabel(name), { capabilityType: capabilityType(name), source: safeName(String(capture.source ?? "UNKNOWN")) }, ev);
      captureProducers.set(name, capability); edgeIds.push(graph.edge("PRODUCES", operation, capability, false, ev)); nodeIds.push(capability);
      if (["INVITATION", "SIGNED_CAPABILITY"].includes(capabilityType(name))) edgeIds.push(graph.edge("ISSUES", operation, capability, false, ev));
    }
  }
  if (!nodeIds.length) return;
  for (const ref of captureReferences(testCase)) if (!captureProducers.has(ref)) unresolved.add(`producer for capture ${ref}`);
  const authorization = record(testCase.authorization);
  const disposable = authorization?.disposableAccounts === true || authorization?.disposableEntities === true || authorization?.disposableResource === true || authorization?.disposableTarget === true || authorization?.disposableFixtures === true;
  const cleanupOutcome = String(observation?.cleanupOutcome ?? "");
  const cleanupVerified = !stateChanging || (isVerifiedAdaptiveCleanup(cleanupOutcome) && cleanupSeen) || (testCase.cleanupRequired !== true && disposable && /^NOT_REQUIRED$/i.test(cleanupOutcome));
  const requiredBindings = [...new Set([
    ...unresolved,
    ...(!exact ? ["conclusive executed contract"] : []),
    ...(stateChanging && !cleanupSeen && !disposable ? ["cleanup transition or disposable fixture proof"] : []),
    ...(stateChanging && !cleanupVerified ? ["verified cleanup evidence"] : []),
    ...(stateChanging && (observation?.preStateVerified === false || !ordered.some((entry) => entry.phase === "PRECONDITION")) ? ["exact precondition"] : []),
    ...(stateChanging && (observation?.postStateVerified === false || !ordered.some((entry) => ["EFFECT", "VERIFY"].includes(entry.phase))) ? ["authoritative effect verification"] : [])
  ])];
  graph.path(`${engineId} ${caseId}`, nodeIds, edgeIds, stateChanging ? "STATE_CHANGE_PROPOSED" : exact && !requiredBindings.length ? "READ_ONLY_AUTO_COMPILE_CANDIDATE" : "EVIDENCE_ONLY", engineId, fingerprint ? [fingerprint] : [], requiredBindings, [ev]);
}

class GraphBuilder {
  private readonly nodes = new Map<string, AdaptiveAttackNode>();
  private readonly edges = new Map<string, AdaptiveAttackEdge>();
  private readonly paths = new Map<string, AdaptiveAttackPath>();
  private readonly producerSet = new Set<string>();
  private truncated = false;
  private readonly maxNodes = 1200;
  private readonly maxEdges = 3000;
  private readonly maxPaths = 500;

  public node(kind: AdaptiveAttackNodeKind, semanticKey: string, label: string, attributes: AdaptiveAttackNode["attributes"], itemEvidence: AdaptiveGraphEvidence): string {
    const id = hash(`node\0${kind}\0${semanticKey}`); this.producerSet.add(itemEvidence.producer);
    const existing = this.nodes.get(id);
    if (existing) { this.nodes.set(id, { ...existing, attributes: { ...existing.attributes, ...sanitizeAttributes(attributes), stateChanging: existing.attributes.stateChanging === true || attributes.stateChanging === true }, evidence: mergeEvidence(existing.evidence, itemEvidence) }); return id; }
    if (this.nodes.size >= this.maxNodes) { this.truncated = true; return id; }
    this.nodes.set(id, { id, kind, semanticKey: clampSafe(semanticKey, 500), label: clampSafe(label, 160), attributes: sanitizeAttributes(attributes), evidence: [itemEvidence] });
    return id;
  }

  public edge(kind: AdaptiveAttackEdgeKind, from: string, to: string, stateChanging: boolean, itemEvidence: AdaptiveGraphEvidence): string {
    const id = hash(`edge\0${kind}\0${from}\0${to}`); this.producerSet.add(itemEvidence.producer);
    const existing = this.edges.get(id);
    if (existing) { this.edges.set(id, { ...existing, stateChanging: existing.stateChanging || stateChanging, evidence: mergeEvidence(existing.evidence, itemEvidence) }); return id; }
    if (!this.nodes.has(from) || !this.nodes.has(to) || this.edges.size >= this.maxEdges) { this.truncated = true; return id; }
    this.edges.set(id, { id, kind, from, to, stateChanging, evidence: [itemEvidence] }); return id;
  }

  public path(label: string, nodeIds: readonly string[], edgeIds: readonly string[], automationState: AdaptiveAttackPath["automationState"], engineId: string, sourceCaseFingerprints: readonly string[], requiredBindings: readonly string[], pathEvidence: readonly AdaptiveGraphEvidence[]): void {
    const requestedEdges = [...new Set(edgeIds)].filter((id) => this.edges.has(id));
    const allNodes = [...new Set([...nodeIds, ...requestedEdges.flatMap((id) => { const edge = this.edges.get(id)!; return [edge.from, edge.to]; })])];
    const retainedNodes = allNodes.filter((id) => this.nodes.has(id)).slice(0, 100);
    if (!retainedNodes.length) return;
    const retainedSet = new Set(retainedNodes);
    const retainedEdges = requestedEdges.filter((id) => { const edge = this.edges.get(id)!; return retainedSet.has(edge.from) && retainedSet.has(edge.to); }).slice(0, 150);
    const incomplete = retainedNodes.length !== allNodes.length || retainedEdges.length !== new Set(edgeIds).size;
    if (incomplete) { this.truncated = true; requiredBindings = [...requiredBindings, "complete bounded graph path"]; }
    const stateChanging = automationState === "STATE_CHANGE_PROPOSED" || retainedNodes.some((id) => this.nodes.get(id)?.attributes.stateChanging === true) || retainedEdges.some((id) => this.edges.get(id)?.stateChanging);
    const mutability = stateChanging ? "STATE_CHANGING" : "READ_ONLY";
    if (stateChanging) automationState = "STATE_CHANGE_PROPOSED";
    else if (requiredBindings.length) automationState = "EVIDENCE_ONLY";
    const semantic = { label: clampSafe(label, 200), retainedNodes: [...retainedNodes].sort(), mutability, engineId, sourceCaseFingerprints: [...sourceCaseFingerprints].sort() };
    const id = hash(`path\0${JSON.stringify(semantic)}`);
    if (this.paths.has(id)) return;
    if (this.paths.size >= this.maxPaths) { this.truncated = true; return; }
    this.paths.set(id, { id, label: semantic.label, nodeIds: semantic.retainedNodes, edgeIds: retainedEdges.sort(), mutability, automationState, contractReadiness: requiredBindings.length ? "REQUIRES_BINDINGS" : "COMPLETE", engineId: safeName(engineId), sourceCaseFingerprints: [...new Set(sourceCaseFingerprints.map(validFingerprint).filter(Boolean))].sort(), requiredBindings: [...new Set(requiredBindings.map(safeName))].sort(), evidence: pathEvidence.slice(0, 6) });
  }

  public finish(): AdaptiveAttackStateGraph {
    const nodes = [...this.nodes.values()].sort((left, right) => left.id.localeCompare(right.id));
    const edges = [...this.edges.values()].sort((left, right) => left.id.localeCompare(right.id));
    const paths = [...this.paths.values()].sort((left, right) => left.id.localeCompare(right.id));
    const counts = Object.fromEntries((["ACTOR", "ROLE", "TENANT", "OBJECT", "ROUTE", "PARAMETER", "OPERATION", "BROWSER_STATE", "CAPABILITY", "PRECONDITION", "EFFECT", "CLEANUP"] as AdaptiveAttackNodeKind[]).map((kind) => [kind, nodes.filter((node) => node.kind === kind).length])) as Record<AdaptiveAttackNodeKind, number>;
    const payload = { schemaVersion: 1 as const, bounds: { maxNodes: this.maxNodes, maxEdges: this.maxEdges, maxPaths: this.maxPaths, truncated: this.truncated }, nodes, edges, paths, coverage: { ...counts, EDGES: edges.length, PATHS: paths.length, READ_ONLY_PATHS: paths.filter((path) => path.mutability === "READ_ONLY").length, STATE_CHANGING_PATHS: paths.filter((path) => path.mutability === "STATE_CHANGING").length }, producers: [...this.producerSet].sort() };
    return { ...payload, graphFingerprint: digest(payload) };
  }
}

function evidence(producer: string, semantics: unknown, strength: AdaptiveGraphEvidence["strength"]): AdaptiveGraphEvidence { return { producer: safeName(producer), fingerprint: digest({ producer, semantics, strength }), strength }; }

function mergeEvidence(current: readonly AdaptiveGraphEvidence[], next: AdaptiveGraphEvidence): AdaptiveGraphEvidence[] { return current.some((item) => item.fingerprint === next.fingerprint) ? [...current] : [...current, next].slice(0, 6); }
function requestKey(raw: string, method: string, base: string): string { return adaptiveRequestIdentity(raw, method, base) ?? ""; }
function captureReferences(value: unknown): string[] { const output = new Set<string>(); walk(value, (item) => { if (item.source === "CAPTURE" && typeof item.ref === "string") output.add(safeName(item.ref)); for (const child of Object.values(item)) if (typeof child === "string") for (const match of child.matchAll(/\{\{CAPTURE:([A-Za-z0-9._-]+)\}\}/g)) output.add(safeName(match[1]!)); }); return [...output]; }
function capabilityType(name: string): string { return /invite/i.test(name) ? "INVITATION" : /signed|link|capability/i.test(name) ? "SIGNED_CAPABILITY" : /session|refresh|access|token|jwt/i.test(name) ? "TOKEN" : /code|otp|totp|recovery/i.test(name) ? "ONE_TIME_CODE" : "CAPTURED_VALUE"; }
function capabilityLabel(name: string): string { const type = capabilityType(name); return type === "INVITATION" ? "Invitation capability" : type === "SIGNED_CAPABILITY" ? "Signed capability" : type === "TOKEN" ? "Token capability" : type === "ONE_TIME_CODE" ? "One-time capability" : "Bound workflow value"; }
function normalizeMethod(value: string): string { const method = value.toUpperCase(); return /^[A-Z]{2,12}$/.test(method) ? method : "UNKNOWN"; }
function safeOrigin(value: string): string { try { return new URL(value).origin.slice(0, 300); } catch { return "unknown-origin"; } }
function safePath(value: string): string { const path = value.split("?")[0]!.replace(/\/(?:tokens?|secrets?|reset-password|password-reset|verify-email|magic-link)\/[^/]+/gi, (match) => `${match.slice(0, match.lastIndexOf("/"))}/:token`).replace(/\/[0-9]{2,}(?=\/|$)/g, "/:id").replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, "/:id").replace(/\/[A-Za-z0-9_-]{32,}(?=\/|$)/g, "/:token").replace(/[\r\n\0|]/g, "_"); return (path.startsWith("/") ? path : `/${path}`).slice(0, 500); }
function safeName(value: string): string { return redactText(value).replace(/[\r\n\0|<>]/g, "_").slice(0, 160); }
function clampSafe(value: string, maximum: number): string { return redactText(value).replace(/[\r\n\0|<>]/g, "_").slice(0, maximum); }
function validFingerprint(value: unknown): string { return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value) ? value.toLowerCase() : ""; }
function sanitizeAttributes(value: AdaptiveAttackNode["attributes"]): AdaptiveAttackNode["attributes"] { return Object.fromEntries(Object.entries(value).slice(0, 30).map(([key, child]) => [safeName(key), typeof child === "string" ? safeName(child) : child])); }
function records(value: unknown): Record<string, unknown>[] { return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item)) : []; }
function record(value: unknown): Record<string, unknown> | undefined { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function walk(value: unknown, visit: (item: Record<string, unknown>) => void): void { if (Array.isArray(value)) { value.forEach((item) => walk(item, visit)); return; } const item = record(value); if (!item) return; visit(item); Object.values(item).forEach((child) => walk(child, visit)); }
function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function digest(value: unknown): string { return hash(JSON.stringify(sort(value))); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); const item = record(value); if (!item) return value; return Object.fromEntries(Object.entries(item).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, sort(child)])); }

function redactText(value: string): string { return value.replace(/\bBearer\s+[^\s]+/gi, "[redacted]").replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "[redacted]").replace(/(?:password|secret|api[-_]?key|access[-_]?token|refresh[-_]?token)\s*[=:]\s*[^\s,;]+/gi, "[redacted]"); }
