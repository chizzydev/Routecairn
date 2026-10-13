import type { RouteCairnReport, BrowserLearnedTestCase } from "../../reports/ReportTypes.js";

import type { LiveAcceptanceLane } from "../contracts/LiveAcceptanceSchemas.js";

import { compileBillingReadOnlyCase, compileBusinessInvariantReadOnlyCase, compileGraphqlIntrospectionCase, compileOperationalHealthCase, compileRouteReadOnlyCase, compileSupabaseReadOnlyCase, type AdaptiveCompiledReadOnlyCase } from "./AdaptiveReadOnlyCompiler.js";

import { adaptiveHttpUrl } from "./AdaptiveEvidenceSafety.js";

import { buildAdaptiveAttackStateGraph, type AdaptiveAttackPath, type AdaptiveAttackStateGraph } from "./AdaptiveAttackStateGraph.js";

import { advancedEngineCatalog } from "../contracts/AdvancedEngineSchemas.js";

import { compileExecutedContracts, type AdaptiveCompiledContract } from "./AdaptiveContractCompiler.js";

import { adaptiveDigest, adaptiveExecutionFingerprint } from "./AdaptiveCanonical.js";

/** Value-only evidence synthesis. Persistence, review and execution remain in the service. */

export interface AdaptiveInventory {
  schemaVersion: 1 | 2;
  buildFingerprint: string;
  buildEvidence: boolean;
  producers: string[];
  origins: string[];
  routes: Array<{ key: string; origin?: string; protocol: "REST" | "GRAPHQL"; method: string; pathTemplate: string; source: string; stateChanging: boolean }>;
  fields: Array<{ key: string; pagePath: string; name: string; controlType: string; access: string }>;
  apiFields: Array<{ key: string; path: string; classification: string; expectation: string }>;
  cookies: Array<{ key: string; origin: string; name: string; classification: string; httpOnly?: boolean; secure?: boolean; sameSite?: string }>;
  graphql: string[];
  graphqlOperations: Array<{ key: string; kind: string; routeAliases: string[]; fingerprint: string }>;
  adminRoutes: string[];
  roles: string[];
  versions: string[];
  supabaseResources: Array<{ key: string; surface: string; resource: string; operations: string[]; actors: string[] }>;
  lifecycleCategories: string[];
  workflowCases: Array<{ key: string; workflowId: string; fingerprint: string; executionState: string }>;
  attackGraph?: AdaptiveAttackStateGraph;
}

export function buildAdaptiveInventory(report: RouteCairnReport, workflowCases: AdaptiveInventory["workflowCases"]): AdaptiveInventory {
  const routes = new Map<string, AdaptiveInventory["routes"][number]>();
  const origins = new Set<string>([new URL(report.target).origin]);
  const addRoute = (raw: string, method: string, protocol: "REST" | "GRAPHQL", source: string) => { try { const url = adaptiveHttpUrl(raw, report.target); if (!url) return; origins.add(url.origin); const pathTemplate = safePath(url.pathname); const normalizedMethod = method.toUpperCase().slice(0, 12); const key = `${protocol}:${normalizedMethod}:${url.origin}${pathTemplate}`; routes.set(key, { key, origin: url.origin, protocol, method: normalizedMethod, pathTemplate, source, stateChanging: !["GET", "HEAD", "OPTIONS"].includes(normalizedMethod) }); } catch { /* invalid learned URL omitted */ } };
  for (const item of report.apiMapper?.endpoints ?? []) addRoute(item.endpoint, item.method, item.endpoint.toLowerCase().includes("graphql") ? "GRAPHQL" : "REST", "api-mapper");
  for (const item of report.browserCrawl?.authentication?.learnedTestCases ?? []) addRoute(item.endpoint, item.method, item.endpoint.toLowerCase().includes("graphql") ? "GRAPHQL" : "REST", "browser-learning");
  for (const item of report.apiGraphql?.inventory ?? []) addRoute(item.path, item.documentedMethods[0] ?? "POST", item.protocol, "api-graphql-inventory");
  const fields = (report.browserCrawl?.authentication?.fields ?? []).flatMap((item) => { const url = adaptiveHttpUrl(item.pageUrl, report.target); if (!url) return []; const pagePath = safePath(url.pathname); const name = safeName(item.name); return [{ key: `${url.origin}${pagePath}:${name}:${safeName(item.controlType)}`, pagePath, name, controlType: safeName(item.controlType), access: item.access }]; }).sort(byKey);
  const cookies = (report.browserCrawl?.authentication?.storage ?? []).filter((item) => item.storage === "cookie").map((item) => ({ key: `${safeName(item.origin)}:${safeName(item.name)}`, origin: safeName(item.origin), name: safeName(item.name), classification: item.classification, ...(item.httpOnly !== undefined ? { httpOnly: item.httpOnly } : {}), ...(item.secure !== undefined ? { secure: item.secure } : {}), ...(item.sameSite ? { sameSite: safeName(item.sameSite) } : {}) })).sort(byKey);
  const graphql = [...new Set([...(report.apiMapper?.graphQlEndpoints ?? []), ...(report.apiProbe?.graphQlEndpoints ?? []), ...(report.apiGraphql?.inventory?.filter((item) => item.protocol === "GRAPHQL").map((item) => item.path) ?? [])].flatMap((item) => { const url = adaptiveHttpUrl(item, report.target); return url && url.origin === new URL(report.target).origin ? [safePath(url.pathname)] : []; }))].sort();
  const graphqlOperations = (report.apiGraphql?.checks ?? []).filter((item) => item.protocols.includes("GRAPHQL")).map((item) => ({ key: `${safeName(item.kind)}:${item.routeAliases.map(safeName).sort().join(",")}:${item.comparisonFingerprint}`, kind: safeName(item.kind), routeAliases: item.routeAliases.map(safeName).sort(), fingerprint: item.comparisonFingerprint })).sort(byKey);
  const apiFields = (report.apiGraphql?.checks ?? []).flatMap((check) => check.fields.map((item) => ({ key: `${safeName(check.checkId)}:${safeName(item.path)}`, path: safeName(item.path), classification: safeName(item.classification), expectation: safeName(item.expectation) }))).sort(byKey);
  const supabaseResources = (report.supabaseAuthorization?.resourceCoverage ?? []).map((item) => ({ key: `${item.surface}:${safeName(item.resource)}`, surface: item.surface, resource: safeName(item.resource), operations: [...item.operations].sort(), actors: [...item.actors].sort() })).sort(byKey);
  const lifecycleCategories = Object.entries(report.authenticationLifecycle?.coverage ?? {}).filter(([, value]) => value.planned > 0).map(([key]) => key).sort();
  const roles = [...new Set([
    ...(report.authenticationLifecycle?.observations ?? []).flatMap((item) => item.actorModel.flatMap((actor) => [actor.safeAlias, actor.relationship, actor.tenantAlias ?? ""])),
    ...(report.businessInvariant?.observations ?? []).flatMap((item) => item.actorModel.flatMap((actor) => [actor.safeAlias, actor.relationship, actor.tenantAlias ?? ""])),
    ...(report.apiGraphql?.authorizationMatrices ?? []).flatMap((item) => item.cells.flatMap((cell) => [cell.actorAlias, cell.relationship])),
    ...(report.supabaseAuthorization?.observations ?? []).flatMap((item) => [item.actor, item.boundary])
  ].filter(Boolean).map(safeName))].sort();
  const versions = [...new Set((report.apiGraphql?.inventory ?? []).flatMap((item) => item.version ? [safeName(item.version)] : []))].sort();
  const reportCases = observedWorkflowCases(report);
  const mergedCases = new Map([...workflowCases, ...reportCases].map((item) => [item.key, item]));
  const producers = [report.apiMapper && "api-mapper", report.apiProbe && "api-probe", report.apiGraphql && "api-graphql", report.browserCrawl?.authentication && "browser-learning", report.supabaseAuthorization && "supabase-authorization", report.authenticationLifecycle && "authentication-lifecycle", report.businessInvariant && "business-invariant", report.controlledRace && "controlled-race", report.linkPortalSecurity && "link-portal-export-security", report.operationalEndpointSecurity && "operational-endpoint-security", report.billingEntitlement && "billing-entitlement-security", report.activeVulnerability && "active-vulnerability-validation", report.protocolSecurity && "protocol-security"].filter((item): item is string => Boolean(item)).sort();
  const buildSignals = { technologies: report.technologies.map((item) => item.name).sort(), nextBuild: report.nextJsReview?.buildIds ?? [] };
  const attackGraph = buildAdaptiveAttackStateGraph(report);
  return { schemaVersion: 2, buildFingerprint: adaptiveDigest(buildSignals), buildEvidence: buildSignals.technologies.length > 0 || buildSignals.nextBuild.length > 0, producers, origins: [...origins].sort(), routes: [...routes.values()].sort(byKey), fields, apiFields, cookies, graphql, graphqlOperations, adminRoutes: [...new Set((report.browserCrawl?.authentication?.adminRoutes ?? []).flatMap((item) => { const url = adaptiveHttpUrl(item, report.target); return url ? [safePath(url.pathname)] : []; }))].sort(), roles, versions, supabaseResources, lifecycleCategories, workflowCases: [...mergedCases.values()].sort(byKey), attackGraph };
}

function observedWorkflowCases(report: RouteCairnReport): AdaptiveInventory["workflowCases"] {
  const output: AdaptiveInventory["workflowCases"] = [];
  const add = (workflowId: string, values: readonly unknown[], idFields: readonly string[] = ["caseId", "checkId", "id"]): void => {
    for (const value of values) {
      if (!value || typeof value !== "object") continue;
      const item = value as Record<string, unknown>;
      const alias = idFields.map((field) => item[field]).find((candidate) => typeof candidate === "string") as string | undefined;
      const fingerprint = typeof item.comparisonFingerprint === "string" && /^[a-f0-9]{64}$/i.test(item.comparisonFingerprint) ? item.comparisonFingerprint.toLowerCase() : undefined;
      if (!alias || !fingerprint) continue;
      const outcome = String(item.outcome ?? item.observedDecision ?? "OBSERVED");
      output.push({ key: `${workflowId}:${safeName(alias)}:${fingerprint}`, workflowId, fingerprint, executionState: /BLOCKED/.test(outcome) ? "BLOCKED" : /INCONCLUSIVE|ERROR|FAILED/.test(outcome) ? "FAILED" : "COMPLETED" });
    }
  };
  add("supabase-authorization", report.supabaseAuthorization?.observations ?? []);
  add("supabase-static-risk", report.supabaseAuthorization?.staticRisks ?? []);
  add("authentication-lifecycle", report.authenticationLifecycle?.observations ?? []);
  add("business-invariant", report.businessInvariant?.observations ?? []);
  add("controlled-race", report.controlledRace?.observations ?? []);
  add("api-graphql-authorization", report.apiGraphql?.checks ?? []);
  add("api-schema-comparison", report.apiGraphql?.schemaComparisons ?? [], ["routeId"]);
  add("link-portal-export-security", report.linkPortalSecurity?.observations ?? []);
  add("operational-endpoint-security", report.operationalEndpointSecurity?.observations ?? []);
  add("billing-entitlement-security", report.billingEntitlement?.observations ?? []);
  add("active-vulnerability-validation", report.activeVulnerability?.cases ?? []);
  add("protocol-security", report.protocolSecurity?.observations ?? []);
  return output;
}

export function compareAdaptiveInventories(before: AdaptiveInventory, after: AdaptiveInventory, includeRemoved: boolean): AdaptiveDrift[] {
  const output: AdaptiveDrift[] = [];
  const covered = (producer: string): boolean => (before.producers ?? []).includes(producer) && (after.producers ?? []).includes(producer);
  const routeRemovalCovered = [...new Set(before.routes.map((item) => item.source))].every((source) => (after.producers ?? []).includes(source === "api-graphql-inventory" ? "api-graphql" : source));
  compareSet(before.routes, after.routes, "key", "NEW_ROUTE", "REMOVED_ROUTE", output, includeRemoved && routeRemovalCovered, (item) => item.stateChanging ? "HIGH" : "MEDIUM");
  compareSet(before.graphql.map((key) => ({ key })), after.graphql.map((key) => ({ key })), "key", "NEW_GRAPHQL_OPERATION", "REMOVED_GRAPHQL_OPERATION", output, includeRemoved && covered("api-graphql"), () => "HIGH");
  compareSet(before.graphqlOperations ?? [], after.graphqlOperations ?? [], "key", "NEW_GRAPHQL_TEST_CONTRACT", "REMOVED_GRAPHQL_TEST_CONTRACT", output, includeRemoved && covered("api-graphql"), () => "HIGH");
  compareSet(before.origins.map((key) => ({ key })), after.origins.map((key) => ({ key })), "key", "NEW_ORIGIN", "REMOVED_ORIGIN", output, includeRemoved && routeRemovalCovered, () => "HIGH");
  compareSet(before.adminRoutes.map((key) => ({ key })), after.adminRoutes.map((key) => ({ key })), "key", "NEW_ADMIN_ROUTE", "REMOVED_ADMIN_ROUTE", output, includeRemoved && covered("browser-learning"), () => "HIGH");
  const allBeforeProducersCovered = (before.producers ?? []).every((producer) => (after.producers ?? []).includes(producer));
  compareSet((before.roles ?? []).map((key) => ({ key })), (after.roles ?? []).map((key) => ({ key })), "key", "NEW_ACTOR_ROLE", "REMOVED_ACTOR_ROLE", output, includeRemoved && allBeforeProducersCovered, () => "MEDIUM");
  compareSet((before.versions ?? []).map((key) => ({ key })), (after.versions ?? []).map((key) => ({ key })), "key", "NEW_API_VERSION", "REMOVED_API_VERSION", output, includeRemoved && covered("api-graphql"), () => "HIGH");
  compareSet(before.lifecycleCategories.map((key) => ({ key })), after.lifecycleCategories.map((key) => ({ key })), "key", "NEW_LIFECYCLE_CATEGORY", "REMOVED_LIFECYCLE_CATEGORY", output, includeRemoved && covered("authentication-lifecycle"), () => "MEDIUM");
  compareSet(before.supabaseResources, after.supabaseResources, "key", "NEW_DATA_RESOURCE", "REMOVED_DATA_RESOURCE", output, includeRemoved && covered("supabase-authorization"), () => "HIGH");
  const workflowRemovalCovered = [...new Set(before.workflowCases.map((item) => item.workflowId))].every((workflow) => (after.producers ?? []).includes(workflow) || after.workflowCases.some((item) => item.workflowId === workflow));
  compareSet(before.workflowCases, after.workflowCases, "key", "NEW_TEST_CONTRACT", "REMOVED_TEST_CONTRACT", output, includeRemoved && workflowRemovalCovered, () => "HIGH");
  const previousFields = new Map(before.fields.map((item) => [item.key, item]));
  for (const item of after.fields) { const old = previousFields.get(item.key); if (!old && item.access === "writable") output.push(drift("NEW_WRITABLE_FIELD", "HIGH", item.key, `New writable browser field observed at ${item.pagePath}.`)); else if (old && old.access !== item.access) output.push(drift("FIELD_ACCESS_CHANGED", item.access === "writable" ? "HIGH" : "MEDIUM", item.key, `Browser field access changed from ${old.access} to ${item.access}.`)); }
  const previousCookies = new Map(before.cookies.map((item) => [item.key, item]));
  for (const item of after.cookies) { const old = previousCookies.get(item.key); if (!old && item.classification === "authentication") output.push(drift("NEW_AUTH_COOKIE", "HIGH", item.key, "A new authentication cookie was observed.")); else if (old && adaptiveDigest(old) !== adaptiveDigest(item)) output.push(drift("COOKIE_SECURITY_CHANGED", "HIGH", item.key, "Authentication or cookie security attributes changed.")); }
  const previousApiFields = new Map((before.apiFields ?? []).map((item) => [item.key, item]));
  for (const item of after.apiFields ?? []) { const old = previousApiFields.get(item.key); if (!old) output.push(drift("NEW_API_RESPONSE_FIELD", /secret|token|credential|payment|identity|private|sensitive/i.test(item.classification) ? "HIGH" : "MEDIUM", item.key, `A new API response field classification was observed at ${item.path}.`)); else if (adaptiveDigest(old) !== adaptiveDigest(item)) output.push(drift("API_FIELD_EXPECTATION_CHANGED", "HIGH", item.key, "An API response field classification or expected exposure changed.")); }
  const previousResources = new Map(before.supabaseResources.map((item) => [item.key, item]));
  for (const item of after.supabaseResources) { const old = previousResources.get(item.key); if (old && adaptiveDigest(old) !== adaptiveDigest(item)) output.push(drift("DATA_RESOURCE_POLICY_CHANGED", "HIGH", item.key, "A Supabase/PostgREST resource actor or operation boundary changed.")); }
  compareAttackGraphs(before.attackGraph, after.attackGraph, includeRemoved, output);
  if (before.buildEvidence && after.buildEvidence && before.buildFingerprint !== after.buildFingerprint) output.push(drift("BUILD_CHANGED", "INFO", "build", "The observed product/build fingerprint changed; required acceptance coverage must be re-evaluated."));
  return output;
}

function compareAttackGraphs(before: AdaptiveAttackStateGraph | undefined, after: AdaptiveAttackStateGraph | undefined, includeRemoved: boolean, output: AdaptiveDrift[]): void {
  if (!after) return;
  if (!before) {
    output.push(drift("ATTACK_GRAPH_ESTABLISHED", "INFO", after.graphFingerprint, `An evidence-backed attack-state graph was established with ${after.nodes.length} nodes, ${after.edges.length} relationships, and ${after.paths.length} paths.`));
    return;
  }
  const start = output.length;
  const limit = 200;
  let truncated = false;
  const push = (item: AdaptiveDrift): void => { if (output.length - start < limit - 1) output.push(item); else truncated = true; };
  const previousNodes = new Map(before.nodes.map((item) => [item.id, item]));
  const currentNodes = new Map(after.nodes.map((item) => [item.id, item]));
  for (const node of after.nodes) if (!previousNodes.has(node.id) && ["ACTOR", "ROLE", "TENANT", "OBJECT", "CAPABILITY", "OPERATION", "BROWSER_STATE"].includes(node.kind)) push(drift(`NEW_GRAPH_${node.kind}`, ["CAPABILITY", "OPERATION"].includes(node.kind) ? "HIGH" : "MEDIUM", node.id, `A new evidence-backed ${node.kind.toLowerCase().replaceAll("_", " ")} was observed: ${node.label}.`));
  const previousEdges = new Map(before.edges.map((item) => [item.id, item]));
  for (const edge of after.edges) if (!previousEdges.has(edge.id) && (["OWNS", "ISSUES", "CONSUMES", "PRODUCES", "EFFECTS", "CLEANED_BY"].includes(edge.kind) || edge.stateChanging)) push(drift(`NEW_GRAPH_${edge.kind}_RELATIONSHIP`, edge.stateChanging || ["OWNS", "ISSUES", "CONSUMES"].includes(edge.kind) ? "HIGH" : "MEDIUM", edge.id, `A new evidence-backed ${edge.kind.toLowerCase().replaceAll("_", " ")} relationship was observed.`));
  const previousPaths = new Map(before.paths.map((item) => [item.id, item]));
  const currentPaths = new Map(after.paths.map((item) => [item.id, item]));
  for (const path of after.paths) {
    const old = previousPaths.get(path.id);
    if (!old) push(drift(path.mutability === "STATE_CHANGING" ? "NEW_STATE_CHANGING_GRAPH_PATH" : "NEW_READ_ONLY_GRAPH_PATH", path.mutability === "STATE_CHANGING" ? "HIGH" : "MEDIUM", path.id, `A new ${path.mutability.toLowerCase().replaceAll("_", " ")} attack-state path was observed: ${path.label}.`));
    else if (adaptiveDigest(graphPathContract(old)) !== adaptiveDigest(graphPathContract(path))) push(drift("GRAPH_PATH_CONTRACT_CHANGED", "HIGH", path.id, `The evidence, readiness, or required bindings changed for attack-state path ${path.label}.`));
  }
  const removalCovered = includeRemoved && !before.bounds.truncated && !after.bounds.truncated && before.producers.every((producer) => after.producers.includes(producer));
  if (removalCovered) {
    for (const node of before.nodes) if (!currentNodes.has(node.id) && ["ACTOR", "ROLE", "TENANT", "OBJECT", "CAPABILITY", "OPERATION", "BROWSER_STATE"].includes(node.kind)) push(drift(`REMOVED_GRAPH_${node.kind}`, "MEDIUM", node.id, `A previously observed ${node.kind.toLowerCase().replaceAll("_", " ")} is no longer present: ${node.label}.`));
    for (const path of before.paths) if (!currentPaths.has(path.id)) push(drift("REMOVED_GRAPH_PATH", path.mutability === "STATE_CHANGING" ? "HIGH" : "MEDIUM", path.id, `A previously observed attack-state path is no longer present: ${path.label}.`));
  }
  if (truncated) output.push(drift("ATTACK_GRAPH_DRIFT_TRUNCATED", "INFO", after.graphFingerprint, `Attack-state graph drift was capped at ${limit} records for bounded review.`));
}

function graphPathContract(path: AdaptiveAttackPath): unknown { return { mutability: path.mutability, automationState: path.automationState, contractReadiness: path.contractReadiness, engineId: path.engineId, sourceCaseFingerprints: path.sourceCaseFingerprints, requiredBindings: path.requiredBindings, evidence: path.evidence }; }

export function synthesizeAdaptiveRecommendations(report: RouteCairnReport, inventory: AdaptiveInventory, drifts: AdaptiveDrift[]): AdaptiveRecommendation[] {
  const result = new Map<string, AdaptiveRecommendation>();
  const graph = inventory.attackGraph;
  const coveredGraphPaths = new Set<string>();
  const graphPathIdsForRoute = (method: string, pathTemplate: string, mutability?: AdaptiveAttackPath["mutability"]): string[] => {
    if (!graph) return [];
    const operationIds = new Set(graph.nodes.filter((node) => node.kind === "OPERATION" && (node.attributes.origin === undefined || node.attributes.origin === new URL(report.target).origin) && node.attributes.method === method.toUpperCase() && node.attributes.pathTemplate === pathTemplate).map((node) => node.id));
    return graph.paths.filter((path) => (!mutability || path.mutability === mutability) && path.nodeIds.some((id) => operationIds.has(id))).map((path) => path.id).slice(0, 32);
  };
  const graphPathIdsForCases = (engineId: string, fingerprints: readonly string[]): string[] => graph ? graph.paths.filter((path) => path.engineId === engineId && path.sourceCaseFingerprints.some((fingerprint) => fingerprints.includes(fingerprint))).map((path) => path.id).slice(0, 32) : [];
  type Compiled = AdaptiveCompiledReadOnlyCase | AdaptiveCompiledContract;
  const add = (item: Omit<AdaptiveRecommendation, "sourceFingerprint" | "operatorApprovalRequired"> & { source: unknown; compiled?: Compiled | undefined; graphPathIds?: readonly string[] }) => {
    const graphPathIds = [...new Set((item.graphPathIds ?? []).filter((id) => /^[a-f0-9]{64}$/.test(id)))].sort().slice(0, 32);
    graphPathIds.forEach((id) => coveredGraphPaths.add(id));
    const sourceFingerprint = adaptiveDigest(graphPathIds.length ? { evidence: item.source, graphPathIds } : item.source);
    const key = `${item.category}:${sourceFingerprint}`;
    const graphBinding = graph && graphPathIds.length ? { attackGraphBinding: { graphFingerprint: graph.graphFingerprint, graphPathIds } } : {};
    const draft = item.compiled ? executableDraft({ ...item.draft, ...graphBinding }, item.compiled, sourceFingerprint) : { ...item.draft, ...graphBinding, automation: { state: "REQUIRES_BINDINGS", compilerVersion: 1, mutationApprovalRequired: item.mutationHypothesis, unresolvedBindings: item.requiredBindings } };
    const approvalRequired = item.compiled ? "mutationApprovalRequired" in item.compiled && item.compiled.mutationApprovalRequired : true;
    result.set(key, { category: item.category, engineId: item.engineId, laneKind: item.laneKind, mutationHypothesis: item.mutationHypothesis, sourceFingerprint, operatorApprovalRequired: approvalRequired, draft, requiredBindings: item.compiled ? [] : item.requiredBindings });
  };
  for (const compiled of compileExecutedContracts(report)) {
    const graphPathIds = graphPathIdsForCases(compiled.engineId, compiled.sourceCaseFingerprints);
    if (!graphPathIds.length || graphPathIds.some((id) => graph?.paths.find((path) => path.id === id)?.contractReadiness !== "COMPLETE")) continue;
    add({
      category: `EXACT_CONTRACT_REPLAY_${compiled.engineId.toUpperCase().replaceAll("-", "_")}`,
      engineId: compiled.engineId,
      laneKind: engineLane(compiled.engineId),
      mutationHypothesis: compiled.mutationApprovalRequired,
      source: { engineId: compiled.engineId, evidenceFingerprint: compiled.evidenceFingerprint, sourceCaseFingerprints: compiled.sourceCaseFingerprints },
      draft: { exactExecutedContract: true, sourceCaseFingerprints: compiled.sourceCaseFingerprints },
      requiredBindings: [],
      compiled,
      graphPathIds
    });
  }
  for (const candidate of report.browserCrawl?.authentication?.learnedTestCases ?? []) {
    const candidateUrl = adaptiveHttpUrl(candidate.endpoint, report.target);
    if (!candidateUrl || candidateUrl.origin !== new URL(report.target).origin) continue;
    const candidatePath = safePath(candidateUrl.pathname);
    const candidateGraphPaths = graphPathIdsForRoute(candidate.method, candidatePath, candidate.classification === "MUTATION_HYPOTHESIS" ? "STATE_CHANGING" : "READ_ONLY");
    for (const category of candidate.suggestedLifecycleCategories) add({ category: `LIFECYCLE_${category}`, engineId: "authentication-lifecycle", laneKind: "AUTHENTICATION_LIFECYCLE", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { category, method: candidate.method, endpoint: candidatePath, fields: candidate.observedFieldNames.map(safeName).sort(), bodyFormat: candidate.requestBodyFormat ?? "NONE", authorizationContext: candidate.authorizationContext, classification: candidate.classification }, draft: learnedDraft(candidate, category), requiredBindings: lifecycleBindings(category), graphPathIds: candidateGraphPaths });
    const path = candidatePath;
    if (/graphql/i.test(path)) { const compiled = candidate.classification === "READ_ONLY_OBSERVATION" ? compileGraphqlIntrospectionCase(report, path) : undefined; add({ category: compiled ? "GRAPHQL_INTROSPECTION_READ_ONLY" : "GRAPHQL_OPERATION_REVIEW", engineId: "api-graphql-authorization", laneKind: "API_GRAPHQL_AUTHORIZATION", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { method: candidate.method, path, fields: candidate.observedFieldNames.map(safeName).sort() }, draft: { sourceCandidateId: candidate.id, protocol: "GRAPHQL", pathTemplate: path, method: candidate.method, executable: Boolean(compiled) }, requiredBindings: ["named operation", "actor matrix", "field expectations", "tenant expectation"], compiled, graphPathIds: candidateGraphPaths }); }
    if (/signed|invite|portal|export|download/i.test(path)) add({ category: "CAPABILITY_LINK_REVIEW", engineId: "link-portal-export-security", laneKind: "DATA_AUTHORIZATION", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { method: candidate.method, path, fields: candidate.observedFieldNames.map(safeName).sort() }, draft: { sourceCandidateId: candidate.id, pathTemplate: path, method: candidate.method, executable: false }, requiredBindings: ["resource owner", "tenant", "expiry", "tamper/replay assertions", "cleanup"] });
    if (/webhook|cron|job|health|admin|worker/i.test(path)) {
      const operational = candidate.classification === "READ_ONLY_OBSERVATION" ? compileOperationalHealthCase(report, { protocol: "REST", method: candidate.method, pathTemplate: path, source: "browser-learning", stateChanging: false }) : undefined;
      add({ category: operational ? "OPERATIONAL_HEALTH_READ_ONLY" : "OPERATIONAL_ENDPOINT_REVIEW", engineId: "operational-endpoint-security", laneKind: "OPERATIONAL_ENDPOINTS", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { method: candidate.method, path, fields: candidate.observedFieldNames.map(safeName).sort() }, draft: { sourceCandidateId: candidate.id, pathTemplate: path, method: candidate.method, executable: Boolean(operational) }, requiredBindings: operational ? [] : ["endpoint kind", "authorized actor", "signature/auth expectation", "replay/workload bounds", "cleanup"], compiled: operational });
    }
    if (/checkout|billing|payment|subscription|plan|entitlement|premium|refund|invoice/i.test(path)) {
      const billing = candidate.classification === "READ_ONLY_OBSERVATION" ? compileBillingReadOnlyCase(report, { protocol: "REST", method: candidate.method, pathTemplate: path, source: "browser-learning", stateChanging: false }) : undefined;
      add({ category: billing ? "SYNTHETIC_BILLING_READ_ONLY" : "SYNTHETIC_BILLING_REVIEW", engineId: "billing-entitlement-security", laneKind: "BILLING_ENTITLEMENTS", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { method: candidate.method, path, fields: candidate.observedFieldNames.map(safeName).sort() }, draft: { sourceCandidateId: candidate.id, pathTemplate: path, method: candidate.method, providerMode: "SYNTHETIC_ONLY", realPaymentExecution: "FORBIDDEN", executable: Boolean(billing) }, requiredBindings: billing ? [] : ["test-provider fixture", "synthetic event", "account ownership", "authoritative entitlement verification", "cleanup"], compiled: billing });
    }
    if (!/graphql|signed|invite|portal|export|download|webhook|cron|job|health|admin|worker|checkout|billing|payment|subscription|plan|entitlement|premium|refund|invoice/i.test(path) && candidate.classification === "READ_ONLY_OBSERVATION") {
      const invariant = compileBusinessInvariantReadOnlyCase(report, { protocol: "REST", method: candidate.method, pathTemplate: path, source: "browser-learning", stateChanging: false });
      if (invariant) add({ category: "BUSINESS_INVARIANT_READ_ONLY", engineId: "business-invariant", laneKind: "BUSINESS_LOGIC", mutationHypothesis: false, source: { method: candidate.method, path, kind: "stable-observation" }, draft: { sourceCandidateId: candidate.id, pathTemplate: path, method: candidate.method, executable: true }, requiredBindings: [], compiled: invariant });
    }
  }
  for (const item of inventory.routes.filter((route) => (!route.origin || route.origin === new URL(report.target).origin) && (route.source === "api-mapper" || route.source === "api-graphql-inventory" || (route.source === "browser-learning" && !route.stateChanging)))) {
    const compiled = item.protocol === "REST" ? compileRouteReadOnlyCase(report, item) : !item.stateChanging ? compileGraphqlIntrospectionCase(report, item.pathTemplate) : undefined;
    const routeGraphPaths = graphPathIdsForRoute(item.method, item.pathTemplate, compiled || !item.stateChanging ? "READ_ONLY" : "STATE_CHANGING");
    add({ category: compiled ? (item.protocol === "REST" ? "API_READ_ONLY_REGRESSION" : "GRAPHQL_INTROSPECTION_READ_ONLY") : "API_AUTHORIZATION_MATRIX", engineId: "api-graphql-authorization", laneKind: "API_GRAPHQL_AUTHORIZATION", mutationHypothesis: item.stateChanging && !compiled, source: item, draft: { protocol: item.protocol, pathTemplate: item.pathTemplate, documentedMethods: [item.method], executable: Boolean(compiled) }, requiredBindings: ["Account A/B object identities", "expected decisions", "response field rules"], compiled, graphPathIds: item.stateChanging ? [] : routeGraphPaths });
    if (item.stateChanging) {
      add({ category: "BUSINESS_INVARIANT_CANDIDATE", engineId: "business-invariant", laneKind: "BUSINESS_LOGIC", mutationHypothesis: true, source: { method: item.method, pathTemplate: item.pathTemplate }, draft: { pathTemplate: item.pathTemplate, method: item.method, executable: false }, requiredBindings: ["pre-state", "bounded action sequence", "expected invariant", "authoritative post-state", "verified cleanup"], graphPathIds: routeGraphPaths });
    } else {
      const invariant = item.protocol === "REST" ? compileBusinessInvariantReadOnlyCase(report, item) : undefined;
      if (invariant) add({ category: "BUSINESS_INVARIANT_READ_ONLY", engineId: "business-invariant", laneKind: "BUSINESS_LOGIC", mutationHypothesis: false, source: { method: item.method, pathTemplate: item.pathTemplate, kind: "stable-observation" }, draft: { pathTemplate: item.pathTemplate, method: item.method, executable: true }, requiredBindings: [], compiled: invariant });
    }
    if (/signed|invite|portal|export|download|report|evidence/i.test(item.pathTemplate)) add({ category: "CAPABILITY_LINK_REVIEW", engineId: "link-portal-export-security", laneKind: "DATA_AUTHORIZATION", mutationHypothesis: item.stateChanging, source: { method: item.method, pathTemplate: item.pathTemplate }, draft: { pathTemplate: item.pathTemplate, method: item.method, executable: false }, requiredBindings: ["resource owner", "tenant", "expiry", "tamper/replay assertions", "cleanup"] });
    if (/webhook|cron|job|health|incident|admin|worker|status|readiness|liveness/i.test(item.pathTemplate)) { const operational = compileOperationalHealthCase(report, item); add({ category: operational ? "OPERATIONAL_HEALTH_READ_ONLY" : "OPERATIONAL_ENDPOINT_REVIEW", engineId: "operational-endpoint-security", laneKind: "OPERATIONAL_ENDPOINTS", mutationHypothesis: item.stateChanging, source: { method: item.method, pathTemplate: item.pathTemplate }, draft: { pathTemplate: item.pathTemplate, method: item.method, executable: Boolean(operational) }, requiredBindings: ["endpoint kind", "authorized actor", "signature/auth expectation", "replay/workload bounds", "cleanup"], compiled: operational }); }
    if (/checkout|billing|payment|subscription|plan|entitlement|premium|refund|invoice/i.test(item.pathTemplate)) {
      const billing = item.protocol === "REST" ? compileBillingReadOnlyCase(report, item) : undefined;
      add({ category: billing ? "SYNTHETIC_BILLING_READ_ONLY" : "SYNTHETIC_BILLING_REVIEW", engineId: "billing-entitlement-security", laneKind: "BILLING_ENTITLEMENTS", mutationHypothesis: item.stateChanging, source: { method: item.method, pathTemplate: item.pathTemplate }, draft: { pathTemplate: item.pathTemplate, method: item.method, providerMode: "SYNTHETIC_ONLY", realPaymentExecution: "FORBIDDEN", executable: Boolean(billing) }, requiredBindings: billing ? [] : ["test-provider fixture", "synthetic event", "account ownership", "authoritative entitlement verification", "cleanup"], compiled: billing });
    }
  }
  for (const path of inventory.graphql) {
    const compiled = compileGraphqlIntrospectionCase(report, path);
    if (!compiled) continue;
    add({ category: "GRAPHQL_INTROSPECTION_READ_ONLY", engineId: "api-graphql-authorization", laneKind: "API_GRAPHQL_AUTHORIZATION", mutationHypothesis: false, source: { protocol: "GRAPHQL", path, kind: "generated-introspection" }, draft: { protocol: "GRAPHQL", pathTemplate: path, operation: "GENERATED_INTROSPECTION", executable: true }, requiredBindings: [], compiled });
  }
  for (const item of inventory.supabaseResources) { const compiled = item.operations.every((operation) => operation === "SELECT") ? compileSupabaseReadOnlyCase(report, item) : undefined; add({ category: compiled ? "SUPABASE_ANONYMOUS_READ_REGRESSION" : "SUPABASE_AUTHORIZATION_MATRIX", engineId: "supabase-authorization", laneKind: "DATA_AUTHORIZATION", mutationHypothesis: item.operations.some((operation) => operation !== "SELECT"), source: item, draft: { surface: item.surface, resource: item.resource, operations: item.operations, actors: item.actors, executable: Boolean(compiled) }, requiredBindings: ["Account A/B and tenant identities", "exact object bindings", "expected decisions", "sensitive columns", "cleanup for writes"], compiled }); }
  for (const path of graph?.paths.filter((item) => item.mutability === "STATE_CHANGING" && !coveredGraphPaths.has(item.id)) ?? []) {
    if (!advancedEngineCatalog.some((entry) => entry.id === path.engineId)) continue;
    const nodeKinds = [...new Set(path.nodeIds.map((id) => graph?.nodes.find((node) => node.id === id)?.kind).filter((kind): kind is NonNullable<typeof kind> => Boolean(kind)))];
    const requiredBindings = path.requiredBindings.length ? [...path.requiredBindings] : ["compiler-valid exact execution contract", "explicit operator review"];
    add({ category: "ATTACK_GRAPH_STATE_TRANSITION", engineId: path.engineId, laneKind: engineLane(path.engineId), mutationHypothesis: true, source: { graphPathId: path.id, engineId: path.engineId, sourceCaseFingerprints: path.sourceCaseFingerprints }, draft: { graphPathId: path.id, label: path.label, nodeKinds, contractReadiness: path.contractReadiness, executable: false }, requiredBindings, graphPathIds: [path.id] });
  }
  for (const item of drifts.filter((entry) => entry.severity === "HIGH")) add({ category: `DRIFT_${item.type}`, engineId: driftEngine(item.type), laneKind: driftLane(item.type), mutationHypothesis: false, source: item, draft: { semanticKey: item.semanticKey, safeSummary: item.summary }, requiredBindings: ["operator review", "exact regression case", "authoritative expected outcome"] });
  return [...result.values()];
}

function learnedDraft(candidate: BrowserLearnedTestCase, category: string): Record<string, unknown> { return { sourceCandidateId: candidate.id, category, method: candidate.method, pathTemplate: safePath(new URL(candidate.endpoint).pathname), requestBodyFormat: candidate.requestBodyFormat ?? "UNKNOWN", observedFieldNames: candidate.observedFieldNames.map(safeName).sort(), observedStatusCodes: [...candidate.observedStatusCodes].sort(), state: "DRAFT_REQUIRES_OPERATOR_CASE", executable: false }; }

function executableDraft(summary: Record<string, unknown>, compiled: AdaptiveCompiledReadOnlyCase | AdaptiveCompiledContract, sourceFingerprint: string): Record<string, unknown> { const exactContract = "mutationApprovalRequired" in compiled; const compilerVersion = exactContract ? 2 : 1; const mutationApprovalRequired = exactContract && compiled.mutationApprovalRequired; const automation = { state: mutationApprovalRequired ? "READY_APPROVAL_GATED" : "READY_READ_ONLY", compilerVersion, evidenceStrength: compiled.evidenceStrength, evidenceFingerprint: compiled.evidenceFingerprint, requestCount: compiled.requestCount, cleanupRequestCount: exactContract ? compiled.cleanupRequestCount : 0, authentication: exactContract ? compiled.authentication : "public", mutationApprovalRequired, summary: compiled.summary }; const executionFingerprintValue = adaptiveExecutionFingerprint(compiled.engineId, sourceFingerprint, compiled.evidenceFingerprint, compiled.engineConfiguration, compilerVersion); return { ...summary, executable: true, automation, engineConfiguration: compiled.engineConfiguration, executionFingerprint: executionFingerprintValue }; }

function lifecycleBindings(category: string): string[] { const common = ["disposable actor", "exact assertions", "expiring authorization", "verified cleanup"]; if (/RESET|INVITATION|MFA|PASSKEY|RECOVERY|LINKING|VERIFICATION/.test(category)) common.push("single-use token/fixture binding"); if (/EXPIRATION/.test(category)) common.push("bounded wait contract"); return common; }

function driftEngine(type: string): string { return type.includes("COOKIE") || type.includes("AUTH") ? "authentication-lifecycle" : type.includes("DATA") ? "supabase-authorization" : type.includes("WRITABLE") ? "business-invariant" : "api-graphql-authorization"; }

function driftLane(type: string): LiveAcceptanceLane["kind"] { return type.includes("COOKIE") || type.includes("AUTH") ? "AUTHENTICATION_LIFECYCLE" : type.includes("DATA") ? "DATA_AUTHORIZATION" : type.includes("WRITABLE") ? "BUSINESS_LOGIC" : "API_GRAPHQL_AUTHORIZATION"; }

function engineLane(engineId: string): LiveAcceptanceLane["kind"] { return engineId === "authentication-lifecycle" ? "AUTHENTICATION_LIFECYCLE" : engineId === "api-graphql-authorization" ? "API_GRAPHQL_AUTHORIZATION" : engineId === "supabase-authorization" || engineId === "link-portal-export-security" ? "DATA_AUTHORIZATION" : engineId === "billing-entitlement-security" ? "BILLING_ENTITLEMENTS" : engineId === "operational-endpoint-security" ? "OPERATIONAL_ENDPOINTS" : "BUSINESS_LOGIC"; }

function compareSet<T extends Record<string, unknown>>(before: T[], after: T[], key: keyof T, added: string, removed: string, output: AdaptiveDrift[], includeRemoved: boolean, severity: (item: T) => AdaptiveDrift["severity"]): void { const old = new Map(before.map((item) => [String(item[key]), item])); const next = new Map(after.map((item) => [String(item[key]), item])); for (const [id, item] of next) if (!old.has(id)) output.push(drift(added, severity(item), id, `${added.replaceAll("_", " ").toLowerCase()} observed: ${id}.`)); if (includeRemoved) for (const id of old.keys()) if (!next.has(id)) output.push(drift(removed, "MEDIUM", id, `${removed.replaceAll("_", " ").toLowerCase()} observed: ${id}.`)); }

function drift(type: string, severity: AdaptiveDrift["severity"], semanticKey: string, summary: string): AdaptiveDrift { return { type, severity, semanticKey, summary }; }

function safePath(value: string): string { const path = value.split("?")[0]!.replace(/\/(?:tokens?|secrets?|reset-password|password-reset|verify-email|magic-link)\/[^/]+/gi, (match) => `${match.slice(0, match.lastIndexOf("/"))}/:token`).replace(/\/[0-9]{2,}(?=\/|$)/g, "/:id").replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, "/:id").replace(/\/[A-Za-z0-9_-]{32,}(?=\/|$)/g, "/:token"); return (path.startsWith("/") ? path : `/${path}`).slice(0, 500); }

function safeName(value: string): string { return value.replace(/[\r\n\0|]/g, "_").slice(0, 160); }

function byKey<T extends { key: string }>(a: T, b: T): number { return a.key.localeCompare(b.key); }

export interface AdaptiveDrift { type: string; severity: "INFO" | "LOW" | "MEDIUM" | "HIGH"; semanticKey: string; summary: string }

export interface AdaptiveRecommendation { category: string; engineId: string; laneKind: LiveAcceptanceLane["kind"]; sourceFingerprint: string; mutationHypothesis: boolean; operatorApprovalRequired: boolean; draft: Record<string, unknown>; requiredBindings: string[] }
