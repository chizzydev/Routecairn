import { createHash } from "node:crypto";
import type { Finding } from "../core/findings/Finding.js";
import type { RouteCairnReport } from "../reports/ReportTypes.js";
import { referencesFor, wstgAreaFor, wstgAreas } from "./StandardsCatalog.js";
import { mappingFor, mappingForFinding } from "./StandardsMappings.js";
import type { StandardsCoverageCase, StandardsCoverageGap, StandardsCoverageOutcome, StandardsCoverageReport, StandardsReference, StandardsRequirementCoverage } from "./StandardsCoverageTypes.js";

type CoverageInput = Omit<RouteCairnReport, "standardsCoverage"> & { standardsCoverage?: never };
type UnknownRecord = Record<string, unknown>;

interface AddCaseInput {
  moduleId: string;
  caseId: unknown;
  label?: unknown;
  discriminator?: unknown;
  outcome?: unknown;
  finding?: boolean;
  matched?: boolean;
  inconclusive?: boolean;
  blocked?: boolean;
  requestTransmitted?: boolean;
  evidenceRefs?: readonly string[];
  references?: readonly StandardsReference[];
}

export function buildStandardsCoverage(report: CoverageInput): StandardsCoverageReport {
  const cases = new Map<string, StandardsCoverageCase>();
  const findings = report.findings ?? [];
  const add = (input: AddCaseInput): void => {
    const caseId = safeCaseId(input.caseId);
    if (!caseId) return;
    const key = `${input.moduleId}/${caseId}`;
    const linkedFindings = findingsForCase(findings, input.moduleId, caseId);
    const outcome = classifyOutcome(input, linkedFindings.length > 0);
    const references = input.references ? [...input.references] : referencesFor(mappingFor(input.moduleId, safeText(input.discriminator)));
    const next: StandardsCoverageCase = {
      moduleId: input.moduleId,
      caseId,
      label: boundedLabel(input.label, caseId),
      outcome,
      executed: true,
      ...(input.requestTransmitted === undefined ? {} : { requestTransmitted: input.requestTransmitted }),
      findingIds: linkedFindings.map((finding) => finding.id).sort(),
      evidenceRefs: input.evidenceRefs?.length ? [...new Set(input.evidenceRefs)].sort() : [evidenceRef(input.moduleId, caseId)],
      references
    };
    const existing = cases.get(key);
    cases.set(key, existing ? mergeCase(existing, next) : next);
  };

  collectStructuredCases(report, add);
  collectDiscoveryCases(report, add);
  collectCompletedModuleReviews(report, add);
  collectUnlinkedFindings(findings, cases, add);

  const caseList = [...cases.values()].sort((left, right) => left.moduleId.localeCompare(right.moduleId) || left.caseId.localeCompare(right.caseId));
  const requirements = requirementCoverage(caseList);
  const areas = wstgAreas.map((area) => {
    const relevant = caseList.filter((item) => item.references.some((reference) => reference.framework === "OWASP_WSTG" && wstgAreaFor(reference.id) === area.id && reference.strength === "DIRECT"));
    const conclusiveCases = relevant.filter((item) => item.outcome === "FINDING" || item.outcome === "NO_FINDING").length;
    const requirementIds = [...new Set(relevant.flatMap((item) => item.references.filter((reference) => reference.framework === "OWASP_WSTG" && wstgAreaFor(reference.id) === area.id && reference.strength === "DIRECT").map((reference) => reference.id)))].sort((left, right) => naturalId(left).localeCompare(naturalId(right), undefined, { numeric: true }));
    return { id: area.id, title: area.title, status: relevant.length === 0 ? "NOT_ASSESSED" as const : conclusiveCases === 0 ? "PARTIAL" as const : "COVERED" as const, executedCases: relevant.length, conclusiveCases, requirementIds };
  });
  const counts = countOutcomes(caseList);
  const apiRiskObjectives = ([
    { id: "API4:2023", title: "Unrestricted Resource Consumption" },
    { id: "API6:2023", title: "Unrestricted Access to Sensitive Business Flows" },
    { id: "API10:2023", title: "Unsafe Consumption of APIs" }
  ] as const).map((objective) => {
    const relevant = caseList.filter((item) => item.references.some((reference) => reference.framework === "OWASP_API_TOP_10" && reference.id === objective.id && reference.strength === "DIRECT"));
    const conclusiveCases = relevant.filter((item) => item.outcome === "FINDING" || item.outcome === "NO_FINDING").length;
    return { ...objective, engineIds: [...new Set(relevant.map((item) => item.moduleId))].sort(), executedCases: relevant.length, conclusiveCases, status: relevant.length === 0 ? "NOT_ASSESSED" as const : conclusiveCases === 0 ? "PARTIAL" as const : "COVERED" as const };
  });
  return {
    schemaVersion: 1,
    generatedAt: report.metadata.completedAt,
    catalog: { wstg: "latest", wstgSnapshotDate: "2026-09-28", asvs: "5.0.0", apiSecurityTop10: "2023", cwe: "current", capec: "current" },
    accounting: {
      plannedModules: report.scanPlan.modules.length,
      executedCases: caseList.length,
      directlyMappedCases: caseList.filter((item) => item.references.some((ref) => ref.strength === "DIRECT")).length,
      supportingOnlyCases: caseList.filter((item) => item.references.length > 0 && item.references.every((ref) => ref.strength === "SUPPORTING")).length,
      unmappedCases: caseList.filter((item) => item.references.length === 0).length,
      ...counts
    },
    cases: caseList,
    requirements,
    wstgAreas: areas,
    apiRiskObjectives,
    gaps: priorityGaps(requirements),
    notes: [
      "Coverage records executed or attempted RouteCairn cases; it does not certify conformance with an entire standard.",
      "A requirement is only counted from retained case evidence. Planned modules and absent cases do not count as coverage.",
      "CWE and CAPEC references classify applicable weakness and attack patterns; they are supporting mappings rather than verification requirements.",
      "Inconclusive and blocked cases remain distinct and never count as a passing verification."
    ]
  };
}

function collectStructuredCases(report: CoverageInput, add: (value: AddCaseInput) => void): void {
  for (const item of report.activeVulnerability?.cases ?? []) add({ moduleId: "active-vulnerability-validation", caseId: item.caseId, label: item.label, discriminator: item.vulnerabilityClass, outcome: item.outcome, requestTransmitted: item.strategiesExecuted > 0 });
  for (const item of report.protocolSecurity?.observations ?? []) add({ moduleId: "protocol-security", caseId: item.caseId, label: item.label, discriminator: item.kind, outcome: item.outcome, requestTransmitted: item.outcome !== "BLOCKED" });
  for (const item of report.authenticationLifecycle?.observations ?? []) add({ moduleId: "authentication-lifecycle", caseId: item.caseId, label: item.label, discriminator: item.category, outcome: item.outcome, requestTransmitted: item.steps.some((step) => step.transmitted) });
  for (const item of report.businessInvariant?.observations ?? []) add({ moduleId: "business-invariant", caseId: item.caseId, label: item.label, discriminator: item.category, outcome: item.outcome, requestTransmitted: item.actions.some((step) => step.attemptsTransmitted > 0) });
  for (const item of report.controlledRace?.observations ?? []) add({ moduleId: "controlled-race", caseId: item.caseId, label: item.label, discriminator: item.category, outcome: item.outcome, requestTransmitted: item.groups.some((group) => group.requests.some((request) => request.transmitted)) });
  for (const item of report.apiGraphql?.checks ?? []) add({ moduleId: "api-graphql-authorization", caseId: item.checkId, label: item.label, discriminator: item.kind, outcome: item.outcome, requestTransmitted: item.requests.length > 0 });
  for (const item of report.apiGraphql?.schemaComparisons ?? []) add({ moduleId: "api-graphql-authorization", caseId: `schema/${item.routeId}`, label: item.routeAlias, discriminator: "SCHEMA_INVENTORY", outcome: item.outcome, requestTransmitted: true });
  for (const item of report.linkPortalSecurity?.observations ?? []) add({ moduleId: "link-portal-export-security", caseId: item.caseId, label: item.label, discriminator: item.category, outcome: item.outcome, requestTransmitted: item.steps.some((step) => step.transmitted) });
  for (const item of report.operationalEndpointSecurity?.observations ?? []) add({ moduleId: "operational-endpoint-security", caseId: item.caseId, label: item.label, discriminator: item.category, outcome: item.outcome, requestTransmitted: item.steps.some((step) => step.transmitted) });
  for (const item of report.billingEntitlement?.observations ?? []) add({ moduleId: "billing-entitlement-security", caseId: item.caseId, label: item.label, discriminator: item.category, outcome: item.outcome, requestTransmitted: item.steps.some((step) => step.attemptsTransmitted > 0) });
  for (const item of report.privilegeMutation?.observations ?? []) add({ moduleId: "privilege-mutation-testing", caseId: item.caseId, label: item.caseId, discriminator: item.intent, outcome: item.securityOutcome, requestTransmitted: item.requestTransmitted });
  for (const item of report.supabaseAuthorization?.observations ?? []) add({ moduleId: "supabase-authorization", caseId: item.caseId, label: item.caseId, discriminator: `${item.surface}_${item.operation}`, outcome: item.observedDecision, matched: item.matchedExpectation, finding: Boolean(item.findingCategory), requestTransmitted: true });
  for (const item of report.objectPairTesting?.cases ?? []) add({ moduleId: "object-pair-testing", caseId: item.caseId, label: item.objectType, finding: item.confirmedIssues.length > 0, matched: item.confirmedIssues.length === 0, inconclusive: item.inconclusive, requestTransmitted: [item.baselineA, item.baselineB, item.aToB, item.bToA].some((entry) => entry.response.statusCode !== undefined) });
  for (const item of report.fieldExposureTesting?.cases ?? []) add({ moduleId: "field-exposure-testing", caseId: item.caseId, label: item.objectType, finding: item.confirmedIssues.length > 0, matched: item.confirmedIssues.length === 0, inconclusive: item.inconclusive, requestTransmitted: item.executedRequests > 0 });
  for (const item of report.authorizationMatrix?.cases ?? []) add({ moduleId: "authorization-matrix-testing", caseId: `${item.matrixId}/${item.caseId}`, label: item.caseId, discriminator: item.findingCategory ?? item.actorRelationship, outcome: item.observedDecision, matched: item.matchedExpectation, finding: Boolean(item.findingCategory), requestTransmitted: item.statusCode !== undefined });
  for (const item of report.equivalentRouteTesting?.observations ?? []) add({ moduleId: "equivalent-route-testing", caseId: `${item.routeSetId}/${item.cellId}`, label: item.routeLabel, discriminator: item.findingCategory ?? item.routeCategory, outcome: item.observedDecision, matched: item.matchedExpectation, finding: Boolean(item.findingCategory), requestTransmitted: item.statusCode !== undefined });
  for (const item of report.collectionAuthorization?.observations ?? []) add({ moduleId: "collection-authorization-testing", caseId: `${item.collectionId}/${item.caseId}`, label: item.caseId, discriminator: item.findingCategory ?? item.category, outcome: item.observedDecision, matched: item.matchedExpectation, finding: Boolean(item.findingCategory), requestTransmitted: item.statusCode !== undefined });
  for (const item of report.bulkAuthorization?.observations ?? []) add({ moduleId: "bulk-authorization-testing", caseId: `${item.definitionId}/${item.caseId}`, label: item.caseId, discriminator: item.findingCategory ?? item.operationType, outcome: item.observedDecision, finding: Boolean(item.findingCategory), requestTransmitted: item.statusCode !== undefined });
  for (const item of report.fileAuthorization?.observations ?? []) add({ moduleId: "file-authorization-testing", caseId: `${item.definitionId}/${item.caseId}`, label: item.caseId, discriminator: item.findingCategory ?? item.category, outcome: item.observedDecision, finding: Boolean(item.findingCategory), requestTransmitted: item.statusCode !== undefined });
  for (const item of report.secretBoundary?.observations ?? []) add({ moduleId: "secret-boundary", caseId: item.comparisonFingerprint, label: `${item.surface}/${item.candidateName}`, discriminator: item.surface, outcome: item.outcome, requestTransmitted: true });
  for (const [profile, item] of Object.entries({ primary: report.identityVerification?.primary, accountA: report.identityVerification?.accountA, accountB: report.identityVerification?.accountB })) if (item) add({ moduleId: "identity-verification", caseId: profile, label: `${item.profileLabel} identity verification`, discriminator: item.category, outcome: item.verified ? "PASS" : "INCONCLUSIVE", inconclusive: !item.verified, requestTransmitted: item.statusCode !== undefined });
  for (const block of report.proofMode?.blocks ?? []) {
    const findingId = block.source === "finding" ? block.id.replace(/^proof-/, "") : undefined;
    const finding = findingId ? report.findings.find((item) => item.id === findingId) : undefined;
    const mapping = finding ? mappingForFinding(finding.type) : mappingFor("object-pair-testing");
    add({ moduleId: "proof-mode", caseId: block.id, label: block.title, discriminator: block.source, outcome: block.comparisons.some((comparison) => comparison.response.error) ? "INCONCLUSIVE" : "OBSERVED", requestTransmitted: block.comparisons.length > 0, references: referencesFor(mapping) });
  }
  if (report.browserCrawl?.authentication) add({ moduleId: "browser-crawler", caseId: "authenticated-browser-bootstrap", label: "Authenticated browser bootstrap", discriminator: "BROWSER_STORAGE", outcome: report.browserCrawl.authentication.bootstrapSucceeded ? "PASS" : "BLOCKED", requestTransmitted: report.browserCrawl.authentication.bootstrapSucceeded });
  for (const item of report.browserCrawl?.authentication?.storage ?? []) add({ moduleId: "browser-crawler", caseId: `storage/${shortHash(`${item.origin}:${item.storage}:${item.name}`)}`, label: `${item.storage} storage observation`, discriminator: "BROWSER_STORAGE", outcome: "OBSERVED", requestTransmitted: false });
}

function collectDiscoveryCases(report: CoverageInput, add: (value: AddCaseInput) => void): void {
  for (const [index, item] of (report.baseline?.probes ?? []).entries()) add({ moduleId: "baseline", caseId: `probe/${index + 1}/${shortHash(item.url)}`, label: "Baseline response probe", discriminator: "BASELINE", outcome: item.error ? "INCONCLUSIVE" : "OBSERVED", requestTransmitted: true });
  for (const item of report.technologies) add({ moduleId: "tech-fingerprint", caseId: `technology/${shortHash(item.name)}`, label: item.name, discriminator: item.category, outcome: "OBSERVED", requestTransmitted: false });
  for (const item of report.jsIntelligence?.scripts ?? []) add({ moduleId: "js-intelligence", caseId: `script/${shortHash(item.scriptUrl)}`, label: "JavaScript asset review", discriminator: "SCRIPT", outcome: item.downloaded ? "OBSERVED" : "INCONCLUSIVE", requestTransmitted: item.downloaded });
  for (const [index, item] of report.discoveredUrls.entries()) add({ moduleId: sourceModule(item.source), caseId: `observation/${index + 1}/${shortHash(item.url)}`, label: "Endpoint observation", discriminator: item.source, outcome: item.falsePositiveStatus === "likely-false-positive" ? "INCONCLUSIVE" : "OBSERVED", requestTransmitted: true });
  for (const item of report.apiMapper?.endpoints ?? []) add({ moduleId: "api-mapper", caseId: `route/${shortHash(`${item.method}:${item.endpoint}`)}`, label: `${item.method} API route`, discriminator: item.routeType, outcome: "OBSERVED", requestTransmitted: false });
  for (const item of report.apiProbe?.endpointsReviewed ?? []) add({ moduleId: "api-probe", caseId: `endpoint/${shortHash(item.endpoint)}`, label: "API endpoint probe", discriminator: "API_RECONNAISSANCE", outcome: Object.values(item.statusByMethod).some((status) => status !== "error") ? "OBSERVED" : "INCONCLUSIVE", requestTransmitted: true });
  for (const item of report.authSurface?.surfaces ?? []) add({ moduleId: "auth-surface", caseId: `surface/${shortHash(item.endpoint)}`, label: item.purpose, discriminator: item.abuseCategories.join("_"), outcome: "OBSERVED", requestTransmitted: false });
  for (const item of report.authenticatedScan?.results ?? []) add({ moduleId: "authenticated-testing", caseId: `comparison/${shortHash(item.url)}`, label: "Anonymous/authenticated comparison", discriminator: item.classification, outcome: item.classification === "inconclusive" || item.classification === "auth-error" ? "INCONCLUSIVE" : "OBSERVED", requestTransmitted: true });
  for (const item of report.roleComparison?.results ?? []) add({ moduleId: "role-comparison", caseId: `comparison/${shortHash(item.url)}`, label: "Role comparison", discriminator: item.classification, outcome: item.classification === "inconclusive" || item.classification === "role-error" ? "INCONCLUSIVE" : "OBSERVED", requestTransmitted: true });
  for (const item of report.stateAwareApi?.reviewedEndpoints ?? []) add({ moduleId: "state-aware-api", caseId: `endpoint/${shortHash(item.endpoint)}`, label: "State-aware API comparison", discriminator: item.accessComparison.signal, outcome: item.accessComparison.signal === "inconclusive" ? "INCONCLUSIVE" : "OBSERVED", requestTransmitted: item.safeMethodsTested.some((method) => method.statusCode !== undefined) });
  for (const item of report.parameterAnalysis?.analyzedUrls ?? []) add({ moduleId: "parameter-analysis", caseId: `url/${shortHash(item.url)}`, label: "Request parameter analysis", discriminator: item.highRisk ? "HIGH_RISK_PARAMETER" : "PARAMETER_INVENTORY", outcome: "OBSERVED", requestTransmitted: false });
  for (const [index, item] of (report.nextJsReview?.observations ?? []).entries()) { const record = item as unknown as UnknownRecord; add({ moduleId: "nextjs-review", caseId: `observation/${index + 1}/${shortHash(safeText(record.url) || safeText(record.path) || String(index))}`, label: "Next.js security observation", discriminator: safeText(record.category), outcome: "OBSERVED", requestTransmitted: true }); }
  for (const item of report.nextJsReview?.manifests ?? []) add({ moduleId: "nextjs-review", caseId: `manifest/${shortHash(item.url)}`, label: `${item.kind} review`, discriminator: item.parseStatus, outcome: nextJsOutcome(item.parseStatus), requestTransmitted: true });
  for (const item of report.nextJsReview?.dataRoutes ?? []) add({ moduleId: "nextjs-review", caseId: `data-route/${shortHash(item.url)}`, label: "Next.js data route review", discriminator: item.cacheRisk, outcome: item.cacheRisk === "not-reachable" ? "INCONCLUSIVE" : "OBSERVED", requestTransmitted: item.statusCode !== undefined });
  for (const item of report.nextJsReview?.sourceMaps ?? []) add({ moduleId: "nextjs-review", caseId: `source-map/${shortHash(item.url)}`, label: "Source map review", discriminator: item.parseStatus, outcome: nextJsOutcome(item.parseStatus), requestTransmitted: true });
}

function collectCompletedModuleReviews(report: CoverageInput, add: (value: AddCaseInput) => void): void {
  if (report.execution?.status !== "COMPLETED") return;
  const moduleReviews = new Set(["header-review", "cookie-review", "cors-review", "method-review", "exposure-review", "parameter-analysis", "vulnerability-workflows", "workflow-validation"]);
  for (const plan of report.scanPlan.modules) if (moduleReviews.has(plan.id)) {
    const moduleFindings = report.findings.filter((finding) => finding.sourceModule === plan.id);
    add({ moduleId: plan.id, caseId: "module-review", label: `${plan.id} completed review`, discriminator: plan.id, outcome: moduleFindings.length ? "FAIL" : "PASS", finding: moduleFindings.length > 0, requestTransmitted: report.metadata.totalRequests > 0 });
  }
}

function collectUnlinkedFindings(findings: readonly Finding[], cases: Map<string, StandardsCoverageCase>, add: (value: AddCaseInput) => void): void {
  const linked = new Set([...cases.values()].flatMap((item) => item.findingIds));
  for (const finding of findings) if (!linked.has(finding.id)) {
    const caseId = `finding/${finding.id}`;
    add({ moduleId: finding.sourceModule || "finding-analysis", caseId, label: finding.title, discriminator: finding.type, outcome: "FAIL", finding: true, requestTransmitted: true, evidenceRefs: [evidenceRef(finding.sourceModule || "finding-analysis", caseId)] });
    const key = `${finding.sourceModule || "finding-analysis"}/${caseId}`;
    const item = cases.get(key);
    if (item && item.references.length === 0) cases.set(key, { ...item, findingIds: [finding.id], references: referencesFor(mappingForFinding(finding.type)) });
  }
}

function requirementCoverage(cases: readonly StandardsCoverageCase[]): StandardsRequirementCoverage[] {
  const values = new Map<string, { reference: StandardsReference; cases: StandardsCoverageCase[] }>();
  for (const testCase of cases) for (const reference of testCase.references) {
    const key = `${reference.framework}/${reference.id}`;
    const entry = values.get(key) ?? { reference, cases: [] };
    entry.cases.push(testCase);
    values.set(key, entry);
  }
  return [...values.values()].map(({ reference, cases: linked }) => ({
    framework: reference.framework, id: reference.id, title: reference.title, url: reference.url,
    directCases: new Set(linked.filter((item) => item.references.some((ref) => ref.framework === reference.framework && ref.id === reference.id && ref.strength === "DIRECT")).map(caseKey)).size,
    supportingCases: new Set(linked.filter((item) => item.references.some((ref) => ref.framework === reference.framework && ref.id === reference.id && ref.strength === "SUPPORTING")).map(caseKey)).size,
    findings: linked.filter((item) => item.outcome === "FINDING").length,
    noFindings: linked.filter((item) => item.outcome === "NO_FINDING").length,
    inconclusive: linked.filter((item) => item.outcome === "INCONCLUSIVE").length,
    blocked: linked.filter((item) => item.outcome === "BLOCKED").length,
    observed: linked.filter((item) => item.outcome === "OBSERVED").length,
    caseIds: [...new Set(linked.map(caseKey))].sort()
  })).sort((left, right) => left.framework.localeCompare(right.framework) || naturalId(left.id).localeCompare(naturalId(right.id), undefined, { numeric: true }));
}

function priorityGaps(requirements: readonly StandardsRequirementCoverage[]): StandardsCoverageGap[] {
  const targets = [
    { framework: "OWASP_WSTG" as const, id: "WSTG-CRYP-01", title: "Transport cryptography", priority: "HIGH" as const },
    { framework: "OWASP_WSTG" as const, id: "WSTG-ERRH-01", title: "Error handling", priority: "MEDIUM" as const },
    { framework: "OWASP_WSTG" as const, id: "WSTG-CLNT-01", title: "DOM client-side injection", priority: "HIGH" as const },
    { framework: "OWASP_WSTG" as const, id: "WSTG-INJT-05", title: "Generalized database injection", priority: "HIGH" as const },
    { framework: "OWASP_API_TOP_10" as const, id: "API4:2023", title: "Unrestricted Resource Consumption", priority: "HIGH" as const },
    { framework: "OWASP_API_TOP_10" as const, id: "API6:2023", title: "Sensitive Business Flow Abuse", priority: "HIGH" as const },
    { framework: "OWASP_API_TOP_10" as const, id: "API10:2023", title: "Unsafe Consumption of APIs", priority: "HIGH" as const }
  ];
  return targets.flatMap<StandardsCoverageGap>((target) => {
    const item = requirements.find((entry) => entry.framework === target.framework && entry.id === target.id);
    if (!item) return [{ ...target, status: "NOT_ASSESSED", reason: "No retained executed case mapped directly to this coverage objective." }];
    if (item.directCases === 0) return [{ ...target, status: "SUPPORTING_ONLY", reason: "Only weakness or attack-pattern classification is available; no direct standards verification case was retained." }];
    if (item.findings + item.noFindings === 0) return [{ ...target, status: "INCONCLUSIVE_ONLY", reason: "Mapped cases were observed, blocked, or inconclusive and do not provide a conclusive verification result." }];
    return [];
  });
}

function classifyOutcome(input: AddCaseInput, linkedFinding: boolean): StandardsCoverageOutcome {
  const value = safeText(input.outcome).toUpperCase();
  if (linkedFinding || input.finding || value === "FAIL" || value === "PROVEN" || value.endsWith("_PROVEN")) return "FINDING";
  if (input.blocked || /BLOCKED|NOT_ASSESSED|BUDGET_EXHAUSTED|RATE_LIMITED|CREDENTIAL_UNAVAILABLE/.test(value)) return "BLOCKED";
  if (input.inconclusive || /INCONCLUSIVE|UNAVAILABLE|UNPARSEABLE|NOT_PARSEABLE|ERROR|UNVERIFIED|NOT_VERIFIED/.test(value)) return "INCONCLUSIVE";
  if (input.matched === true || value === "PASS" || value === "SECURE_FOR_CASE" || value === "NO_FINDING" || value === "MUTATION_REJECTED") return "NO_FINDING";
  return "OBSERVED";
}

function findingsForCase(findings: readonly Finding[], moduleId: string, caseId: string): Finding[] {
  const tail = caseId.includes("/") ? caseId.slice(caseId.lastIndexOf("/") + 1) : caseId;
  return findings.filter((finding) => (finding.workflow?.workflowId === moduleId && [caseId, tail].includes(finding.workflow.caseId)) || (finding.sourceModule === moduleId && [caseId, tail].includes(finding.workflowCase?.id ?? "")));
}

function mergeCase(left: StandardsCoverageCase, right: StandardsCoverageCase): StandardsCoverageCase {
  const rank: Record<StandardsCoverageOutcome, number> = { FINDING: 5, INCONCLUSIVE: 4, BLOCKED: 3, NO_FINDING: 2, OBSERVED: 1 };
  const references = new Map([...left.references, ...right.references].map((item) => [`${item.framework}/${item.id}`, item]));
  return { ...left, outcome: rank[right.outcome] > rank[left.outcome] ? right.outcome : left.outcome, requestTransmitted: left.requestTransmitted === true || right.requestTransmitted === true, findingIds: [...new Set([...left.findingIds, ...right.findingIds])].sort(), evidenceRefs: [...new Set([...left.evidenceRefs, ...right.evidenceRefs])].sort(), references: [...references.values()].sort(referenceSort) };
}

function countOutcomes(cases: readonly StandardsCoverageCase[]): Pick<StandardsCoverageReport["accounting"], "findings" | "noFindings" | "inconclusive" | "blocked" | "observed"> {
  return { findings: cases.filter((item) => item.outcome === "FINDING").length, noFindings: cases.filter((item) => item.outcome === "NO_FINDING").length, inconclusive: cases.filter((item) => item.outcome === "INCONCLUSIVE").length, blocked: cases.filter((item) => item.outcome === "BLOCKED").length, observed: cases.filter((item) => item.outcome === "OBSERVED").length };
}

function sourceModule(source: string): string {
  const value = source.toLowerCase();
  if (value.includes("path") || value.includes("wordlist")) return "path-discovery";
  if (value.includes("browser")) return "browser-crawler";
  if (value.includes("javascript") || value.includes("script")) return "js-intelligence";
  return "path-discovery";
}

function nextJsOutcome(status: unknown): "OBSERVED" | "INCONCLUSIVE" | "BLOCKED" {
  const value = safeText(status).toUpperCase();
  if (value === "BUDGET_EXHAUSTED" || value === "OUT_OF_SCOPE" || value === "CANCELLED") return "BLOCKED";
  if (value === "MALFORMED" || value === "UNSUPPORTED_SHAPE" || value === "TOO_LARGE" || value === "REQUEST_FAILED") return "INCONCLUSIVE";
  return "OBSERVED";
}

function caseKey(value: StandardsCoverageCase): string { return `${value.moduleId}/${value.caseId}`; }
function evidenceRef(moduleId: string, caseId: string): string { return `standards-evidence://${moduleId}/${shortHash(`${moduleId}\0${caseId}`, 32)}`; }
function shortHash(value: string, length = 16): string { return createHash("sha256").update(value).digest("hex").slice(0, length); }
function safeText(value: unknown): string { return typeof value === "string" ? value : value === undefined || value === null ? "" : String(value); }
function safeCaseId(value: unknown): string { const normalized = safeText(value).trim().replace(/[\r\n\t]/g, " "); return normalized.slice(0, 240); }
function boundedLabel(value: unknown, fallback: string): string { return (safeText(value).trim() || fallback).replace(/[\r\n\t]/g, " ").slice(0, 240); }
function naturalId(value: string): string { return value.replaceAll(":", "-").replaceAll(".", "-"); }
function referenceSort(left: StandardsReference, right: StandardsReference): number { return left.framework.localeCompare(right.framework) || naturalId(left.id).localeCompare(naturalId(right.id), undefined, { numeric: true }); }
