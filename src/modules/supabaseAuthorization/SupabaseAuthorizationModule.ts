import { authHeadersForProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import { securityContractFingerprint } from "../../core/comparisons/SecurityContractFingerprint.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { ControlledMutationContract } from "../../core/offensive/ControlledMutationTypes.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type {
  SupabaseAuthorizationObservation,
  SupabaseAuthorizationReport,
  SupabaseFindingCategory,
  SupabaseObservedDecision,
  SupabaseStaticRisk
} from "../../reports/SupabaseAuthorizationReport.js";
import { parseSafeFieldPath, valueAtSafePath } from "../fieldExposureTesting/SafeFieldPath.js";
import { isWriteOperation } from "./SupabaseAuthorizationPlanner.js";
import type { SupabaseActor, SupabaseAuthorizationCasePlan, SupabaseAuthorizationPlan, SupabaseOperation } from "./SupabaseAuthorizationTypes.js";

export class SupabaseAuthorizationModule implements RouteCairnPlugin {
  public readonly name = "supabase-authorization";
  public readonly description = "Verifies Supabase PostgREST, RLS, storage, RPC, relationship, and service-role boundaries.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeSupabaseAuthorization(context);
    return { pluginName: this.name, supabaseAuthorization: report, findings: findingsFromReport(report), notes: report.notes };
  }
}

export async function executeSupabaseAuthorization(context: ScanContext): Promise<SupabaseAuthorizationReport> {
  const plan = context.options.plan.supabaseAuthorization;
  if (!plan) return disabledReport();
  const anonKey = process.env[plan.anonKeyEnv];
  const serviceRoleKey = plan.serviceRoleKeyEnv ? process.env[plan.serviceRoleKeyEnv] : undefined;
  const observations: SupabaseAuthorizationObservation[] = [];
  for (const casePlan of plan.cases) {
    const identityReason = identityBlockReason(context, casePlan);
    if (identityReason) {
      observations.push(finalizeObservation(baseObservation(casePlan, "IDENTITY_UNVERIFIED", undefined, [identityReason])));
      continue;
    }
    const credentials = credentialsFor(context, casePlan.actor, anonKey, serviceRoleKey);
    if (!credentials.available) {
      observations.push(finalizeObservation(baseObservation(casePlan, "CREDENTIAL_UNAVAILABLE", undefined, [credentials.reason])));
      continue;
    }
    if (isWriteOperation(casePlan.operation, casePlan.method)) {
      observations.push(await executeMutation(context, casePlan, credentials.headers));
      continue;
    }
    const response = await context.createHttpClient().send({
      url: casePlan.url,
      method: casePlan.method,
      headers: { Accept: "application/json", ...casePlan.headers, ...credentials.headers },
      skipCache: true,
      disableRetries: true,
      ...(casePlan.surface === "STORAGE" && casePlan.method === "GET" ? { streamLimitBytes: plan.maxSignedUrlBytes, retainBodyPreview: true } : {})
    });
    observations.push(await classifyRead(context, plan, casePlan, response));
  }

  const anonKeyClassification = classifyJwtRole(anonKey);
  const staticRisks = [
    ...analyzeSupabaseCatalog(plan),
    ...(anonKeyClassification === "SERVICE_ROLE_JWT" ? [risk("ANON_KEY_SERVICE_ROLE_CLAIM", "Critical", plan.anonKeyEnv, "The key configured as the anon key carries a service_role JWT claim.", ["jwt.role=service_role", "key material redacted"])] : []),
    ...(anonKeyClassification === "SECRET_KEY" ? [risk("ANON_KEY_IS_SECRET_KEY", "Critical", plan.anonKeyEnv, "The anonymous credential is a Supabase secret key, not a publishable/anon key.", ["prefix=sb_secret_", "key material redacted"])] : []),
    ...(anonKey && serviceRoleKey && anonKey === serviceRoleKey ? [risk("ANON_SERVICE_KEY_REUSE", "Critical", plan.anonKeyEnv, "Anonymous and service-role credential references resolved to the same key.", ["credential equality confirmed", "key material redacted"])] : [])
  ];
  const accessMatrix = emptyMatrix();
  for (const observation of observations) {
    const cell = accessMatrix[observation.actor][observation.operation];
    if (isAllowedObservation(observation.observedDecision)) cell.allowed += 1;
    else if (isDeniedObservation(observation.observedDecision)) cell.denied += 1;
    else cell.inconclusive += 1;
  }
  const serviceCases = observations.filter((item) => item.actor === "SERVICE_ROLE");
  const serviceRoleBoundaryVerified = serviceCases.some((service) => service.expectedDecision === "ALLOW" && service.matchedExpectation && observations.some((lower) => lower.actor !== "SERVICE_ROLE" && lower.resource === service.resource && lower.operation === service.operation && lower.expectedDecision === "DENY" && lower.matchedExpectation));
  const coverage = coverageFor(plan, observations);
  return {
    enabled: true,
    projectOrigin: plan.projectOrigin,
    plannedCases: plan.cases.length,
    executedCases: observations.filter((item) => !["CREDENTIAL_UNAVAILABLE", "IDENTITY_UNVERIFIED", "BLOCKED_BY_SAFETY"].includes(item.observedDecision)).length,
    confirmedIssues: observations.filter((item) => item.findingCategory).length + staticRisks.filter((item) => item.severity === "High" || item.severity === "Critical").length,
    accessMatrix,
    anonKeyClassification,
    serviceRoleConfigured: Boolean(serviceRoleKey),
    serviceRoleBoundaryVerified,
    observations,
    staticRisks,
    resourceCoverage: resourceCoverageFor(plan),
    coverage,
    notes: [
      ...plan.notes,
      "PostgREST 200 responses containing an empty array are classified as an RLS-filtered empty result, not as allowed object access.",
      "A successful response becomes confirmed access only when every configured identity assertion matches the same returned row/object.",
      "Catalog risks are configuration evidence; runtime observations independently verify actual API behavior."
    ]
  };
}

async function executeMutation(context: ScanContext, casePlan: SupabaseAuthorizationCasePlan, actorHeaders: Record<string, string>): Promise<SupabaseAuthorizationObservation> {
  const contract = context.options.controlledMutationContracts?.find((item) => item.caseId === casePlan.mutationContractCaseId);
  if (!contract) return finalizeObservation(baseObservation(casePlan, "BLOCKED_BY_SAFETY", undefined, ["No exact expiring controlled-mutation contract was supplied; no mutation was transmitted."]));
  const mismatch = mutationContractMismatch(contract, casePlan, actorHeaders);
  if (mismatch) return finalizeObservation(baseObservation(casePlan, "BLOCKED_BY_SAFETY", undefined, [`Mutation contract mismatch: ${mismatch}; no mutation was transmitted.`]));
  const result = await context.runControlledMutation(contract);
  const observed: SupabaseObservedDecision = result.securityOutcome === "EXPLOIT_PROVEN" ? "MUTATION_PROVEN" : result.securityOutcome === "SECURE_FOR_CASE" ? "MUTATION_REJECTED" : result.securityOutcome === "BLOCKED_BY_SAFETY" ? "BLOCKED_BY_SAFETY" : "MUTATION_INCONCLUSIVE";
  return finalizeObservation({
    ...baseObservation(casePlan, observed, undefined, [...result.notes, `Cleanup outcome: ${result.cleanupOutcome}.`]),
    identityConfirmed: Boolean(result.preStateHash),
    cleanupOutcome: result.cleanupOutcome,
    ...(result.attackResponseHash ? { bodyHash: result.attackResponseHash } : {})
  });
}

function mutationContractMismatch(contract: ControlledMutationContract, casePlan: SupabaseAuthorizationCasePlan, actorHeaders: Record<string, string>): string | undefined {
  if (contract.caseId !== casePlan.mutationContractCaseId) return "case id differs";
  if (contract.attack.request.url !== casePlan.url) return "attack URL differs";
  if (contract.attack.request.method !== casePlan.method) return "attack method differs";
  if (contract.targetOrigin !== new URL(casePlan.url).origin) return "target origin differs";
  const expectedEffect = casePlan.operation === "INSERT" ? "CREATE_DISPOSABLE" : casePlan.operation === "DELETE" ? "DELETE" : "UPDATE_EXISTING";
  if (contract.attack.semanticEffect !== expectedEffect) return "semantic effect differs";
  const actualHeaders = lowerHeaders(contract.attack.request.headers ?? {});
  for (const [name, value] of Object.entries(lowerHeaders(actorHeaders))) if (actualHeaders[name] !== value) return `actor credential header ${name} differs`;
  return undefined;
}

async function classifyRead(context: ScanContext, plan: SupabaseAuthorizationPlan, casePlan: SupabaseAuthorizationCasePlan, response: HttpResponse): Promise<SupabaseAuthorizationObservation> {
  if (response.error?.name === "RequestBudgetExceeded" || response.error?.name === "OutOfScopeRequest" || response.error?.name === "OutOfScopeRedirect") return finalizeObservation(baseObservation(casePlan, "BLOCKED_BY_SAFETY", response, [response.error.message]));
  if (response.error) return finalizeObservation(baseObservation(casePlan, "EXECUTION_ERROR", response, [response.error.message]));
  if (response.statusCode === 429) return finalizeObservation(baseObservation(casePlan, "RATE_LIMITED", response, ["Rate limiting is not treated as an authorization denial."]));
  if (response.statusCode === 401 || response.statusCode === 403 || response.statusCode === 404 || response.statusCode === 406) return finalizeObservation(baseObservation(casePlan, "ACCESS_DENIED", response, ["The endpoint denied authentication/authorization or concealed the resource."]));
  if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) return finalizeObservation(baseObservation(casePlan, "EXECUTION_ERROR", response, ["Unexpected response status could not establish authorization behavior."]));
  if ((response.contentLength ?? 0) > plan.maxResponseBytes) return finalizeObservation(baseObservation(casePlan, "BLOCKED_BY_SAFETY", response, ["Response exceeded the configured Supabase analysis limit."]));
  if (casePlan.method === "HEAD") return finalizeObservation({ ...baseObservation(casePlan, "ACCESS_ALLOWED", response, ["HEAD returned success; object identity was not body-confirmed."]), identityConfirmed: false });
  const body = bodyPreviewForAnalysis(response) ?? "";
  const parsed = parseJson(body);
  if (parsed === undefined) return finalizeObservation(baseObservation(casePlan, "RESPONSE_UNPARSEABLE", response, ["Successful response was not bounded parseable JSON."]));
  if (casePlan.operation === "SIGNED_URL" && casePlan.signedUrl) return classifySignedUrl(context, plan, casePlan, response, parsed);
  const records = recordsFor(parsed, casePlan.responseShape);
  if (records.length === 0) return finalizeObservation(baseObservation(casePlan, "EMPTY_RESULT", response, ["PostgREST returned no visible rows/objects."]));
  const matching = records.find((record) => assertionsMatch(record, casePlan.identityAssertions));
  const sensitiveColumnsObserved = unique(records.flatMap((record) => casePlan.forbiddenColumns.filter((column) => hasOwnPath(record, column))));
  return finalizeObservation({
    ...baseObservation(casePlan, "ACCESS_ALLOWED", response, [matching ? "Configured identity assertions matched a returned row/object." : "A successful non-empty response was observed, but configured identity assertions did not match the same row/object."]),
    identityConfirmed: casePlan.identityAssertions.length > 0 && Boolean(matching),
    sensitiveColumnsObserved
  });
}

async function classifySignedUrl(context: ScanContext, plan: SupabaseAuthorizationPlan, casePlan: SupabaseAuthorizationCasePlan, response: HttpResponse, parsed: unknown): Promise<SupabaseAuthorizationObservation> {
  const settings = casePlan.signedUrl!;
  const signedValue = valueAt(parsed, settings.responseField);
  if (typeof signedValue !== "string") return finalizeObservation(baseObservation(casePlan, "EMPTY_RESULT", response, ["Configured signed URL field was absent."]));
  let signed: URL;
  try { signed = new URL(signedValue, plan.projectOrigin); }
  catch { return finalizeObservation(baseObservation(casePlan, "RESPONSE_UNPARSEABLE", response, ["Configured signed URL field was not a valid URL."])); }
  const originAllowed = settings.allowedOrigins.includes(signed.origin);
  const pathMatched = !settings.expectedPathContains || signed.pathname.includes(settings.expectedPathContains);
  if (!originAllowed || !pathMatched) return finalizeObservation({ ...baseObservation(casePlan, "SIGNED_URL_ISSUED", response, [!originAllowed ? "Signed URL origin was outside the exact allowlist." : "Signed URL path did not match the configured object boundary."]), identityConfirmed: false });
  const issuance = { ...baseObservation(casePlan, "SIGNED_URL_ISSUED" as const, response, ["Signed URL origin and configured path boundary matched."]), identityConfirmed: true };
  if (!settings.followOnce) return finalizeObservation(issuance);
  const follow = await context.createHttpClient().send({ url: signed.toString(), method: "GET", headers: { "Accept-Encoding": "identity" }, skipCache: true, disableRetries: true, streamLimitBytes: plan.maxSignedUrlBytes, maxStreamContentLength: plan.maxSignedUrlBytes, retainBodyPreview: false });
  if (follow.statusCode === 401 || follow.statusCode === 403 || follow.statusCode === 404) return finalizeObservation({ ...issuance, observedDecision: "SIGNED_URL_DOWNLOAD_DENIED", statusCode: follow.statusCode, notes: [...issuance.notes, "The exact signed URL was followed once without application credentials and denied."] });
  if (follow.statusCode && follow.statusCode >= 200 && follow.statusCode < 300 && !follow.error) return finalizeObservation({ ...issuance, observedDecision: "SIGNED_URL_DOWNLOAD_ALLOWED", statusCode: follow.statusCode, ...(follow.bodyHash ? { bodyHash: follow.bodyHash } : {}), notes: [...issuance.notes, "The exact signed URL was followed once without application credentials within the configured byte cap."] });
  return finalizeObservation({ ...issuance, observedDecision: follow.error ? "BLOCKED_BY_SAFETY" : "EXECUTION_ERROR", notes: [...issuance.notes, follow.error?.message ?? "Signed URL follow returned an inconclusive status."] });
}

export function analyzeSupabaseCatalog(plan: SupabaseAuthorizationPlan): SupabaseStaticRisk[] {
  const risks: SupabaseStaticRisk[] = [];
  const tableByName = new Map(plan.catalog.tables.flatMap((table) => [[`${table.schema}.${table.name}`, table], [table.name, table]]));
  for (const schema of plan.catalog.exposedSchemas) if (!plan.catalog.expectedExposedSchemas.includes(schema)) risks.push(risk("UNEXPECTED_EXPOSED_SCHEMA", "High", schema, `Schema ${schema} is exposed through PostgREST but is not on the expected allowlist.`, [`expected=${plan.catalog.expectedExposedSchemas.join(",") || "none"}`]));
  for (const table of plan.catalog.tables.filter((item) => item.exposed)) {
    const resource = `${table.schema}.${table.name}`;
    if (!table.rlsEnabled) risks.push(risk("RLS_DISABLED_EXPOSED_TABLE", "Critical", resource, "An exposed table does not have row-level security enabled.", ["rlsEnabled=false", "exposed=true"]));
    else if (!table.rlsForced) risks.push(risk("RLS_NOT_FORCED", "Low", resource, "RLS is enabled but not forced for table-owner access.", ["rlsEnabled=true", "rlsForced=false"]));
    const anonWrite = table.grants.find((grant) => grant.role === "anon" && grant.operations.some((op) => op === "INSERT" || op === "UPDATE" || op === "DELETE"));
    if (anonWrite) risks.push(risk("ANON_WRITE_GRANT", table.rlsEnabled ? "High" : "Critical", resource, "The anon role has a table write grant; policies must constrain every write path.", [`operations=${anonWrite.operations.join(",")}`]));
    for (const column of table.columns.filter((item) => item.sensitive && item.exposedTo.includes("anon"))) risks.push(risk("SENSITIVE_COLUMN_ANON_EXPOSURE", "High", `${resource}.${column.name}`, "A sensitive column is declared exposed to the anon role.", ["sensitive=true", "role=anon"]));
  }
  for (const fn of plan.catalog.functions.filter((item) => item.exposed && item.securityDefiner)) {
    const resource = `${fn.schema}.${fn.name}`;
    if (fn.executableBy.includes("anon") || fn.executableBy.includes("public")) risks.push(risk("SECURITY_DEFINER_PUBLIC_EXECUTE", "Critical", resource, "A SECURITY DEFINER function is executable by anon/public.", [`executableBy=${fn.executableBy.join(",")}`]));
    if (fn.searchPath.length === 0 || fn.searchPath.includes("public")) risks.push(risk("SECURITY_DEFINER_UNSAFE_SEARCH_PATH", "High", resource, "A SECURITY DEFINER function has an empty or mutable public search_path.", [`searchPath=${fn.searchPath.join(",") || "unset"}`]));
    if (fn.usesDynamicSql) risks.push(risk("SECURITY_DEFINER_DYNAMIC_SQL", "High", resource, "A SECURITY DEFINER function is declared to use dynamic SQL.", ["usesDynamicSql=true"]));
  }
  for (const bucket of plan.catalog.storageBuckets) {
    if (bucket.public) risks.push(risk("PUBLIC_STORAGE_BUCKET", "Medium", bucket.name, "Storage bucket is public; confirm every object is intentionally public.", ["public=true"]));
    if (!bucket.public && !bucket.ownershipEnforced) risks.push(risk("STORAGE_OWNERSHIP_NOT_ENFORCED", "High", bucket.name, "A private storage bucket lacks declared ownership enforcement.", ["public=false", "ownershipEnforced=false"]));
  }
  for (const relationship of plan.catalog.relationships.filter((item) => item.exposed)) {
    const from = tableByName.get(relationship.from);
    const to = tableByName.get(relationship.to);
    if ((from && !from.rlsEnabled) || (to && !to.rlsEnabled)) risks.push(risk("RELATIONSHIP_TRAVERSAL_RISK", "High", relationship.name, "An exposed PostgREST relationship traverses a table without RLS.", [`from=${relationship.from}`, `to=${relationship.to}`]));
  }
  return risks;
}

function finalizeObservation(observation: SupabaseAuthorizationObservation): SupabaseAuthorizationObservation {
  const allowed = ["ACCESS_ALLOWED", "SIGNED_URL_ISSUED", "SIGNED_URL_DOWNLOAD_ALLOWED", "MUTATION_PROVEN"].includes(observation.observedDecision);
  const denied = ["ACCESS_DENIED", "EMPTY_RESULT", "SIGNED_URL_DOWNLOAD_DENIED", "MUTATION_REJECTED"].includes(observation.observedDecision);
  const matchedExpectation = observation.expectedDecision === "OBSERVE_ONLY" || (observation.expectedDecision === "ALLOW" ? allowed : denied);
  const sensitive = observation.sensitiveColumnsObserved.length > 0;
  const findingCategory = sensitive ? "SENSITIVE_COLUMN_EXPOSURE" : observation.expectedDecision === "DENY" && allowed && (observation.identityConfirmed || observation.operation === "SIGNED_URL") ? findingCategoryFor(observation) : undefined;
  return {
    ...observation,
    matchedExpectation,
    ...(findingCategory ? { findingCategory } : {}),
    confidence: findingCategory && observation.identityConfirmed ? "CONFIRMED" : findingCategory ? "HIGH" : observation.observedDecision.endsWith("INCONCLUSIVE") || observation.observedDecision === "RESPONSE_UNPARSEABLE" ? "INCONCLUSIVE" : matchedExpectation ? "HIGH" : "MEDIUM"
  };
}

function findingCategoryFor(observation: SupabaseAuthorizationObservation): SupabaseFindingCategory {
  if (observation.boundary === "CROSS_TENANT") return "CROSS_TENANT_ACCESS";
  if (observation.boundary === "CROSS_USER") return "CROSS_USER_ACCESS";
  if (observation.boundary === "SERVICE_ROLE") return "SERVICE_ROLE_BOUNDARY_BYPASS";
  if (observation.surface === "STORAGE") return observation.operation === "SIGNED_URL" ? "SIGNED_URL_BOUNDARY_BYPASS" : "STORAGE_AUTHORIZATION_BYPASS";
  if (observation.surface === "RPC") return "RPC_AUTHORIZATION_BYPASS";
  if (observation.surface === "RELATIONSHIP") return "RELATIONSHIP_TRAVERSAL_BYPASS";
  if (observation.operation === "INSERT") return "RLS_INSERT_BYPASS";
  if (observation.operation === "UPDATE") return "RLS_UPDATE_BYPASS";
  if (observation.operation === "DELETE") return "RLS_DELETE_BYPASS";
  return "RLS_READ_BYPASS";
}

function baseObservation(casePlan: SupabaseAuthorizationCasePlan, observedDecision: SupabaseObservedDecision, response: HttpResponse | undefined, notes: string[]): SupabaseAuthorizationObservation {
  return {
    caseId: casePlan.id,
    comparisonFingerprint: casePlan.comparisonFingerprint,
    surface: casePlan.surface,
    resource: casePlan.resource,
    operation: casePlan.operation,
    actor: casePlan.actor,
    boundary: casePlan.boundary,
    expectedDecision: casePlan.expectedDecision,
    observedDecision,
    matchedExpectation: false,
    identityConfirmed: false,
    sensitiveColumnsObserved: [],
    method: casePlan.method,
    url: safeCaseUrl(response?.finalUrl ?? casePlan.url, casePlan),
    ...(typeof response?.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response?.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response?.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response?.bodyHash ? { bodyHash: response.bodyHash } : {}),
    confidence: "INCONCLUSIVE",
    notes
  };
}

function credentialsFor(context: ScanContext, actor: SupabaseActor, anonKey: string | undefined, serviceRoleKey: string | undefined): { available: true; headers: Record<string, string> } | { available: false; reason: string } {
  if (!anonKey) return { available: false, reason: "Anon key environment variable was unavailable." };
  if (/[\r\n]/.test(anonKey)) return { available: false, reason: "Anon key environment variable contained forbidden header characters." };
  if (actor === "ANONYMOUS") return { available: true, headers: { apikey: anonKey } };
  if (actor === "SERVICE_ROLE") return serviceRoleKey && !/[\r\n]/.test(serviceRoleKey) ? { available: true, headers: { apikey: serviceRoleKey, Authorization: `Bearer ${serviceRoleKey}` } } : { available: false, reason: serviceRoleKey ? "Service-role key environment variable contained forbidden header characters." : "Service-role key environment variable was unavailable." };
  const profile = actor === "ACCOUNT_A" ? context.options.authProfileSet?.accountA : context.options.authProfileSet?.accountB;
  if (!profile) return { available: false, reason: `${actor} auth profile was unavailable.` };
  const profileHeaders = Object.fromEntries(Object.entries(authHeadersForProfile(profile)).filter(([name]) => name.toLowerCase() !== "apikey"));
  return { available: true, headers: { ...profileHeaders, apikey: anonKey } };
}

function identityBlockReason(context: ScanContext, casePlan: SupabaseAuthorizationCasePlan): string | undefined {
  if (!casePlan.requireVerifiedIdentity || (casePlan.actor !== "ACCOUNT_A" && casePlan.actor !== "ACCOUNT_B")) return undefined;
  const result = casePlan.actor === "ACCOUNT_A" ? context.state.getIdentityVerification()?.accountA : context.state.getIdentityVerification()?.accountB;
  if (!result?.verified) return `${casePlan.actor} required verified identity but verification was ${result?.category ?? "missing"}.`;
  const report = context.state.getIdentityVerification();
  if (report?.accountA?.verified && report.accountB?.verified && report.accountA.principalHash === report.accountB.principalHash) return "Account A and Account B resolved to the same verified principal.";
  return undefined;
}

function assertionsMatch(record: Record<string, unknown>, assertions: SupabaseAuthorizationCasePlan["identityAssertions"]): boolean {
  return assertions.every((assertion) => Object.is(valueAt(record, assertion.path), assertion.expectedValue));
}

function valueAt(source: unknown, path: string): unknown {
  if (!source || typeof source !== "object") return undefined;
  return valueAtSafePath(source as Record<string, unknown>, parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 100, code: "SUPABASE_AUTH_FIELD_PATH_INVALID" })).value;
}

function hasOwnPath(source: Record<string, unknown>, path: string): boolean {
  const parsed = parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 100, code: "SUPABASE_AUTH_FIELD_PATH_INVALID" });
  return valueAtSafePath(source, parsed).state.startsWith("PRESENT_");
}

function recordsFor(parsed: unknown, shape: SupabaseAuthorizationCasePlan["responseShape"]): Record<string, unknown>[] {
  if (shape === "VOID") return [];
  if (Array.isArray(parsed)) return parsed.filter(isRecord);
  return isRecord(parsed) ? [parsed] : [];
}

function parseJson(value: string): unknown | undefined { try { return JSON.parse(value) as unknown; } catch { return undefined; } }
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function unique<T>(values: T[]): T[] { return [...new Set(values)]; }
function lowerHeaders(headers: Record<string, string>): Record<string, string> { return Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value])); }

function safeUrl(value: string): string {
  try {
    const url = new URL(value);
    for (const key of [...new Set([...url.searchParams.keys()])]) url.searchParams.set(key, "<redacted>");
    return url.toString();
  } catch { return "<invalid-url>"; }
}

function safeCaseUrl(value: string, casePlan: SupabaseAuthorizationCasePlan): string {
  const redacted = [
    ...casePlan.identityAssertions.flatMap((assertion) => typeof assertion.expectedValue === "string" ? [assertion.expectedValue] : []),
    ...(casePlan.signedUrl?.expectedPathContains ? [casePlan.signedUrl.expectedPathContains.split("/").filter(Boolean).at(-1) ?? casePlan.signedUrl.expectedPathContains] : [])
  ].reduce((current, secret) => current.split(encodeURIComponent(secret)).join("<object:redacted>").split(secret).join("<object:redacted>"), value);
  return safeUrl(redacted);
}

function classifyJwtRole(key: string | undefined): SupabaseAuthorizationReport["anonKeyClassification"] {
  if (!key) return "UNAVAILABLE";
  if (key.startsWith("sb_publishable_")) return "PUBLISHABLE_KEY";
  if (key.startsWith("sb_secret_")) return "SECRET_KEY";
  const parts = key.split(".");
  if (parts.length !== 3 || !parts[1]) return "OPAQUE";
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as { role?: unknown };
    return payload.role === "anon" ? "ANON_JWT" : payload.role === "service_role" ? "SERVICE_ROLE_JWT" : "OTHER_JWT";
  } catch { return "OPAQUE"; }
}

function emptyMatrix(): SupabaseAuthorizationReport["accessMatrix"] {
  const cell = () => ({ allowed: 0, denied: 0, inconclusive: 0 });
  const row = (): Record<SupabaseOperation, { allowed: number; denied: number; inconclusive: number }> => ({ SELECT: cell(), INSERT: cell(), UPDATE: cell(), DELETE: cell(), INVOKE: cell(), SIGNED_URL: cell() });
  return { ANONYMOUS: row(), ACCOUNT_A: row(), ACCOUNT_B: row(), SERVICE_ROLE: row() };
}

function isAllowedObservation(value: SupabaseObservedDecision): boolean { return ["ACCESS_ALLOWED", "SIGNED_URL_ISSUED", "SIGNED_URL_DOWNLOAD_ALLOWED", "MUTATION_PROVEN"].includes(value); }
function isDeniedObservation(value: SupabaseObservedDecision): boolean { return ["ACCESS_DENIED", "EMPTY_RESULT", "SIGNED_URL_DOWNLOAD_DENIED", "MUTATION_REJECTED"].includes(value); }

function resourceCoverageFor(plan: SupabaseAuthorizationPlan): SupabaseAuthorizationReport["resourceCoverage"] {
  const groups = new Map<string, SupabaseAuthorizationReport["resourceCoverage"][number]>();
  for (const item of plan.cases) {
    const key = `${item.surface}:${item.resource}`;
    const current = groups.get(key) ?? { surface: item.surface, resource: item.resource, operations: [], actors: [] };
    if (!current.operations.includes(item.operation)) current.operations.push(item.operation);
    if (!current.actors.includes(item.actor)) current.actors.push(item.actor);
    groups.set(key, current);
  }
  return [...groups.values()].sort((left, right) => `${left.surface}:${left.resource}`.localeCompare(`${right.surface}:${right.resource}`));
}

function coverageFor(plan: SupabaseAuthorizationPlan, observations: SupabaseAuthorizationObservation[]): SupabaseAuthorizationReport["coverage"] {
  const has = (predicate: (item: SupabaseAuthorizationCasePlan) => boolean) => plan.cases.some(predicate);
  const actors = new Set(plan.cases.map((item) => item.actor));
  return {
    tableRead: has((item) => item.surface === "TABLE" && item.operation === "SELECT"),
    tableInsert: has((item) => item.surface === "TABLE" && item.operation === "INSERT"),
    tableUpdate: has((item) => item.surface === "TABLE" && item.operation === "UPDATE"),
    tableDelete: has((item) => item.surface === "TABLE" && item.operation === "DELETE"),
    crossUser: has((item) => item.boundary === "CROSS_USER"),
    crossTenant: has((item) => item.boundary === "CROSS_TENANT"),
    sensitiveColumns: has((item) => item.forbiddenColumns.length > 0),
    storage: has((item) => item.surface === "STORAGE"),
    signedUrls: has((item) => item.operation === "SIGNED_URL"),
    rpc: has((item) => item.surface === "RPC"),
    securityDefiner: plan.catalog.functions.length > 0,
    publicSchemas: plan.catalog.exposedSchemas.length > 0,
    relationships: plan.catalog.relationships.length > 0 && has((item) => item.surface === "RELATIONSHIP"),
    accountPair: actors.has("ACCOUNT_A") && actors.has("ACCOUNT_B") && observations.some((item) => item.actor === "ACCOUNT_A") && observations.some((item) => item.actor === "ACCOUNT_B"),
    serviceRole: actors.has("SERVICE_ROLE") && observations.some((item) => item.actor === "SERVICE_ROLE")
  };
}

function risk(category: SupabaseStaticRisk["category"], severity: SupabaseStaticRisk["severity"], resource: string, summary: string, evidence: string[]): SupabaseStaticRisk {
  return { id: `${category}-${resource}`.replace(/[^a-z0-9_-]/gi, "-").toLowerCase(), comparisonFingerprint: securityContractFingerprint("supabase-catalog-risk", { category, resource, evidence }), category, severity, resource, summary, evidence };
}

function findingsFromReport(report: SupabaseAuthorizationReport): Finding[] {
  const scorer = new RiskScorer();
  const runtime = report.observations.filter((item): item is SupabaseAuthorizationObservation & { findingCategory: SupabaseFindingCategory } => Boolean(item.findingCategory)).map((item) => {
    const severity = item.findingCategory === "SENSITIVE_COLUMN_EXPOSURE" ? "High" as const : "Critical" as const;
    return {
      id: `supabase-${item.caseId}`.replace(/[^a-z0-9_-]/gi, "-").toLowerCase(),
      title: `Supabase authorization issue: ${item.findingCategory}`,
      type: "Supabase Authorization Issue" as const,
      severity,
      confidence: item.confidence === "CONFIRMED" ? "High" as const : "Medium" as const,
      url: item.url,
      method: item.method,
      ...(item.statusCode ? { statusCode: item.statusCode } : {}),
      evidence: { url: item.url, method: item.method, ...(item.statusCode ? { statusCode: item.statusCode } : {}), ...(item.bodyHash ? { bodyHash: item.bodyHash } : {}), source: `Supabase case ${item.caseId}; actor=${item.actor}; surface=${item.surface}; resource=${item.resource}; expected=${item.expectedDecision}; observed=${item.observedDecision}; credential values and query values redacted.`, severityReason: "A controlled Supabase authorization boundary was bypassed with exact operator-supplied evidence.", reproductionNotes: ["Use the same authorized actor and exact predeclared resource.", "Do not enumerate adjacent tables, rows, buckets, objects, functions, or relationships."] },
      impact: "A caller may access or mutate Supabase data, storage objects, or RPC behavior outside the intended RLS or ownership policy.",
      recommendation: "Enforce least-privilege grants and RLS policies for every operation; validate auth.uid(), tenant, ownership, storage object identity, RPC execute grants, and SECURITY DEFINER search_path.",
      manualTestingSuggestions: ["Verify the supplied expected policy with the application owner.", "Repeat the exact Account A/Account B matrix cell after policy remediation."],
      tags: ["supabase", "postgrest", "rls", item.findingCategory.toLowerCase().replace(/_/g, "-")],
      riskScore: scorer.score({ severity, confidence: item.confidence === "CONFIRMED" ? "High" : "Medium", falsePositiveStatus: "likely-valid", tags: ["supabase", "rls"] }),
      workflowCase: { id: item.caseId, comparisonFingerprint: item.comparisonFingerprint, ...(item.cleanupOutcome ? { cleanupOutcome: item.cleanupOutcome } : {}) },
      sourceModule: "supabase-authorization",
      falsePositiveStatus: "likely-valid" as const,
      timestamp: new Date().toISOString()
    };
  });
  const staticFindings = report.staticRisks.filter((item) => item.severity === "High" || item.severity === "Critical").map((item) => ({
    id: `supabase-static-${item.id}`,
    title: `Supabase configuration risk: ${item.category}`,
    type: "Supabase Configuration Risk" as const,
    severity: item.severity,
    confidence: "High" as const,
    url: report.projectOrigin ?? "",
    method: "CATALOG",
    evidence: { url: report.projectOrigin ?? "", method: "CATALOG", source: `${item.summary} ${item.evidence.join("; ")}`, severityReason: "Operator-supplied PostgreSQL/Supabase catalog evidence indicates an unsafe authorization configuration." },
    impact: "The exposed Supabase surface may permit unintended access or privilege escalation.",
    recommendation: "Review the exact catalog object, revoke broad grants, enable and test RLS, and harden SECURITY DEFINER functions and storage policies.",
    manualTestingSuggestions: ["Confirm the catalog snapshot is current.", "Verify actual behavior with the corresponding controlled matrix cases."],
    tags: ["supabase", "configuration", item.category.toLowerCase().replace(/_/g, "-")],
    riskScore: scorer.score({ severity: item.severity, confidence: "High", falsePositiveStatus: "likely-valid", tags: ["supabase", "configuration"] }),
    workflowCase: { id: item.id, comparisonFingerprint: item.comparisonFingerprint },
    sourceModule: "supabase-authorization",
    falsePositiveStatus: "likely-valid" as const,
    timestamp: new Date().toISOString()
  }));
  return [...runtime, ...staticFindings];
}

function disabledReport(): SupabaseAuthorizationReport {
  return { enabled: false, plannedCases: 0, executedCases: 0, confirmedIssues: 0, accessMatrix: emptyMatrix(), anonKeyClassification: "UNAVAILABLE", serviceRoleConfigured: false, serviceRoleBoundaryVerified: false, observations: [], staticRisks: [], resourceCoverage: [], coverage: { tableRead: false, tableInsert: false, tableUpdate: false, tableDelete: false, crossUser: false, crossTenant: false, sensitiveColumns: false, storage: false, signedUrls: false, rpc: false, securityDefiner: false, publicSchemas: false, relationships: false, accountPair: false, serviceRole: false }, notes: ["Supabase authorization testing was not selected."] };
}
