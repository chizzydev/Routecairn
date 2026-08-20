import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import type {
  EquivalentRouteActorPlan,
  EquivalentRouteCellPlan,
  EquivalentRouteDefinitionPlan,
  EquivalentRouteSetPlan,
  EquivalentRouteTestingPlan
} from "../../core/planning/ScanPlan.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { parseSafeFieldPath } from "../fieldExposureTesting/SafeFieldPath.js";

const objectPlaceholder = "{{OBJECT_ID}}";
const tenantPlaceholder = "{{TENANT_ID}}";
const encodedObjectPlaceholder = "%7B%7BOBJECT_ID%7D%7D";
const encodedTenantPlaceholder = "%7B%7BTENANT_ID%7D%7D";
const maxFileBytes = 256 * 1024;
const maxRouteSets = 5;
const maxRoutesPerSet = 8;
const maxActorsPerSet = 3;
const maxCells = 60;
const maxIdentifierLength = 256;
const maxTemplateLength = 2048;
const forbiddenEndpointWords = /(?:delete|remove|cancel|purchase|pay|transfer|withdraw|approve|reject|publish|submit|invite|reset|activate|deactivate|suspend|logout|consume-on-read|generate|create-export|start-export|archive)/i;
const generatorPattern = /(?:\.\.|\*|\||=>|function\s*\(|regex|regexp|range|increment|decrement|random|uuid-v|eval|for\s*\(|while\s*\(|v\{\{|v\d+\.\.v\d+)/i;
const secretLikePattern = /(?:authorization|cookie|session|csrf|xsrf|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|bearer\s+[a-z0-9._~+/=-]+)/i;

const routeCategorySchema = z.enum(["CANONICAL", "LEGACY", "VERSIONED", "NESTED", "TOP_LEVEL", "EXPORT", "SUMMARY", "DETAIL", "MOBILE", "WEB", "ALIAS", "COMPATIBILITY", "RELATIONSHIP", "ALTERNATE_FORMAT", "CUSTOM_DECLARED"]);
const relationshipSchema = z.enum(["OWNER", "NON_OWNER", "SAME_TENANT_MEMBER", "SAME_TENANT_ADMIN", "CROSS_TENANT_MEMBER", "CROSS_TENANT_ADMIN", "ADMINISTRATOR", "MODERATOR", "SUSPENDED", "ACTIVE", "SHARED_PRINCIPAL", "PUBLIC", "CUSTOM_DECLARED_RELATIONSHIP"]);
const equivalencePolicySchema = z.enum(["AUTHORIZATION_ONLY", "SAME_OBJECT", "SAME_PUBLIC_BOUNDARY", "SAME_OWNER_BOUNDARY", "SAME_TENANT_BOUNDARY", "SAME_ROLE_BOUNDARY", "SAME_STATE_BOUNDARY", "MUST_NOT_EXCEED_REFERENCE_ROUTE"]);
const expectedDecisionSchema = z.enum(["MUST_ALLOW", "MUST_DENY", "MUST_REQUIRE_AUTHENTICATION", "MUST_RETURN_NOT_FOUND", "MUST_MATCH_CANONICAL_DECISION", "MUST_MATCH_REFERENCE_ROUTE", "MUST_NOT_EXCEED_CANONICAL_ACCESS", "MUST_NOT_EXCEED_PUBLIC_ACCESS", "OBSERVE_ONLY"]);

const actorSchema = z
  .object({
    id: z.string().min(1).max(80),
    relationship: relationshipSchema,
    authProfile: z.enum(["account_a", "account_b"]).optional(),
    safeAlias: z.string().min(1).max(80).optional(),
    principalId: z.string().min(1).max(maxIdentifierLength).optional(),
    tenantId: z.string().min(1).max(maxIdentifierLength).optional(),
    role: z.string().min(1).max(120).optional(),
    accountState: z.string().min(1).max(120).optional()
  })
  .strict();

const routeSchema = z
  .object({
    id: z.string().min(1).max(120),
    label: z.string().min(1).max(120),
    category: routeCategorySchema,
    isCanonical: z.boolean().default(false),
    deprecated: z.boolean().default(false),
    expectedPublic: z.boolean().default(false),
    template: z
      .object({
        id: z.string().min(1).max(120),
        method: z.literal("GET"),
        url: z.string().min(1).max(maxTemplateLength),
        headers: z.record(z.string().max(512)).default({})
      })
      .strict(),
    objectIdentityField: z.string().min(1).max(160).optional(),
    responseEnvelopePath: z.string().min(1).max(160).optional(),
    objectStateField: z.string().min(1).max(160).optional(),
    expectedContentType: z.string().min(1).max(120).default("application/json"),
    representationType: z.string().min(1).max(80).default("json"),
    equivalencePolicy: equivalencePolicySchema.optional(),
    referenceRouteId: z.string().min(1).max(120).optional(),
    expectations: z.record(expectedDecisionSchema)
  })
  .strict();

const routeSetSchema = z
  .object({
    id: z.string().min(1).max(120),
    name: z.string().min(1).max(160),
    objectType: z.string().min(1).max(80),
    objectId: z.string().min(1).max(maxIdentifierLength),
    canonicalRouteId: z.string().min(1).max(120),
    equivalencePolicy: equivalencePolicySchema.default("AUTHORIZATION_ONLY"),
    objectIdentityField: z.string().min(1).max(160),
    objectStateField: z.string().min(1).max(160).optional(),
    expectedObjectState: z.string().min(1).max(120).optional(),
    requireVerifiedIdentity: z.boolean().default(true),
    actors: z.array(actorSchema).min(1).max(maxActorsPerSet),
    routes: z.array(routeSchema).min(2).max(maxRoutesPerSet)
  })
  .strict();

export const equivalentRouteInputSchema = z
  .object({
    schemaVersion: z.literal(1).default(1),
    maxRouteSets: z.number().int().positive().max(maxRouteSets).default(3),
    maxRoutesPerSet: z.number().int().positive().max(maxRoutesPerSet).default(6),
    maxActorsPerSet: z.number().int().positive().max(maxActorsPerSet).default(3),
    maxCells: z.number().int().positive().max(maxCells).default(40),
    maxResponseBytes: z.number().int().positive().max(512 * 1024).default(65536),
    maxPreviewLength: z.number().int().positive().max(512).default(120),
    routeSets: z.array(routeSetSchema).min(1).max(maxRouteSets)
  })
  .strict();

export type EquivalentRouteInput = z.infer<typeof equivalentRouteInputSchema>;

export async function loadEquivalentRouteInput(filePath: string): Promise<EquivalentRouteInput> {
  const rawBuffer = await readFile(filePath);
  if (rawBuffer.byteLength > maxFileBytes) {
    throw new AppError(`Equivalent route input exceeds maximum size ${maxFileBytes} bytes.`, "EQUIVALENT_ROUTE_FILE_TOO_LARGE");
  }
  let json: unknown;
  try {
    json = JSON.parse(rawBuffer.toString("utf8").replace(/^\uFEFF/, ""));
  } catch {
    throw new AppError("Equivalent route input is not valid JSON.", "EQUIVALENT_ROUTE_JSON_INVALID");
  }
  const parsed = equivalentRouteInputSchema.safeParse(json);
  if (!parsed.success) {
    throw new AppError(parsed.error.message, "EQUIVALENT_ROUTE_INPUT_INVALID");
  }
  return parsed.data;
}

export function planEquivalentRouteTesting(input: EquivalentRouteInput, options: { target: string; scope: RouteCairnScope; authProfileSet?: AuthProfileSet }): EquivalentRouteTestingPlan {
  if (input.routeSets.length > input.maxRouteSets) {
    throw new AppError(`Equivalent route input contains ${input.routeSets.length} route sets, exceeding maxRouteSets ${input.maxRouteSets}.`, "EQUIVALENT_ROUTE_TOO_MANY_SETS");
  }
  const scopeMatcher = new ScopeMatcher(options.target, options.scope);
  const routeSets = input.routeSets.map((routeSet) => planRouteSet(routeSet, input, scopeMatcher, options.authProfileSet));
  const requestMatrix = routeSets.flatMap((routeSet) => [...routeSet.cells]);
  if (requestMatrix.length > input.maxCells) {
    throw new AppError(`Equivalent route input resolves ${requestMatrix.length} actor-route cells, exceeding maxCells ${input.maxCells}.`, "EQUIVALENT_ROUTE_TOO_MANY_CELLS");
  }
  return deepFreeze({
    schemaVersion: 1,
    enabled: true,
    routeSets,
    requestMatrix,
    maxRouteSets: input.maxRouteSets,
    maxRoutesPerSet: input.maxRoutesPerSet,
    maxActorsPerSet: input.maxActorsPerSet,
    maxCells: input.maxCells,
    maxRequests: requestMatrix.length,
    maxResponseBytes: input.maxResponseBytes,
    maxPreviewLength: input.maxPreviewLength,
    notes: [
      "Equivalent-route testing executes only operator-supplied GET actor-route cells.",
      "Runtime responses do not add routes, aliases, versions, actors, objects, methods, or cases.",
      "A successful response is treated as allowed only when configured object identity and state are confirmed."
    ]
  });
}

function planRouteSet(input: EquivalentRouteInput["routeSets"][number], limits: EquivalentRouteInput, scopeMatcher: ScopeMatcher, authProfileSet: AuthProfileSet | undefined): EquivalentRouteSetPlan {
  if (input.routes.length > limits.maxRoutesPerSet) throw new AppError(`Equivalent route set "${input.id}" exceeds maxRoutesPerSet ${limits.maxRoutesPerSet}.`, "EQUIVALENT_ROUTE_TOO_MANY_ROUTES");
  if (input.actors.length > limits.maxActorsPerSet) throw new AppError(`Equivalent route set "${input.id}" exceeds maxActorsPerSet ${limits.maxActorsPerSet}.`, "EQUIVALENT_ROUTE_TOO_MANY_ACTORS");
  validateIdentifier(input.objectId, `${input.id}.objectId`);
  parseSafeFieldPath(input.objectIdentityField, { maxDepth: 8, maxArrayIndex: 50, code: "EQUIVALENT_ROUTE_OBJECT_FIELD_INVALID" });
  if (input.objectStateField) parseSafeFieldPath(input.objectStateField, { maxDepth: 8, maxArrayIndex: 50, code: "EQUIVALENT_ROUTE_OBJECT_FIELD_INVALID" });
  if (input.expectedObjectState && !input.objectStateField) throw new AppError(`Equivalent route set "${input.id}" declares expectedObjectState without objectStateField.`, "EQUIVALENT_ROUTE_OBJECT_STATE_FIELD_REQUIRED");

  const actors = input.actors.map((actor) => actorPlan(actor, authProfileSet));
  validateActors(input.id, actors, authProfileSet);
  const actorById = new Map(actors.map((actor) => [actor.id, actor]));
  const routes = input.routes.map((route) => routePlan(route, input, scopeMatcher));
  validateRoutes(input, routes, actors);

  const cells = routes.flatMap((route) =>
    actors.map((actor) => {
      const expectedDecision = input.routes.find((candidate) => candidate.id === route.id)?.expectations[actor.id];
      if (!expectedDecision) throw new AppError(`Equivalent route "${route.id}" is missing expectation for actor "${actor.id}".`, "EQUIVALENT_ROUTE_EXPECTATION_REQUIRED");
      const routeInput = input.routes.find((candidate) => candidate.id === route.id);
      if (!routeInput) throw new AppError(`Equivalent route "${route.id}" is unavailable.`, "EQUIVALENT_ROUTE_UNKNOWN_ROUTE");
      const url = applyPlaceholders(routeInput.template.url, input.objectId, tenantValueForActor(actor, input, authProfileSet), input.id, route.id);
      const decision = scopeMatcher.decide(url, "GET");
      if (!decision.allowed || !decision.normalizedUrl) throw new AppError(`Equivalent route "${route.id}" is out of scope: ${decision.reason}.`, "EQUIVALENT_ROUTE_OUT_OF_SCOPE");
      const objectStateField = route.objectStateField ?? input.objectStateField;
      return {
        id: `${input.id}:${route.id}:${actor.id}`,
        routeSetId: input.id,
        actorId: actor.id,
        actorRelationship: actor.relationship,
        ...(actor.authSlot ? { authSlot: actor.authSlot } : {}),
        routeId: route.id,
        routeLabel: route.label,
        routeCategory: route.category,
        isCanonical: route.id === input.canonicalRouteId,
        ...(route.referenceRouteId ? { referenceRouteId: route.referenceRouteId } : {}),
        canonicalRouteId: input.canonicalRouteId,
        objectType: input.objectType,
        objectId: input.objectId,
        objectIdHash: hashValue(input.objectId, "object"),
        ...(input.expectedObjectState ? { expectedObjectState: input.expectedObjectState, expectedObjectStateHash: hashValue(input.expectedObjectState, "object-state") } : {}),
        expectedDecision,
        equivalencePolicy: route.equivalencePolicy,
        requireVerifiedIdentity: input.requireVerifiedIdentity && Boolean(actor.authSlot),
        ...(actor.tenantIdHash ? { expectedTenantHash: actor.tenantIdHash } : {}),
        ...(actor.roleHash ? { expectedRoleHash: actor.roleHash } : {}),
        ...(actor.accountStateHash ? { expectedAccountStateHash: actor.accountStateHash } : {}),
        objectIdentityField: route.objectIdentityField ?? input.objectIdentityField,
        ...(route.responseEnvelopePath ? { responseEnvelopePath: route.responseEnvelopePath } : {}),
        ...(objectStateField ? { objectStateField } : {}),
        expectedContentType: route.expectedContentType,
        representationType: route.representationType,
        url: decision.normalizedUrl
      } satisfies EquivalentRouteCellPlan;
    })
  );

  for (const cell of cells) {
    if (!actorById.has(cell.actorId)) throw new AppError(`Equivalent route cell references unknown actor "${cell.actorId}".`, "EQUIVALENT_ROUTE_UNKNOWN_ACTOR");
  }

  return {
    id: input.id,
    name: input.name,
    objectType: input.objectType,
    objectId: input.objectId,
    objectIdHash: hashValue(input.objectId, "object"),
    canonicalRouteId: input.canonicalRouteId,
    objectIdentityField: input.objectIdentityField,
    ...(input.objectStateField ? { objectStateField: input.objectStateField } : {}),
    ...(input.expectedObjectState ? { expectedObjectState: input.expectedObjectState, expectedObjectStateHash: hashValue(input.expectedObjectState, "object-state") } : {}),
    equivalencePolicy: input.equivalencePolicy,
    actors,
    routes,
    cells
  };
}

function routePlan(route: EquivalentRouteInput["routeSets"][number]["routes"][number], routeSet: EquivalentRouteInput["routeSets"][number], scopeMatcher: ScopeMatcher): EquivalentRouteDefinitionPlan {
  validateTemplate(route.template, route.id);
  if (route.objectIdentityField) parseSafeFieldPath(route.objectIdentityField, { maxDepth: 8, maxArrayIndex: 50, code: "EQUIVALENT_ROUTE_OBJECT_FIELD_INVALID" });
  if (route.responseEnvelopePath) parseSafeFieldPath(route.responseEnvelopePath, { maxDepth: 8, maxArrayIndex: 50, code: "EQUIVALENT_ROUTE_OBJECT_FIELD_INVALID" });
  if (route.objectStateField) parseSafeFieldPath(route.objectStateField, { maxDepth: 8, maxArrayIndex: 50, code: "EQUIVALENT_ROUTE_OBJECT_FIELD_INVALID" });
  const probeUrl = applyPlaceholders(route.template.url, routeSet.objectId, "routecairn-tenant", routeSet.id, route.id);
  const decision = scopeMatcher.decide(probeUrl, "GET");
  if (!decision.allowed) throw new AppError(`Equivalent route "${route.id}" is out of scope: ${decision.reason}.`, "EQUIVALENT_ROUTE_OUT_OF_SCOPE");
  return {
    id: route.id,
    label: route.label,
    category: route.id === routeSet.canonicalRouteId ? "CANONICAL" : route.category,
    isCanonical: route.id === routeSet.canonicalRouteId,
    deprecated: route.deprecated,
    expectedPublic: route.expectedPublic,
    template: { id: route.template.id, method: "GET", urlTemplate: route.template.url, headers: route.template.headers },
    ...(route.objectIdentityField ? { objectIdentityField: route.objectIdentityField } : {}),
    ...(route.responseEnvelopePath ? { responseEnvelopePath: route.responseEnvelopePath } : {}),
    ...(route.objectStateField ? { objectStateField: route.objectStateField } : {}),
    expectedContentType: route.expectedContentType,
    representationType: route.representationType,
    equivalencePolicy: route.equivalencePolicy ?? routeSet.equivalencePolicy,
    ...(route.referenceRouteId ? { referenceRouteId: route.referenceRouteId } : {})
  };
}

function actorPlan(actor: EquivalentRouteInput["routeSets"][number]["actors"][number], authProfileSet: AuthProfileSet | undefined): EquivalentRouteActorPlan {
  if (actor.relationship === "PUBLIC") {
    if (actor.authProfile) throw new AppError(`Public equivalent-route actor "${actor.id}" must not reference an auth profile.`, "EQUIVALENT_ROUTE_PUBLIC_AUTH_INVALID");
    return { id: actor.id, relationship: "PUBLIC", redactedLabel: actor.safeAlias ?? "Public" };
  }
  if (!authProfileSet) throw new AppError("Equivalent route testing with authenticated actors requires --auth-a and --auth-b.", "EQUIVALENT_ROUTE_AUTH_PAIR_REQUIRED");
  if (!actor.authProfile) throw new AppError(`Authenticated equivalent-route actor "${actor.id}" must reference account_a or account_b.`, "EQUIVALENT_ROUTE_AUTH_PROFILE_REQUIRED");
  const profile = actor.authProfile === "account_a" ? authProfileSet.accountA : authProfileSet.accountB;
  const principalId = actor.principalId ?? profile.principalId;
  if (!principalId) throw new AppError(`Equivalent route actor "${actor.id}" requires declared principalId metadata.`, "EQUIVALENT_ROUTE_PRINCIPAL_ID_REQUIRED");
  if (actor.principalId && profile.principalId && actor.principalId !== profile.principalId) throw new AppError(`Equivalent route actor "${actor.id}" principal metadata does not match its auth profile.`, "EQUIVALENT_ROUTE_PRINCIPAL_ID_MISMATCH");
  if (actor.tenantId && profile.tenantId && actor.tenantId !== profile.tenantId) throw new AppError(`Equivalent route actor "${actor.id}" tenant metadata does not match its auth profile.`, "EQUIVALENT_ROUTE_TENANT_MISMATCH");
  if (actor.role && profile.role && actor.role !== profile.role) throw new AppError(`Equivalent route actor "${actor.id}" role metadata does not match its auth profile.`, "EQUIVALENT_ROUTE_ROLE_MISMATCH");
  if (actor.accountState && profile.accountState && actor.accountState !== profile.accountState) throw new AppError(`Equivalent route actor "${actor.id}" account-state metadata does not match its auth profile.`, "EQUIVALENT_ROUTE_ACCOUNT_STATE_MISMATCH");
  return {
    id: actor.id,
    relationship: actor.relationship,
    redactedLabel: actor.safeAlias ?? profile.safeAlias ?? profile.label,
    authSlot: actor.authProfile,
    principalIdHash: hashValue(principalId, "principal"),
    ...(actor.tenantId ?? profile.tenantId ? { tenantIdHash: hashValue(actor.tenantId ?? profile.tenantId ?? "", "tenant") } : {}),
    ...(actor.role ?? profile.role ? { roleHash: hashValue(actor.role ?? profile.role ?? "", "role") } : {}),
    ...(actor.accountState ?? profile.accountState ? { accountStateHash: hashValue(actor.accountState ?? profile.accountState ?? "", "account-state") } : {})
  };
}

function validateRoutes(input: EquivalentRouteInput["routeSets"][number], routes: readonly EquivalentRouteDefinitionPlan[], actors: readonly EquivalentRouteActorPlan[]): void {
  if (new Set(routes.map((route) => route.id)).size !== routes.length) throw new AppError(`Equivalent route set "${input.id}" contains duplicate route IDs.`, "EQUIVALENT_ROUTE_DUPLICATE_ROUTE");
  const canonical = routes.filter((route) => route.id === input.canonicalRouteId);
  if (canonical.length !== 1) throw new AppError(`Equivalent route set "${input.id}" must declare exactly one canonical route.`, "EQUIVALENT_ROUTE_CANONICAL_REQUIRED");
  const explicitCanonicalFlags = input.routes.filter((route) => route.isCanonical);
  if (explicitCanonicalFlags.length > 1) throw new AppError(`Equivalent route set "${input.id}" declares multiple canonical routes.`, "EQUIVALENT_ROUTE_MULTIPLE_CANONICAL");
  if (explicitCanonicalFlags.length === 1 && explicitCanonicalFlags[0]?.id !== input.canonicalRouteId) throw new AppError(`Equivalent route set "${input.id}" has conflicting canonical route declarations.`, "EQUIVALENT_ROUTE_CANONICAL_CONFLICT");
  if (routes.length < 2) throw new AppError(`Equivalent route set "${input.id}" requires at least one alternate route.`, "EQUIVALENT_ROUTE_ALTERNATE_REQUIRED");
  const actorIds = new Set(actors.map((actor) => actor.id));
  for (const route of input.routes) {
    for (const actor of actors) {
      if (!Object.prototype.hasOwnProperty.call(route.expectations, actor.id)) throw new AppError(`Equivalent route "${route.id}" is missing expectation for actor "${actor.id}".`, "EQUIVALENT_ROUTE_EXPECTATION_REQUIRED");
    }
    for (const actorId of Object.keys(route.expectations)) {
      if (!actorIds.has(actorId)) throw new AppError(`Equivalent route "${route.id}" references unknown actor "${actorId}".`, "EQUIVALENT_ROUTE_UNKNOWN_ACTOR");
    }
  }
  validateReferences(input.id, routes);
}

function validateActors(routeSetId: string, actors: readonly EquivalentRouteActorPlan[], profileSet: AuthProfileSet | undefined): void {
  if (new Set(actors.map((actor) => actor.id)).size !== actors.length) throw new AppError(`Equivalent route set "${routeSetId}" contains duplicate actor IDs.`, "EQUIVALENT_ROUTE_DUPLICATE_ACTOR");
  const seenPrincipals = new Map<string, string>();
  for (const actor of actors.filter((item) => item.authSlot)) {
    if (!actor.principalIdHash) continue;
    const previous = seenPrincipals.get(actor.principalIdHash);
    if (previous && previous !== actor.id) throw new AppError(`Equivalent route set "${routeSetId}" maps distinct actors to the same declared principal.`, "EQUIVALENT_ROUTE_IDENTICAL_PRINCIPAL");
    seenPrincipals.set(actor.principalIdHash, actor.id);
  }
  if (!profileSet) return;
  const usedSlots = new Set(actors.map((actor) => actor.authSlot).filter(Boolean));
  if (usedSlots.has("account_a") && usedSlots.has("account_b")) {
    const accountA = stableAuthFingerprint(profileSet.accountA.headers, profileSet.accountA.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
    const accountB = stableAuthFingerprint(profileSet.accountB.headers, profileSet.accountB.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
    if (accountA === accountB) throw new AppError(`Equivalent route set "${routeSetId}" maps distinct actors to reused authentication material.`, "EQUIVALENT_ROUTE_IDENTICAL_AUTH_MATERIAL");
  }
}

function validateReferences(routeSetId: string, routes: readonly EquivalentRouteDefinitionPlan[]): void {
  const byId = new Map(routes.map((route) => [route.id, route]));
  for (const route of routes) {
    if (route.referenceRouteId && route.referenceRouteId === route.id) throw new AppError(`Equivalent route "${route.id}" cannot reference itself.`, "EQUIVALENT_ROUTE_REFERENCE_SELF");
    if (route.referenceRouteId && !byId.has(route.referenceRouteId)) throw new AppError(`Equivalent route "${route.id}" references missing route "${route.referenceRouteId}".`, "EQUIVALENT_ROUTE_REFERENCE_INVALID");
    const seen = new Set<string>();
    let cursor: string | undefined = route.referenceRouteId;
    while (cursor) {
      if (seen.has(cursor) || cursor === route.id) throw new AppError(`Equivalent route set "${routeSetId}" contains a reference cycle.`, "EQUIVALENT_ROUTE_REFERENCE_CYCLE");
      seen.add(cursor);
      cursor = byId.get(cursor)?.referenceRouteId;
    }
  }
}

function validateTemplate(template: EquivalentRouteInput["routeSets"][number]["routes"][number]["template"], routeId: string): void {
  if (template.method !== "GET") throw new AppError(`Equivalent route "${routeId}" must use GET.`, "EQUIVALENT_ROUTE_METHOD_UNSAFE");
  const decodedUrl = template.url.split(encodedObjectPlaceholder).join(objectPlaceholder).split(encodedTenantPlaceholder).join(tenantPlaceholder);
  if ((decodedUrl.match(/\{\{OBJECT_ID\}\}/g) ?? []).length !== 1) throw new AppError(`Equivalent route "${routeId}" must contain exactly one {{OBJECT_ID}} placeholder.`, "EQUIVALENT_ROUTE_TEMPLATE_PLACEHOLDER_INVALID");
  if ((decodedUrl.match(/\{\{[A-Z_]+\}\}/g) ?? []).some((placeholder) => placeholder !== objectPlaceholder && placeholder !== tenantPlaceholder)) throw new AppError(`Equivalent route "${routeId}" contains undeclared placeholders.`, "EQUIVALENT_ROUTE_TEMPLATE_PLACEHOLDER_INVALID");
  if (!template.url.startsWith("http://") && !template.url.startsWith("https://")) throw new AppError(`Equivalent route "${routeId}" must use http or https.`, "EQUIVALENT_ROUTE_TEMPLATE_PROTOCOL_INVALID");
  if (forbiddenEndpointWords.test(template.url) || generatorPattern.test(template.url)) throw new AppError(`Equivalent route "${routeId}" appears unsafe or dynamic.`, "EQUIVALENT_ROUTE_TEMPLATE_UNSAFE");
  if (urlHasEmbeddedSecret(template.url)) throw new AppError(`Equivalent route "${routeId}" appears to contain secret-like material.`, "EQUIVALENT_ROUTE_TEMPLATE_SECRET_FORBIDDEN");
  for (const [name, value] of Object.entries(template.headers)) {
    if (name.toLowerCase() === "authorization" || name.toLowerCase() === "cookie" || name.toLowerCase().startsWith("x-csrf") || secretLikePattern.test(name) || secretLikePattern.test(value)) {
      throw new AppError(`Equivalent route "${routeId}" must not embed authentication or secret-like headers.`, "EQUIVALENT_ROUTE_TEMPLATE_SECRET_FORBIDDEN");
    }
  }
  try {
    normalizeUrl(template.url.split(objectPlaceholder).join("routecairn-object").split(encodedObjectPlaceholder).join("routecairn-object").split(tenantPlaceholder).join("routecairn-tenant").split(encodedTenantPlaceholder).join("routecairn-tenant"));
  } catch {
    throw new AppError(`Equivalent route "${routeId}" does not produce a valid URL.`, "EQUIVALENT_ROUTE_TEMPLATE_URL_INVALID");
  }
}

function validateIdentifier(value: string, label: string): void {
  if (value.length > maxIdentifierLength || generatorPattern.test(value) || /^\s*\d+\s*-\s*\d+\s*$/.test(value) || value.includes(",") || /[\r\n]/.test(value)) {
    throw new AppError(`Equivalent route identifier "${label}" must be one exact operator-supplied value.`, "EQUIVALENT_ROUTE_IDENTIFIER_UNSAFE");
  }
}

function tenantValueForActor(actor: EquivalentRouteActorPlan, routeSet: EquivalentRouteInput["routeSets"][number], authProfileSet: AuthProfileSet | undefined): string | undefined {
  const inputActor = routeSet.actors.find((candidate) => candidate.id === actor.id);
  if (!inputActor || inputActor.relationship === "PUBLIC") return undefined;
  if (inputActor.tenantId) return inputActor.tenantId;
  if (!actor.authSlot || !authProfileSet) return undefined;
  return actor.authSlot === "account_a" ? authProfileSet.accountA.tenantId : authProfileSet.accountB.tenantId;
}

function applyPlaceholders(templateUrl: string, objectId: string, tenantId: string | undefined, routeSetId: string, routeId: string): string {
  validateIdentifier(objectId, `${routeSetId}.${routeId}.objectId`);
  let url = templateUrl.split(objectPlaceholder).join(encodeURIComponent(objectId)).split(encodedObjectPlaceholder).join(encodeURIComponent(objectId));
  if (url.includes(tenantPlaceholder) || url.includes(encodedTenantPlaceholder)) {
    if (!tenantId) throw new AppError(`Equivalent route "${routeId}" requires tenant metadata for {{TENANT_ID}} substitution.`, "EQUIVALENT_ROUTE_TENANT_REQUIRED");
    validateIdentifier(tenantId, `${routeSetId}.${routeId}.tenantId`);
    url = url.split(tenantPlaceholder).join(encodeURIComponent(tenantId)).split(encodedTenantPlaceholder).join(encodeURIComponent(tenantId));
  }
  return url;
}

function urlHasEmbeddedSecret(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) return true;
    for (const [name, value] of parsed.searchParams) if (secretLikePattern.test(name) || secretLikePattern.test(value)) return true;
    return false;
  } catch {
    return secretLikePattern.test(url);
  }
}

function hashValue(value: string, scope: string): string {
  return createHash("sha256").update(`routecairn-equivalent-route-${scope}-v1`).update("\0").update(value).digest("hex").slice(0, 16);
}

function stableAuthFingerprint(headers: Record<string, string>, cookies: string): string {
  return createHash("sha256").update(JSON.stringify(Object.entries(headers).sort())).update(cookies).digest("hex");
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) return value;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
  return value;
}
