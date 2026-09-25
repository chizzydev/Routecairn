import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { collectionAuthorizationInputSchema, type CollectionAuthorizationInput } from "../../modules/collectionAuthorization/CollectionAuthorizationPlanner.js";
import { fileAuthorizationInputSchema, type FileAuthorizationInput } from "../../modules/fileAuthorization/FileAuthorizationPlanner.js";
import { objectPairInputSchema, type ObjectPairInput } from "../../modules/objectPairTesting/ObjectPairPlanner.js";
import type { SafeInventoryImportInput } from "./SafeInventoryImporter.js";

type Actor = "account_a" | "account_b";
interface DiscoveryConfig {
  enabled: boolean;
  seedPaths: string[];
  maxRoutes: number;
  maxPages: number;
  maxObjectsPerActor: number;
  idFields: string[];
  ownerFields: string[];
  tenantFields: string[];
  fileFields: string[];
  resultArrayPaths: string[];
  requiredParameterValues: Record<string, string>;
}
interface Source { id: string; kind: string; document?: unknown }

export interface AuthorizationInventoryObservation {
  body: unknown;
  headers: Readonly<Record<string, string | string[]>>;
}

export interface AuthorizationInventoryDiscoveryResult {
  objectPairTesting?: ObjectPairInput;
  collectionAuthorization?: CollectionAuthorizationInput;
  fileAuthorization?: FileAuthorizationInput;
  discoveredObjects: number;
  followedPages: number;
  resolvedParameters: number;
  warnings: string[];
}

interface Candidate {
  id: string;
  label: string;
  objectType: string;
  collectionUrl: string;
  detailTemplate?: string;
  idParameter?: string;
}

interface DiscoveredObject {
  actor: Actor;
  id: string;
  idPath: string;
  ownerPath?: string;
  tenantPath?: string;
  ownerId?: string;
  tenantId?: string;
  value: Record<string, unknown>;
}

interface ActorInventory {
  actor: Actor;
  requestUrl: string;
  objects: DiscoveredObject[];
  pagination?: NonNullable<CollectionAuthorizationInput["collections"][number]["pagination"]>;
  resultArrayPath?: string;
  pages: number;
}

export async function discoverAuthorizationInventory(
  input: SafeInventoryImportInput,
  target: string,
  authProfiles: AuthProfileSet | undefined,
  fetch: (url: string, actor: Actor) => Promise<AuthorizationInventoryObservation>
): Promise<AuthorizationInventoryDiscoveryResult> {
  const config: DiscoveryConfig = input.acquisition.authorizationDiscovery;
  if (!config.enabled) return emptyResult();
  if (!authProfiles) return { ...emptyResult(), warnings: ["Authorization discovery was enabled but account A/B authentication profiles were not supplied."] };
  if (!authProfiles.accountA.principalId || !authProfiles.accountB.principalId) {
    return { ...emptyResult(), warnings: ["Authorization discovery requires principalId on both account authentication profiles."] };
  }
  if (authProfiles.accountA.principalId === authProfiles.accountB.principalId) {
    return { ...emptyResult(), warnings: ["Authorization discovery requires distinct account A/B principals."] };
  }

  const candidates = discoverCandidates(input.sources as Source[], target, config).slice(0, config.maxRoutes);
  const warnings: string[] = [];
  const observations: Array<{ candidate: Candidate; inventories: ActorInventory[] }> = [];
  let followedPages = 0;
  for (const candidate of candidates) {
    const inventories: ActorInventory[] = [];
    for (const actor of ["account_a", "account_b"] as const) {
      try {
        const inventory = await acquireActorInventory(candidate, actor, config, authProfiles, fetch);
        inventories.push(inventory);
        followedPages += Math.max(0, inventory.pages - 1);
      } catch (error) {
        warnings.push(`${candidate.label} (${actor}) was skipped: ${error instanceof Error ? error.message : "request failed"}`);
      }
    }
    if (inventories.length) observations.push({ candidate, inventories });
  }

  const objectPairs = compileObjectPairs(observations, authProfiles, config);
  const collections = compileCollections(observations, authProfiles, config);
  const files = compileFiles(observations, authProfiles, config);
  const discoveredObjects = observations.reduce((count, item) => count + item.inventories.reduce((sum, inventory) => sum + inventory.objects.length, 0), 0);
  const resolvedParameters = candidates.filter((candidate) => candidate.detailTemplate).length;
  if (!candidates.length) warnings.push("No bounded GET collection routes could be derived from the supplied schemas, collections, HAR, or seed paths.");
  if (candidates.length && !objectPairs) warnings.push("No object pair had exact principal or tenant evidence for both actors; no cross-account object cases were compiled.");
  return {
    ...(objectPairs ? { objectPairTesting: objectPairs } : {}),
    ...(collections ? { collectionAuthorization: collections } : {}),
    ...(files ? { fileAuthorization: files } : {}),
    discoveredObjects,
    followedPages,
    resolvedParameters,
    warnings
  };
}

function discoverCandidates(sources: Source[], target: string, config: DiscoveryConfig): Candidate[] {
  const candidates: Candidate[] = [];
  for (const source of sources) {
    if (source.kind === "OPENAPI") candidates.push(...openApiCandidates(source.id, source.document, target, config));
    if (source.kind === "POSTMAN") candidates.push(...postmanCandidates(source.id, source.document, target));
    if (source.kind === "HAR") candidates.push(...harCandidates(source.id, source.document, target));
  }
  config.seedPaths.forEach((path, index) => {
    const url = safeUrl(path, target);
    if (url) candidates.push({ id: safeId(`seed-${index + 1}`), label: `Seed ${new URL(url).pathname}`, objectType: objectTypeFor(new URL(url).pathname), collectionUrl: url });
  });
  return dedupe(candidates, (item) => item.collectionUrl);
}

function openApiCandidates(sourceId: string, document: unknown, target: string, config: DiscoveryConfig): Candidate[] {
  if (!record(document) || !record(document.paths)) return [];
  const base = openApiBase(document, target);
  const paths = Object.entries(document.paths).filter((entry): entry is [string, Record<string, unknown>] => entry[0].startsWith("/") && record(entry[1]));
  const detailRoutes = paths.flatMap(([path, item]) => {
    const operation = record(item.get) ? item.get : undefined;
    if (!operation) return [];
    const placeholders = [...path.matchAll(/\{([^}]+)\}/g)].map((match) => match[1]!).filter(Boolean);
    if (!placeholders.length) return [];
    const idParameter = placeholders.find((name) => !isTenantParameter(name, config) && (config.idFields.includes(name) || /(?:^id$|Id$|_id$|uuid$)/i.test(name)));
    if (!idParameter) return [];
    const tenantParameter = placeholders.find((name) => isTenantParameter(name, config));
    const rendered = resolveRequiredParameters(path, item, operation, config.requiredParameterValues, [idParameter, ...(tenantParameter ? [tenantParameter] : [])], document);
    if (!rendered) return [];
    const template = tenantParameter ? rendered.url.replace(`{${tenantParameter}}`, "{{TENANT_ID}}") : rendered.url;
    return [{ path, idParameter, template, resolvedCount: rendered.resolvedCount }];
  });
  const values: Candidate[] = [];
  for (const [path, item] of paths) {
    const operation = record(item.get) ? item.get : undefined;
    if (!operation) continue;
    const placeholders = [...path.matchAll(/\{([^}]+)\}/g)].map((match) => match[1]!).filter(Boolean);
    if (placeholders.some((name) => !isTenantParameter(name, config))) continue;
    const rendered = resolveRequiredParameters(path, item, operation, config.requiredParameterValues, placeholders, document);
    if (!rendered) continue;
    const templated = placeholders.reduce((value, name) => value.replace(`{${name}}`, "{{TENANT_ID}}"), rendered.url);
    const collectionUrl = placeholders.length ? safeTemplate(templated, base) : safeUrl(templated, base);
    if (!collectionUrl) continue;
    const detail = detailRoutes
      .filter((candidate) => routeStem(candidate.path) === routeStem(path))
      .sort((left, right) => left.path.length - right.path.length)[0];
    const detailTemplate = detail ? safeTemplate(detail.template.replace(`{${detail.idParameter}}`, "{{OBJECT_ID}}"), base) : undefined;
    values.push({
      id: safeId(`${sourceId}-${path}`),
      label: text(operation.summary) ?? text(operation.operationId) ?? `GET ${path}`,
      objectType: objectTypeFor(path),
      collectionUrl,
      ...(detailTemplate && detail ? { detailTemplate, idParameter: detail.idParameter } : {})
    });
  }
  return values;
}

function postmanCandidates(sourceId: string, document: unknown, target: string): Candidate[] {
  if (!record(document) || !Array.isArray(document.item)) return [];
  const result: Candidate[] = [];
  const visit = (items: unknown[]): void => {
    for (const item of items) {
      if (!record(item)) continue;
      if (Array.isArray(item.item)) { visit(item.item); continue; }
      const request = record(item.request) ? item.request : undefined;
      if (!request || String(request.method ?? "GET").toUpperCase() !== "GET") continue;
      const raw = typeof request.url === "string" ? request.url : record(request.url) ? text(request.url.raw) : undefined;
      if (!raw || /\{\{|\}\}|\{[^}]+\}/.test(raw)) continue;
      const url = safeUrl(raw, target);
      if (url) result.push({ id: safeId(`${sourceId}-${result.length + 1}`), label: text(item.name) ?? `GET ${new URL(url).pathname}`, objectType: objectTypeFor(new URL(url).pathname), collectionUrl: url });
    }
  };
  visit(document.item);
  return result;
}

function harCandidates(sourceId: string, document: unknown, target: string): Candidate[] {
  const entries = record(document) && record(document.log) && Array.isArray(document.log.entries) ? document.log.entries : [];
  return entries.flatMap((entry, index) => {
    if (!record(entry) || !record(entry.request) || String(entry.request.method).toUpperCase() !== "GET") return [];
    const url = safeUrl(text(entry.request.url) ?? "", target);
    return url ? [{ id: safeId(`${sourceId}-${index + 1}`), label: `HAR ${new URL(url).pathname}`, objectType: objectTypeFor(new URL(url).pathname), collectionUrl: url }] : [];
  });
}

async function acquireActorInventory(candidate: Candidate, actor: Actor, config: DiscoveryConfig, profiles: AuthProfileSet, fetch: (url: string, actor: Actor) => Promise<AuthorizationInventoryObservation>): Promise<ActorInventory> {
  const profile = actor === "account_a" ? profiles.accountA : profiles.accountB;
  const requestUrl = renderActorUrl(candidate.collectionUrl, profile.tenantId);
  if (!requestUrl) throw new Error("tenant-scoped route requires declared tenantId metadata");
  let url: string | undefined = requestUrl;
  let pages = 0;
  let pagination: ActorInventory["pagination"];
  let resultArrayPath: string | undefined;
  const objects: DiscoveredObject[] = [];
  const visited = new Set<string>();
  while (url && pages < config.maxPages && objects.length < config.maxObjectsPerActor) {
    if (visited.has(url)) break;
    visited.add(url);
    const response = await fetch(url, actor);
    pages += 1;
    const extracted = extractObjects(response.body, config);
    resultArrayPath ??= extracted.path;
    for (const value of extracted.values) {
      const discovered = discoveredObject(value, actor, config);
      if (discovered && !objects.some((item) => item.id === discovered.id)) objects.push(discovered);
      if (objects.length >= config.maxObjectsPerActor) break;
    }
    const next = nextPage(response, url, config.maxPages);
    pagination ??= next.pagination;
    url = next.url;
  }
  return { actor, requestUrl, objects, ...(pagination ? { pagination } : {}), ...(resultArrayPath ? { resultArrayPath } : {}), pages };
}

function extractObjects(body: unknown, config: DiscoveryConfig): { values: Record<string, unknown>[]; path?: string } {
  if (Array.isArray(body)) return { values: body.filter(record) };
  if (!record(body)) return { values: [] };
  for (const path of config.resultArrayPaths) {
    const value = atPath(body, path);
    if (Array.isArray(value)) {
      const values = value.flatMap((item) => record(item) && record(item.node) ? [item.node] : record(item) ? [item] : []);
      if (values.length) return { values, path: path.endsWith(".edges") || path === "edges" ? `${path}.node` : path };
    }
  }
  return hasAnyField(body, config.idFields) ? { values: [body] } : { values: [] };
}

function discoveredObject(value: Record<string, unknown>, actor: Actor, config: DiscoveryConfig): DiscoveredObject | undefined {
  const id = firstScalar(value, config.idFields);
  if (!id || !safeIdentifierValue(id.value)) return undefined;
  const owner = firstScalar(value, config.ownerFields);
  const tenant = firstScalar(value, config.tenantFields);
  return {
    actor,
    id: id.value,
    idPath: id.path,
    ...(owner && safeIdentifierValue(owner.value) ? { ownerPath: owner.path, ownerId: owner.value } : {}),
    ...(tenant && safeIdentifierValue(tenant.value) ? { tenantPath: tenant.path, tenantId: tenant.value } : {}),
    value
  };
}

function compileObjectPairs(observations: Array<{ candidate: Candidate; inventories: ActorInventory[] }>, profiles: AuthProfileSet, config: DiscoveryConfig): ObjectPairInput | undefined {
  const cases: Array<Record<string, unknown>> = [];
  for (const observation of observations) {
    if (!observation.candidate.detailTemplate || cases.length >= Math.min(20, config.maxRoutes)) continue;
    const a = evidencedObject(observation.inventories.find((item) => item.actor === "account_a")?.objects ?? [], profiles.accountA.principalId!, profiles.accountA.tenantId);
    const b = evidencedObject(observation.inventories.find((item) => item.actor === "account_b")?.objects ?? [], profiles.accountB.principalId!, profiles.accountB.tenantId);
    if (!a || !b || a.id === b.id) continue;
    const privateOwners = a.ownerId === profiles.accountA.principalId && b.ownerId === profiles.accountB.principalId;
    const tenantEvidence = Boolean(a.tenantId && b.tenantId && profiles.accountA.tenantId === a.tenantId && profiles.accountB.tenantId === b.tenantId);
    if (!privateOwners && !tenantEvidence) continue;
    cases.push({
      id: safeId(`discovered-${observation.candidate.id}`),
      objectType: observation.candidate.objectType,
      expectedVisibility: privateOwners ? "PRIVATE_TO_OWNER" : "TENANT_VISIBLE",
      template: { id: safeId(`template-${observation.candidate.id}`), method: "GET", url: observation.candidate.detailTemplate, headers: {} },
      accountAObject: assertionFor(a, observation.candidate, profiles.accountA.principalId!, profiles.accountA.tenantId),
      accountBObject: assertionFor(b, observation.candidate, profiles.accountB.principalId!, profiles.accountB.tenantId)
    });
  }
  if (!cases.length) return undefined;
  return objectPairInputSchema.parse({ schemaVersion: 1, maxPairs: cases.length, principals: { accountA: principalMetadata(profiles.accountA), accountB: principalMetadata(profiles.accountB) }, cases }) as ObjectPairInput;
}

function compileCollections(observations: Array<{ candidate: Candidate; inventories: ActorInventory[] }>, profiles: AuthProfileSet, config: DiscoveryConfig): CollectionAuthorizationInput | undefined {
  const collections: Array<Record<string, unknown>> = [];
  for (const [index, observation] of observations.entries()) {
    if (collections.length >= 5) break;
    if (observation.candidate.collectionUrl.includes("{{TENANT_ID}}")) continue;
    const aInventory = observation.inventories.find((item) => item.actor === "account_a");
    const bInventory = observation.inventories.find((item) => item.actor === "account_b");
    if (!aInventory || !bInventory) continue;
    const a = evidencedObject(aInventory.objects, profiles.accountA.principalId!, profiles.accountA.tenantId);
    const b = evidencedObject(bInventory.objects, profiles.accountB.principalId!, profiles.accountB.tenantId);
    if (!a && !b) continue;
    const known: Array<Record<string, unknown>> = [];
    if (a) known.push(knownObject(a, "account-a-object", "account-a"));
    if (b) known.push(knownObject(b, "account-b-object", "account-b"));
    const sameTenant = Boolean(profiles.accountA.tenantId && profiles.accountA.tenantId === profiles.accountB.tenantId);
    const cases: Array<Record<string, unknown>> = [];
    if (a) cases.push({ id: "account-a-own", actorId: "account-a", knownObjectId: "account-a-object", expectedMembership: "MUST_CONTAIN", requireVerifiedIdentity: true, summaryExpectations: [] });
    if (b) cases.push({ id: "account-b-own", actorId: "account-b", knownObjectId: "account-b-object", expectedMembership: "MUST_CONTAIN", requireVerifiedIdentity: true, summaryExpectations: [] });
    if (b) cases.push({ id: "account-a-other", actorId: "account-a", knownObjectId: "account-b-object", expectedMembership: sameTenant ? "MAY_CONTAIN" : "MUST_NOT_CONTAIN", expectedActorRelationship: sameTenant ? "SAME_TENANT_MEMBER" : "CROSS_TENANT_MEMBER", requireVerifiedIdentity: true, summaryExpectations: [] });
    if (a) cases.push({ id: "account-b-other", actorId: "account-b", knownObjectId: "account-a-object", expectedMembership: sameTenant ? "MAY_CONTAIN" : "MUST_NOT_CONTAIN", expectedActorRelationship: sameTenant ? "SAME_TENANT_MEMBER" : "CROSS_TENANT_MEMBER", requireVerifiedIdentity: true, summaryExpectations: [] });
    const pagination = aInventory.pagination ?? bInventory.pagination;
    collections.push({
      id: safeId(`discovered-collection-${index + 1}`), label: observation.candidate.label.slice(0, 160), category: "LIST", method: "GET", url: observation.candidate.collectionUrl, headers: {}, expectedContentType: "application/json", completeness: pagination ? "COMPLETE_COLLECTION" : "FIXED_RESULT_WINDOW",
      ...(aInventory.resultArrayPath ?? bInventory.resultArrayPath ? { resultArrayPath: aInventory.resultArrayPath ?? bInventory.resultArrayPath } : {}),
      objectIdPath: a?.idPath ?? b?.idPath,
      ...(a?.tenantPath ?? b?.tenantPath ? { objectTenantPath: a?.tenantPath ?? b?.tenantPath } : {}),
      ...(a?.ownerPath ?? b?.ownerPath ? { objectOwnerPath: a?.ownerPath ?? b?.ownerPath } : {}),
      ...(pagination ? { pagination } : {}), maxInspectedEntries: Math.max(20, config.maxObjectsPerActor * 2), maxResponseBytes: 65536, maxJsonDepth: 10,
      actors: [actorDefinition("account-a", "account_a", profiles.accountA), actorDefinition("account-b", "account_b", profiles.accountB)], knownObjects: known, cases
    });
  }
  if (!collections.length) return undefined;
  const parsed = collectionAuthorizationInputSchema.parse({ schemaVersion: 1, maxCollections: collections.length, maxCasesPerCollection: 4, maxKnownObjects: 2, maxRequests: collections.length * 4 * config.maxPages, collections } as unknown);
  return parsed as CollectionAuthorizationInput;
}

function compileFiles(observations: Array<{ candidate: Candidate; inventories: ActorInventory[] }>, profiles: AuthProfileSet, config: DiscoveryConfig): FileAuthorizationInput | undefined {
  const found: Array<{ url: string; owner: Actor; tenantId?: string }> = [];
  for (const observation of observations) for (const inventory of observation.inventories) for (const object of inventory.objects) {
    if (!evidencedObject([object], inventory.actor === "account_a" ? profiles.accountA.principalId! : profiles.accountB.principalId!, inventory.actor === "account_a" ? profiles.accountA.tenantId : profiles.accountB.tenantId)) continue;
    for (const field of config.fileFields) {
      const value = atPath(object.value, field);
      if (typeof value !== "string") continue;
      const url = fileUrl(value, inventory.requestUrl, field);
      if (url && !found.some((item) => item.url === url)) found.push({ url, owner: inventory.actor, ...(object.tenantId ? { tenantId: object.tenantId } : {}) });
    }
  }
  const bounded = found.slice(0, 20);
  if (!bounded.length) return undefined;
  const compiled: Array<{ id: string; fileRef: string; safeAlias: string; owner: Actor; tenantId?: string; url: string }> = [];
  for (const [index, item] of bounded.entries()) {
    const parsed = new URL(item.url);
    const segments = parsed.pathname.split("/");
    const encoded = segments.pop();
    if (!encoded || hasSensitiveQuery(parsed)) continue;
    let fileRef: string;
    try { fileRef = decodeURIComponent(encoded); } catch { continue; }
    if (!safeIdentifierValue(fileRef) || /\.\./.test(fileRef)) continue;
    segments.push("{{FILE_KEY}}");
    const id = `discovered-file-${index + 1}`;
    compiled.push({ id, fileRef, safeAlias: `Discovered file ${index + 1}`, owner: item.owner, ...(item.tenantId ? { tenantId: item.tenantId } : {}), url: `${parsed.origin}${segments.join("/")}${parsed.search}` });
  }
  if (!compiled.length) return undefined;
  const definitions: Array<Record<string, unknown>> = [];
  let maxCasesPerDefinition = 1;
  let maxFilesPerDefinition = 1;
  let totalCases = 0;
  for (const owner of ["account_a", "account_b"] as const) {
    const group = compiled.filter((file) => file.owner === owner);
    if (!group.length) continue;
    const foreign = owner === "account_a" ? "account_b" : "account_a";
    const ownerProfile = owner === "account_a" ? profiles.accountA : profiles.accountB;
    const foreignProfile = foreign === "account_a" ? profiles.accountA : profiles.accountB;
    const sameTenant = Boolean(ownerProfile.tenantId && ownerProfile.tenantId === foreignProfile.tenantId);
    const ownerId = `${owner}-owner`;
    const foreignId = `${foreign}-foreign`;
    const files = group.map((file) => ({ id: file.id, fileRef: file.fileRef, safeAlias: file.safeAlias, ownerActorId: ownerId, ...(file.tenantId ? { tenantId: file.tenantId } : {}), expectedPublic: false }));
    const cases: Array<Record<string, unknown>> = [];
    for (const file of group) {
      cases.push({ id: `${file.id}-owner`, label: `Owner access to ${file.safeAlias}`, category: "DIRECT_DOWNLOAD", actorId: ownerId, fileRefId: file.id, method: "GET", url: file.url, placeholder: "FILE_KEY", headers: {}, expectedDecision: "MUST_ALLOW_CONTENT", requireVerifiedIdentity: true, identityStrategy: "OBSERVE_ONLY", contentProofMode: "BOUNDED_PREFIX", rangeLength: 4096, maxProbeBytes: 4096 });
      cases.push({ id: `${file.id}-foreign`, label: `Foreign access to ${file.safeAlias}`, category: "DIRECT_DOWNLOAD", actorId: foreignId, fileRefId: file.id, method: "GET", url: file.url, placeholder: "FILE_KEY", headers: {}, expectedDecision: sameTenant ? "OBSERVE_ONLY" : "MUST_DENY_CONTENT", requireVerifiedIdentity: true, identityStrategy: "OBSERVE_ONLY", contentProofMode: "BOUNDED_PREFIX", rangeLength: 4096, maxProbeBytes: 4096 });
    }
    definitions.push({ id: `discovered-${owner}-files`, label: `Files discovered for ${owner}`, actors: [actorDefinition(ownerId, owner, ownerProfile, "OWNER"), actorDefinition(foreignId, foreign, foreignProfile, sameTenant ? "SAME_TENANT_MEMBER" : "CROSS_TENANT_MEMBER")], files, cases });
    maxCasesPerDefinition = Math.max(maxCasesPerDefinition, cases.length);
    maxFilesPerDefinition = Math.max(maxFilesPerDefinition, files.length);
    totalCases += cases.length;
  }
  const parsed = fileAuthorizationInputSchema.parse({ schemaVersion: 1, maxDefinitions: definitions.length, maxCasesPerDefinition, maxFilesPerDefinition, maxRequests: totalCases, definitions } as unknown);
  return parsed as FileAuthorizationInput;
}

function nextPage(response: AuthorizationInventoryObservation, currentUrl: string, maxPages: number): { url?: string; pagination?: ActorInventory["pagination"] } {
  const link = header(response.headers, "link");
  const linkMatch = link?.match(/<([^>]+)>\s*;[^,]*rel\s*=\s*"?next"?/i);
  if (linkMatch?.[1]) {
    const url = constrainedNextUrl(linkMatch[1], currentUrl);
    if (url) return { url, pagination: { mode: "LINK_HEADER", maxPages: Math.max(2, maxPages), allowedQueryParameters: addedPaginationKeys(currentUrl, url) } };
  }
  if (!record(response.body)) return {};
  for (const path of ["next", "nextPage", "links.next", "pagination.next"]) {
    const value = atPath(response.body, path);
    if (typeof value !== "string" || !value) continue;
    const url = constrainedNextUrl(value, currentUrl);
    if (url) return { url, pagination: { mode: "JSON_URL", nextPath: path, maxPages: Math.max(2, maxPages), allowedQueryParameters: addedPaginationKeys(currentUrl, url) } };
  }
  for (const path of ["nextCursor", "cursor.next", "pageInfo.endCursor", "pagination.nextCursor"]) {
    const value = atPath(response.body, path);
    if (typeof value !== "string" && typeof value !== "number") continue;
    const parameter = path.toLowerCase().includes("cursor") ? "cursor" : "after";
    const url = new URL(currentUrl); url.searchParams.set(parameter, String(value));
    return { url: url.toString(), pagination: { mode: "JSON_CURSOR", nextPath: path, cursorQueryParameter: parameter, maxPages: Math.max(2, maxPages) } };
  }
  return {};
}

function resolveRequiredParameters(path: string, pathItem: Record<string, unknown>, operation: Record<string, unknown>, overrides: Record<string, string>, unresolvedPathParameters: string[] = [], document?: Record<string, unknown>): { url: string; resolvedCount: number } | undefined {
  const parameters = [...(Array.isArray(pathItem.parameters) ? pathItem.parameters : []), ...(Array.isArray(operation.parameters) ? operation.parameters : [])]
    .flatMap((parameter) => {
      if (!record(parameter)) return [];
      const resolved = document ? resolveLocalReference(document, parameter) : parameter;
      return resolved ? [resolved] : [];
    });
  let rendered = path;
  let resolvedCount = 0;
  const query = new URLSearchParams();
  for (const parameter of parameters) {
    if (parameter.required !== true) continue;
    const name = text(parameter.name); const location = text(parameter.in);
    if (!name || !location) return undefined;
    if (location === "path" && unresolvedPathParameters.includes(name)) continue;
    const schema = record(parameter.schema) ? parameter.schema : {};
    const value = overrides[name] ?? scalarString(parameter.example ?? schema.example ?? schema.default ?? (Array.isArray(schema.enum) ? schema.enum[0] : undefined));
    if (value === undefined || value.length > 256 || /[\r\n\0]/.test(value)) return undefined;
    if (location === "path") rendered = rendered.replace(`{${name}}`, encodeURIComponent(value));
    else if (location === "query") query.set(name, value);
    else return undefined;
    resolvedCount += 1;
  }
  if ([...rendered.matchAll(/\{([^}]+)\}/g)].some((match) => !unresolvedPathParameters.includes(match[1]!))) return undefined;
  const suffix = query.toString();
  return { url: suffix ? `${rendered}${rendered.includes("?") ? "&" : "?"}${suffix}` : rendered, resolvedCount };
}

function resolveLocalReference(document: Record<string, unknown>, value: Record<string, unknown>): Record<string, unknown> | undefined {
  if (typeof value.$ref !== "string") return value;
  if (!value.$ref.startsWith("#/")) return undefined;
  let current: unknown = document;
  for (const encoded of value.$ref.slice(2).split("/")) {
    let segment: string;
    try { segment = decodeURIComponent(encoded).replace(/~1/g, "/").replace(/~0/g, "~"); } catch { return undefined; }
    if (!record(current) || !Object.prototype.hasOwnProperty.call(current, segment)) return undefined;
    current = current[segment];
  }
  return record(current) ? current : undefined;
}

function assertionFor(object: DiscoveredObject, candidate: Candidate, principalId: string, tenantId?: string): Record<string, unknown> {
  return { id: object.id, source: `Authenticated ${candidate.label} response matched declared identity metadata.`, confirmedSafeToTest: true, readOnly: true, ...(object.tenantId ?? tenantId ? { tenantId: object.tenantId ?? tenantId } : {}), expectedObjectIdField: object.idPath, ...(object.ownerId === principalId && object.ownerPath ? { expectedOwnerField: object.ownerPath } : {}), ...(object.tenantId && object.tenantPath ? { expectedTenantField: object.tenantPath } : {}) };
}

function evidencedObject(objects: DiscoveredObject[], principalId: string, tenantId?: string): DiscoveredObject | undefined {
  return objects.find((object) => object.ownerId === principalId) ?? (tenantId ? objects.find((object) => object.tenantId === tenantId) : undefined);
}

function principalMetadata(profile: AuthProfileSet["accountA"]): { expectedAccountId?: string; tenantId?: string; role?: string } {
  return { ...(profile.principalId ? { expectedAccountId: profile.principalId } : {}), ...(profile.tenantId ? { tenantId: profile.tenantId } : {}), ...(profile.role ? { role: profile.role } : {}) };
}

function actorDefinition(id: string, slot: Actor, profile: AuthProfileSet["accountA"], relationship = "OWNER"): Record<string, unknown> {
  return { id, relationship, authProfile: slot, safeAlias: profile.safeAlias ?? profile.label, principalId: profile.principalId, ...(profile.tenantId ? { tenantId: profile.tenantId } : {}), ...(profile.role ? { role: profile.role } : {}), ...(profile.accountState ? { accountState: profile.accountState } : {}) };
}

function knownObject(object: DiscoveredObject, id: string, ownerActorId: string): Record<string, unknown> {
  return { id, objectId: object.id, objectType: "discovered-object", ownerActorId, ...(object.tenantId ? { tenantId: object.tenantId } : {}), safeAlias: id, expectedPublic: false, expectedShared: false, confirmedSafeToTest: true };
}

function openApiBase(document: Record<string, unknown>, target: string): string {
  const server = Array.isArray(document.servers) && record(document.servers[0]) ? text(document.servers[0].url) : undefined;
  return server && !server.includes("{") ? safeUrl(server, target) ?? new URL(target).origin : new URL(target).origin;
}

function routeStem(path: string): string {
  return path.replace(/\/\{[^}]+\}/g, "").replace(/\/$/, "").toLowerCase();
}

function objectTypeFor(path: string): string {
  const values = path.split("/").filter(Boolean).filter((part) => !part.startsWith("{") && !/^(?:api|v\d+|rest)$/i.test(part));
  return safeId(values.at(-1) ?? "object").slice(0, 80);
}

function safeTemplate(value: string, base: string): string | undefined {
  const objectMarker = "ROUTECAIRN_OBJECT_ID";
  const tenantMarker = "ROUTECAIRN_TENANT_ID";
  const url = safeUrl(value.replaceAll("{{OBJECT_ID}}", objectMarker).replaceAll("{{TENANT_ID}}", tenantMarker), base);
  return url?.replaceAll(objectMarker, "{{OBJECT_ID}}").replaceAll(tenantMarker, "{{TENANT_ID}}");
}

function renderActorUrl(template: string, tenantId?: string): string | undefined {
  if (!template.includes("{{TENANT_ID}}")) return template;
  if (!tenantId || !safeIdentifierValue(tenantId)) return undefined;
  return template.replaceAll("{{TENANT_ID}}", encodeURIComponent(tenantId));
}

function isTenantParameter(name: string, config: DiscoveryConfig): boolean {
  return config.tenantFields.includes(name) || /^(?:tenant|tenantId|tenant_id|organization|organizationId|organization_id|org|orgId|org_id|workspace|workspaceId|workspace_id)$/i.test(name);
}

function safeUrl(value: string, base: string): string | undefined {
  try {
    const url = new URL(value, base);
    const expected = new URL(base);
    if (!["http:", "https:"].includes(url.protocol) || url.origin !== expected.origin || url.username || url.password || url.hash || hasSensitiveQuery(url)) return undefined;
    return url.toString();
  } catch { return undefined; }
}

function fileUrl(value: string, base: string, field: string): string | undefined {
  if (!/(?:url|path|key|file|download|attachment|document)/i.test(field) && !/\.(?:pdf|zip|docx?|xlsx?|pptx?|csv|png|jpe?g|gif|webp|mp[34]|wav|mov|tar|gz)(?:$|[?#])/i.test(value)) return undefined;
  const url = safeUrl(value, base);
  if (!url || !/\.(?:pdf|zip|docx?|xlsx?|pptx?|csv|png|jpe?g|gif|webp|mp[34]|wav|mov|tar|gz)(?:$|[?#])/i.test(url)) return undefined;
  return url;
}

function constrainedNextUrl(value: string, current: string): string | undefined {
  const url = safeUrl(value, current); if (!url) return undefined;
  const before = new URL(current); const after = new URL(url);
  if (before.pathname !== after.pathname) return undefined;
  if ([...after.searchParams.keys()].some((key) => !/^(?:page|p|cursor|next|nextPage|offset|continuation|continuationToken|after|before|start|skip|limit|per_page|page_size)$/i.test(key) && !before.searchParams.has(key))) return undefined;
  return url;
}

function addedPaginationKeys(before: string, after: string): string[] {
  const first = new URL(before); return [...new URL(after).searchParams.keys()].filter((key) => !first.searchParams.has(key));
}

function firstScalar(value: Record<string, unknown>, fields: string[]): { path: string; value: string } | undefined {
  for (const path of fields) { const item = atPath(value, path); const rendered = scalarString(item); if (rendered !== undefined) return { path, value: rendered }; }
  return undefined;
}

function atPath(value: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((current, segment) => record(current) ? current[segment] : undefined, value);
}

function hasAnyField(value: Record<string, unknown>, fields: string[]): boolean { return fields.some((field) => atPath(value, field) !== undefined); }
function scalarString(value: unknown): string | undefined { return typeof value === "string" || typeof value === "number" ? String(value) : undefined; }
function safeIdentifierValue(value: string): boolean { return value.length > 0 && value.length <= 256 && !/[\r\n\0{}]/.test(value) && !/(?:bearer\s|password|secret|token=|signature=)/i.test(value); }
function hasSensitiveQuery(url: URL): boolean { return [...url.searchParams.keys()].some((key) => /(?:token|secret|password|api.?key|signature|jwt|code)/i.test(key)); }
function header(headers: AuthorizationInventoryObservation["headers"], name: string): string | undefined { const key = Object.keys(headers).find((item) => item.toLowerCase() === name); const value = key ? headers[key] : undefined; return Array.isArray(value) ? value.join(", ") : value; }
function safeId(value: string): string { return value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 120) || "discovered"; }
function text(value: unknown): string | undefined { return typeof value === "string" && value.length ? value : undefined; }
function record(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function dedupe<T>(values: T[], key: (value: T) => string): T[] { const seen = new Set<string>(); return values.filter((value) => { const item = key(value); if (seen.has(item)) return false; seen.add(item); return true; }); }
function emptyResult(): AuthorizationInventoryDiscoveryResult { return { discoveredObjects: 0, followedPages: 0, resolvedParameters: 0, warnings: [] }; }
