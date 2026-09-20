import { readFile } from "node:fs/promises";
import { z } from "zod";
import { AppError } from "../../core/errors/AppError.js";
import { apiGraphqlInputSchema, type ApiGraphqlInput } from "../../modules/apiGraphql/ApiGraphqlPlanner.js";
import { collectionAuthorizationInputSchema, type CollectionAuthorizationInput } from "../../modules/collectionAuthorization/CollectionAuthorizationPlanner.js";
import { fileAuthorizationInputSchema, type FileAuthorizationInput } from "../../modules/fileAuthorization/FileAuthorizationPlanner.js";
import { supabaseAuthorizationInputSchema, type SupabaseAuthorizationInput } from "../../modules/supabaseAuthorization/SupabaseAuthorizationPlanner.js";

const maxImportBytes = 4 * 1024 * 1024;
const sourceBase = z.object({ id: z.string().regex(/^[A-Za-z0-9._-]{1,80}$/) });
const openApiSource = sourceBase.extend({ kind: z.literal("OPENAPI"), document: z.unknown() }).strict();
const postmanSource = sourceBase.extend({ kind: z.literal("POSTMAN"), document: z.unknown() }).strict();
const harSource = sourceBase.extend({ kind: z.literal("HAR"), document: z.unknown() }).strict();
const graphqlSource = sourceBase.extend({ kind: z.literal("GRAPHQL_SCHEMA"), endpoint: z.string().url().max(2048), document: z.unknown() }).strict();
const supabaseSource = sourceBase.extend({ kind: z.literal("SUPABASE_CATALOG"), projectUrl: z.string().url().max(2048), anonKeyEnv: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/).default("SUPABASE_ANON_KEY"), document: z.unknown() }).strict();

export const safeInventoryImportInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  maxRoutes: z.number().int().min(1).max(100).default(60),
  maxGraphqlOperations: z.number().int().min(1).max(50).default(20),
  maxFiles: z.number().int().min(1).max(40).default(20),
  maxCollections: z.number().int().min(1).max(5).default(3),
  sources: z.array(z.discriminatedUnion("kind", [openApiSource, postmanSource, harSource, graphqlSource, supabaseSource])).min(1).max(20)
}).strict();

export type SafeInventoryImportInput = z.infer<typeof safeInventoryImportInputSchema>;

export interface SafeInventoryImportResult {
  apiGraphql?: ApiGraphqlInput;
  collectionAuthorization?: CollectionAuthorizationInput;
  fileAuthorization?: FileAuthorizationInput;
  supabaseAuthorization?: SupabaseAuthorizationInput;
  summary: {
    sources: number;
    routes: number;
    graphqlOperations: number;
    files: number;
    collections: number;
    supabaseResources: number;
    blockedMutations: number;
    skipped: number;
    warnings: string[];
  };
}

interface ImportedRoute {
  sourceId: string;
  url: string;
  method: "GET" | "HEAD" | "OPTIONS";
  safeAlias: string;
  fields: string[];
}

interface GraphqlEndpoint {
  sourceId: string;
  url: string;
  fields: Array<{ name: string; objectResult: boolean }>;
  mutationCount: number;
}

interface HarFile { sourceId: string; url: string; method: "GET" | "HEAD"; mimeType?: string }
interface HarCollection { sourceId: string; url: string; pagination: NonNullable<CollectionAuthorizationInput["collections"][number]["pagination"]> }

export async function loadSafeInventoryImport(filePath: string): Promise<SafeInventoryImportInput> {
  const raw = await readFile(filePath);
  if (raw.byteLength > maxImportBytes) throw new AppError(`Inventory import exceeds ${maxImportBytes} bytes.`, "INVENTORY_IMPORT_FILE_TOO_LARGE");
  let json: unknown;
  try { json = JSON.parse(raw.toString("utf8").replace(/^\uFEFF/, "")); }
  catch { throw new AppError("Inventory import is not valid JSON.", "INVENTORY_IMPORT_JSON_INVALID"); }
  const parsed = safeInventoryImportInputSchema.safeParse(json);
  if (!parsed.success) throw new AppError(parsed.error.message, "INVENTORY_IMPORT_INPUT_INVALID");
  return parsed.data;
}

export function compileSafeInventoryImport(rawInput: SafeInventoryImportInput, target: string): SafeInventoryImportResult {
  const input = safeInventoryImportInputSchema.parse(rawInput);
  const origin = new URL(target).origin;
  const routes: ImportedRoute[] = [];
  const graphql: GraphqlEndpoint[] = [];
  const files: HarFile[] = [];
  const collections: HarCollection[] = [];
  const warnings: string[] = [];
  let blockedMutations = 0;
  let skipped = 0;
  let supabase: SupabaseAuthorizationInput | undefined;

  for (const source of input.sources) {
    if (source.kind === "OPENAPI") {
      const result = importOpenApi(source.id, source.document, origin);
      routes.push(...result.routes); blockedMutations += result.blockedMutations; skipped += result.skipped;
    } else if (source.kind === "POSTMAN") {
      const result = importPostman(source.id, source.document, origin);
      routes.push(...result.routes); blockedMutations += result.blockedMutations; skipped += result.skipped;
    } else if (source.kind === "HAR") {
      const result = importHar(source.id, source.document, origin);
      routes.push(...result.routes); files.push(...result.files); collections.push(...result.collections); blockedMutations += result.blockedMutations; skipped += result.skipped;
    } else if (source.kind === "GRAPHQL_SCHEMA") {
      const endpoint = importGraphql(source.id, source.endpoint, source.document, origin);
      if (endpoint) { graphql.push(endpoint); blockedMutations += endpoint.mutationCount; } else skipped += 1;
    } else {
      if (supabase) { warnings.push(`Supabase source ${source.id} was skipped because one catalog is already active.`); skipped += 1; continue; }
      const compiled = importSupabase(source, origin);
      files.push(...compiled.files);
      blockedMutations += compiled.blockedOperations;
      if (compiled.input) supabase = compiled.input;
      if (!compiled.input && !compiled.files.length) skipped += 1;
    }
  }

  const uniqueRoutes = dedupe(routes, (item) => `${item.method} ${item.url}`).slice(0, input.maxRoutes);
  skipped += Math.max(0, dedupe(routes, (item) => `${item.method} ${item.url}`).length - uniqueRoutes.length);
  const apiGraphql = compileApi(uniqueRoutes, graphql, input.maxGraphqlOperations);
  const uniqueFiles = dedupe(files, (item) => `${item.method} ${item.url}`).slice(0, input.maxFiles);
  const uniqueCollections = dedupe(collections, (item) => item.url).slice(0, input.maxCollections);
  const fileAuthorization = compileFiles(uniqueFiles);
  const collectionAuthorization = compileCollections(uniqueCollections);
  const graphqlOperations = graphql.reduce((total, item) => total + Math.min(item.fields.length, input.maxGraphqlOperations), 0);
  const supabaseResources = supabase ? supabase.catalog.tables.length + supabase.catalog.functions.length + supabase.catalog.storageBuckets.length + supabase.catalog.relationships.length : 0;
  if (blockedMutations) warnings.push(`${blockedMutations} state-changing or unverified operation(s) were inventoried but not compiled for execution.`);
  return {
    ...(apiGraphql ? { apiGraphql } : {}),
    ...(collectionAuthorization ? { collectionAuthorization } : {}),
    ...(fileAuthorization ? { fileAuthorization } : {}),
    ...(supabase ? { supabaseAuthorization: supabase } : {}),
    summary: { sources: input.sources.length, routes: uniqueRoutes.length, graphqlOperations, files: uniqueFiles.length, collections: uniqueCollections.length, supabaseResources, blockedMutations, skipped, warnings }
  };
}

function importOpenApi(sourceId: string, document: unknown, origin: string): { routes: ImportedRoute[]; blockedMutations: number; skipped: number } {
  if (!record(document) || !record(document.paths)) return { routes: [], blockedMutations: 0, skipped: 1 };
  const base = openApiBase(document, origin);
  const routes: ImportedRoute[] = [];
  let blockedMutations = 0; let skipped = 0;
  for (const [path, pathItem] of Object.entries(document.paths)) {
    if (!path.startsWith("/") || /[\r\n]/.test(path) || !record(pathItem)) { skipped += 1; continue; }
    for (const [rawMethod, operation] of Object.entries(pathItem)) {
      const method = rawMethod.toUpperCase();
      if (!["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"].includes(method) || !record(operation)) continue;
      if (!["GET", "HEAD", "OPTIONS"].includes(method)) { blockedMutations += 1; continue; }
      if (path.includes("{") || requiredParameters(pathItem, operation) || requiresAuthentication(document, operation)) { skipped += 1; continue; }
      const url = safeSameOriginUrl(path, base, origin); if (!url) { skipped += 1; continue; }
      routes.push({ sourceId, url, method: method as ImportedRoute["method"], safeAlias: string(operation.summary) ?? string(operation.operationId) ?? `${method} ${path}`, fields: responseFields(operation) });
    }
  }
  return { routes, blockedMutations, skipped };
}

function importPostman(sourceId: string, document: unknown, origin: string): { routes: ImportedRoute[]; blockedMutations: number; skipped: number } {
  if (!record(document) || !Array.isArray(document.item)) return { routes: [], blockedMutations: 0, skipped: 1 };
  const routes: ImportedRoute[] = []; let blockedMutations = 0; let skipped = 0;
  const visit = (items: unknown[]): void => { for (const item of items) {
    if (!record(item)) { skipped += 1; continue; }
    if (Array.isArray(item.item)) { visit(item.item); continue; }
    const request = record(item.request) ? item.request : undefined; if (!request) { skipped += 1; continue; }
    const method = String(request.method ?? "GET").toUpperCase();
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) { blockedMutations += 1; continue; }
    if (hasSensitiveHeaders(request.header) || (record(request.auth) && request.auth.type !== "noauth")) { skipped += 1; continue; }
    const rawUrl = typeof request.url === "string" ? request.url : record(request.url) ? string(request.url.raw) : undefined;
    if (!rawUrl || /\{\{|\}\}/.test(rawUrl)) { skipped += 1; continue; }
    const url = safeSameOriginUrl(rawUrl, origin, origin); if (!url) { skipped += 1; continue; }
    routes.push({ sourceId, url, method: method as ImportedRoute["method"], safeAlias: string(item.name) ?? `${method} ${new URL(url).pathname}`, fields: [] });
  } };
  visit(document.item);
  return { routes, blockedMutations, skipped };
}

function importHar(sourceId: string, document: unknown, origin: string): { routes: ImportedRoute[]; files: HarFile[]; collections: HarCollection[]; blockedMutations: number; skipped: number } {
  const entries = record(document) && record(document.log) && Array.isArray(document.log.entries) ? document.log.entries : [];
  const routes: ImportedRoute[] = []; const files: HarFile[] = []; const collections: HarCollection[] = [];
  let blockedMutations = 0; let skipped = 0;
  for (const entry of entries) {
    if (!record(entry) || !record(entry.request) || !record(entry.response)) { skipped += 1; continue; }
    const method = String(entry.request.method ?? "GET").toUpperCase();
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) { blockedMutations += 1; continue; }
    if (hasSensitiveHeaders(entry.request.headers)) { skipped += 1; continue; }
    const url = safeSameOriginUrl(string(entry.request.url) ?? "", origin, origin); const status = number(entry.response.status);
    if (!url || !status || status < 200 || status >= 300) { skipped += 1; continue; }
    const content = record(entry.response.content) ? entry.response.content : {};
    const mimeType = string(content.mimeType) ?? headerValue(entry.response.headers, "content-type");
    routes.push({ sourceId, url, method: method as ImportedRoute["method"], safeAlias: `${method} ${new URL(url).pathname}`, fields: jsonFields(content.text) });
    if ((method === "GET" || method === "HEAD") && fileLike(url, mimeType)) files.push({ sourceId, url, method, ...(mimeType ? { mimeType } : {}) });
    const pagination = harPagination(entry.response, url, content.text);
    if (method === "GET" && pagination) collections.push({ sourceId, url, pagination });
  }
  return { routes, files, collections, blockedMutations, skipped };
}

function importGraphql(sourceId: string, endpoint: string, document: unknown, origin: string): GraphqlEndpoint | undefined {
  const url = safeSameOriginUrl(endpoint, origin, origin); if (!url) return undefined;
  const root = record(document) && record(document.data) && record(document.data.__schema) ? document.data.__schema : record(document) && record(document.__schema) ? document.__schema : undefined;
  if (!root || !Array.isArray(root.types)) return { sourceId, url, fields: [], mutationCount: 0 };
  const queryName = record(root.queryType) ? string(root.queryType.name) : undefined;
  const mutationName = record(root.mutationType) ? string(root.mutationType.name) : undefined;
  const types = root.types.filter(record);
  const query = types.find((item) => item.name === queryName);
  const mutation = types.find((item) => item.name === mutationName);
  const fields = (query && Array.isArray(query.fields) ? query.fields : []).filter(record).flatMap((field) => {
    const name = string(field.name); if (!name || name.startsWith("__")) return [];
    const args = Array.isArray(field.args) ? field.args.filter(record) : [];
    if (args.some((arg) => nonNullType(arg.type) && arg.defaultValue == null)) return [];
    return [{ name, objectResult: objectType(field.type) }];
  });
  return { sourceId, url, fields, mutationCount: mutation && Array.isArray(mutation.fields) ? mutation.fields.length : 0 };
}

function importSupabase(source: z.infer<typeof supabaseSource>, origin: string): { input?: SupabaseAuthorizationInput; files: HarFile[]; blockedOperations: number } {
  const projectUrl = safeProjectOrigin(source.projectUrl, origin); if (!projectUrl || !record(source.document)) return { files: [], blockedOperations: 0 };
  const catalogSource = record(source.document.catalog) ? source.document.catalog : source.document;
  const tables = arrayRecords(catalogSource.tables).flatMap((item) => {
    const name = identifier(item.name); const schema = identifier(item.schema) ?? "public"; if (!name) return [];
    const columns = arrayRecords(item.columns).flatMap((column) => { const columnName = identifier(column.name); return columnName ? [{ name: columnName, sensitive: Boolean(column.sensitive), exposedTo: stringArray(column.exposedTo) }] : []; });
    return [{ schema, name, exposed: item.exposed !== false, rlsEnabled: Boolean(item.rlsEnabled ?? item.rls_enabled), rlsForced: Boolean(item.rlsForced ?? item.rls_forced), grants: [], columns }];
  });
  const functions = arrayRecords(catalogSource.functions).flatMap((item) => { const name = identifier(item.name); if (!name) return []; return [{ schema: identifier(item.schema) ?? "public", name, exposed: item.exposed !== false, securityDefiner: Boolean(item.securityDefiner ?? item.security_definer), executableBy: stringArray(item.executableBy), searchPath: stringArray(item.searchPath), usesDynamicSql: Boolean(item.usesDynamicSql) }]; });
  const storageBuckets = arrayRecords(catalogSource.storageBuckets ?? catalogSource.buckets).flatMap((item) => { const name = identifier(item.name ?? item.id); if (!name) return []; return [{ name, public: Boolean(item.public), ownershipEnforced: Boolean(item.ownershipEnforced), allowedOperations: {} }]; });
  const relationships = arrayRecords(catalogSource.relationships).flatMap((item) => { const name = identifier(item.name); const from = identifier(item.from); const to = identifier(item.to); return name && from && to ? [{ name, from, to, exposed: item.exposed !== false }] : []; });
  const publicBuckets = new Set(storageBuckets.filter((bucket) => bucket.public).map((bucket) => bucket.name));
  const files = arrayRecords(catalogSource.storageObjects ?? catalogSource.objects).flatMap((item) => {
    const bucket = identifier(item.bucket ?? item.bucketId); const objectPath = string(item.path ?? item.name);
    if (!bucket || !objectPath || item.public !== true || !publicBuckets.has(bucket) || objectPath.length > 512 || objectPath.startsWith("/") || /(?:\.\.|[\r\n\0{}\\])/.test(objectPath)) return [];
    const encodedPath = objectPath.split("/").map(encodeURIComponent).join("/");
    const mimeType = string(item.mimeType);
    return [{ sourceId: source.id, url: `${projectUrl}/storage/v1/object/public/${encodeURIComponent(bucket)}/${encodedPath}`, method: "GET" as const, ...(mimeType ? { mimeType } : {}) }];
  });
  const tableCases = tables.filter((table) => table.exposed).map((table, index) => ({ id: `imported-table-${index + 1}`, surface: "TABLE" as const, resource: table.name, operation: "SELECT" as const, actor: "ANONYMOUS" as const, expectedDecision: "OBSERVE_ONLY" as const, boundary: "NONE" as const, method: "GET" as const, url: `${projectUrl}/rest/v1/${encodeURIComponent(table.name)}?select=*&limit=1`, headers: {}, responseShape: "LIST" as const, identityAssertions: [], forbiddenColumns: table.columns.filter((column) => column.sensitive).map((column) => column.name), requireVerifiedIdentity: false }));
  const relationshipCases = relationships.filter((relationship) => relationship.exposed).map((relationship, index) => ({ id: `imported-relationship-${index + 1}`, surface: "RELATIONSHIP" as const, resource: relationship.name, operation: "SELECT" as const, actor: "ANONYMOUS" as const, expectedDecision: "OBSERVE_ONLY" as const, boundary: "NONE" as const, method: "GET" as const, url: `${projectUrl}/rest/v1/${encodeURIComponent(relationship.from)}?select=*,${encodeURIComponent(relationship.to)}(*)&limit=1`, headers: {}, responseShape: "LIST" as const, identityAssertions: [], forbiddenColumns: [], requireVerifiedIdentity: false }));
  const bucketCases = storageBuckets.filter((bucket) => bucket.public).map((bucket, index) => ({ id: `imported-bucket-${index + 1}`, surface: "STORAGE" as const, resource: bucket.name, operation: "SELECT" as const, actor: "ANONYMOUS" as const, expectedDecision: "OBSERVE_ONLY" as const, boundary: "NONE" as const, method: "GET" as const, url: `${projectUrl}/storage/v1/bucket/${encodeURIComponent(bucket.name)}`, headers: {}, responseShape: "SINGLE" as const, identityAssertions: [], forbiddenColumns: [], requireVerifiedIdentity: false }));
  const cases = [...tableCases, ...relationshipCases, ...bucketCases].slice(0, 200);
  if (!cases.length) return { files, blockedOperations: functions.length };
  return { input: supabaseAuthorizationInputSchema.parse({ schemaVersion: 1, projectUrl, anonKeyEnv: source.anonKeyEnv, maxCases: Math.max(1, cases.length), cases, catalog: { exposedSchemas: [...new Set(tables.filter((item) => item.exposed).map((item) => item.schema))], expectedExposedSchemas: ["public"], tables, functions, storageBuckets, relationships } }), files, blockedOperations: functions.length };
}

function compileApi(routes: ImportedRoute[], graphql: GraphqlEndpoint[], maxGraphqlOperations: number): ApiGraphqlInput | undefined {
  const actor = { id: "imported-anonymous", safeAlias: "Imported anonymous read", authSlot: "anonymous" as const, relationship: "PUBLIC" };
  const routeInputs: Array<Record<string, unknown>> = []; const checks: Array<Record<string, unknown>> = [];
  routes.forEach((route, index) => { const id = `imported-rest-${index + 1}`; routeInputs.push({ id, safeAlias: route.safeAlias.slice(0, 100), protocol: "REST", kind: "FUNCTION", functionName: `read-${index + 1}`, url: route.url, pathTemplate: new URL(route.url).pathname, documented: true, documentedMethods: [route.method], documentedResponseFields: route.fields }); checks.push({ id: `${id}-observe`, matrixId: `${id}-matrix`, label: `Observe ${route.method} ${new URL(route.url).pathname}`, kind: "FUNCTION_AUTHORIZATION", routeId: id, actorId: actor.id, requireVerifiedIdentity: false, request: { method: route.method, headers: {} }, response: { expectedDecision: "OBSERVE", allowedStatuses: [200, 201, 202, 204, 206, 304], deniedStatuses: [400, 401, 403, 404, 405, 409, 422], fieldRules: route.fields.map((path) => ({ path, classification: "PUBLIC", expectation: "OBSERVE" })) } }); });
  graphql.forEach((endpoint, endpointIndex) => { const id = `imported-graphql-${endpointIndex + 1}`; routeInputs.push({ id, safeAlias: "Imported GraphQL endpoint", protocol: "GRAPHQL", kind: "FUNCTION", functionName: "graphql", url: endpoint.url, pathTemplate: new URL(endpoint.url).pathname, documented: true, documentedMethods: ["POST"], documentedResponseFields: [], operatorConfirmedNonMutatingPost: true }); checks.push({ id: `${id}-introspection`, label: "Observe GraphQL introspection availability", kind: "GRAPHQL_INTROSPECTION", routeId: id, actorId: actor.id, requireVerifiedIdentity: false, expectedClassification: "OBSERVE" }); endpoint.fields.slice(0, maxGraphqlOperations).forEach((field, fieldIndex) => checks.push({ id: `${id}-query-${fieldIndex + 1}`, matrixId: `${id}-query-${fieldIndex + 1}-matrix`, label: `Observe GraphQL query ${field.name}`, kind: "FUNCTION_AUTHORIZATION", routeId: id, actorId: actor.id, requireVerifiedIdentity: false, request: { method: "POST", headers: {}, graphql: { operationName: `RouteCairnImported${fieldIndex + 1}`, document: `query RouteCairnImported${fieldIndex + 1} { ${field.name}${field.objectResult ? " { __typename }" : ""} }`, variables: {} }, operatorConfirmedNonMutating: true }, response: { expectedDecision: "OBSERVE", allowedStatuses: [200], deniedStatuses: [400, 401, 403, 404, 405, 422], fieldRules: [] } })); });
  if (!checks.length) return undefined;
  const boundedChecks = checks.slice(0, 100); const usedRouteIds = new Set(boundedChecks.flatMap((item) => [string(item.routeId), string(item.baselineRouteId), string(item.candidateRouteId)].filter((value): value is string => Boolean(value))));
  return apiGraphqlInputSchema.parse({ schemaVersion: 1, maxRequests: Math.min(300, Math.max(1, boundedChecks.length)), actors: [actor], routes: routeInputs.filter((item) => usedRouteIds.has(String(item.id))).slice(0, 100), checks: boundedChecks });
}

function compileFiles(files: HarFile[]): FileAuthorizationInput | undefined {
  const compiled = files.flatMap((file, index) => { const parsed = new URL(file.url); const segments = parsed.pathname.split("/"); const encoded = segments.pop(); if (!encoded) return []; let fileRef: string; try { fileRef = decodeURIComponent(encoded); } catch { return []; } if (!fileRef || fileRef.length > 512 || /(?:\.\.|[\r\n\0{}])/i.test(fileRef)) return []; segments.push("{{FILE_KEY}}"); const template = `${parsed.origin}${segments.join("/")}${parsed.search}`; return [{ file: { id: `imported-file-${index + 1}`, fileRef, safeAlias: `Imported file ${index + 1}`, ...(file.mimeType ? { fileType: file.mimeType.slice(0, 80) } : {}), expectedPublic: true }, testCase: { id: `imported-file-${index + 1}-observe`, label: `Observe imported file ${index + 1}`, category: "OBSERVE_ONLY", actorId: "imported-public", fileRefId: `imported-file-${index + 1}`, method: file.method, url: template, placeholder: "FILE_KEY", headers: {}, expectedDecision: "OBSERVE_ONLY", requireVerifiedIdentity: false, identityStrategy: "OBSERVE_ONLY", contentProofMode: file.method === "HEAD" ? "HEADERS_ONLY" : "BOUNDED_PREFIX", ...(file.method === "GET" ? { rangeLength: 4096, maxProbeBytes: 4096 } : {}) } }]; });
  if (!compiled.length) return undefined;
  return fileAuthorizationInputSchema.parse({ schemaVersion: 1, maxDefinitions: 1, maxCasesPerDefinition: compiled.length, maxFilesPerDefinition: compiled.length, maxRequests: compiled.length, definitions: [{ id: "imported-files", label: "Imported file inventory", actors: [{ id: "imported-public", relationship: "PUBLIC", safeAlias: "Public" }], files: compiled.map((item) => item.file), cases: compiled.map((item) => item.testCase) }] });
}

function compileCollections(collections: HarCollection[]): CollectionAuthorizationInput | undefined {
  if (!collections.length) return undefined;
  const values = collections.map((item, index) => ({ id: `imported-collection-${index + 1}`, label: `Imported paginated collection ${index + 1}`, category: "LIST" as const, method: "GET" as const, url: item.url, headers: {}, expectedContentType: "application/json", completeness: "SUMMARY_ONLY" as const, pagination: item.pagination, actors: [{ id: "imported-public", relationship: "PUBLIC" as const, safeAlias: "Public" }], knownObjects: [], cases: [{ id: `imported-collection-${index + 1}-observe`, actorId: "imported-public", expectedMembership: "OBSERVE_ONLY" as const, requireVerifiedIdentity: false, summaryExpectations: [] }] }));
  const maxRequests = values.reduce((total, item) => total + item.pagination.maxPages, 0);
  return collectionAuthorizationInputSchema.parse({ schemaVersion: 1, maxCollections: values.length, maxCasesPerCollection: 1, maxRequests, collections: values });
}

function openApiBase(document: Record<string, unknown>, origin: string): string { const server = Array.isArray(document.servers) && record(document.servers[0]) ? string(document.servers[0].url) : undefined; return server && !/[{}]/.test(server) ? safeSameOriginUrl(server, origin, origin) ?? origin : origin; }
function requiredParameters(pathItem: Record<string, unknown>, operation: Record<string, unknown>): boolean { return [...(Array.isArray(pathItem.parameters) ? pathItem.parameters : []), ...(Array.isArray(operation.parameters) ? operation.parameters : [])].filter(record).some((item) => item.required === true); }
function requiresAuthentication(document: Record<string, unknown>, operation: Record<string, unknown>): boolean { const security = operation.security ?? document.security; return Array.isArray(security) && security.length > 0; }
function responseFields(operation: Record<string, unknown>): string[] { const responses = record(operation.responses); const success = responses ? Object.entries(responses).find(([key]) => /^2\d\d$/.test(key) || key === "default")?.[1] : undefined; const content = record(success) ? record(success.content) : undefined; const media = content ? Object.values(content).find(record) : undefined; let schema = media ? media.schema : undefined; if (record(schema) && schema.type === "array") schema = schema.items; return record(schema) && record(schema.properties) ? Object.keys(schema.properties).filter((key) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)).slice(0, 100) : []; }
function harPagination(response: Record<string, unknown>, url: string, body: unknown): HarCollection["pagination"] | undefined { const link = headerValue(response.headers, "link"); if (link && /rel\s*=\s*"?next"?/i.test(link)) { const match = link.match(/<([^>]+)>\s*;[^,]*rel\s*=\s*"?next"?/i); if (!match?.[1]) return undefined; try { const next = new URL(match[1], url); const initial = new URL(url); if (next.origin !== initial.origin || next.pathname !== initial.pathname) return undefined; const added = [...next.searchParams.keys()].filter((key) => !initial.searchParams.has(key) && /^(?:page|p|cursor|offset|after|before|start|skip|continuationToken)$/i.test(key)); return { mode: "LINK_HEADER", maxPages: 3, allowedQueryParameters: added }; } catch { return undefined; } } const parsed = parseJson(body); if (!record(parsed)) return undefined; for (const key of ["nextCursor", "cursor", "continuationToken"]) if (typeof parsed[key] === "string" || typeof parsed[key] === "number") return { mode: "JSON_CURSOR", nextPath: key, cursorQueryParameter: key, maxPages: 3 }; for (const key of ["next", "nextPage"]) if (typeof parsed[key] === "string") { try { const next = new URL(parsed[key], url); const initial = new URL(url); if (next.origin !== initial.origin || next.pathname !== initial.pathname) continue; const added = [...next.searchParams.keys()].filter((name) => !initial.searchParams.has(name) && /^(?:page|p|cursor|offset|after|before|start|skip|continuationToken)$/i.test(name)); return { mode: "JSON_URL", nextPath: key, maxPages: 3, allowedQueryParameters: added }; } catch { continue; } } return undefined; }
function headerValue(headers: unknown, name: string): string | undefined { const item = arrayRecords(headers).find((header) => String(header.name).toLowerCase() === name); return item ? string(item.value) : undefined; }
function hasSensitiveHeaders(headers: unknown): boolean { return arrayRecords(headers).some((header) => /^(?:authorization|cookie|proxy-authorization|x-api-key|x-csrf-token|x-xsrf-token)$/i.test(String(header.name))); }
function fileLike(url: string, mimeType?: string): boolean { if (mimeType && !/^(?:application\/(?:json|xml|javascript)|text\/|image\/svg\+xml)/i.test(mimeType)) return true; return /\.(?:pdf|zip|docx?|xlsx?|pptx?|csv|png|jpe?g|gif|webp|mp[34]|wav|mov|avi|tar|gz)(?:$|[?#])/i.test(url); }
function jsonFields(text: unknown): string[] { const parsed = parseJson(text); if (record(parsed)) return Object.keys(parsed).filter((key) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)).slice(0, 100); const first = Array.isArray(parsed) ? parsed.find(record) : undefined; return first ? Object.keys(first).filter((key) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)).slice(0, 100) : []; }
function safeSameOriginUrl(value: string, base: string, origin: string): string | undefined { try { const url = new URL(value, base); if (!["http:", "https:"].includes(url.protocol) || url.origin !== origin || url.username || url.password || url.hash || [...url.searchParams.keys()].some((key) => /(?:token|secret|password|api.?key|signature|jwt)/i.test(key))) return undefined; return url.toString(); } catch { return undefined; } }
function safeProjectOrigin(value: string, targetOrigin: string): string | undefined { try { const url = new URL(value); if (url.origin !== targetOrigin || url.username || url.password || (url.pathname !== "/" && url.pathname !== "") || url.search || url.hash) return undefined; return url.origin; } catch { return undefined; } }
function nonNullType(value: unknown): boolean { return record(value) && value.kind === "NON_NULL"; }
function objectType(value: unknown): boolean { let current = value; while (record(current) && (current.kind === "NON_NULL" || current.kind === "LIST")) current = current.ofType; return record(current) && (current.kind === "OBJECT" || current.kind === "INTERFACE" || current.kind === "UNION"); }
function parseJson(value: unknown): unknown { if (typeof value !== "string" || value.length > 512 * 1024) return undefined; try { return JSON.parse(value); } catch { return undefined; } }
function record(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function arrayRecords(value: unknown): Record<string, unknown>[] { return Array.isArray(value) ? value.filter(record) : []; }
function string(value: unknown): string | undefined { return typeof value === "string" && value.length ? value : undefined; }
function number(value: unknown): number | undefined { return typeof value === "number" && Number.isFinite(value) ? value : undefined; }
function stringArray(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string").slice(0, 24) : []; }
function identifier(value: unknown): string | undefined { return typeof value === "string" && /^[A-Za-z_][A-Za-z0-9_$.-]{0,127}$/.test(value) ? value : undefined; }
function dedupe<T>(values: T[], key: (value: T) => string): T[] { const seen = new Set<string>(); return values.filter((value) => { const item = key(value); if (seen.has(item)) return false; seen.add(item); return true; }); }
