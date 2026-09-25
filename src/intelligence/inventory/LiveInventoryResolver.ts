import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import { authHeadersForProfile, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { TargetAuthorizationGuard, type TargetAuthorization } from "../../core/authorization/TargetAuthorization.js";
import { AppError } from "../../core/errors/AppError.js";
import { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import {
  compileSafeInventoryImport,
  safeInventoryImportInputSchema,
  type SafeInventoryImportInput,
  type SafeInventoryImportResult
} from "./SafeInventoryImporter.js";
import { discoverAuthorizationInventory, type AuthorizationInventoryObservation } from "./AuthorizationInventoryDiscovery.js";
import { collectionAuthorizationInputSchema, type CollectionAuthorizationInput } from "../../modules/collectionAuthorization/CollectionAuthorizationPlanner.js";
import { fileAuthorizationInputSchema, type FileAuthorizationInput } from "../../modules/fileAuthorization/FileAuthorizationPlanner.js";

type InventorySource = SafeInventoryImportInput["sources"][number];
type AcquisitionActor = "anonymous" | "primary" | "account_a" | "account_b";

export interface LiveInventoryResolutionOptions {
  scope: RouteCairnScope;
  authProfile?: AuthProfile;
  authProfileSet?: AuthProfileSet;
  targetAuthorization?: TargetAuthorization;
  abortSignal?: AbortSignal;
  userAgent?: string;
}

interface AcquisitionStats {
  fetched: number;
  authenticated: number;
  discovered: number;
  resolvedEnvironments: number;
  warnings: string[];
  discoveredObjects: number;
  followedPages: number;
  resolvedParameters: number;
}

const defaultDiscoveryPaths = [
  "/openapi.json",
  "/swagger.json",
  "/api/openapi.json",
  "/api/swagger.json",
  "/v3/api-docs",
  "/.well-known/openapi.json"
];

const introspectionQuery = `query RouteCairnInventoryIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name
      fields(includeDeprecated: true) {
        name
        args { name defaultValue type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}`;

export async function resolveSafeInventoryImport(
  rawInput: SafeInventoryImportInput,
  target: string,
  options: LiveInventoryResolutionOptions
): Promise<SafeInventoryImportResult> {
  const input = safeInventoryImportInputSchema.parse(rawInput);
  const stats: AcquisitionStats = { fetched: 0, authenticated: 0, discovered: 0, resolvedEnvironments: 0, discoveredObjects: 0, followedPages: 0, resolvedParameters: 0, warnings: [] };
  const guard = options.targetAuthorization ? new TargetAuthorizationGuard(options.targetAuthorization) : undefined;
  const broker = new RequestSafetyBroker({
    userAgent: options.userAgent ?? options.scope.userAgent,
    timeoutMs: input.acquisition.timeoutMs,
    bodyPreviewBytes: input.acquisition.maxDocumentBytes,
    maxResponseBytes: input.acquisition.maxDocumentBytes,
    rateLimitPerSecond: Math.min(input.acquisition.rateLimitPerSecond, options.scope.rateLimitPerSecond),
    concurrency: Math.min(input.acquisition.concurrency, options.scope.concurrency),
    maxRequests: input.acquisition.maxFetches,
    retry: { maxAttempts: 1, baseDelayMs: 50, maxDelayMs: 50, retryStatusCodes: [] },
    allowedPrivateOrigins: privateOriginsFor(input),
    ...(options.abortSignal ? { abortSignal: options.abortSignal } : {})
  }, new ScopeMatcher(target, options.scope, guard), () => {});

  const resolvedSources: InventorySource[] = [];
  let autonomousDiscovery: Awaited<ReturnType<typeof discoverAuthorizationInventory>> | undefined;
  try {
    for (const source of input.sources) {
      options.abortSignal?.throwIfAborted();
      if (isLocalSource(source)) {
        resolvedSources.push(source);
        continue;
      }
      if (source.kind === "OPENAPI_URL") {
        const document = await fetchJson(broker, source.url, "GET", actorHeaders(source.actor, options), input.acquisition.maxDocumentBytes, stats);
        if (!isOpenApi(document)) throw new AppError("Fetched OpenAPI source does not contain an OpenAPI paths document.", "INVENTORY_OPENAPI_DOCUMENT_INVALID");
        resolvedSources.push({ id: source.id, kind: "OPENAPI", document });
      } else if (source.kind === "POSTMAN_URL") {
        const headers = actorHeaders(source.actor, options);
        const fetchedDocument = await fetchJson(broker, source.collectionUrl, "GET", headers, input.acquisition.maxDocumentBytes, stats);
        const document = isRecord(fetchedDocument) && isRecord(fetchedDocument.collection) ? fetchedDocument.collection : fetchedDocument;
        if (!isRecord(document) || !Array.isArray(document.item)) throw new AppError("Fetched Postman source does not contain a collection item array.", "INVENTORY_POSTMAN_DOCUMENT_INVALID");
        const fetchedEnvironment = source.environmentUrl
          ? await fetchJson(broker, source.environmentUrl, "GET", headers, input.acquisition.maxDocumentBytes, stats)
          : source.environment;
        const environment = isRecord(fetchedEnvironment) && isRecord(fetchedEnvironment.environment) ? fetchedEnvironment.environment : fetchedEnvironment;
        if (environment !== undefined || source.variables) stats.resolvedEnvironments += 1;
        resolvedSources.push({ id: source.id, kind: "POSTMAN", document, ...(environment !== undefined ? { environment } : {}), ...(source.variables ? { variables: source.variables } : {}) });
      } else if (source.kind === "HAR_URL") {
        const document = await fetchJson(broker, source.url, "GET", actorHeaders(source.actor, options), input.acquisition.maxDocumentBytes, stats);
        if (!isRecord(document) || !isRecord(document.log) || !Array.isArray(document.log.entries)) throw new AppError("Fetched HAR source does not contain log entries.", "INVENTORY_HAR_DOCUMENT_INVALID");
        resolvedSources.push({ id: source.id, kind: "HAR", document });
      } else if (source.kind === "GRAPHQL_INTROSPECTION") {
        const document = await fetchGraphqlSchema(broker, source.endpoint, actorHeaders(source.actor, options), input.acquisition.maxDocumentBytes, stats);
        if (!hasGraphqlSchema(document)) throw new AppError("GraphQL introspection response did not include __schema.", "INVENTORY_GRAPHQL_SCHEMA_MISSING");
        resolvedSources.push({ id: source.id, kind: "GRAPHQL_SCHEMA", endpoint: source.endpoint, document });
      } else if (source.kind === "SUPABASE_LIVE") {
        resolvedSources.push(await acquireSupabase(source, broker, options, input.acquisition.maxDocumentBytes, stats));
      } else {
        resolvedSources.push(...await discoverService(source, broker, options, target, input.acquisition.maxDocumentBytes, stats));
      }
    }
    autonomousDiscovery = await discoverAuthorizationInventory(
      safeInventoryImportInputSchema.parse({ ...input, sources: resolvedSources }),
      target,
      options.authProfileSet,
      async (url, actor) => fetchJsonObservation(broker, url, actorHeaders(actor, options), input.acquisition.maxDocumentBytes, stats)
    );
    stats.discoveredObjects += autonomousDiscovery.discoveredObjects;
    stats.followedPages += autonomousDiscovery.followedPages;
    stats.resolvedParameters += autonomousDiscovery.resolvedParameters;
    stats.warnings.push(...autonomousDiscovery.warnings);
  } finally {
    await broker.close();
  }

  if (!resolvedSources.length) throw new AppError("Live inventory acquisition produced no usable sources.", "INVENTORY_ACQUISITION_EMPTY");
  const compiled = compileSafeInventoryImport(safeInventoryImportInputSchema.parse({ ...input, sources: resolvedSources }), target, { scope: options.scope });
  if (autonomousDiscovery?.objectPairTesting) compiled.objectPairTesting = autonomousDiscovery.objectPairTesting;
  if (autonomousDiscovery?.collectionAuthorization) compiled.collectionAuthorization = mergeCollectionInputs(compiled.collectionAuthorization, autonomousDiscovery.collectionAuthorization);
  if (autonomousDiscovery?.fileAuthorization) compiled.fileAuthorization = mergeFileInputs(compiled.fileAuthorization, autonomousDiscovery.fileAuthorization);
  compiled.summary.sources = input.sources.length;
  if (stats.fetched || stats.discovered || stats.discoveredObjects || stats.resolvedEnvironments || stats.warnings.length) {
    compiled.summary.acquisition = { fetches: stats.fetched, authenticatedFetches: stats.authenticated, discoveredItems: stats.discovered + stats.discoveredObjects, resolvedEnvironments: stats.resolvedEnvironments };
    compiled.summary.warnings.push(
      `Live acquisition fetched ${stats.fetched} document(s), including ${stats.authenticated} authenticated request(s), discovered ${stats.discovered + stats.discoveredObjects} service/object item(s), followed ${stats.followedPages} bounded page(s), resolved ${stats.resolvedParameters} parameterized route(s), and resolved ${stats.resolvedEnvironments} Postman environment(s).`,
      ...stats.warnings
    );
  }
  return compiled;
}

/** Returns a stricter execution grant whose request ceiling includes every
 * acquisition attempt already charged to the bug-bounty authorization. */
export function reserveInventoryAcquisitionBudget(authorization: TargetAuthorization | undefined, result: SafeInventoryImportResult | undefined): TargetAuthorization | undefined {
  const fetches = result?.summary.acquisition?.fetches ?? 0;
  if (!authorization?.bugBounty || fetches === 0) return authorization;
  const remaining = authorization.bugBounty.maxRequests - fetches;
  if (remaining < 1) throw new AppError("Inventory acquisition exhausted the target-authorization request budget before scan execution.", "INVENTORY_TARGET_AUTHORIZATION_BUDGET_EXHAUSTED");
  return targetAuthorizationSchemaClone(authorization, remaining);
}

function targetAuthorizationSchemaClone(authorization: TargetAuthorization, remaining: number): TargetAuthorization {
  return { ...authorization, bugBounty: authorization.bugBounty ? { ...authorization.bugBounty, maxRequests: remaining } : undefined };
}

function isLocalSource(source: InventorySource): source is Extract<InventorySource, { kind: "OPENAPI" | "POSTMAN" | "HAR" | "GRAPHQL_SCHEMA" | "SUPABASE_CATALOG" }> {
  return ["OPENAPI", "POSTMAN", "HAR", "GRAPHQL_SCHEMA", "SUPABASE_CATALOG"].includes(source.kind);
}

function actorHeaders(actor: AcquisitionActor, options: LiveInventoryResolutionOptions): Record<string, string> {
  if (actor === "anonymous") return { Accept: "application/json" };
  const profile = actor === "primary" ? options.authProfile : actor === "account_a" ? options.authProfileSet?.accountA : options.authProfileSet?.accountB;
  if (!profile) throw new AppError(`Inventory acquisition actor ${actor} has no matching authentication profile.`, "INVENTORY_ACQUISITION_AUTH_REQUIRED");
  return { ...authHeadersForProfile(profile), Accept: "application/json" };
}

async function fetchJson(
  broker: RequestSafetyBroker,
  url: string,
  method: "GET" | "POST",
  headers: Record<string, string>,
  maxBytes: number,
  stats: AcquisitionStats,
  body?: string
): Promise<unknown> {
  return (await fetchJsonObservation(broker, url, headers, maxBytes, stats, method, body)).body;
}

async function fetchJsonObservation(
  broker: RequestSafetyBroker,
  url: string,
  headers: Record<string, string>,
  maxBytes: number,
  stats: AcquisitionStats,
  method: "GET" | "POST" = "GET",
  body?: string
): Promise<AuthorizationInventoryObservation> {
  if (stats.fetched >= 100) throw new AppError("Inventory acquisition fetch limit was exceeded.", "INVENTORY_ACQUISITION_LIMIT");
  let document: unknown;
  let bodyObserved = false;
  let parseError: unknown;
  const response = await broker.send({
    url,
    method,
    headers,
    ...(body !== undefined ? { body } : {}),
    disableRedirects: true,
    disableRetries: true,
    skipCache: true,
    retainBodyPreview: true,
    transientBodyConsumer: (bodyPreview) => {
      bodyObserved = true;
      try { document = JSON.parse(bodyPreview); }
      catch (error) { parseError = error; }
    },
    streamLimitBytes: maxBytes,
    maxStreamContentLength: maxBytes
  });
  stats.fetched += 1;
  if (Object.keys(headers).some((name) => /^(?:authorization|cookie|x-api-key|apikey)$/i.test(name))) stats.authenticated += 1;
  if (response.error) throw new AppError(`Inventory acquisition failed for ${safeUrlLabel(url)}: ${response.error.name}.`, "INVENTORY_ACQUISITION_FAILED");
  if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) throw new AppError(`Inventory acquisition returned HTTP ${response.statusCode ?? "unknown"} for ${safeUrlLabel(url)}.`, "INVENTORY_ACQUISITION_STATUS");
  if (response.streamTruncated || (response.bytesRead ?? 0) > maxBytes) throw new AppError(`Inventory document exceeded ${maxBytes} bytes.`, "INVENTORY_ACQUISITION_DOCUMENT_TOO_LARGE");
  if (!bodyObserved || parseError) throw new AppError(`Inventory response from ${safeUrlLabel(url)} was not valid JSON.`, "INVENTORY_ACQUISITION_JSON_INVALID");
  return { body: document, headers: response.headers };
}

async function fetchGraphqlSchema(
  broker: RequestSafetyBroker,
  endpoint: string,
  headers: Record<string, string>,
  maxBytes: number,
  stats: AcquisitionStats
): Promise<unknown> {
  const body = JSON.stringify({ operationName: "RouteCairnInventoryIntrospection", query: introspectionQuery, variables: {} });
  return fetchJson(broker, endpoint, "POST", { ...headers, "Content-Type": "application/json" }, maxBytes, stats, body);
}

async function discoverService(
  source: Extract<InventorySource, { kind: "SERVICE_DISCOVERY" }>,
  broker: RequestSafetyBroker,
  options: LiveInventoryResolutionOptions,
  target: string,
  maxBytes: number,
  stats: AcquisitionStats
): Promise<InventorySource[]> {
  const targetBase = source.baseUrl ?? new URL(target).origin;
  const headers = actorHeaders(source.actor, options);
  const acquired: InventorySource[] = [];
  let ordinal = 0;
  for (const path of source.paths ?? defaultDiscoveryPaths) {
    const url = new URL(path, targetBase).toString();
    try {
      const document = await fetchJson(broker, url, "GET", headers, maxBytes, stats);
      if (isOpenApi(document)) {
        acquired.push({ id: boundedId(source.id, `openapi-${++ordinal}`), kind: "OPENAPI", document });
        stats.discovered += 1;
      } else {
        stats.warnings.push(`Discovery response at ${new URL(url).pathname} was JSON but not an OpenAPI document.`);
      }
    } catch (error) {
      stats.warnings.push(discoveryWarning(url, error));
    }
  }
  for (const path of source.graphqlEndpoints) {
    const endpoint = new URL(path, targetBase).toString();
    try {
      const document = await fetchGraphqlSchema(broker, endpoint, headers, maxBytes, stats);
      if (!hasGraphqlSchema(document)) throw new AppError("Response did not include __schema.", "INVENTORY_GRAPHQL_SCHEMA_MISSING");
      acquired.push({ id: boundedId(source.id, `graphql-${++ordinal}`), kind: "GRAPHQL_SCHEMA", endpoint, document });
      stats.discovered += 1;
    } catch (error) {
      stats.warnings.push(discoveryWarning(endpoint, error));
    }
  }
  return acquired;
}

async function acquireSupabase(
  source: Extract<InventorySource, { kind: "SUPABASE_LIVE" }>,
  broker: RequestSafetyBroker,
  options: LiveInventoryResolutionOptions,
  maxBytes: number,
  stats: AcquisitionStats
): Promise<Extract<InventorySource, { kind: "SUPABASE_CATALOG" }>> {
  const projectUrl = canonicalOrigin(source.projectUrl);
  const anonKey = process.env[source.anonKeyEnv];
  if (!anonKey) throw new AppError(`Environment variable ${source.anonKeyEnv} is required for live Supabase catalog acquisition.`, "INVENTORY_SUPABASE_KEY_REQUIRED");
  if (/[\r\n]/.test(anonKey)) throw new AppError("Supabase anon key contains invalid characters.", "INVENTORY_SUPABASE_KEY_INVALID");
  const actor = actorHeaders(source.actor, options);
  const headers: Record<string, string> = { ...actor, apikey: anonKey };
  if (!Object.keys(headers).some((name) => name.toLowerCase() === "authorization")) headers.Authorization = `Bearer ${anonKey}`;
  const openApi = await fetchJson(broker, new URL(source.openApiPath, `${projectUrl}/`).toString(), "GET", headers, maxBytes, stats);
  const generated = catalogFromPostgrest(openApi);
  if (generated.tables.length) stats.warnings.push("PostgREST does not expose authoritative RLS state; discovered tables are conservatively marked RLS-enabled unless an exact catalog overrides them.");
  let external: unknown;
  if (source.catalogUrl) external = await fetchJson(broker, source.catalogUrl, "GET", headers, maxBytes, stats);
  const supplied = isRecord(external) && isRecord(external.catalog) ? external.catalog : isRecord(external) ? external : {};
  let buckets: unknown[] = [];
  if (source.includeBuckets) {
    const bucketUrl = new URL(source.bucketsPath, `${projectUrl}/`).toString();
    try {
      const response = await fetchJson(broker, bucketUrl, "GET", headers, maxBytes, stats);
      buckets = Array.isArray(response) ? response : isRecord(response) && Array.isArray(response.data) ? response.data : [];
    } catch (error) {
      stats.warnings.push(discoveryWarning(bucketUrl, error));
    }
  }
  const storageObjects: unknown[] = [];
  if (source.enumeratePublicObjects) {
    const enumerableBuckets = mergeNamed(buckets, array(supplied.storageBuckets ?? supplied.buckets));
    for (const bucket of enumerableBuckets.filter((item) => isRecord(item) && item.public === true)) {
      const bucketName = String((bucket as Record<string, unknown>).name ?? (bucket as Record<string, unknown>).id ?? "");
      if (!/^[A-Za-z_][A-Za-z0-9_$.-]{0,127}$/.test(bucketName)) continue;
      const path = source.objectListPathTemplate.replace("{bucket}", encodeURIComponent(bucketName));
      const listUrl = new URL(path, `${projectUrl}/`).toString();
      const body = JSON.stringify({ prefix: "", limit: source.maxObjectsPerBucket, offset: 0, sortBy: { column: "name", order: "asc" } });
      try {
        const response = await fetchJson(broker, listUrl, "POST", { ...headers, "Content-Type": "application/json" }, maxBytes, stats, body);
        const objects = Array.isArray(response) ? response : isRecord(response) && Array.isArray(response.data) ? response.data : [];
        for (const item of objects.slice(0, source.maxObjectsPerBucket)) {
          if (!isRecord(item) || typeof item.name !== "string") continue;
          const metadata = isRecord(item.metadata) ? item.metadata : {};
          storageObjects.push({ bucket: bucketName, path: item.name, public: true, ...(typeof metadata.mimetype === "string" ? { mimeType: metadata.mimetype } : {}) });
        }
      } catch (error) {
        stats.warnings.push(discoveryWarning(listUrl, error));
      }
    }
  }
  const document = {
    catalog: {
      ...supplied,
      tables: mergeNamed(generated.tables, array(supplied.tables)),
      functions: mergeNamed(generated.functions, array(supplied.functions)),
      relationships: mergeNamed(generated.relationships, array(supplied.relationships)),
      storageBuckets: mergeNamed(buckets, array(supplied.storageBuckets ?? supplied.buckets)),
      storageObjects: [...array(supplied.storageObjects ?? supplied.objects), ...storageObjects]
    }
  };
  stats.discovered += generated.tables.length + generated.functions.length + buckets.length + storageObjects.length;
  return { id: source.id, kind: "SUPABASE_CATALOG", projectUrl, anonKeyEnv: source.anonKeyEnv, document };
}

function catalogFromPostgrest(document: unknown): { tables: unknown[]; functions: unknown[]; relationships: unknown[] } {
  if (!isRecord(document) || !isRecord(document.paths)) throw new AppError("Supabase PostgREST endpoint did not return an OpenAPI document.", "INVENTORY_SUPABASE_OPENAPI_INVALID");
  const schemas = isRecord(document.components) && isRecord(document.components.schemas) ? document.components.schemas : isRecord(document.definitions) ? document.definitions : {};
  const tables: unknown[] = [];
  const functions: unknown[] = [];
  const relationships: unknown[] = [];
  const seenTables = new Set<string>();
  for (const path of Object.keys(document.paths)) {
    const match = path.match(/^\/?([^/?{}]+)$/);
    const rpc = path.match(/^\/?rpc\/([^/?{}]+)$/);
    if (rpc) {
      functions.push({ schema: "public", name: decodeURIComponent(rpc[1]!), exposed: true, securityDefiner: false, executableBy: [], searchPath: [], usesDynamicSql: false });
      continue;
    }
    if (!match) continue;
    const name = decodeURIComponent(match[1]!);
    if (!/^[A-Za-z_][A-Za-z0-9_$.-]{0,127}$/.test(name) || seenTables.has(name)) continue;
    seenTables.add(name);
    const schema = isRecord(schemas[name]) ? schemas[name] : {};
    const properties = isRecord(schema.properties) ? schema.properties : {};
    tables.push({ schema: "public", name, exposed: true, rlsEnabled: true, rlsForced: false, columns: Object.keys(properties).map((column) => ({ name: column, sensitive: sensitiveColumn(column), exposedTo: [] })) });
    for (const [column, descriptor] of Object.entries(properties)) {
      if (!isRecord(descriptor) || typeof descriptor.$ref !== "string") continue;
      const target = descriptor.$ref.split("/").pop();
      if (target && target !== name) relationships.push({ name: `${name}_${column}`, from: name, to: target, exposed: true });
    }
  }
  return { tables, functions, relationships };
}

function isOpenApi(value: unknown): boolean {
  return isRecord(value) && isRecord(value.paths) && (typeof value.openapi === "string" || typeof value.swagger === "string");
}

function hasGraphqlSchema(value: unknown): boolean {
  return isRecord(value) && ((isRecord(value.data) && isRecord(value.data.__schema)) || isRecord(value.__schema));
}

function canonicalOrigin(value: string): string {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || (url.pathname !== "/" && url.pathname !== "") || url.search || url.hash) {
    throw new AppError("Live catalog projectUrl must be an exact HTTP(S) origin.", "INVENTORY_PROJECT_URL_INVALID");
  }
  return url.origin;
}

function mergeNamed(first: unknown[], second: unknown[]): unknown[] {
  const seen = new Set<string>();
  return [...second, ...first].filter((value) => {
    if (!isRecord(value)) return false;
    const name = String(value.name ?? value.id ?? "");
    if (!name || seen.has(name)) return false;
    seen.add(name);
    return true;
  });
}

function sensitiveColumn(name: string): boolean {
  return /(?:password|secret|token|api.?key|ssn|credit|card|cvv|private|credential)/i.test(name);
}

function privateOriginsFor(input: SafeInventoryImportInput): string[] {
  const values = input.sources.flatMap((source) => {
    if (source.kind === "OPENAPI_URL" || source.kind === "HAR_URL") return [source.url];
    if (source.kind === "POSTMAN_URL") return [source.collectionUrl, ...(source.environmentUrl ? [source.environmentUrl] : [])];
    if (source.kind === "GRAPHQL_INTROSPECTION") return [source.endpoint];
    if (source.kind === "SUPABASE_LIVE") return [source.projectUrl, ...(source.catalogUrl ? [source.catalogUrl] : [])];
    if (source.kind === "SERVICE_DISCOVERY" && source.baseUrl) return [source.baseUrl];
    return [];
  });
  return [...new Set(values.flatMap((value) => { try { return [new URL(value).origin]; } catch { return []; } }))];
}

function array(value: unknown): unknown[] { return Array.isArray(value) ? value : []; }
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function boundedId(base: string, suffix: string): string { return `${base}-${suffix}`.slice(0, 80).replace(/-+$/, ""); }
function safeUrlLabel(value: string): string { try { const url = new URL(value); return `${url.origin}${url.pathname}`; } catch { return "invalid-url"; } }
function discoveryWarning(url: string, error: unknown): string { return `Discovery skipped ${new URL(url).pathname}: ${error instanceof Error ? error.message : "request failed"}`; }

function mergeCollectionInputs(existing: CollectionAuthorizationInput | undefined, discovered: CollectionAuthorizationInput): CollectionAuthorizationInput {
  if (!existing) return discovered;
  const collections: CollectionAuthorizationInput["collections"] = [];
  let requestCount = 0;
  for (const item of [...existing.collections, ...discovered.collections]) {
    const requests = item.cases.length * (item.pagination?.maxPages ?? 1);
    if (collections.length >= 5 || requestCount + requests > 100) continue;
    collections.push(item); requestCount += requests;
  }
  const maxCasesPerCollection = Math.max(...collections.map((item) => item.cases.length));
  const maxKnownObjects = Math.max(1, ...collections.map((item) => item.knownObjects.length));
  return collectionAuthorizationInputSchema.parse({ schemaVersion: 1, maxCollections: collections.length, maxCasesPerCollection, maxKnownObjects, maxRequests: requestCount, collections });
}

function mergeFileInputs(existing: FileAuthorizationInput | undefined, discovered: FileAuthorizationInput): FileAuthorizationInput {
  if (!existing) return discovered;
  const definitions: FileAuthorizationInput["definitions"] = [];
  let requestCount = 0;
  for (const item of [...existing.definitions, ...discovered.definitions]) {
    if (definitions.length >= 5 || requestCount + item.cases.length > 120) continue;
    definitions.push(item); requestCount += item.cases.length;
  }
  const maxCasesPerDefinition = Math.max(...definitions.map((item) => item.cases.length));
  const maxFilesPerDefinition = Math.max(...definitions.map((item) => item.files.length));
  return fileAuthorizationInputSchema.parse({ schemaVersion: 1, maxDefinitions: definitions.length, maxCasesPerDefinition, maxFilesPerDefinition, maxRequests: requestCount, definitions });
}
