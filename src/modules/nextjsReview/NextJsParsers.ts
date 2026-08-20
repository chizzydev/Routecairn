import { createHash } from "node:crypto";
import { SecretPatternDetector } from "../exposureReview/SecretPatternDetector.js";
import type {
  NextJsCacheMetadata,
  NextJsManifestReview,
  NextJsParseStatus,
  NextJsRouterKind,
  NextJsSourceMapReview
} from "../../reports/ReportTypes.js";

export interface NextJsParserLimits {
  maxBodyBytes: number;
  maxInlineMapEncodedBytes: number;
  maxInlineMapDecodedBytes: number;
  maxEntries: number;
  maxDepth: number;
  maxStringLength: number;
  maxSourcesContentBytes: number;
}

export const defaultNextJsParserLimits: NextJsParserLimits = Object.freeze({
  maxBodyBytes: 512 * 1024,
  maxInlineMapEncodedBytes: 384 * 1024,
  maxInlineMapDecodedBytes: 512 * 1024,
  maxEntries: 2_000,
  maxDepth: 24,
  maxStringLength: 64 * 1024,
  maxSourcesContentBytes: 256 * 1024
});

export interface TransientSensitivityCandidate {
  category: string;
  fieldPath: string;
  valueType: string;
  valueLength: number;
  confidence: "HIGH" | "MEDIUM";
  rawValue: string;
}

export interface ParsedNextData {
  status: NextJsParseStatus;
  buildId?: string;
  page?: string;
  routerKind: NextJsRouterKind;
  propertyPaths: string[];
  runtimeConfigPaths: string[];
  sensitivity: TransientSensitivityCandidate[];
  notes: string[];
}

export interface ParsedStructuredBody {
  status: NextJsParseStatus;
  propertyPaths: string[];
  sensitivity: TransientSensitivityCandidate[];
  notes: string[];
}

const forbiddenKeys = new Set(["__proto__", "prototype", "constructor"]);
const privateFieldPattern = /^(?:ssn|socialsecuritynumber|taxid|passwordhash|privateemail|privatephone|privateaddress|sessionsecret|signingsecret|accesstoken|refreshtoken|privatekey)$/i;
const secretNamePattern = /(?:secret|password|passwd|private[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?secret|signing[_-]?secret|database[_-]?url)/i;
const harmlessPlaceholderPattern = /^(?:example|sample|placeholder|changeme|replace[_-]?me|your[_-].*|xxx+|test|public)$/i;

export function extractNextDataFromHtml(html: string, limits: NextJsParserLimits = defaultNextJsParserLimits): ParsedNextData {
  if (byteLength(html) > limits.maxBodyBytes) return emptyNextData("TOO_LARGE", "HTML exceeded the bounded Next.js parser limit.");
  const open = /<script\b[^>]*\bid\s*=\s*["']__NEXT_DATA__["'][^>]*>/i.exec(html);
  if (!open || open.index === undefined) return emptyNextData("UNSUPPORTED_SHAPE", "No __NEXT_DATA__ script was present.");
  const start = open.index + open[0].length;
  const end = html.toLowerCase().indexOf("</script", start);
  if (end < 0) return emptyNextData("MALFORMED", "The __NEXT_DATA__ script was truncated.");
  const parsed = parseJsonBounded(html.slice(start, end), limits);
  if (!parsed.value) return emptyNextData(parsed.status, parsed.note);
  const root = parsed.value;
  const buildId = safeString(root.buildId, 256);
  const page = safeRoute(root.page);
  const structure = analyzeValue(root, limits);
  const runtimeConfig = isRecord(root.runtimeConfig) ? root.runtimeConfig : isRecord(root.publicRuntimeConfig) ? root.publicRuntimeConfig : undefined;
  const runtimeConfigPaths = runtimeConfig ? analyzeValue(runtimeConfig, limits, "runtimeConfig").propertyPaths : [];
  return {
    status: "PARSED",
    ...(buildId ? { buildId } : {}),
    ...(page ? { page } : {}),
    routerKind: "PAGES_ROUTER",
    propertyPaths: structure.propertyPaths,
    runtimeConfigPaths,
    sensitivity: dedupeSensitivity([
      ...structure.sensitivity,
      ...secretCandidatesFromText(JSON.stringify(runtimeConfig ?? {}), "runtimeConfig")
    ]),
    notes: ["Parsed __NEXT_DATA__ as bounded JSON without executing inline script."]
  };
}

export function analyzeStructuredBody(body: string, limits: NextJsParserLimits = defaultNextJsParserLimits): ParsedStructuredBody {
  const parsed = parseJsonBounded(body, limits);
  if (!parsed.value) return { status: parsed.status, propertyPaths: [], sensitivity: [], notes: [parsed.note] };
  const analyzed = analyzeValue(parsed.value, limits);
  return { status: "PARSED", ...analyzed, notes: ["Parsed bounded JSON structure; raw values were not retained."] };
}

export function parseManifest(body: string, url: string, limits: NextJsParserLimits = defaultNextJsParserLimits): NextJsManifestReview {
  const kind = manifestKind(url, body);
  const json = extractJsonOrAssignedObject(body, limits);
  if (!json.text) return manifestFailure(url, kind, json.status, json.note);
  const parsed = parseJsonBounded(json.text, limits);
  if (!parsed.value) return manifestFailure(url, kind, parsed.status, parsed.note);
  const entries = collectManifestStrings(parsed.value, limits);
  if (entries.all.length === 0 && kind === "UNKNOWN") return manifestFailure(url, kind, "UNSUPPORTED_SHAPE", "Manifest did not match a supported bounded structure.");
  const routes = entries.all.filter((value) => isRouteTemplate(value)).map(normalizeRouteTemplate);
  const assets = entries.all.filter((value) => isAssetReference(value));
  return {
    url,
    kind,
    parseStatus: "PARSED",
    routes: unique(routes).slice(0, limits.maxEntries),
    assets: unique(assets).slice(0, limits.maxEntries),
    processedEntries: Math.min(entries.total, limits.maxEntries),
    totalEntries: entries.total,
    truncated: entries.truncated,
    notes: [entries.truncated ? `Processed ${limits.maxEntries} of ${entries.total} manifest entries due to the configured limit.` : `Processed ${entries.total} manifest entries.`]
  };
}

export function extractSourceMapReferences(source: string, scriptUrl: string, limits: NextJsParserLimits = defaultNextJsParserLimits): Array<{ url: string; inlineBody?: string; outOfScopeScheme?: boolean }> {
  if (byteLength(source) > limits.maxBodyBytes) return [];
  const results: Array<{ url: string; inlineBody?: string; outOfScopeScheme?: boolean }> = [];
  const pattern = /(?:\/\/[#@]|\/\*#)\s*sourceMappingURL=([^\s*]+)(?:\s*\*\/)?/g;
  for (const match of source.matchAll(pattern)) {
    const raw = match[1]?.trim();
    if (!raw) continue;
    if (raw.startsWith("data:")) {
      const decoded = decodeInlineSourceMap(raw, limits);
      results.push({ url: `${scriptUrl}#inline-source-map`, ...(decoded ? { inlineBody: decoded } : {}) });
      continue;
    }
    try {
      const resolved = new URL(raw, scriptUrl);
      const disallowed = !["http:", "https:"].includes(resolved.protocol) || Boolean(resolved.username || resolved.password);
      results.push({ url: disallowed ? redactUrlCredentials(resolved.toString()) : resolved.toString(), ...(disallowed ? { outOfScopeScheme: true } : {}) });
    } catch {
      // Malformed references are safely ignored.
    }
    if (results.length >= 64) break;
  }
  return results;
}

export function parseSourceMap(body: string, url: string, inline: boolean, limits: NextJsParserLimits = defaultNextJsParserLimits): NextJsSourceMapReview & { transientSensitivity: TransientSensitivityCandidate[] } {
  if (byteLength(body) > limits.maxBodyBytes) return sourceMapFailure(url, inline, "TOO_LARGE", "Source map exceeded the bounded parser limit.");
  const parsed = parseJsonBounded(body, limits);
  if (!parsed.value) return sourceMapFailure(url, inline, parsed.status, parsed.note);
  const root = parsed.value;
  if (root.version !== 3 || !Array.isArray(root.sources)) return sourceMapFailure(url, inline, "UNSUPPORTED_SHAPE", "Source map did not have a supported version 3 structure.");
  const sources = root.sources.slice(0, limits.maxEntries).flatMap((value) => typeof value === "string" ? [redactSourcePath(value)] : []);
  const sourceContents = Array.isArray(root.sourcesContent) ? root.sourcesContent.slice(0, limits.maxEntries) : [];
  let inspectedBytes = 0;
  const transientSensitivity: TransientSensitivityCandidate[] = [];
  sourceContents.forEach((value, index) => {
    if (typeof value !== "string" || inspectedBytes >= limits.maxSourcesContentBytes) return;
    const remaining = limits.maxSourcesContentBytes - inspectedBytes;
    const bounded = value.slice(0, remaining);
    inspectedBytes += byteLength(bounded);
    transientSensitivity.push(...secretCandidatesFromText(bounded, sources[index] ?? `sourcesContent[${index}]`));
  });
  const mappings = typeof root.mappings === "string" ? root.mappings : "";
  const names = Array.isArray(root.names) ? root.names : [];
  return {
    url,
    classification: /\/_next\/static\//.test(url) ? "nextjs-public-source-map-review" : "generic-source-map-review",
    severityHint: transientSensitivity.length > 0 ? "medium" : "low",
    reason: transientSensitivity.length > 0
      ? "Public source map contained validated secret-pattern evidence; raw values were excluded."
      : "Public source-map availability is informational unless sensitive security material is demonstrated.",
    parseStatus: "PARSED",
    version: 3,
    ...(safeString(root.file, 512) ? { file: redactSourcePath(String(root.file)) } : {}),
    sourceCount: root.sources.length,
    sourcesContentCount: sourceContents.filter((value) => typeof value === "string").length,
    namesCount: names.length,
    mappingSize: byteLength(mappings),
    sourcePaths: sources,
    sensitivitySignals: [],
    inline,
    transientSensitivity: dedupeSensitivity(transientSensitivity)
  };
}

export function normalizeRouteTemplate(value: string): string {
  const trimmed = value.trim().replace(/\\/g, "/");
  if (!trimmed.startsWith("/") || trimmed.includes("\0")) return "";
  const withoutGroups = trimmed.split("/").filter((segment) => !/^\([^/]+\)$/.test(segment)).join("/") || "/";
  return withoutGroups.replace(/\/{2,}/g, "/").replace(/\/$/, "") || "/";
}

export function isDynamicRouteTemplate(route: string): boolean {
  return /\[(?:\[)?(?:\.\.\.)?[^\]]+\](?:\])?/.test(route);
}

export function derivePagesDataUrl(baseUrl: string, buildId: string, concreteRoute: string): string | undefined {
  if (!buildId || buildId.length > 256 || isDynamicRouteTemplate(concreteRoute) || !isConcreteRoute(concreteRoute)) return undefined;
  try {
    const base = new URL(baseUrl);
    const route = new URL(concreteRoute, base);
    if (route.origin !== base.origin) return undefined;
    const pathname = route.pathname === "/" ? "/index" : route.pathname.replace(/\/$/, "");
    const encodedBuild = encodeURIComponent(buildId);
    return new URL(`/_next/data/${encodedBuild}${pathname}.json${route.search}`, base).toString();
  } catch {
    return undefined;
  }
}

export function classifyRscSurface(url: string, contentType = "", headers: Readonly<Record<string, string | readonly string[]>> = {}, body = ""): boolean {
  const headerText = Object.entries(headers).map(([name, value]) => `${name}:${Array.isArray(value) ? value.join(",") : value}`).join(" ");
  return /text\/x-component|application\/x-component/i.test(contentType)
    || /(?:^|[?&])_rsc=/.test(url)
    || /\bRSC\s*:\s*1\b|Next-Router-State-Tree|Next-Router-Prefetch/i.test(headerText)
    || /^\s*\d+:[A-Z][\[{]/m.test(body.slice(0, 2048));
}

export function cacheMetadata(headers: Readonly<Record<string, string | readonly string[]>>, actor: NextJsCacheMetadata["actor"], bodyFingerprint?: string, sensitivity: NextJsCacheMetadata["dataSensitivity"] = "NONE"): NextJsCacheMetadata {
  const get = (name: string): string | undefined => {
    const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
    return typeof entry === "string" ? entry : entry?.join(", ");
  };
  const etag = get("etag");
  const cacheControl = get("cache-control");
  const expires = get("expires");
  const lastModified = get("last-modified");
  const nextJsCacheState = get("x-nextjs-cache");
  const surrogateControl = get("surrogate-control");
  const age = Number.parseInt(get("age") ?? "", 10);
  const cdnIndicators = ["cf-cache-status", "x-cache", "x-vercel-cache", "x-served-by"].flatMap((name) => get(name) ? [name] : []);
  return {
    ...(cacheControl ? { cacheControl } : {}),
    ...(Number.isFinite(age) && age >= 0 ? { age } : {}),
    ...(etag ? { etagFingerprint: shortFingerprint(etag) } : {}),
    vary: (get("vary") ?? "").split(",").map((value) => value.trim()).filter(Boolean).slice(0, 32),
    ...(expires ? { expires } : {}),
    ...(lastModified ? { lastModified } : {}),
    ...(nextJsCacheState ? { nextJsCacheState } : {}),
    ...(surrogateControl ? { surrogateControl } : {}),
    cdnIndicators,
    actor,
    ...(bodyFingerprint ? { bodyFingerprint } : {}),
    dataSensitivity: sensitivity
  };
}

export function shortFingerprint(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex").slice(0, 24)}`;
}

export function safeBuildIdDisplay(buildId: string): string {
  return buildId.length <= 24 && /^[a-zA-Z0-9._-]+$/.test(buildId) ? buildId : shortFingerprint(buildId);
}

function analyzeValue(root: Record<string, unknown>, limits: NextJsParserLimits, prefix = ""): { propertyPaths: string[]; sensitivity: TransientSensitivityCandidate[] } {
  const propertyPaths: string[] = [];
  const sensitivity: TransientSensitivityCandidate[] = [];
  const queue: Array<{ value: unknown; path: string; depth: number }> = [{ value: root, path: prefix, depth: 0 }];
  let processed = 0;
  while (queue.length > 0 && processed < limits.maxEntries) {
    const item = queue.shift();
    if (!item || item.depth > limits.maxDepth) continue;
    if (Array.isArray(item.value)) {
      item.value.slice(0, limits.maxEntries - processed).forEach((value, index) => queue.push({ value, path: `${item.path}[${index}]`, depth: item.depth + 1 }));
      continue;
    }
    if (!isRecord(item.value)) continue;
    for (const [key, value] of Object.entries(item.value)) {
      if (processed++ >= limits.maxEntries) break;
      if (forbiddenKeys.has(key)) continue;
      const path = item.path ? `${item.path}.${key}` : key;
      propertyPaths.push(path.slice(0, 512));
      if (typeof value === "string") {
        const raw = value.slice(0, limits.maxStringLength);
        if (isSensitiveFieldValue(key, raw)) sensitivity.push(candidateForField(key, path, raw));
        sensitivity.push(...secretCandidatesFromText(`${key}=${raw}`, path));
      } else if (value !== null && typeof value === "object") {
        queue.push({ value, path, depth: item.depth + 1 });
      }
    }
  }
  return { propertyPaths: unique(propertyPaths), sensitivity: dedupeSensitivity(sensitivity) };
}

function secretCandidatesFromText(text: string, fieldPath: string): TransientSensitivityCandidate[] {
  const detector = new SecretPatternDetector();
  return detector.detectForTransientAnalysis(text, 32).map((match) => ({
    category: match.name,
    fieldPath,
    valueType: "string",
    valueLength: byteLength(match.value),
    confidence: "HIGH" as const,
    rawValue: match.value
  }));
}

function candidateForField(name: string, fieldPath: string, value: string): TransientSensitivityCandidate {
  return {
    category: secretNamePattern.test(name) ? "SECRET_FIELD" : "PRIVATE_FIELD",
    fieldPath,
    valueType: "string",
    valueLength: byteLength(value),
    confidence: secretNamePattern.test(name) ? "HIGH" : "MEDIUM",
    rawValue: value
  };
}

function isSensitiveFieldValue(name: string, value: string): boolean {
  if (value.length < 8 || harmlessPlaceholderPattern.test(value)) return false;
  if (/^NEXT_PUBLIC_/i.test(name) && !secretNamePattern.test(name.replace(/^NEXT_PUBLIC_/i, ""))) return false;
  return privateFieldPattern.test(name) || secretNamePattern.test(name);
}

function parseJsonBounded(text: string, limits: NextJsParserLimits): { status: NextJsParseStatus; value?: Record<string, unknown>; note: string } {
  if (byteLength(text) > limits.maxBodyBytes) return { status: "TOO_LARGE", note: "JSON-like artifact exceeded the bounded parser limit." };
  try {
    let unsafeKey = false;
    const value: unknown = JSON.parse(text, (key, child) => {
      if (forbiddenKeys.has(key)) unsafeKey = true;
      return child;
    });
    if (unsafeKey || !isRecord(value)) return { status: "UNSUPPORTED_SHAPE", note: unsafeKey ? "Artifact contained a forbidden prototype-related key." : "Artifact root was not an object." };
    const bounded = validateStructure(value, limits);
    return bounded ? { status: "PARSED", value, note: "Parsed." } : { status: "TOO_LARGE", note: "Artifact exceeded structural depth, entry, or string limits." };
  } catch {
    return { status: "MALFORMED", note: "Artifact was not valid bounded JSON." };
  }
}

function validateStructure(root: unknown, limits: NextJsParserLimits): boolean {
  const queue: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 0 }];
  let entries = 0;
  while (queue.length > 0) {
    const item = queue.shift();
    if (!item || item.depth > limits.maxDepth || entries++ > limits.maxEntries * 4) return false;
    if (typeof item.value === "string" && byteLength(item.value) > limits.maxStringLength) return false;
    if (Array.isArray(item.value)) {
      if (item.value.length > limits.maxEntries) return false;
      item.value.forEach((value) => queue.push({ value, depth: item.depth + 1 }));
    } else if (isRecord(item.value)) {
      const entriesHere = Object.entries(item.value);
      if (entriesHere.length > limits.maxEntries || entriesHere.some(([key]) => forbiddenKeys.has(key))) return false;
      entriesHere.forEach(([, value]) => queue.push({ value, depth: item.depth + 1 }));
    }
  }
  return true;
}

function extractJsonOrAssignedObject(body: string, limits: NextJsParserLimits): { status: NextJsParseStatus; text?: string; note: string } {
  if (byteLength(body) > limits.maxBodyBytes) return { status: "TOO_LARGE", note: "Manifest exceeded the parser body limit." };
  const trimmed = body.trim();
  if (trimmed.startsWith("{")) return { status: "PARSED", text: trimmed, note: "JSON manifest." };
  const equals = trimmed.indexOf("=");
  if (equals < 0 || !/^(?:self\.)?__[A-Z0-9_]+\s*=/i.test(trimmed.slice(0, equals + 1))) return { status: "UNSUPPORTED_SHAPE", note: "Manifest wrapper was not a supported assignment shape." };
  const start = trimmed.indexOf("{", equals);
  if (start < 0) return { status: "MALFORMED", note: "Manifest assignment did not contain an object." };
  const end = balancedObjectEnd(trimmed, start);
  if (end < 0 || !/^\s*;?\s*$/.test(trimmed.slice(end + 1))) return { status: "MALFORMED", note: "Manifest assignment contained malformed or trailing executable content." };
  return { status: "PARSED", text: trimmed.slice(start, end + 1), note: "Safely extracted assignment object without execution." };
}

function balancedObjectEnd(text: string, start: number): number {
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = start; index < text.length; index += 1) {
    const char = text[index] ?? "";
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = "";
      continue;
    }
    if (char === '"') { quote = char; continue; }
    if (char === "{") depth += 1;
    if (char === "}" && --depth === 0) return index;
  }
  return -1;
}

function collectManifestStrings(root: Record<string, unknown>, limits: NextJsParserLimits): { all: string[]; total: number; truncated: boolean } {
  const all: string[] = [];
  const queue: unknown[] = [root];
  let total = 0;
  while (queue.length > 0) {
    const value = queue.shift();
    if (typeof value === "string") {
      total += 1;
      if (all.length < limits.maxEntries) all.push(value.slice(0, limits.maxStringLength));
    } else if (Array.isArray(value)) {
      queue.push(...value.slice(0, limits.maxEntries));
    } else if (isRecord(value)) {
      for (const [key, child] of Object.entries(value).slice(0, limits.maxEntries)) {
        if (forbiddenKeys.has(key)) continue;
        if (key.startsWith("/")) { total += 1; if (all.length < limits.maxEntries) all.push(key); }
        queue.push(child);
      }
    }
    if (total > limits.maxEntries * 4) break;
  }
  return { all: unique(all), total, truncated: total > limits.maxEntries };
}

function decodeInlineSourceMap(uri: string, limits: NextJsParserLimits): string | undefined {
  if (byteLength(uri) > limits.maxInlineMapEncodedBytes) return undefined;
  const comma = uri.indexOf(",");
  if (comma < 0 || !/^data:application\/(?:json|octet-stream)(?:;charset=[^;,]+)?;base64$/i.test(uri.slice(0, comma))) return undefined;
  try {
    const decoded = Buffer.from(uri.slice(comma + 1), "base64");
    if (decoded.byteLength > limits.maxInlineMapDecodedBytes) return undefined;
    return decoded.toString("utf8");
  } catch {
    return undefined;
  }
}

function manifestKind(url: string, body: string): NextJsManifestReview["kind"] {
  if (/_buildManifest|BUILD_MANIFEST/i.test(`${url} ${body.slice(0, 128)}`)) return "BUILD_MANIFEST";
  if (/_ssgManifest|SSG_MANIFEST/i.test(`${url} ${body.slice(0, 128)}`)) return "SSG_MANIFEST";
  if (/routes-manifest/i.test(url)) return "ROUTE_MANIFEST";
  if (/app-(?:build-)?manifest/i.test(url)) return "APP_MANIFEST";
  return "UNKNOWN";
}

function manifestFailure(url: string, kind: NextJsManifestReview["kind"], parseStatus: NextJsParseStatus, note: string): NextJsManifestReview {
  return { url, kind, parseStatus, routes: [], assets: [], processedEntries: 0, totalEntries: 0, truncated: false, notes: [note] };
}

function sourceMapFailure(url: string, inline: boolean, parseStatus: NextJsParseStatus, reason: string): NextJsSourceMapReview & { transientSensitivity: TransientSensitivityCandidate[] } {
  return { url, classification: /\/_next\/static\//.test(url) ? "nextjs-public-source-map-review" : "generic-source-map-review", severityHint: "low", reason, parseStatus, inline, transientSensitivity: [] };
}

function emptyNextData(status: NextJsParseStatus, note: string): ParsedNextData {
  return { status, routerKind: "UNKNOWN", propertyPaths: [], runtimeConfigPaths: [], sensitivity: [], notes: [note] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isRouteTemplate(value: string): boolean {
  return value.startsWith("/") && !value.startsWith("/_next/") && !/\.(?:js|css|map|json|png|jpg|svg|woff2?)$/i.test(value);
}

function isAssetReference(value: string): boolean {
  return /(?:^|\/)static\/|\.(?:js|css|map|json)$/i.test(value);
}

function isConcreteRoute(value: string): boolean {
  return value.startsWith("/") && !isDynamicRouteTemplate(value) && !/\0|\\/.test(value);
}

function safeRoute(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = normalizeRouteTemplate(value);
  return normalized || undefined;
}

function safeString(value: unknown, maximum: number): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= maximum ? value : undefined;
}

function redactSourcePath(value: string): string {
  const noCredentials = redactUrlCredentials(value);
  return noCredentials
    .replace(/^[A-Za-z]:\\Users\\[^\\/]+/i, "<local-user>")
    .replace(/^\/Users\/[^/]+/i, "<local-user>")
    .replace(/^\/home\/[^/]+/i, "<local-user>")
    .replace(/(?:\.\.\/){2,}/g, "<parent>/")
    .slice(0, 512);
}

function redactUrlCredentials(value: string): string {
  try { const url = new URL(value); url.username = ""; url.password = ""; return url.toString(); } catch { return value.replace(/:\/\/[^/@]+@/, "://<redacted>@"); }
}

function dedupeSensitivity<T extends TransientSensitivityCandidate>(items: T[]): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.category}:${item.fieldPath}:${shortFingerprint(item.rawValue)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 64);
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort();
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}
