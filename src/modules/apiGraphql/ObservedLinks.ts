import { createHash } from "node:crypto";
import { load } from "cheerio";
export const OBSERVED_LINK_ALGORITHM = "bounded-native-response-links-v2";
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
export interface ObservedLinks {
  algorithm: typeof OBSERVED_LINK_ALGORITHM;
  responseFingerprint: string;
  requestFingerprint: string;
  candidates: { path: string; evidenceFingerprint: string; source: "JSON_LINK" | "HTML_ANCHOR" }[];
  excluded: Record<string, number>;
  truncated: boolean;
}
/** Passive analysis only. Never resolves DNS or follows an advertised link. */
export function observeLinks(body: string, requestUrl: string, contentType: string, complete: boolean): ObservedLinks {
  const result: ObservedLinks = {
    algorithm: OBSERVED_LINK_ALGORITHM,
    responseFingerprint: hash(body),
    requestFingerprint: hash(requestUrl),
    candidates: [],
    excluded: {},
    truncated: !complete
  };
  const excluded = (reason: string) => {
    result.excluded[reason] = (result.excluded[reason] ?? 0) + 1;
  };
  if (!complete || Buffer.byteLength(body) > 8192) {
    excluded("INCOMPLETE_RESPONSE");
    return result;
  }
  const origin = new URL(requestUrl).origin,
    seen = new Set<string>();
  let count = 0;
  const link = (raw: unknown, source: "JSON_LINK" | "HTML_ANCHOR", method: unknown = "GET") => {
    if (++count > 32) {
      result.truncated = true;
      excluded("LINK_LIMIT");
      return;
    }
    if (method !== "GET") {
      excluded("NON_GET_ADVERTISEMENT");
      return;
    }
    if (typeof raw !== "string" || raw.length > 1000 || /[\\\x00-\x20\x7f%?#]/.test(raw)) {
      excluded("UNSAFE_LINK");
      return;
    }
    try {
      const u = new URL(raw, requestUrl);
      if (u.origin !== origin || !["http:", "https:"].includes(u.protocol)) {
        excluded("ORIGIN_MISMATCH");
        return;
      }
      if (
        u.username ||
        u.password ||
        u.search ||
        u.hash ||
        !/^\/(?:[A-Za-z0-9._~-]+\/?)*$/.test(u.pathname) ||
        /(?:^|\/)(?:password|token|secret|cookie|session|logout|delete|remove)(?:\/|$)/i.test(u.pathname)
      ) {
        excluded("UNSAFE_LINK");
        return;
      }
      // URL normalization must not conceal traversal or alternate parser spelling.
      if (/(?:^|\/)\.{1,2}(?:\/|$)/.test(raw) || raw.startsWith("//")) {
        excluded("NORMALIZATION_AMBIGUITY");
        return;
      }
      if (seen.has(u.pathname)) {
        excluded("DUPLICATE");
        return;
      }
      seen.add(u.pathname);
      result.candidates.push({ path: u.pathname, evidenceFingerprint: hash(source + "\0" + raw), source });
    } catch {
      excluded("INVALID_LINK");
    }
  };
  if (/\bjson\b/i.test(contentType)) {
    let nodes = 0;
    const visit = (value: unknown, depth: number) => {
      if (++nodes > 512 || depth > 12) {
        result.truncated = true;
        return;
      }
      if (!value || typeof value !== "object") return;
      if (Array.isArray(value)) {
        for (const v of value.slice(0, 512)) visit(v, depth + 1);
        if (value.length > 512) result.truncated = true;
        return;
      }
      const v = value as Record<string, unknown>;
      if (Object.hasOwn(v, "href")) link(v.href, "JSON_LINK", v.method ?? "GET");
      // JSON:API and HAL advertise concrete URLs in named link containers. Never infer URLs from IDs.
      // Restrict keys and reuse exactly the same origin, method, normalization and size checks.
      for (const container of [v.links, v._links]) {
        if (!container || typeof container !== "object" || Array.isArray(container)) continue;
        for (const [rel, item] of Object.entries(container).slice(0, 33)) {
          if (!["self", "next", "prev", "first", "last", "related"].includes(rel)) continue;
          if (typeof item === "string") link(item, "JSON_LINK");
        }
      }
      for (const [k, c] of Object.entries(v).slice(0, 512))
        if (!["__proto__", "constructor", "prototype", "href"].includes(k)) visit(c, depth + 1);
    };
    try {
      visit(JSON.parse(body), 0);
    } catch {
      excluded("INVALID_JSON");
    }
  } else if (/\bhtml\b/i.test(contentType)) {
    const $ = load(body);
    if ($("base[href]").length) {
      excluded("HTML_BASE_OVERRIDE");
      result.truncated = true;
      return result;
    }
    $("a[href], link[rel=next][href], link[rel=prev][href]")
      .slice(0, 33)
      .each((_, a) => {
        link($(a).attr("href"), "HTML_ANCHOR", $(a).attr("data-method") ?? "GET");
      });
  } else excluded("UNSUPPORTED_CONTENT_TYPE");
  result.candidates.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return result;
}
