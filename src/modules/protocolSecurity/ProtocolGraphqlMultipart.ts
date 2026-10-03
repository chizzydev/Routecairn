import type { BoundedHttpResult } from "./ProtocolTransports.js";

/** A bounded complete response parser; never treat a truncated prefix as
 * finished delivery or silently discard parts beyond the operator's limit. */
export function parseGraphqlParts(response: BoundedHttpResult, maxParts: number): Record<string, unknown>[] {
  const contentType = String(response.headers["content-type"] ?? "");
  const object = (text: string): Record<string, unknown> => {
    let value: unknown; try { value = JSON.parse(text); } catch { throw new Error("GRAPHQL_INCREMENTAL_JSON_INVALID"); }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("GRAPHQL_INCREMENTAL_OBJECT_REQUIRED");
    return value as Record<string, unknown>;
  };
  if (!/^multipart\/mixed\b/i.test(contentType)) {
    if (!/^application\/json\b/i.test(contentType)) throw new Error("GRAPHQL_INCREMENTAL_CONTENT_TYPE_INVALID");
    return [object(response.body.toString("utf8"))];
  }
  const boundary = /boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i.exec(contentType)?.slice(1).find(Boolean);
  if (!boundary || boundary.length > 70 || /[\r\n]/.test(boundary)) throw new Error("GRAPHQL_INCREMENTAL_BOUNDARY_INVALID");
  const escaped = boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pieces = response.body.toString("utf8").split(new RegExp(`(?:^|\\r?\\n)--${escaped}(?=--|\\r?\\n)`));
  if (pieces.shift()?.trim() || pieces.length < 2 || !/^--\s*$/.test(pieces.pop()!)) throw new Error("GRAPHQL_INCREMENTAL_DELIVERY_TRUNCATED");
  if (pieces.length > maxParts) throw new Error("GRAPHQL_INCREMENTAL_PART_LIMIT_EXCEEDED");
  return pieces.map((part) => {
    const split = part.search(/\r?\n\r?\n/);
    if (split < 0 || !/(?:^|\r?\n)content-type:\s*application\/json\b/i.test(part.slice(0, split))) throw new Error("GRAPHQL_INCREMENTAL_PART_HEADERS_INVALID");
    return object(part.slice(split).trim());
  });
}
