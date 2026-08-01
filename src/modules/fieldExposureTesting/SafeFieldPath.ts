import { AppError } from "../../core/errors/AppError.js";

export type FieldPresenceState =
  | "PRESENT_VALUE"
  | "PRESENT_NULL"
  | "PRESENT_EMPTY_STRING"
  | "PRESENT_REDACTED"
  | "ABSENT"
  | "PATH_PARENT_MISSING"
  | "TYPE_MISMATCH"
  | "INDEX_OUT_OF_BOUNDS";

export interface SafeFieldSegment {
  key: string;
  index?: number;
}

const segmentPattern = /^([A-Za-z_$][A-Za-z0-9_$]*)(?:\[(0|[1-9][0-9]{0,2})\])?$/;
const forbiddenSegments = new Set(["__proto__", "prototype", "constructor"]);

export function parseSafeFieldPath(path: string, options: { maxDepth: number; maxArrayIndex: number; code: string }): readonly SafeFieldSegment[] {
  if (!path || path.length > 160) {
    throw new AppError(`Field path "${path}" is empty or too long.`, options.code);
  }
  if (/[*?]|\.{2}|\[.*[:*?].*\]|\(|\)|\||=>|function|eval/i.test(path)) {
    throw new AppError(`Field path "${path}" uses unsupported traversal syntax.`, options.code);
  }

  const parts = path.split(".");
  if (parts.length > options.maxDepth) {
    throw new AppError(`Field path "${path}" exceeds maximum depth ${options.maxDepth}.`, options.code);
  }

  return parts.map((part) => {
    const match = part.match(segmentPattern);
    if (!match || !match[1] || forbiddenSegments.has(match[1])) {
      throw new AppError(`Field path "${path}" contains an unsupported segment.`, options.code);
    }
    const index = match[2] === undefined ? undefined : Number(match[2]);
    if (typeof index === "number" && index > options.maxArrayIndex) {
      throw new AppError(`Field path "${path}" uses array index ${index}, exceeding maximum ${options.maxArrayIndex}.`, options.code);
    }
    return { key: match[1], ...(typeof index === "number" ? { index } : {}) };
  });
}

export function valueAtSafePath(source: Record<string, unknown> | undefined, segments: readonly SafeFieldSegment[]): { state: FieldPresenceState; value?: unknown } {
  if (!source) {
    return { state: "TYPE_MISMATCH" };
  }

  let value: unknown = source;
  for (const [index, segment] of segments.entries()) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return { state: "PATH_PARENT_MISSING" };
    }

    if (!Object.prototype.hasOwnProperty.call(value, segment.key)) {
      return { state: index === segments.length - 1 ? "ABSENT" : "PATH_PARENT_MISSING" };
    }
    value = (value as Record<string, unknown>)[segment.key];

    if (typeof segment.index === "number") {
      if (!Array.isArray(value)) {
        return { state: "TYPE_MISMATCH" };
      }
      if (segment.index >= value.length) {
        return { state: "INDEX_OUT_OF_BOUNDS" };
      }
      value = value[segment.index];
    }
  }

  if (value === null) return { state: "PRESENT_NULL", value };
  if (value === "") return { state: "PRESENT_EMPTY_STRING", value };
  if (typeof value === "string" && /^(?:\*+|x+|redacted|null)$/i.test(value.trim())) return { state: "PRESENT_REDACTED", value };
  return { state: "PRESENT_VALUE", value };
}

