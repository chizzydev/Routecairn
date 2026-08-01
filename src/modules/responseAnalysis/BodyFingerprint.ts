import type { HttpResponse } from "../../core/http/HttpTypes.js";

export interface BodyFingerprint {
  statusCode?: number;
  title?: string;
  contentLength?: number;
  bodyHash?: string;
}

export function fingerprintResponse(response: HttpResponse): BodyFingerprint {
  return {
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response.title ? { title: response.title } : {}),
    ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response.bodyHash ? { bodyHash: response.bodyHash } : {})
  };
}

export function hasSimilarLength(left: number | undefined, right: number | undefined): boolean {
  if (typeof left !== "number" || typeof right !== "number") {
    return false;
  }

  const tolerance = Math.max(50, Math.round(Math.max(left, right) * 0.08));
  return Math.abs(left - right) <= tolerance;
}
