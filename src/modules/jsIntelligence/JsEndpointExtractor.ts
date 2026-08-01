export interface JsEndpointExtraction {
  endpoints: string[];
  absoluteUrls: string[];
  websocketUrls: string[];
  cloudReferences: string[];
}

const quotedStringPattern = /["'`]([^"'`\\]{1,240})["'`]/g;
const absoluteUrlPattern = /\bhttps?:\/\/[a-z0-9.-]+(?::\d+)?[^\s"'`),;]*/gi;
const websocketUrlPattern = /\bwss?:\/\/[a-z0-9.-]+(?::\d+)?[^\s"'`),;]*/gi;
const endpointPattern = /^\/(?:api|graphql|admin|dashboard|internal|auth|login|reset-password|forgot-password|users?|accounts?|orders?|cart|export|invite|otp)(?:[/?#][^"'`]*)?$/i;
const routeStringPattern = /^\/[a-z0-9][a-z0-9/_:.-]{1,120}(?:[/?#][^"'`]*)?$/i;
const cloudReferencePattern = /\b(?:[a-z0-9.-]+\.firebaseio\.com|firebasestorage\.googleapis\.com|[a-z0-9.-]+\.supabase\.co|s3\.amazonaws\.com|[a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.cloudfront\.net)\b/gi;

export class JsEndpointExtractor {
  public extract(source: string): JsEndpointExtraction {
    const endpoints = new Set<string>();
    const absoluteUrls = new Set<string>();
    const websocketUrls = new Set<string>();
    const cloudReferences = new Set<string>();

    for (const match of source.matchAll(absoluteUrlPattern)) {
      if (match[0]) {
        absoluteUrls.add(cleanToken(match[0]));
      }
    }

    for (const match of source.matchAll(websocketUrlPattern)) {
      if (match[0]) {
        websocketUrls.add(cleanToken(match[0]));
      }
    }

    for (const match of source.matchAll(cloudReferencePattern)) {
      if (match[0]) {
        cloudReferences.add(cleanToken(match[0]));
      }
    }

    for (const match of source.matchAll(quotedStringPattern)) {
      const value = match[1]?.trim();

      if (!value) {
        continue;
      }

      if (endpointPattern.test(value) || routeStringPattern.test(value)) {
        endpoints.add(value);
      }
    }

    return {
      endpoints: [...endpoints],
      absoluteUrls: [...absoluteUrls],
      websocketUrls: [...websocketUrls],
      cloudReferences: [...cloudReferences]
    };
  }
}

function cleanToken(value: string): string {
  return value.replace(/[\\.,;]+$/g, "");
}
