import type { HttpRequest, HttpResponse, RedirectHop } from "./HttpTypes.js";

/** Destination scope does not grant reuse of another origin's supplied material.
 * Custom header names can carry API keys; do not infer sensitivity by name.
 * Refuse instead of silently switching an authenticated operation to anonymous. */
export function crossesRequestMaterialBoundary(request: HttpRequest, currentUrl: string, nextUrl: string): boolean {
  return (
    new URL(nextUrl).origin !== new URL(currentUrl).origin &&
    (Object.keys(request.headers ?? {}).length > 0 || !!request.body?.length)
  );
}

/** Preserve the actual native response and its completeness metadata when a
 * redirect is refused. The caller still performs ordinary evidence redaction. */
export function refusedRedirect(
  request: HttpRequest,
  response: HttpResponse,
  currentUrl: string,
  nextUrl: string,
  chain: RedirectHop[],
  reason: string
): HttpResponse {
  return {
    ...response,
    requestedUrl: request.url,
    finalUrl: currentUrl,
    method: request.method,
    redirectChain: chain,
    redirectLocation: nextUrl,
    error: { name: "OutOfScopeRedirect", message: `Redirect blocked by scan-wide broker: ${reason}.` }
  };
}
