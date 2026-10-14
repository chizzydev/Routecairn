import { HttpError } from "./DashboardHttpSupport.js";
import { withTrustedDiscoveryDatabaseDeadline } from "../execution/TrustedDiscoveryDatabaseDeadline.js";
import { ZodError } from "zod";
import { SessionError } from "../auth/LocalSession.js";
import { OrganizationPermissionError } from "../operations/OrganizationService.js";
import { TrustedDiscoveryDenial } from "../execution/TrustedDiscoverySource.js";
import { TrustedDiscoveryStageAError } from "../execution/TrustedDiscoveryReviewStore.js";
import {
  trustedDiscoveryReviewSchema,
  trustedDiscoveryPreconsentSchema,
  trustedDiscoveryStageAFacts,
} from "../execution/TrustedDiscoveryOperatorService.js";
import {
  readJson,
  requireRuntimeSession,
  requireRuntimeMutation,
  sendJson,
  type ApiContext,
} from "./DashboardApiContext.js";

/** Exact Stage A routes, intercepted before general mutation handling. There is no
 * execution handler, operation field, queue dispatch or transport call in this file. */
export async function handleTrustedDiscoveryStageA(context: ApiContext): Promise<void> {
  const { request, response, url, trustedDiscovery } = context;
  response.setHeader("cache-control", "no-store");
  let authority: object | undefined;
  try {
    withTrustedDiscoveryDatabaseDeadline(context.database, () => requireRuntimeSession(context));
    if (
      context.mode !== "server" ||
      !trustedDiscovery ||
      request.method !== "POST" ||
      !["/api/trusted-discovery/review", "/api/trusted-discovery/pre-consent"].includes(url.pathname)
    ) {
      sendJson(response, 404, trustedDiscoveryStageAFacts("DISABLED"));
      return;
    }
    const mutationCsrf = request.headers["x-csrf-token"];
    withTrustedDiscoveryDatabaseDeadline(context.database, () =>
      requireRuntimeMutation(context, typeof mutationCsrf === "string" ? mutationCsrf : undefined),
    );
    const selected = request.headers["x-routecairn-organization-id"];
    if (typeof selected !== "string" || !/^[a-f0-9-]{36}$/i.test(selected) || url.search)
      throw new TrustedDiscoveryStageAError("DENIED_AUTHORITY", 403);
    // Reject non-owner or foreign membership before consuming an untrusted body.
    // Re-capture after the await; this early check never becomes retained authority.
    authority = withTrustedDiscoveryDatabaseDeadline(context.database, () =>
      context.serverSessions!.captureTrustedDiscoverySession(
        request,
        typeof mutationCsrf === "string" ? mutationCsrf : undefined,
      ),
    );
    const native = context.serverSessions!.revalidateTrustedDiscoverySession(authority);
    if (context.organizations.require(selected, native.userId, "resources.use", false) !== "OWNER")
      throw new TrustedDiscoveryStageAError("DENIED_AUTHORITY", 403);
    context.serverSessions!.releaseTrustedDiscoverySession(authority);
    authority = undefined;
    const raw = await readJson(request);
    const input = url.pathname.endsWith("/review")
      ? trustedDiscoveryReviewSchema.parse(raw)
      : trustedDiscoveryPreconsentSchema.parse(raw);
    const csrf = request.headers["x-csrf-token"];
    authority = withTrustedDiscoveryDatabaseDeadline(context.database, () =>
      context.serverSessions!.captureTrustedDiscoverySession(request, typeof csrf === "string" ? csrf : undefined),
    );
    const result = url.pathname.endsWith("/review")
      ? await trustedDiscovery.review(trustedDiscoveryReviewSchema.parse(input), authority, selected)
      : await trustedDiscovery.preconsent(trustedDiscoveryPreconsentSchema.parse(input), authority, selected);
    authority = undefined;
    sendJson(response, 200, result);
  } catch (error) {
    // A storage failure invalidates the shared DB authority; malformed input from one
    // tenant must never cancel another tenant's valid private review.
    const databaseCode = error instanceof Error ? Object.getOwnPropertyDescriptor(error, "code")?.value : undefined;
    if (typeof databaseCode === "string" && /^SQLITE_/.test(databaseCode)) trustedDiscovery?.invalidateAllPending();
    trustedDiscovery?.invalidateStale();
    if (authority) context.serverSessions?.releaseTrustedDiscoverySession(authority);
    const status =
      error instanceof SessionError
        ? 401
        : error instanceof OrganizationPermissionError
          ? 403
          : error instanceof ZodError || error instanceof SyntaxError
            ? 400
            : error instanceof HttpError && [400, 413].includes(error.statusCode)
              ? error.statusCode
              : error instanceof TrustedDiscoveryStageAError
                ? error.status
                : error instanceof TrustedDiscoveryDenial
                  ? 409
                  : 503;
    const code =
      error instanceof SessionError || error instanceof OrganizationPermissionError
        ? "DENIED_AUTHORITY"
        : error instanceof ZodError ||
            error instanceof SyntaxError ||
            (error instanceof HttpError && [400, 413].includes(error.statusCode))
          ? "DENIED_INPUT"
          : error instanceof TrustedDiscoveryStageAError
            ? error.code
            : error instanceof TrustedDiscoveryDenial
              ? "DENIED_SOURCE"
              : "UNAVAILABLE";
    sendJson(response, status, trustedDiscoveryStageAFacts(code));
  }
}
