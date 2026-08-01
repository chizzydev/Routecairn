import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import type { AuthSurfaceAnalysis, AuthSurfaceReport, ResponseObservation } from "../../reports/ReportTypes.js";
import { AuthRouteDetector } from "./AuthRouteDetector.js";

export class AuthSurfaceModule implements RouteCairnPlugin {
  public readonly name = "auth-surface";
  public readonly description = "Detects auth-related routes and adds manual testing guidance.";
  public readonly phase = "analysis";
  private readonly detector = new AuthRouteDetector();

  public async run(context: ScanContext): Promise<ModuleResult> {
    const candidateObservations = context.state
      .getDiscoveredUrls()
      .filter((observation) => observation.falsePositiveStatus !== "likely-false-positive")
      .filter((observation) => isUsefulAuthObservation(observation));

    const rawSurfaces = candidateObservations
      .map((observation) => this.detector.detect(observation))
      .filter((surface): surface is AuthSurfaceAnalysis => typeof surface !== "undefined");
    const surfaces = dedupeSurfaces(rawSurfaces);

    const report: AuthSurfaceReport = {
      surfaces,
      notes: surfaces.length === 0 ? ["No auth surfaces were detected."] : [`Auth surfaces detected: ${surfaces.length} grouped from ${rawSurfaces.length} observations.`]
    };

    return {
      pluginName: this.name,
      authSurface: report,
      notes: report.notes
    };
  }
}

function isUsefulAuthObservation(observation: ResponseObservation): boolean {
  if (typeof observation.statusCode === "number" && observation.statusCode >= 400) {
    return false;
  }

  const pathname = new URL(observation.url).pathname.toLowerCase();
  const authLike = /(?:^|\/)(?:api\/auth|auth|login|signin|sign-in|register|signup|sign-up|reset-password|forgot-password|verify|verification|otp|magic-link|magiclink|oauth|callback|logout|signout|sign-out|session|csrf|me)(?:$|[\/?#-])/.test(pathname);

  if (authLike) {
    return true;
  }

  return observation.falsePositiveStatus === "likely-valid" && /(?:session|csrf)/i.test(observation.title ?? "");
}

function dedupeSurfaces(surfaces: AuthSurfaceAnalysis[]): AuthSurfaceAnalysis[] {
  const byKey = new Map<string, AuthSurfaceAnalysis>();

  for (const surface of surfaces) {
    const normalizedEndpoint = normalizeEndpoint(surface.endpoint);
    const key = `${normalizedEndpoint}:${surface.purpose}`;

    if (!byKey.has(key)) {
      byKey.set(key, { ...surface, endpoint: normalizedEndpoint });
    }
  }

  return [...byKey.values()].sort((left, right) => left.endpoint.localeCompare(right.endpoint));
}

function normalizeEndpoint(endpoint: string): string {
  const url = new URL(endpoint);
  url.hash = "";
  if (url.pathname !== "/") {
    url.pathname = url.pathname.replace(/\/+$/, "");
  }
  url.searchParams.sort();
  return url.toString();
}
