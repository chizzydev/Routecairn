import type { ApiEndpointAnalysis, ResponseObservation } from "../../reports/ReportTypes.js";
import { ManualTestingHintEngine } from "../../intelligence/manualTesting/ManualTestingHintEngine.js";
import { isGraphQlEndpoint } from "./GraphQLDetector.js";

export class ApiRouteClassifier {
  private readonly hintEngine = new ManualTestingHintEngine();

  public classify(observation: ResponseObservation): ApiEndpointAnalysis | undefined {
    const url = new URL(observation.url);
    const pathname = url.pathname.toLowerCase();

    if (!isApiLike(pathname)) {
      return undefined;
    }

    const riskTags = tagsForPath(pathname);

    return {
      endpoint: observation.url,
      method: observation.method,
      routeType: routeTypeForPath(pathname),
      riskTags,
      likelyManualTests: this.hintEngine.hintsForApiTags(riskTags),
      authRelevance: includesAny(riskTags, ["auth", "admin", "session", "privileged"]) ? "high" : "medium",
      hasObjectId: riskTags.includes("object-id"),
      privilegeSensitivity: includesAny(riskTags, ["admin", "privileged"]) ? "high" : "medium",
      dataExposureSensitivity: includesAny(riskTags, ["user-data", "account", "export", "order"]) ? "high" : "medium",
      rateLimitSensitivity: includesAny(riskTags, ["auth", "otp", "invite", "reset-password", "export"]) ? "high" : "medium"
    };
  }
}

function isApiLike(pathname: string): boolean {
  return pathname.startsWith("/api") || isGraphQlEndpoint(pathname);
}

function routeTypeForPath(pathname: string): string {
  if (isGraphQlEndpoint(pathname)) {
    return "graphql";
  }

  if (pathname.includes("/admin")) {
    return "admin-api";
  }

  if (pathname.includes("/auth") || pathname.includes("/session") || pathname.includes("/login")) {
    return "auth-api";
  }

  if (pathname.includes("/users") || pathname.includes("/accounts")) {
    return "identity-api";
  }

  if (pathname.includes("/orders") || pathname.includes("/cart")) {
    return "commerce-api";
  }

  if (pathname.includes("/export") || pathname.includes("/download")) {
    return "export-api";
  }

  return "api";
}

function tagsForPath(pathname: string): string[] {
  const tags = new Set<string>(["api"]);

  if (isGraphQlEndpoint(pathname)) {
    tags.add("graphql");
  }

  if (/\b\d+\b|\/:[a-z_]*id\b|\/[a-f0-9]{8,}\b/i.test(pathname)) {
    tags.add("object-id");
  }

  if (pathname.includes("admin")) {
    tags.add("admin");
    tags.add("privileged");
  }

  if (pathname.includes("auth") || pathname.includes("session") || pathname.includes("login")) {
    tags.add("auth");
  }

  if (pathname.includes("reset-password") || pathname.includes("forgot-password")) {
    tags.add("reset-password");
  }

  if (pathname.includes("otp")) {
    tags.add("otp");
  }

  if (pathname.includes("users") || pathname.includes("accounts")) {
    tags.add("user-data");
    tags.add("account");
    tags.add("data-exposure");
  }

  if (pathname.includes("orders")) {
    tags.add("order");
    tags.add("data-exposure");
  }

  if (pathname.includes("cart")) {
    tags.add("cart");
  }

  if (pathname.includes("export") || pathname.includes("download")) {
    tags.add("export");
    tags.add("data-exposure");
  }

  if (pathname.includes("invite")) {
    tags.add("invite");
  }

  if (tags.has("auth") || tags.has("otp") || tags.has("invite")) {
    tags.add("rate-limit");
  }

  return [...tags];
}

function includesAny(values: string[], expected: string[]): boolean {
  return expected.some((item) => values.includes(item));
}
