import type { AuthSurfaceAnalysis, ResponseObservation } from "../../reports/ReportTypes.js";
import { ManualTestingHintEngine } from "../../intelligence/manualTesting/ManualTestingHintEngine.js";
import { isSessionRoute } from "./SessionIndicatorDetector.js";

export class AuthRouteDetector {
  private readonly hintEngine = new ManualTestingHintEngine();

  public detect(observation: ResponseObservation): AuthSurfaceAnalysis | undefined {
    const url = new URL(observation.url);
    const pathname = url.pathname.toLowerCase();
    const purpose = purposeForPath(pathname);

    if (!purpose) {
      return undefined;
    }

    return {
      endpoint: observation.url,
      purpose,
      abuseCategories: abuseCategoriesForPurpose(purpose),
      rateLimitSensitivity: rateLimitSensitivityForPurpose(purpose),
      accountEnumerationRelevance: enumerationRelevanceForPurpose(purpose),
      suggestedTests: this.hintEngine.hintsForAuthPurpose(purpose)
    };
  }
}

function purposeForPath(pathname: string): string | undefined {
  if (pathname.includes("reset-password") || pathname.includes("forgot-password")) {
    return "password reset";
  }

  if (pathname.includes("register") || pathname.includes("signup") || pathname.includes("sign-up")) {
    return "registration";
  }

  if (pathname.includes("login") || pathname.includes("signin") || pathname.includes("sign-in")) {
    return "login";
  }

  if (pathname.includes("verify") || pathname.includes("verification")) {
    return "email verification";
  }

  if (pathname.includes("otp")) {
    return "otp";
  }

  if (pathname.includes("magic-link") || pathname.includes("magiclink")) {
    return "magic link";
  }

  if (pathname.includes("oauth") || pathname.includes("callback")) {
    return "oauth";
  }

  if (pathname.includes("logout") || pathname.includes("signout") || pathname.includes("sign-out")) {
    return "logout";
  }

  if (isSessionRoute(pathname)) {
    return "session";
  }

  if (pathname.includes("/auth/")) {
    return "auth route";
  }

  return undefined;
}

function abuseCategoriesForPurpose(purpose: string): string[] {
  if (purpose === "password reset") {
    return ["account enumeration", "email flooding", "token handling"];
  }

  if (purpose === "login" || purpose === "registration") {
    return ["account enumeration", "brute force", "rate-limit abuse"];
  }

  if (purpose === "otp" || purpose === "magic link" || purpose === "email verification") {
    return ["rate-limit abuse", "replay", "delivery abuse"];
  }

  if (purpose === "oauth") {
    return ["redirect handling", "account linking", "state validation"];
  }

  if (purpose === "session") {
    return ["session exposure", "cache control", "auth state leakage"];
  }

  return ["access-control review"];
}

function rateLimitSensitivityForPurpose(purpose: string): AuthSurfaceAnalysis["rateLimitSensitivity"] {
  return ["login", "registration", "password reset", "otp", "magic link", "email verification"].includes(purpose) ? "high" : "medium";
}

function enumerationRelevanceForPurpose(purpose: string): AuthSurfaceAnalysis["accountEnumerationRelevance"] {
  return ["login", "registration", "password reset"].includes(purpose) ? "high" : "medium";
}
