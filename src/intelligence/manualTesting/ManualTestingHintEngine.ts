import { apiTestingHints } from "./apiTestingHints.js";
import { authTestingHints } from "./authTestingHints.js";
import { businessLogicHints } from "./businessLogicHints.js";

export class ManualTestingHintEngine {
  public hintsForApiTags(tags: string[]): string[] {
    const hints = new Set<string>();

    if (tags.includes("object-id")) {
      hints.add(apiTestingHints.bola);
    }

    if (tags.includes("admin") || tags.includes("privileged")) {
      hints.add(apiTestingHints.functionAuthorization);
    }

    if (tags.includes("data-exposure")) {
      hints.add(apiTestingHints.excessiveData);
    }

    if (tags.includes("export")) {
      hints.add(apiTestingHints.exportAbuse);
    }

    if (tags.includes("graphql")) {
      hints.add(apiTestingHints.graphql);
    }

    if (tags.includes("rate-limit") || tags.includes("otp") || tags.includes("auth")) {
      hints.add(apiTestingHints.rateLimit);
    }

    if (tags.includes("invite")) {
      hints.add(businessLogicHints.inviteAbuse);
    }

    if (tags.includes("cart") || tags.includes("order")) {
      hints.add(businessLogicHints.cartAbuse);
    }

    if (tags.includes("user-data")) {
      hints.add(businessLogicHints.scraping);
    }

    if (hints.size === 0) {
      hints.add("Review manually for authorization, data exposure, and intended public access.");
    }

    return [...hints];
  }

  public hintsForAuthPurpose(purpose: string): string[] {
    const hints = new Set<string>();
    const normalized = purpose.toLowerCase();

    if (normalized.includes("login") || normalized.includes("register")) {
      hints.add(authTestingHints.enumeration);
      hints.add(authTestingHints.bruteForce);
    }

    if (normalized.includes("reset") || normalized.includes("forgot")) {
      hints.add(authTestingHints.enumeration);
      hints.add(authTestingHints.resetAbuse);
    }

    if (normalized.includes("otp") || normalized.includes("verification") || normalized.includes("magic")) {
      hints.add(authTestingHints.otpAbuse);
    }

    if (normalized.includes("session")) {
      hints.add(authTestingHints.sessionReview);
    }

    if (normalized.includes("oauth")) {
      hints.add(authTestingHints.oauthReview);
    }

    if (hints.size === 0) {
      hints.add("Review the route for intended public exposure and access-control behavior.");
    }

    return [...hints];
  }
}
