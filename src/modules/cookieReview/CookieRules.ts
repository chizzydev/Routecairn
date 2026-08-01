import type { Finding } from "../../core/findings/Finding.js";
import type { Severity } from "../../core/findings/Severity.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { createReviewFinding, headerValues } from "../reviewUtils.js";
import { attributeValue, hasAttribute, parseSetCookie, type ParsedCookie } from "./CookieParser.js";

const sensitiveCookiePattern = /(session|sid|token|auth|jwt|next-auth|laravel_session|connect\.sid)/i;

export function cookieFindings(response: HttpResponse): Finding[] {
  const cookies = headerValues(response.headers, "set-cookie")
    .map(parseSetCookie)
    .filter((cookie) => typeof cookie !== "undefined");
  const findings: Finding[] = [];

  for (const cookie of cookies) {
    const sensitive = isSensitiveCookie(cookie);
    const severity = sensitive ? "Medium" : "Low";

    if (!hasAttribute(cookie, "httponly") && sensitive) {
      findings.push(cookieFinding(response, cookie, "Sensitive cookie is missing HttpOnly", severity, "Cookie does not include HttpOnly."));
    }

    if (!hasAttribute(cookie, "secure") && response.finalUrl.startsWith("https://")) {
      findings.push(cookieFinding(response, cookie, "Cookie is missing Secure", severity, "Cookie does not include Secure."));
    }

    const sameSite = attributeValue(cookie, "samesite");
    if (!sameSite) {
      findings.push(cookieFinding(response, cookie, "Cookie is missing SameSite", sensitive ? "Low" : "Informational", "Cookie does not include SameSite."));
    }

    if (sameSite?.toLowerCase() === "none" && !hasAttribute(cookie, "secure")) {
      findings.push(cookieFinding(response, cookie, "SameSite=None cookie is missing Secure", "Medium", "Cookie has SameSite=None without Secure."));
    }

    const domain = attributeValue(cookie, "domain");
    if (domain?.startsWith(".")) {
      findings.push(cookieFinding(response, cookie, "Cookie uses a broad Domain attribute", sensitive ? "Medium" : "Low", `Cookie Domain=${domain}.`));
    }
  }

  return findings;
}

function isSensitiveCookie(cookie: ParsedCookie): boolean {
  return sensitiveCookiePattern.test(cookie.name);
}

function cookieFinding(response: HttpResponse, cookie: ParsedCookie, title: string, severity: Severity, evidence: string): Finding {
  return createReviewFinding({
    title,
    type: "Cookie Issue",
    severity,
    confidence: "High",
    response,
    sourceModule: "cookie-review",
    evidence: `${cookie.name}: ${evidence}`,
    impact: "Cookie attribute weaknesses can increase impact from XSS, network exposure, or cross-site request contexts depending on application behavior.",
    recommendation: "Set appropriate Secure, HttpOnly, SameSite, and Domain attributes based on the cookie purpose.",
    tags: ["cookies", isSensitiveCookie(cookie) ? "sensitive-cookie" : "cookie"]
  });
}
