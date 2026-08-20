import type { Finding } from "../../core/findings/Finding.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import { createReviewFinding, headerValue } from "../reviewUtils.js";

export function headerFindings(response: HttpResponse): Finding[] {
  if (response.error || typeof response.statusCode !== "number") {
    return [];
  }

  const findings: Finding[] = [];
  const headers = headersForAnalysis(response);
  const csp = headerValue(headers, "content-security-policy");
  const hsts = headerValue(headers, "strict-transport-security");
  const xContentType = headerValue(headers, "x-content-type-options");
  const xFrame = headerValue(headers, "x-frame-options");
  const referrerPolicy = headerValue(headers, "referrer-policy");
  const server = headerValue(headers, "server");
  const poweredBy = headerValue(headers, "x-powered-by");
  const isHttps = response.finalUrl.startsWith("https://");

  if (!csp) {
    findings.push(
      createReviewFinding({
        title: "Content-Security-Policy header is missing",
        type: "Security Header Issue",
        severity: "Low",
        confidence: "High",
        response,
        sourceModule: "header-review",
        evidence: "Missing Content-Security-Policy header.",
        impact: "Missing CSP reduces browser-side mitigation against XSS and content injection.",
        recommendation: "Add a CSP appropriate for the application and avoid broad script/style allowances.",
        tags: ["headers", "csp"]
      })
    );
  } else {
    if (csp.includes("'unsafe-eval'")) {
      findings.push(
        createReviewFinding({
          title: "Content-Security-Policy allows unsafe-eval",
          type: "Security Header Issue",
          severity: "Medium",
          confidence: "High",
          response,
          sourceModule: "header-review",
          evidence: "CSP contains unsafe-eval.",
          impact: "unsafe-eval can weaken CSP protection and increase XSS exploitability.",
          recommendation: "Remove unsafe-eval where possible and use safer build/runtime patterns.",
          tags: ["headers", "csp"]
        })
      );
    }

    if (csp.includes("'unsafe-inline'")) {
      findings.push(
        createReviewFinding({
          title: "Content-Security-Policy allows unsafe-inline",
          type: "Security Header Issue",
          severity: "Low",
          confidence: "High",
          response,
          sourceModule: "header-review",
          evidence: "CSP contains unsafe-inline.",
          impact: "unsafe-inline weakens CSP protection against injected script or style content.",
          recommendation: "Use nonces, hashes, or stricter script/style directives where practical.",
          tags: ["headers", "csp"]
        })
      );
    }
  }

  if (isHttps && !hsts) {
    findings.push(
      createReviewFinding({
        title: "Strict-Transport-Security header is missing",
        type: "Security Header Issue",
        severity: "Medium",
        confidence: "High",
        response,
        sourceModule: "header-review",
        evidence: "HTTPS response did not include HSTS.",
        impact: "Missing HSTS can allow downgrade or SSL stripping attacks in some network positions.",
        recommendation: "Set Strict-Transport-Security with an appropriate max-age after validating HTTPS readiness.",
        tags: ["headers", "hsts"]
      })
    );
  }

  if (!xContentType) {
    findings.push(
      createReviewFinding({
        title: "X-Content-Type-Options header is missing",
        type: "Security Header Issue",
        severity: "Low",
        confidence: "High",
        response,
        sourceModule: "header-review",
        evidence: "Missing X-Content-Type-Options header.",
        impact: "Missing nosniff may allow MIME type confusion in some browser contexts.",
        recommendation: "Set X-Content-Type-Options: nosniff.",
        tags: ["headers", "nosniff"]
      })
    );
  }

  if (!xFrame && !csp?.toLowerCase().includes("frame-ancestors")) {
    findings.push(
      createReviewFinding({
        title: "Clickjacking protection header is missing",
        type: "Security Header Issue",
        severity: "Low",
        confidence: "Medium",
        response,
        sourceModule: "header-review",
        evidence: "Missing X-Frame-Options and CSP frame-ancestors.",
        impact: "Pages may be frameable if no other controls exist.",
        recommendation: "Set CSP frame-ancestors or X-Frame-Options where framing is not intended.",
        tags: ["headers", "clickjacking"]
      })
    );
  }

  if (!referrerPolicy) {
    findings.push(
      createReviewFinding({
        title: "Referrer-Policy header is missing",
        type: "Security Header Issue",
        severity: "Informational",
        confidence: "High",
        response,
        sourceModule: "header-review",
        evidence: "Missing Referrer-Policy header.",
        impact: "Browsers may send more referrer information than intended.",
        recommendation: "Set a Referrer-Policy such as strict-origin-when-cross-origin.",
        tags: ["headers", "privacy"]
      })
    );
  }

  if (poweredBy) {
    findings.push(
      createReviewFinding({
        title: "X-Powered-By header discloses technology",
        type: "Security Header Issue",
        severity: "Informational",
        confidence: "High",
        response,
        sourceModule: "header-review",
        evidence: `X-Powered-By: ${poweredBy}`,
        impact: "Technology disclosure can help attackers fingerprint the stack, but is usually low impact alone.",
        recommendation: "Remove unnecessary technology disclosure headers.",
        tags: ["headers", "fingerprinting"]
      })
    );
  }

  if (server && /\d+\.\d+/.test(server)) {
    findings.push(
      createReviewFinding({
        title: "Server header may disclose version information",
        type: "Security Header Issue",
        severity: "Informational",
        confidence: "Medium",
        response,
        sourceModule: "header-review",
        evidence: `Server: ${server}`,
        impact: "Server version disclosure can assist fingerprinting, but is rarely exploitable alone.",
        recommendation: "Avoid exposing precise server versions where operationally possible.",
        tags: ["headers", "fingerprinting"]
      })
    );
  }

  return findings;
}
