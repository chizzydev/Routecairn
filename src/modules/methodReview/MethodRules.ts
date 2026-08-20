import type { Finding } from "../../core/findings/Finding.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import { createReviewFinding, headerValue } from "../reviewUtils.js";

const dangerousMethodPattern = /\b(?:PUT|DELETE|PATCH|TRACE)\b/i;

export function methodFindings(response: HttpResponse): Finding[] {
  const headers = headersForAnalysis(response);
  const allow = headerValue(headers, "allow");
  const corsMethods = headerValue(headers, "access-control-allow-methods");
  const findings: Finding[] = [];

  if (allow && dangerousMethodPattern.test(allow)) {
    findings.push(
      createReviewFinding({
        title: "Endpoint advertises potentially dangerous HTTP methods",
        type: "HTTP Method Issue",
        severity: allow.toUpperCase().includes("TRACE") ? "Medium" : "Low",
        confidence: "Medium",
        response,
        sourceModule: "method-review",
        evidence: `Allow: ${allow}`,
        impact: "Advertised write or diagnostic methods may increase attack surface if they are actually enabled without proper authorization.",
        recommendation: "Verify that unsafe methods are required and protected by authentication and authorization controls.",
        tags: ["methods"],
        manualTestingSuggestions: ["Manually verify whether advertised methods are actually accepted and properly authorized."]
      })
    );
  }

  if (corsMethods && dangerousMethodPattern.test(corsMethods)) {
    findings.push(
      createReviewFinding({
        title: "CORS advertises potentially dangerous HTTP methods",
        type: "HTTP Method Issue",
        severity: "Low",
        confidence: "Medium",
        response,
        sourceModule: "method-review",
        evidence: `Access-Control-Allow-Methods: ${corsMethods}`,
        impact: "Broad CORS method advertisement may increase browser-callable attack surface if paired with permissive origins and credentials.",
        recommendation: "Restrict CORS methods to those required by trusted browser clients.",
        tags: ["methods", "cors"],
        manualTestingSuggestions: ["Confirm whether unsafe methods are accepted and whether CORS permits sensitive cross-origin use."]
      })
    );
  }

  return findings;
}
