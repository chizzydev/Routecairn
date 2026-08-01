import type { Finding } from "../../core/findings/Finding.js";
import type { Severity } from "../../core/findings/Severity.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { createReviewFinding, headerValue } from "../reviewUtils.js";

export function corsFinding(response: HttpResponse, testedOrigin: string): Finding | undefined {
  const acao = headerValue(response.headers, "access-control-allow-origin");
  const credentials = headerValue(response.headers, "access-control-allow-credentials")?.toLowerCase() === "true";
  const methods = headerValue(response.headers, "access-control-allow-methods");

  if (!acao && !methods) {
    return undefined;
  }

  if (acao === "*" && credentials) {
    return createCorsFinding(response, "CORS allows wildcard origin with credentials", "High", `ACAO=* and ACAC=true for Origin ${testedOrigin}.`);
  }

  if (acao === testedOrigin && credentials) {
    return createCorsFinding(
      response,
      "CORS reflects arbitrary origin with credentials",
      "High",
      `ACAO reflected ${testedOrigin} and ACAC=true.`
    );
  }

  if (acao === "null") {
    return createCorsFinding(response, "CORS allows null origin", credentials ? "Medium" : "Low", "ACAO=null was observed.");
  }

  if (acao === "*") {
    return createCorsFinding(
      response,
      "CORS allows wildcard origin",
      "Informational",
      "ACAO=* without credentials. This is often acceptable for public resources."
    );
  }

  if (acao === testedOrigin) {
    return createCorsFinding(
      response,
      "CORS reflects arbitrary origin without credentials",
      "Medium",
      `ACAO reflected ${testedOrigin}, but credentials were not enabled.`
    );
  }

  if (methods && /\b(?:PUT|DELETE|PATCH|TRACE)\b/i.test(methods)) {
    return createCorsFinding(response, "CORS advertises broad methods", "Low", `Access-Control-Allow-Methods: ${methods}`);
  }

  return undefined;
}

function createCorsFinding(response: HttpResponse, title: string, severity: Severity, evidence: string): Finding {
  return createReviewFinding({
    title,
    type: "CORS Issue",
    severity,
    confidence: "High",
    response,
    sourceModule: "cors-review",
    evidence,
    impact: "CORS misconfiguration may allow browser-based cross-origin reads only when sensitive responses and credential behavior align.",
    recommendation: "Restrict allowed origins to trusted origins and avoid credentials with wildcard or reflected origins.",
    tags: ["cors"],
    manualTestingSuggestions: ["Confirm whether sensitive authenticated data is readable cross-origin under the authorized test conditions."]
  });
}
