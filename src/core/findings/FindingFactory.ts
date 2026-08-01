import { createHash } from "node:crypto";
import type { Finding, FindingType } from "./Finding.js";
import type { Confidence } from "./Confidence.js";
import type { Severity } from "./Severity.js";
import type { ResponseObservation } from "../../reports/ReportTypes.js";
import { RiskScorer } from "./RiskScorer.js";
import { evidenceFromObservation } from "../evidence/EvidenceBuilder.js";

export class FindingFactory {
  private readonly riskScorer = new RiskScorer();

  public fromResponseObservation(observation: ResponseObservation, sourceModule: string): Finding | undefined {
    if (observation.falsePositiveStatus === "likely-false-positive") {
      return undefined;
    }

    const type = typeForObservation(observation);
    const severity = severityForType(type);

    const findingBase = {
      id: stableFindingId(type, observation.url, observation.method),
      title: titleForType(type),
      type,
      severity,
      confidence: confidenceForObservation(observation),
      url: observation.url,
      method: observation.method,
      ...(typeof observation.statusCode === "number" ? { statusCode: observation.statusCode } : {}),
      evidence: evidenceFromObservation(observation, {
        source: observation.source,
        severity,
        confidence: confidenceForObservation(observation),
        tags: tagsForType(type)
      }),
      impact: impactForType(type),
      recommendation: recommendationForType(type),
      manualTestingSuggestions: manualTestsForType(type),
      tags: tagsForType(type),
      falsePositiveStatus: observation.falsePositiveStatus,
      sourceModule,
      timestamp: new Date().toISOString()
    };

    return {
      ...findingBase,
      riskScore: this.riskScorer.score(findingBase)
    };
  }
}

function typeForObservation(observation: ResponseObservation): FindingType {
  const pathname = new URL(observation.url).pathname.toLowerCase();

  if (pathname === "/graphql" || pathname.endsWith("/graphql")) {
    return "GraphQL Endpoint";
  }

  if (pathname.startsWith("/api")) {
    return "API Endpoint";
  }

  if (pathname.includes("admin") || pathname.includes("login") || pathname.includes("dashboard")) {
    return "Admin/Login Panel";
  }

  return "Interesting But Needs Manual Testing";
}

function severityForType(type: FindingType): Severity {
  if (type === "GraphQL Endpoint" || type === "API Endpoint") {
    return "Informational";
  }

  return "Low";
}

function confidenceForObservation(observation: ResponseObservation): Confidence {
  return observation.falsePositiveStatus === "likely-valid" ? "Medium" : "Low";
}

function titleForType(type: FindingType): string {
  if (type === "API Endpoint") {
    return "API endpoint discovered";
  }

  if (type === "GraphQL Endpoint") {
    return "GraphQL endpoint discovered";
  }

  if (type === "Admin/Login Panel") {
    return "Admin or login surface discovered";
  }

  return "Interesting surface discovered";
}

function impactForType(type: FindingType): string {
  if (type === "API Endpoint" || type === "GraphQL Endpoint") {
    return "This endpoint may expose application behavior that should be reviewed manually for authorization, data exposure, and rate-limit weaknesses.";
  }

  if (type === "Admin/Login Panel") {
    return "This surface may be relevant for authentication, authorization, account enumeration, or access-control testing.";
  }

  return "This reachable surface may be useful for manual attack surface review.";
}

function recommendationForType(type: FindingType): string {
  if (type === "GraphQL Endpoint") {
    return "Verify intended exposure and manually test introspection, batching, depth limits, and authorization behavior.";
  }

  if (type === "API Endpoint") {
    return "Verify intended exposure and manually test authorization, object access, data exposure, and rate limiting.";
  }

  return "Review whether this route is intended to be public and test access-control behavior within the authorized scope.";
}

function manualTestsForType(type: FindingType): string[] {
  if (type === "GraphQL Endpoint") {
    return ["Check introspection exposure", "Test authorization boundaries", "Review batching and depth behavior"];
  }

  if (type === "API Endpoint") {
    return ["Check object-level authorization", "Review response data exposure", "Test rate-limit behavior"];
  }

  if (type === "Admin/Login Panel") {
    return ["Check account enumeration behavior", "Review access-control boundaries", "Test rate-limit behavior"];
  }

  return ["Review manually for intended exposure"];
}

function tagsForType(type: FindingType): string[] {
  if (type === "GraphQL Endpoint") {
    return ["api", "graphql", "manual-review"];
  }

  if (type === "API Endpoint") {
    return ["api", "manual-review"];
  }

  if (type === "Admin/Login Panel") {
    return ["auth", "admin", "manual-review"];
  }

  return ["surface", "manual-review"];
}

function stableFindingId(type: FindingType, url: string, method: string): string {
  const hash = createHash("sha1").update(`${type}:${method}:${url}`).digest("hex").slice(0, 12);
  return `finding-${hash}`;
}
