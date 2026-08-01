import { describe, expect, it } from "vitest";
import { buildEvidenceTemplates } from "../../src/intelligence/evidenceTemplates/EvidenceTemplateFactory.js";

describe("evidence template factory", () => {
  it("generates the manual proof template families", () => {
    const templates = buildEvidenceTemplates({
      workflows: [
        { category: "idor-bola", title: "IDOR", target: "https://example.test/api/users/123", priority: "high", confidence: "High", evidence: [], relatedEndpoints: ["https://example.test/api/users/123"], safeTestPlan: [], avoidActions: [] },
        { category: "auth-session", title: "Auth", target: "https://example.test/login", priority: "medium", confidence: "High", evidence: [], relatedEndpoints: ["https://example.test/login"], safeTestPlan: [], avoidActions: [] },
        { category: "rate-limit", title: "Rate", target: "https://example.test/reset-password", priority: "medium", confidence: "High", evidence: [], relatedEndpoints: ["https://example.test/reset-password"], safeTestPlan: [], avoidActions: [] },
        { category: "graphql", title: "GraphQL", target: "https://example.test/graphql", priority: "medium", confidence: "High", evidence: [], relatedEndpoints: ["https://example.test/graphql"], safeTestPlan: [], avoidActions: [] }
      ],
      stateAwareApi: {
        safeMethods: ["GET", "HEAD", "OPTIONS"],
        skippedMethods: ["POST", "PUT", "PATCH", "DELETE"],
        candidateCount: 1,
        reviewedEndpoints: [{ endpoint: "https://example.test/api/export", routeType: "api", candidateReasons: ["export-download"], priority: "high", safeMethodsTested: [], skippedMethods: [], accessComparison: { anonymous: {}, signal: "inconclusive", needsManualVerification: true }, evidenceNotes: [] }],
        bolaIdorCandidates: [] ,
        notes: []
      },
      parameterAnalysis: {
        analyzedUrls: [],
        totalParameters: 1,
        highRiskParameters: [],
        riskSummary: { objectId: 0, authorizationSensitive: 0, businessLogic: 1, harmlessNavigation: 0 },
        workflowTargets: [{ url: "https://example.test/search?minPrice=1", reasons: ["business-logic"], suggestedWorkflow: "Business-logic parameter review" }],
        notes: []
      }
    });

    expect(templates.map((template) => template.kind)).toEqual(expect.arrayContaining(["idor-bola", "auth-bypass", "rate-limit", "graphql", "export-download", "price-filter"]));
    expect(templates.every((template) => template.needsManualVerification)).toBe(true);
    expect(templates.every((template) => template.preconditions.length > 0 && template.steps.length > 0 && template.expectedSecureBehavior.length > 0 && template.evidenceToCapture.length > 0 && template.avoidActions.length > 0)).toBe(true);
  });
});
