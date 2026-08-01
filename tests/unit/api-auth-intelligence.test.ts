import { describe, expect, it } from "vitest";
import { ApiRouteClassifier } from "../../src/modules/apiMapper/ApiRouteClassifier.js";
import { AuthRouteDetector } from "../../src/modules/authSurface/AuthRouteDetector.js";
import type { ResponseObservation } from "../../src/reports/ReportTypes.js";

describe("API and auth intelligence", () => {
  it("classifies API endpoints with manual testing hints", () => {
    const classifier = new ApiRouteClassifier();
    const result = classifier.classify(observation("https://example.com/api/users/123/export"));

    expect(result?.routeType).toBe("identity-api");
    expect(result?.riskTags).toEqual(expect.arrayContaining(["object-id", "user-data", "export", "data-exposure"]));
    expect(result?.likelyManualTests.join(" ")).toContain("object-level authorization");
    expect(result?.dataExposureSensitivity).toBe("high");
  });

  it("detects GraphQL endpoints", () => {
    const classifier = new ApiRouteClassifier();
    const result = classifier.classify(observation("https://example.com/graphql"));

    expect(result?.routeType).toBe("graphql");
    expect(result?.riskTags).toEqual(expect.arrayContaining(["graphql"]));
    expect(result?.likelyManualTests.join(" ")).toContain("GraphQL introspection");
  });

  it("does not treat ordinary words containing me as session routes", () => {
    const detector = new AuthRouteDetector();

    expect(detector.detect(observation("https://example.com/best-camera-phones"))).toBeUndefined();
  });

  it("detects auth surfaces with abuse categories", () => {
    const detector = new AuthRouteDetector();
    const result = detector.detect(observation("https://example.com/reset-password"));

    expect(result?.purpose).toBe("password reset");
    expect(result?.abuseCategories).toEqual(expect.arrayContaining(["account enumeration", "email flooding"]));
    expect(result?.suggestedTests.join(" ")).toContain("password reset token");
  });
});

function observation(url: string): ResponseObservation {
  return {
    url,
    method: "GET",
    source: "test",
    statusCode: 200,
    responseTimeMs: 1,
    falsePositiveStatus: "likely-valid",
    classificationReason: "test"
  };
}
