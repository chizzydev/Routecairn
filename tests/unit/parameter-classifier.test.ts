import { describe, expect, it } from "vitest";
import { analyzePathSegment, analyzeQueryParameter } from "../../src/intelligence/parameters/ParameterClassifier.js";

describe("parameter classifier", () => {
  it("classifies authorization and business-logic parameter signals", () => {
    expect(analyzeQueryParameter("userId", "123")).toMatchObject({
      kind: "user-account",
      riskTags: expect.arrayContaining(["object-id", "authorization-sensitive"]),
      confidence: "High"
    });
    expect(analyzeQueryParameter("priceMin", "5000")).toMatchObject({
      kind: "price",
      riskTags: expect.arrayContaining(["business-logic"])
    });
    expect(analyzeQueryParameter("page", "2")).toMatchObject({
      kind: "pagination",
      riskTags: expect.arrayContaining(["harmless-navigation"])
    });
    expect(analyzeQueryParameter("q", "laptop")).toMatchObject({
      kind: "search"
    });
    expect(analyzeQueryParameter("token", "abcdefghijklmnopqrstuvwxyz123456")).toMatchObject({
      kind: "token",
      riskTags: expect.arrayContaining(["authorization-sensitive"])
    });
    expect(analyzePathSegment("550e8400-e29b-41d4-a716-446655440000", 2, "orders")).toMatchObject({
      kind: "uuid",
      location: "path",
      riskTags: expect.arrayContaining(["object-id", "authorization-sensitive"])
    });
  });
});
