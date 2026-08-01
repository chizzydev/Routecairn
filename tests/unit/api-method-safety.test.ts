import { describe, expect, it } from "vitest";
import { classifyApiMethodSafety, isSafeApiMethod } from "../../src/intelligence/apiSafety/ApiMethodSafety.js";

describe("API method safety", () => {
  it("allows only safe API methods by default", () => {
    expect(["GET", "HEAD", "OPTIONS"].every((method) => isSafeApiMethod(method))).toBe(true);
    expect(classifyApiMethodSafety("POST")).toMatchObject({ method: "POST", safety: "destructive-skipped" });
    expect(classifyApiMethodSafety("PUT")).toMatchObject({ method: "PUT", safety: "destructive-skipped" });
    expect(classifyApiMethodSafety("PATCH")).toMatchObject({ method: "PATCH", safety: "destructive-skipped" });
    expect(classifyApiMethodSafety("DELETE")).toMatchObject({ method: "DELETE", safety: "destructive-skipped" });
    expect(classifyApiMethodSafety("TRACE")).toMatchObject({ method: "TRACE", safety: "unknown-skipped" });
  });
});
