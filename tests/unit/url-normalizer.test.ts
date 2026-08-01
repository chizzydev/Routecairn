import { describe, expect, it } from "vitest";
import { normalizeUrl } from "../../src/core/urls/UrlNormalizer.js";

describe("normalizeUrl", () => {
  it("adds https protocol when no protocol is provided", () => {
    expect(normalizeUrl("example.com")).toBe("https://example.com/");
  });

  it("removes fragments and default ports", () => {
    expect(normalizeUrl("https://Example.com:443/a#section")).toBe("https://example.com/a");
  });

  it("sorts query parameters", () => {
    expect(normalizeUrl("https://example.com/search?b=2&a=1")).toBe("https://example.com/search?a=1&b=2");
  });

  it("resolves relative URLs against a base URL", () => {
    expect(normalizeUrl("/api/users", "https://example.com/app/")).toBe("https://example.com/api/users");
  });
});
