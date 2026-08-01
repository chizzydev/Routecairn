import { describe, expect, it } from "vitest";
import { ScopeMatcher } from "../../src/core/scope/ScopeMatcher.js";
import { exampleScope } from "../../src/config/defaults.js";

describe("ScopeMatcher", () => {
  it("allows same-origin URLs for allowed domains", () => {
    const matcher = new ScopeMatcher("https://example.com", exampleScope);

    expect(matcher.decide("https://example.com/api/users").allowed).toBe(true);
  });

  it("rejects out-of-scope domains", () => {
    const matcher = new ScopeMatcher("https://example.com", exampleScope);
    const decision = matcher.decide("https://attacker.example.net/login");

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("different-origin");
  });

  it("rejects disallowed paths", () => {
    const matcher = new ScopeMatcher("https://example.com", exampleScope);
    const decision = matcher.decide("https://example.com/logout");

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("disallowed-path");
  });

  it("rejects unsafe methods that are not in scope", () => {
    const matcher = new ScopeMatcher("https://example.com", exampleScope);
    const decision = matcher.decide("https://example.com/api/users/1", "DELETE");

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("method-not-allowed");
  });

  it("allows wildcard subdomains when same-origin is disabled", () => {
    const matcher = new ScopeMatcher("https://example.com", {
      ...exampleScope,
      sameOriginOnly: false
    });

    expect(matcher.decide("https://app.example.com/dashboard").allowed).toBe(true);
  });
});
