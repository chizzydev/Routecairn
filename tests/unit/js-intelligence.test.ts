import { describe, expect, it } from "vitest";
import { JsEndpointExtractor } from "../../src/modules/jsIntelligence/JsEndpointExtractor.js";
import { PublicConfigAnalyzer } from "../../src/modules/jsIntelligence/PublicConfigAnalyzer.js";
import { ScriptExtractor } from "../../src/modules/jsIntelligence/ScriptExtractor.js";
import { SourceMapDetector } from "../../src/modules/jsIntelligence/SourceMapDetector.js";

describe("JavaScript intelligence helpers", () => {
  it("extracts and resolves script URLs", () => {
    const extractor = new ScriptExtractor();

    expect(
      extractor.extract('<script src="/assets/app.js"></script><script src="https://cdn.example.net/app.js"></script>', "https://example.com/")
    ).toEqual(["https://example.com/assets/app.js", "https://cdn.example.net/app.js"]);
  });

  it("extracts endpoints, URLs, websocket URLs, and cloud references", () => {
    const extractor = new JsEndpointExtractor();
    const result = extractor.extract(`
      const api = "/api/private-from-js";
      const admin = "/admin/settings";
      const absolute = "https://example.com/api/absolute";
      const ws = "wss://example.com/realtime";
      const bucket = "assets.cloudfront.net";
    `);

    expect(result.endpoints).toEqual(expect.arrayContaining(["/api/private-from-js", "/admin/settings"]));
    expect(result.absoluteUrls).toEqual(["https://example.com/api/absolute"]);
    expect(result.websocketUrls).toEqual(["wss://example.com/realtime"]);
    expect(result.cloudReferences).toEqual(["assets.cloudfront.net"]);
  });

  it("classifies public frontend variables without treating them as secrets", () => {
    const analyzer = new PublicConfigAnalyzer();
    const values = analyzer.analyze('const NEXT_PUBLIC_API_BASE = "https://example.com/api"; const baseURL = "/api";');

    expect(values).toEqual(
      expect.arrayContaining([
        {
          name: "NEXT_PUBLIC_API_BASE",
          valuePreview: "https://example.com/api",
          classification: "public-frontend-config"
        },
        {
          name: "baseURL",
          valuePreview: "/api",
          classification: "config-looking-value"
        }
      ])
    );
  });

  it("detects source map references", () => {
    const detector = new SourceMapDetector();

    expect(detector.detect('console.log("ok");\n//# sourceMappingURL=app.js.map', "https://example.com/assets/app.js")).toEqual([
      "https://example.com/assets/app.js.map"
    ]);
  });

  it("does not guess a .map companion when JavaScript has no explicit reference", () => {
    expect(new SourceMapDetector().detect('console.log("no map");', "https://example.com/assets/app.js")).toEqual([]);
  });
});
