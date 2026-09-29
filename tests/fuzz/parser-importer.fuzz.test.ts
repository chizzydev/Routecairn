import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { protocolSecurityInputSchema } from "../../src/modules/protocolSecurity/ProtocolSecurityPlanner.js";
import { compileSafeInventoryImport, safeInventoryImportInputSchema } from "../../src/intelligence/inventory/SafeInventoryImporter.js";

const runs = Number(process.env.ROUTECAIRN_FUZZ_RUNS ?? 750);
const seed = Number(process.env.ROUTECAIRN_FUZZ_SEED ?? 10_202_609);
const jsonValue = fc.jsonValue({ maxDepth: 5 });

describe("bounded parser and importer fuzzing", () => {
  it("keeps public manifest parsers total for arbitrary JSON trees", () => {
    fc.assert(fc.property(jsonValue, (value) => {
      expect(() => protocolSecurityInputSchema.safeParse(value)).not.toThrow();
      expect(() => safeInventoryImportInputSchema.safeParse(value)).not.toThrow();
    }), { numRuns: runs, seed });
  });

  it("compiles generated OpenAPI documents within declared route budgets", () => {
    const safeSegment = fc.stringMatching(/^[a-z][a-z0-9_-]{0,15}$/);
    const method = fc.constantFrom("get", "head", "options", "post", "put", "patch", "delete");
    fc.assert(fc.property(
      fc.integer({ min: 1, max: 20 }),
      fc.array(fc.tuple(safeSegment, method), { minLength: 1, maxLength: 60 }),
      (maxRoutes, entries) => {
        const paths = Object.fromEntries(entries.map(([segment, verb]) => [`/${segment}`, { [verb]: { responses: { "200": { description: "ok" } } } }]));
        const input = safeInventoryImportInputSchema.parse({
          maxRoutes,
          sources: [{ id: "fuzz-openapi", kind: "OPENAPI", document: { openapi: "3.1.0", servers: [{ url: "https://api.example.test" }], paths } }]
        });
        const result = compileSafeInventoryImport(input, "https://api.example.test");
        expect(result.summary.routes).toBeLessThanOrEqual(maxRoutes);
        expect(result.summary.blockedMutations).toBeGreaterThanOrEqual(entries.filter(([, verb]) => ["post", "put", "patch", "delete"].includes(verb)).length === 0 ? 0 : 1);
        for (const route of result.apiGraphql?.restCases ?? []) {
          expect(new URL(route.request.url).origin).toBe("https://api.example.test");
          expect(["GET", "HEAD", "OPTIONS"]).toContain(route.request.method);
        }
      }
    ), { numRuns: Math.max(200, Math.floor(runs / 2)), seed: seed + 1 });
  });

  it("rejects unknown protocol discriminators regardless of surrounding data", () => {
    fc.assert(fc.property(jsonValue, fc.string().filter((value) => !["WEBSOCKET", "SSE", "GRPC_UNARY"].includes(value)), (noise, kind) => {
      const parsed = protocolSecurityInputSchema.safeParse({
        actors: [{ id: "actor", safeAlias: "actor", authSlot: "anonymous", relationship: "none" }],
        cases: [{ ...(typeof noise === "object" && noise !== null && !Array.isArray(noise) ? noise : {}), id: "case", label: "case", actorId: "actor", kind }]
      });
      expect(parsed.success).toBe(false);
    }), { numRuns: runs, seed: seed + 2 });
  });
});
