import { it, expect } from "vitest";
import { hypothesisGenerateSchema } from "../../src/dashboard/contracts/ApplicationHypothesisContracts.js";
const edge = {
  name: "Order authorizes invoice review",
  producer: "order",
  consumer: "invoice",
  identifier: "record.id",
  reference: "record.parent",
  producerVersion: "record.version",
  consumerVersion: "record.version"
};
const input = {
  mapRevisionId: "11111111-1111-4111-8111-111111111111",
  workflow: { name: "Owned order and invoice", routeIds: ["order", "invoice"], relationships: [edge] }
};
it("accepts an explicit evidence-bound producer/consumer declaration in the existing hypothesis contract", () => {
  expect(hypothesisGenerateSchema.safeParse(input).success).toBe(true);
});
it("rejects reversed dependencies, duplicate edges and undeclared routes", () => {
  for (const relationships of [
    [{ ...edge, producer: "invoice", consumer: "order" }],
    [edge, edge],
    [{ ...edge, producer: "missing" }]
  ])
    expect(
      hypothesisGenerateSchema.safeParse({ ...input, workflow: { ...input.workflow, relationships } }).success
    ).toBe(false);
});
it("rejects secret fields and ambiguous versions without broadening observation authority", () => {
  for (const change of [
    { reference: "record.token" },
    { producerVersion: "record.id" },
    { consumerVersion: "record.parent" }
  ])
    expect(
      hypothesisGenerateSchema.safeParse({
        ...input,
        workflow: { ...input.workflow, relationships: [{ ...edge, ...change }] }
      }).success
    ).toBe(false);
});
