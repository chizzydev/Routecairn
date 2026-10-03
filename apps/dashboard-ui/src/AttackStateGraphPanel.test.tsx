// @vitest-environment jsdom
import React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { AttackStateGraphPanel, type AttackStateGraphView } from "./AttackStateGraphPanel";

afterEach(cleanup);
describe("attack graph review", () => {
  it("shows source-to-consumer relationships and exact evidence for the selected path", async () => {
    const graph = fixture();
    graph.nodes = [{ id: "source", kind: "OPERATION", label: "Read original state" }, { id: "consumer", kind: "OPERATION", label: "Restore original state" }];
    graph.edges = [{ id: "dependency", kind: "CONSUMES", from: "consumer", to: "source", stateChanging: true }];
    graph.paths[0] = { ...graph.paths[0]!, label: "Wallet recovery", nodeIds: ["source", "consumer"], edgeIds: ["dependency"], evidence: [{ producer: "business-invariant", strength: "EXACT_EXECUTED_CONTRACT", fingerprint: "a".repeat(64) }], sourceCaseFingerprints: ["b".repeat(64)] };
    render(<AttackStateGraphPanel graph={graph} />);
    await userEvent.click(screen.getByText("Inspect path Wallet recovery"));
    expect(screen.getByText("Restore original state → CONSUMES → Read original state (state-changing)")).toBeTruthy();
    expect(screen.getByText("a".repeat(64))).toBeTruthy();
    expect(screen.getByText("b".repeat(64))).toBeTruthy();
  });

  it("allows all bounded paths to be paged and filtered", async () => {
    render(<AttackStateGraphPanel graph={fixture()} />);
    await userEvent.click(screen.getByRole("button", { name: "Next paths" }));
    expect(screen.getByText(/Showing 51–60 of 60/)).toBeTruthy();
    await userEvent.selectOptions(screen.getByLabelText("Path mutability"), "READ_ONLY");
    expect(screen.queryByRole("button", { name: "Next paths" })).toBeNull();
    expect(screen.getAllByText("READ_ONLY_AUTO_COMPILE_CANDIDATE")).toHaveLength(30);
    await userEvent.type(screen.getByLabelText("Search graph paths"), "route-59");
    expect(screen.getByText("route-59")).toBeTruthy();
    expect(screen.queryByText("route-57")).toBeNull();
  });
});
function fixture(): AttackStateGraphView {
  return { graphFingerprint: "c".repeat(64), bounds: { maxNodes: 1200, maxEdges: 3000, maxPaths: 500, truncated: false }, coverage: { STATE_CHANGING_PATHS: 30 }, producers: ["business-invariant"], nodes: [], edges: [], paths: Array.from({ length: 60 }, (_, index) => ({ id: String(index), label: `route-${index}`, mutability: index % 2 ? "READ_ONLY" : "STATE_CHANGING", automationState: index % 2 ? "READ_ONLY_AUTO_COMPILE_CANDIDATE" : "STATE_CHANGE_PROPOSED", contractReadiness: "COMPLETE", engineId: "business-invariant", requiredBindings: [] })) };
}
