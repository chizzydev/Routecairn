// @vitest-environment jsdom
import React, { useState } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthorizationWorkflowStudio, type WorkflowCapability, type WorkflowDraft, type WorkflowId } from "../../apps/dashboard-ui/src/AuthorizationWorkflowStudio";

const definitions: Array<[WorkflowId, string, string]> = [
  ["object-pair", "Object Pair Authorization", "object-pair-testing"],
  ["field-exposure", "Field Exposure Authorization", "field-exposure-testing"],
  ["authorization-matrix", "Role and State Authorization Matrix", "authorization-matrix-testing"],
  ["equivalent-route", "Equivalent Route Authorization", "equivalent-route-testing"],
  ["collection-authorization", "Collection and Listing Authorization", "collection-authorization-testing"],
  ["bulk-authorization", "Bulk Authorization", "bulk-authorization-testing"],
  ["file-authorization", "File and Download Authorization", "file-authorization-testing"]
];

const capabilities: WorkflowCapability[] = definitions.map(([id, displayName, moduleId]) => ({ id, displayName, moduleId, description: `${displayName} controlled editor`, requiresAccountPair: true, requiresVerifiedIdentity: true, safeMethods: id === "bulk-authorization" ? ["GET", "POST"] : ["GET", "HEAD"], supportedActors: ["OWNER", "NON_OWNER", "PUBLIC"], expectationTypes: ["MUST_ALLOW", "MUST_DENY", "OBSERVE_ONLY"], limits: { maxCases: 20 }, safetyNotes: ["Only exact operator-supplied cases execute."] }));
afterEach(() => cleanup());

describe("Authorization Workflow Studio UI", () => {
  it("derives all seven workflow choices from capability metadata", () => {
    render(<Harness />);
    for (const [, name] of definitions) expect(screen.getByRole("heading", { name })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Enable and add first case" })).toHaveLength(7);
  });

  it.each(definitions)("creates a guided %s configuration with an explicit case", (id, name) => {
    render(<Harness />);
    const card = screen.getByRole("heading", { name }).closest("section")!;
    fireEvent.click(within(card).getByRole("button", { name: "Enable and add first case" }));
    expect(screen.getByRole("region", { name: `${name} editor` })).toBeTruthy();
    expect(screen.getByText(/\d+ configured case/)).toBeTruthy();
    expect(screen.getByText(/No discovery or enumeration occurs/)).toBeTruthy();
    expect(screen.getAllByDisplayValue(/exact-|declare-account|https:\/\/app\.example\.test/i).length).toBeGreaterThan(0);
    expect(id).toBeTruthy();
  });

  it("duplicates, reorders, and deletes cases without generating target-derived cases", () => {
    render(<Harness />);
    fireEvent.click(screen.getAllByRole("button", { name: "Enable and add first case" })[0]!);
    fireEvent.click(screen.getByRole("button", { name: "Duplicate" }));
    expect(screen.getByText("2 configured case(s)")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Delete" })).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Move case 2 up" }));
    fireEvent.click(screen.getAllByRole("button", { name: "Delete" })[1]!);
    expect(screen.getByText("1 configured case(s)")).toBeTruthy();
  });

  it("keeps disabled cases visible and can re-enable them", () => {
    render(<Harness />);
    fireEvent.click(screen.getAllByRole("button", { name: "Enable and add first case" })[0]!);
    fireEvent.click(screen.getByRole("button", { name: "Disable case" }));
    expect(screen.getByText(/Case 1 - Disabled/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Enable case" }));
    expect(screen.getByText(/Case 1 - Enabled/)).toBeTruthy();
  });

  it("keeps invalid advanced JSON visible and blocks prototype-pollution input", () => {
    render(<Harness />);
    fireEvent.click(screen.getAllByRole("button", { name: "Enable and add first case" })[0]!);
    fireEvent.click(screen.getByRole("button", { name: "Advanced JSON" }));
    const editor = screen.getByLabelText("Workflow JSON");
    fireEvent.change(editor, { target: { value: "{not-json" } });
    expect(screen.getByText(/WORKFLOW_ADVANCED_JSON_INVALID/)).toBeTruthy();
    expect((editor as HTMLTextAreaElement).value).toBe("{not-json");
    fireEvent.change(editor, { target: { value: '{"__proto__":{"polluted":true}}' } });
    expect(screen.getByText(/prototype-related keys are forbidden/)).toBeTruthy();
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
  });

  it("imports bounded JSON, preserves advanced mode, and invokes real-preview callback", async () => {
    const preview = vi.fn(async () => undefined);
    render(<Harness onPreview={preview} />);
    fireEvent.click(screen.getAllByRole("button", { name: "Enable and add first case" })[0]!);
    fireEvent.click(screen.getByRole("button", { name: "Advanced JSON" }));
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    const current = (screen.getByLabelText("Workflow JSON") as HTMLTextAreaElement).value;
    fireEvent.change(input, { target: { files: [new File([JSON.stringify({ workflowId: "object-pair", schemaVersion: 1, config: JSON.parse(current) })], "workflow.json", { type: "application/json" })] } });
    await waitFor(() => expect(screen.getByText(/Imported configuration/)).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Preview / Validate" }));
    expect(preview).toHaveBeenCalledOnce();
  });
});

function Harness({ onPreview = async () => undefined }: { onPreview?: () => Promise<void> }) {
  const [workflows, setWorkflows] = useState<WorkflowDraft[]>([]);
  const [modules, setModules] = useState<string[]>([]);
  return <AuthorizationWorkflowStudio workflows={workflows} capabilities={capabilities} selectedModules={modules} target="https://app.example.test" principalA="principal-a" principalB="principal-b" onChange={setWorkflows} onEnableModule={(moduleId) => setModules((current) => [...current, moduleId])} onPreview={onPreview} />;
}
