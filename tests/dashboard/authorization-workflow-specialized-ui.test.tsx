// @vitest-environment jsdom
import React, { useEffect, useState } from "react";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { routeCairnCapabilityRegistry } from "../../src/core/planning/RouteCairnCapabilityRegistry.js";
import {
  AuthorizationWorkflowStudio,
  workflowCaseDeleteBlockReason,
  workflowForRequest,
  type WorkflowCapability,
  type WorkflowDraft,
  type WorkflowId,
} from "../../apps/dashboard-ui/src/AuthorizationWorkflowStudio";
import { immediateWorkflowDiagnostics } from "../../apps/dashboard-ui/src/WorkflowDiagnostics";
import { authorizationWorkflowConfigurationSchema } from "../../src/dashboard/contracts/ScanStudioSchemas.js";

const capabilities = JSON.parse(
  JSON.stringify(routeCairnCapabilityRegistry().controlledWorkflows),
) as WorkflowCapability[];

afterEach(cleanup);

describe("Authorization Workflow Studio specialized controls", () => {
  it.each(capabilities)("exposes every declared enum for $id", (capability) => {
    render(<Harness only={capability.id} />);
    enable(capability.displayName);
    if (capability.id === "collection-authorization") {
      fireEvent.click(screen.getByRole("button", { name: "Add count expectation" }));
      fireEvent.click(screen.getByRole("button", { name: "Add summary expectation" }));
    }
    if (capability.id === "bulk-authorization") {
      fireEvent.click(screen.getByRole("button", { name: "Add single-object baseline" }));
    }
    let optionValues = allOptionValues();
    for (const [group, values] of Object.entries(capability.guidedOptions)) {
      if (group === "postSafetyMode") continue;
      for (const value of values)
        expect(optionValues, `${capability.id}.${group}.${value}`).toContain(value);
    }
    for (const value of capability.expectationTypes)
      expect(optionValues, `${capability.id}.expectation.${value}`).toContain(value);
    if (capability.id === "bulk-authorization") {
      fireEvent.change(screen.getByLabelText("Request style"), {
        target: { value: "JSON_POST" },
      });
      optionValues = [...new Set([...optionValues, ...allOptionValues()])];
      for (const value of capability.guidedOptions.postSafetyMode ?? [])
        expect(optionValues).toContain(value);
      expect(screen.getByLabelText("Fixed JSON body")).toBeTruthy();
    }
  });

  it("creates all seven core-valid configurations in Guided mode and round-trips Advanced JSON", () => {
    let latest: WorkflowDraft[] = [];
    render(<AllHarness onState={(value) => (latest = value)} />);
    for (const capability of capabilities) enable(capability.displayName);
    expect(latest).toHaveLength(7);
    const before = latest.map((workflow) => workflowForRequest(workflow));
    for (const workflow of before)
      expect(authorizationWorkflowConfigurationSchema.parse(workflow)).toEqual(workflow);
    for (const capability of capabilities) {
      const card = screen.getByRole("heading", { name: capability.displayName }).closest("section")!;
      fireEvent.click(within(card).getByRole("button", { name: "Edit" }));
      const expected = structuredClone(latest.find((item) => item.workflowId === capability.id)!.config);
      fireEvent.click(screen.getByRole("button", { name: "Advanced JSON" }));
      const editor = screen.getByLabelText("Workflow JSON") as HTMLTextAreaElement;
      fireEvent.change(editor, { target: { value: JSON.stringify(expected, null, 2) } });
      fireEvent.click(screen.getByRole("button", { name: "Guided" }));
      expect(latest.find((item) => item.workflowId === capability.id)!.config).toEqual(expected);
    }
    const semantic = JSON.parse(JSON.stringify(before));
    expect(JSON.parse(JSON.stringify(before))).toEqual(semantic);
    expect(JSON.stringify(before)).not.toContain("ui-case-");
  });

  it("creates and removes Bulk baseline and pre/post structures without Advanced JSON", () => {
    let latest: WorkflowDraft[] = [];
    render(<Harness only="bulk-authorization" onState={(value) => (latest = value)} />);
    enable("Bulk Authorization");
    fireEvent.click(screen.getByRole("button", { name: "Add single-object baseline" }));
    expect(screen.getByText("Single-object baseline")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Add pre/postcondition check" }));
    expect(screen.getByText(/captured before POST and repeated after POST/i)).toBeTruthy();
    const workflow = latest[0];
    expect(workflow?.workflowId).toBe("bulk-authorization");
    if (workflow?.workflowId !== "bulk-authorization") return;
    expect(workflow.config.definitions[0]!.cases[0]!.objects[0]!.baseline).toBeTruthy();
    expect(workflow.config.definitions[0]!.cases[0]!.postconditionChecks).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Remove baseline" }));
    fireEvent.click(screen.getByRole("button", { name: "Remove pre/postcondition check" }));
    expect(workflowForRequest(latest[0]!).config).not.toHaveProperty("uiCaseIds");
  });

  it("invalid Bulk JSON is blocking and cannot retain the previous executable body", () => {
    let latest: WorkflowDraft[] = [];
    render(<Harness only="bulk-authorization" onState={(value) => (latest = value)} />);
    enable("Bulk Authorization");
    fireEvent.change(screen.getByLabelText("Request style"), {
      target: { value: "JSON_POST" },
    });
    fireEvent.change(screen.getByLabelText("Fixed JSON body"), {
      target: { value: '{"objectIds": {{ executable }}' },
    });
    expect(screen.getByRole("alert").textContent).toContain("Enter valid JSON");
    const workflow = latest[0];
    if (workflow?.workflowId !== "bulk-authorization") throw new Error("missing bulk workflow");
    expect(workflow.config.definitions[0]!.cases[0]!.bodyTemplate).toEqual({ invalidGuidedBody: true });
  });

  it("creates signed URL controls and reports unsafe file inputs inline", () => {
    let latest: WorkflowDraft[] = [];
    render(<Harness only="file-authorization" onState={(value) => (latest = value)} />);
    enable("File and Download Authorization");
    fireEvent.change(screen.getByLabelText("Content proof mode"), {
      target: { value: "SIGNED_URL_ONLY" },
    });
    fireEvent.click(screen.getByLabelText("Explicitly follow one signed URL"));
    expect(screen.getByText("Signed URL follow enabled.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Exact file reference"), {
      target: { value: "../secret.pdf" },
    });
    const workflow = latest[0];
    if (workflow?.workflowId !== "file-authorization") throw new Error("missing file workflow");
    expect(immediateWorkflowDiagnostics(workflow).map((item) => item.code)).toContain("WORKFLOW_FILE_REFERENCE_UNSAFE");
  });

  it("keeps UI case identity stable and blocks referenced-case deletion", () => {
    let latest: WorkflowDraft[] = [];
    const view = render(<Harness only="equivalent-route" onState={(value) => (latest = value)} />);
    enable("Equivalent Route Authorization");
    const ids = [...view.container.querySelectorAll("[data-ui-case-id]")].map((node) => node.getAttribute("data-ui-case-id"));
    fireEvent.click(screen.getByRole("button", { name: "Move case 2 up" }));
    const moved = [...view.container.querySelectorAll("[data-ui-case-id]")].map((node) => node.getAttribute("data-ui-case-id"));
    expect(moved).toEqual([ids[1], ids[0]]);
    const workflow = latest[0];
    if (workflow?.workflowId !== "equivalent-route") throw new Error("missing route workflow");
    expect(
      [0, 1].map((index) => workflowCaseDeleteBlockReason(workflow, index)).filter(Boolean),
    ).toEqual(expect.arrayContaining([expect.stringMatching(/reference|canonical/i)]));
    const request = workflowForRequest(workflow) as unknown as Record<string, unknown>;
    expect(JSON.stringify(request)).not.toContain("ui-case-");
  });

  it("publishes complete guided coverage with no unclassified ordinary fields", () => {
    for (const capability of capabilities) {
      expect(capability.guidedFieldCoverage.length).toBeGreaterThan(10);
      expect(capability.advancedOnlyFields).toEqual([]);
      expect(capability.dashboardSupport).toBe("FULL_DASHBOARD_PARITY");
    }
  });
});

function allOptionValues(): string[] {
  return [...document.querySelectorAll("option")].map((option) => (option as HTMLOptionElement).value);
}

function enable(name: string): void {
  const card = screen.getByRole("heading", { name }).closest("section");
  if (!card) throw new Error(`missing ${name}`);
  fireEvent.click(within(card).getByRole("button", { name: "Enable and add first case" }));
}

function Harness({ only, onState }: { only: WorkflowId; onState?(value: WorkflowDraft[]): void }) {
  const [workflows, setWorkflows] = useState<WorkflowDraft[]>([]);
  useEffect(() => {
    onState?.(workflows);
  }, [workflows, onState]);
  return <AuthorizationWorkflowStudio workflows={workflows} capabilities={capabilities.filter((item) => item.id === only)} selectedModules={capabilities.map((item) => item.moduleId)} target="https://app.example.test" principalA="principal-a" principalB="principal-b" onChange={setWorkflows} onEnableModule={() => undefined} onPreview={async () => undefined} />;
}

function AllHarness({ onState }: { onState(value: WorkflowDraft[]): void }) {
  const [workflows, setWorkflows] = useState<WorkflowDraft[]>([]);
  useEffect(() => {
    onState(workflows);
  }, [workflows, onState]);
  return <AuthorizationWorkflowStudio workflows={workflows} capabilities={capabilities} selectedModules={capabilities.map((item) => item.moduleId)} target="https://app.example.test" principalA="principal-a" principalB="principal-b" onChange={setWorkflows} onEnableModule={() => undefined} onPreview={async () => undefined} />;
}
