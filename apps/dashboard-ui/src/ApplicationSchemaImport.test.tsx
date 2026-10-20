// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@testing-library/react";
import { ApplicationSchemaImport } from "./ApplicationSchemaImport";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
const suggestion = {
  revisionId: "schema-review",
  digest: "d".repeat(64),
  sourceHash: "s".repeat(64),
  candidates: [
    {
      id: "schema-route-1",
      path: "/v2/records/{number}",
      template: "/v2/records/:number",
      method: "GET",
      kind: "OBJECT",
      slots: [{ name: "number", type: "integer" }],
      markers: [
        { path: "record.number", type: "number" },
        { path: "record.workspace", type: "string" }
      ]
    }
  ],
  excluded: [{ method: "DELETE", path: "/v2/records/{number}", reason: "NON_GET_EXCLUDED_NO_AUTHORITY" }]
};
it("keeps upload and inspection inert until explicit chosen slots and markers are completed", async () => {
  const apply = vi.fn();
  vi.mocked(apiMutation).mockResolvedValue(suggestion);
  render(<ApplicationSchemaImport target="owned" disabled={false} onApply={apply} />);
  fireEvent.change(screen.getByLabelText("Local OpenAPI JSON"), {
    target: { files: [{ size: 50, text: async () => '{"openapi":"3.1.0"}' }] }
  });
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Inspect schema suggestions" }) as HTMLButtonElement).disabled).toBe(
      false
    )
  );
  expect(apiMutation).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Inspect schema suggestions" }));
  await screen.findByText(/SCHEMA_SUGGESTED_UNVERIFIED/);
  expect(screen.getByText(/DELETE.*NON_GET_EXCLUDED/)).toBeTruthy();
  expect(apply).not.toHaveBeenCalled();
  fireEvent.click(screen.getByLabelText("Choose /v2/records/{number}"));
  fireEvent.click(screen.getByRole("button", { name: "Use reviewed schema selections" }));
  expect(apply).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText("schema-route-1 slot number"), { target: { value: "42" } });
  fireEvent.change(screen.getByLabelText("schema-route-1 identity marker"), { target: { value: "record.number" } });
  fireEvent.change(screen.getByLabelText("schema-route-1 tenant marker"), { target: { value: "record.workspace" } });
  fireEvent.click(screen.getByRole("button", { name: "Use reviewed schema selections" }));
  expect(apply).toHaveBeenCalledWith(
    [expect.objectContaining({ url: "/v2/records/42", identityPath: "record.number", tenantPath: "record.workspace" })],
    expect.objectContaining({
      revisionId: "schema-review",
      selections: [{ routeId: "schema-route-1", candidateId: "schema-route-1", slots: { number: "42" } }]
    })
  );
  expect(apiMutation).toHaveBeenCalledTimes(1);
});
it("rejects oversize uploads locally and ignores superseded asynchronous file reads", async () => {
  const apply = vi.fn();
  let finish: (value: string) => void = () => {};
  render(<ApplicationSchemaImport target="owned" disabled={false} onApply={apply} />);
  fireEvent.change(screen.getByLabelText("Local OpenAPI JSON"), {
    target: {
      files: [
        {
          size: 50,
          text: () =>
            new Promise<string>((r) => {
              finish = r;
            })
        }
      ]
    }
  });
  fireEvent.change(screen.getByLabelText("Local OpenAPI JSON"), {
    target: { files: [{ size: 262145, text: async () => "bad" }] }
  });
  finish("stale");
  await screen.findByText("Schema exceeds 256 KiB");
  expect((screen.getByRole("button", { name: "Inspect schema suggestions" }) as HTMLButtonElement).disabled).toBe(true);
  expect(apiMutation).not.toHaveBeenCalled();
  expect(apply).not.toHaveBeenCalled();
});
