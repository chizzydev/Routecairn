// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ScanCancellationNotice } from "./ScanCancellationNotice";

describe("ScanCancellationNotice", () => {
  afterEach(cleanup);
  it("explains restoration grace while cancellation is active", () => {
    render(<ScanCancellationNotice status="CANCEL_REQUESTED" hasArtifacts={false} onRecovery={() => undefined} />);
    expect(screen.getByRole("status").textContent).toContain("restoration");
    expect(screen.getByRole("status").textContent).toContain("15-second");
  });
  it("keeps partial artifacts and recovery actionable", () => {
    const recover = vi.fn();
    render(<ScanCancellationNotice status="INTERRUPTED" hasArtifacts onRecovery={recover} />);
    expect(screen.getByRole("status").textContent).toContain("Partial reports");
    screen.getByRole("button", { name: "Offensive Safety recovery" }).click();
    expect(recover).toHaveBeenCalledOnce();
  });
});
