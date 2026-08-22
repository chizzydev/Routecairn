import { describe, expect, it } from "vitest";
import { parseApiMessage, workerProtocolVersion } from "../../../src/dashboard/worker/ScanWorkerProtocol.js";

describe("controlled mutation recovery worker protocol", () => {
  it("accepts a bounded recovery command with an exact case and bundle", () => {
    const message = { protocolVersion: workerProtocolVersion, type: "RECOVER_MUTATION", workerId: "00000000-0000-4000-8000-000000000001", jobId: "00000000-0000-4000-8000-000000000002", sequence: 2, expiresAt: "2099-01-01T00:00:00.000Z", nonce: "1234567890123456", caseId: "role-case-1", bundlePath: "C:/journal/role-case-1.recovery.enc", hmac: "a".repeat(64) };
    expect(() => parseApiMessage(message)).not.toThrow();
  });

  it("rejects recovery commands with traversal bundle paths", () => {
    expect(() => parseApiMessage({ protocolVersion: workerProtocolVersion, type: "RECOVER_MUTATION", workerId: "00000000-0000-4000-8000-000000000001", jobId: "00000000-0000-4000-8000-000000000002", sequence: 2, expiresAt: "2099-01-01T00:00:00.000Z", nonce: "1234567890123456", caseId: "role-case-1", bundlePath: "../role-case-1.recovery.enc", hmac: "a".repeat(64) })).toThrow();
  });
});
