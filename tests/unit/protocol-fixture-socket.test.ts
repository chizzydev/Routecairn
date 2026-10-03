import { createSocket } from "node:dgram";
import { describe, expect, it } from "vitest";
import { bindProtocolFixtureSocket, closeProtocolFixtureSocket } from "../../src/validation/ProtocolFixtureSocket.js";

describe("owned protocol fixture sockets", () => {
  it("binds only loopback, rejects a conflicting listener and closes the actual socket", async () => {
    const socket = await bindProtocolFixtureSocket();
    const port = socket.address().port;
    try {
      expect(socket.address().address).toBe("127.0.0.1");
      await expect(bindProtocolFixtureSocket(port)).rejects.toMatchObject({ code: "EADDRINUSE" });
    } finally { await closeProtocolFixtureSocket(socket); }
    expect(() => socket.address()).toThrow();
    const reused = await bindProtocolFixtureSocket(port);
    await closeProtocolFixtureSocket(reused);
    await closeProtocolFixtureSocket(reused);
  });
  it("handles cleanup for sockets that never started", async () => {
    const socket = createSocket("udp4");
    await closeProtocolFixtureSocket(socket);
    expect(() => socket.address()).toThrow();
  });
});
