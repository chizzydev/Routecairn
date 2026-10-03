import { createSocket, type Socket } from "node:dgram";

/** Own the fixture's UDP listener: the QUIC dependency's default dual-stack
 * listener also binds a wildcard IPv6 address regardless of the supplied host. */
export async function bindProtocolFixtureSocket(port = 0): Promise<Socket> {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("PROTOCOL_FIXTURE_PORT_INVALID");
  const socket = createSocket("udp4");
  try {
    await new Promise<void>((accept, reject) => {
      const timer = setTimeout(() => finish(new Error("PROTOCOL_FIXTURE_UDP_STARTUP_TIMEOUT")), 5000);
      let settled = false;
      const finish = (error?: Error) => { if (settled) return; settled = true; clearTimeout(timer); socket.off("error", failed); error ? reject(error) : accept(); };
      const failed = (error: Error) => finish(error);
      socket.once("error", failed);
      socket.bind(port, "127.0.0.1", () => finish());
    });
    if (socket.address().address !== "127.0.0.1") throw new Error("PROTOCOL_FIXTURE_LOOPBACK_REQUIRED");
    return socket;
  } catch (error) { await closeProtocolFixtureSocket(socket); throw error; }
}

export async function closeProtocolFixtureSocket(socket: Socket): Promise<void> {
  await new Promise<void>((accept, reject) => {
    const timer = setTimeout(() => reject(new Error("PROTOCOL_FIXTURE_UDP_CLEANUP_TIMEOUT")), 2000);
    const done = () => { clearTimeout(timer); accept(); };
    try { socket.close(done); }
    catch (error) { clearTimeout(timer); if ((error as NodeJS.ErrnoException).code === "ERR_SOCKET_DGRAM_NOT_RUNNING") accept(); else reject(error); }
  });
}
