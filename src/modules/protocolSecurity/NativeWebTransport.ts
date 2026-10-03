import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { readFile } from "node:fs/promises";
import type { Socket } from "node:dgram";
import quico, { WebTransport } from "quico";

interface QuicConnection {
  close(code: number, reason: string): void;
}
interface SessionInternals {
  _quic: QuicConnection;
  _udpSocket: Socket;
  _h3: unknown;
  _state: string;
  _readyReject(error: Error): void;
  _closedResolve(): void;
  _setupH3Handlers(): void;
  _sendConnect(): void;
}

/** QUICO 0.4.0's WebTransport wrapper drops TLS options. Use its shared
 * verified socket API, with the already approved IP, inside the isolated worker.
 * Fail closed on an unreviewed runtime version or missing API. */
export async function createPinnedWebTransport(input: { hostname: string; port: number; pinnedAddress: string; ca?: string }, path: string): Promise<WebTransport> {
  const directory = dirname(createRequire(import.meta.url).resolve("quico"));
  const metadata = JSON.parse(await readFile(join(directory, "package.json"), "utf8")) as { version?: string };
  if (metadata.version !== "0.4.0") throw new Error("WEBTRANSPORT_RUNTIME_VERSION_UNSUPPORTED");
  const runtime = await import(pathToFileURL(join(directory, "src/h3.js")).href) as { H3Connection: new (options: { quicConnection: QuicConnection; isServer: false; enableWebTransport: true }) => unknown };
  const api = quico as unknown as { createQuicClientSocket?: (options: { remoteIp: string; remotePort: number; hostname: string; rejectUnauthorized: true; ca?: string; onSocket(q: QuicConnection, socket: Socket): void; onConnect(q: QuicConnection, socket: Socket): void; onError(error: Error): void; onClose(): void }) => Socket };
  if (!api.createQuicClientSocket || typeof runtime.H3Connection !== "function") throw new Error("WEBTRANSPORT_RUNTIME_API_UNSUPPORTED");
  class PinnedSession extends WebTransport {
    public _connect(): void {
      const internals = this as unknown as SessionInternals;
      internals._udpSocket = api.createQuicClientSocket!({
        remoteIp: input.pinnedAddress, remotePort: input.port, hostname: input.hostname,
        rejectUnauthorized: true, ...(input.ca ? { ca: input.ca } : {}),
        onSocket: (connection, socket) => { internals._quic = connection; internals._udpSocket = socket; },
        onConnect: (connection, socket) => { internals._quic = connection; internals._udpSocket = socket; internals._h3 = new runtime.H3Connection({ quicConnection: connection, isServer: false, enableWebTransport: true }); internals._setupH3Handlers(); internals._sendConnect(); },
        onError: (error) => { internals._readyReject(error); this.emit("error", error); },
        onClose: () => { internals._state = "closed"; internals._closedResolve(); this.emit("close"); }
      });
    }
  }
  return new PinnedSession(`https://${input.hostname}:${input.port}${path}`, { rejectUnauthorized: true });
}

export function disposePinnedWebTransport(session: WebTransport): void {
  session.close({ closeCode: 0, reason: "bounded-contract-complete" });
  const socket = (session as unknown as SessionInternals)._udpSocket;
  try { socket?.close(); } catch { /* Already closed after QUIC shutdown. */ }
}
