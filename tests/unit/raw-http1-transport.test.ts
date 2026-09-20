import { createServer, type Server } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sendRawHttp1 } from "../../src/core/http/RawHttp1Transport.js";

let server: Server;
let origin = "";

beforeAll(async () => {
  server = createServer((socket) => {
    socket.on("data", () => {
      socket.end("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirstHTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nproof!");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("TEST_SERVER_ADDRESS_MISSING");
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => { await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); });

describe("raw HTTP/1 transport", () => {
  it("retains bounded response metadata for an ambiguous framing exchange", async () => {
    const response = await sendRawHttp1({
      url: `${origin}/probe`, method: "POST", headers: { "Content-Type": "text/plain" }, body: "fixture", sentinelPath: "/sentinel", marker: "proof!", variant: "CL_TE", timeoutMs: 1000, maxResponseBytes: 8192, userAgent: "RouteCairn/Test", targetOrigin: origin
    });
    expect(response.responseCount).toBe(2);
    expect(response.statusCodes).toEqual([200, 200]);
    expect(response.markerObserved).toBe(true);
    expect(response.transmittedRequests).toBe(2);
    expect(response.bodyPreview).toContain("proof!");
  });
});
