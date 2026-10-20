import { createServer, request } from "node:http";
import { spawn, execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
import { heldOutApplication } from "./heldout-applications.js";
import { heldOutApplicationFixture } from "./heldout-application-fixture.js";
import { windowsProcessBirth } from "../../src/dashboard/worker/WindowsProcessIdentity.js";
import { WorkerProcessCustody } from "../../src/dashboard/worker/WorkerProcessCustody.js";
export async function practicalPythonFixture(mode: "html" | "jsonapi") {
  if (process.platform !== "win32" || !process.env.ROUTECAIRN_WORKER_LAB) throw Error("OWNED_WINDOWS_ONLY");
  const root = createOwnedTestDirectory("python-" + mode),
    exe = execFileSync("py", ["-3", "-c", "import sys;print(sys.executable)"], {
      windowsHide: true,
      encoding: "utf8"
    }).trim();
  const child = spawn(exe, ["-u", resolve("tests/fixtures/practical-sqlite-application.py"), root, mode], {
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"]
  });
  const custody = new WorkerProcessCustody(child, root);
  let stderr = "",
    buffer = "";
  const lines: string[] = [],
    listeners = new Set<() => void>();
  child.stderr.on("data", (b) => (stderr += b));
  child.stdout.on("data", (b) => {
    buffer += b;
    let i;
    while ((i = buffer.indexOf("\n")) >= 0) {
      lines.push(buffer.slice(0, i).trim());
      buffer = buffer.slice(i + 1);
    }
    for (const fn of listeners) fn();
  });
  const next = () =>
    new Promise<string>((yes, no) => {
      const done = () => {
          if (lines.length) {
            clearTimeout(timer);
            listeners.delete(done);
            yes(lines.shift()!);
          }
        },
        timer = setTimeout(() => {
          listeners.delete(done);
          no(Error("PYTHON_CONTROL_TIMEOUT"));
        }, 5000);
      listeners.add(done);
      done();
    });
  try {
    const birth = await windowsProcessBirth(child.pid!, root);
    await custody.bind(birth ?? undefined);
    child.stdin.write("START\n");
    const port = (JSON.parse(await next()) as { port: number }).port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error("PYTHON_PORT");
    const metadata = heldOutApplication("ledger"),
      wire: typeof metadata.wire = [];
    // Shared owned gateway records only method/path/actor/status. All domain routing, SQL and authorization run in Python.
    const server = createServer((req, res) => {
      const actor =
        Object.keys(metadata.actors).find((a) => req.headers.authorization === "Bearer heldout-ledger-" + a) ??
        "anonymous";
      const upstream = request(
        { host: "127.0.0.1", port, path: req.url, method: req.method, headers: req.headers },
        (reply) => {
          wire.push({ method: req.method ?? "", path: req.url ?? "", actor, status: reply.statusCode ?? 0 });
          res.writeHead(reply.statusCode ?? 502, reply.headers);
          reply.pipe(res);
        }
      );
      upstream.on("error", () => {
        res.writeHead(502);
        res.end();
      });
      req.pipe(upstream);
    });
    const app = { ...metadata, server, wire };
    const f = await heldOutApplicationFixture("ledger", true, () => app);
    return {
      ...f,
      async setFixedAsync() {
        child.stdin.write("FIX\n");
        if ((await next()) !== "FIXED") throw Error("PYTHON_FIX_ACK");
      },
      async close() {
        try {
          await f.close();
        } finally {
          child.stdin.end("STOP\n");
          await custody.drain(true);
          writeFileSync(
            join(root, "PYTHON_NATIVE_CUSTODY.json"),
            JSON.stringify(
              {
                mode,
                exe,
                pid: child.pid,
                receipt: custody.receipt(),
                stderr,
                wire,
                domain: "Python stdlib HTTP and SQLite behind owned recording gateway"
              },
              null,
              2
            ),
            { flag: "wx" }
          );
          retainOwnedTestDirectory(root);
        }
      }
    };
  } catch (error) {
    await custody.terminate();
    await custody.drain();
    writeFileSync(join(root, "PYTHON_FAILURE.json"), JSON.stringify({ receipt: custody.receipt(), stderr }), {
      flag: "wx"
    });
    retainOwnedTestDirectory(root);
    throw error;
  }
}
