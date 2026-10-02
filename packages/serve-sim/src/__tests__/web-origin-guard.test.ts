import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { execFileSync } from "child_process";
import { createServer, request, type IncomingMessage } from "http";
import type { AddressInfo } from "net";
import { startLoopbackCdpServer } from "../cdp-bridge";
import { simMiddleware } from "../middleware";
import { createRequestGuard, hostsForBindAddress } from "../request-guard";
import { servePreview, type PreviewServer } from "../runtime";

// Web-origin attack surface of the local server: DNS rebinding (foreign Host),
// cross-origin WebSockets and form posts, token leakage, and CORS.

const TOKEN = "guard-test-token";
const UDID = "11111111-2222-3333-4444-555555555555";

// The preview HTML is normally inlined at build time.
(globalThis as { __PREVIEW_HTML_B64__?: string }).__PREVIEW_HTML_B64__ = Buffer.from(
  "<html><!--__SIM_PREVIEW_CONFIG__--></html>",
).toString("base64");

let server: PreviewServer;
let port: number;

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const probe = createServer();
    probe.listen(0, "127.0.0.1", () => {
      const { port: free } = probe.address() as AddressInfo;
      probe.close(() => resolve(free));
    });
  });
}

beforeAll(async () => {
  port = await freePort();
  // The real standalone server: under `bun test` raw upgrade responses only
  // flush through servePreview's front socket.
  server = await servePreview({
    port,
    middleware: simMiddleware({ basePath: "/", execToken: TOKEN }),
    host: "127.0.0.1",
  });
});

afterAll(() => {
  server?.stop(true);
});

/** Raw request so the Host / Origin headers can be forged (fetch forbids it). */
function raw(
  path: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<{ status: number; headers: IncomingMessage["headers"]; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port, path, method: opts.method ?? "GET", headers: opts.headers },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      },
    );
    req.on("error", reject);
    req.end(opts.body);
  });
}

/** Attempt a WebSocket upgrade; resolves to the HTTP status the server answered with. */
function upgrade(path: string, headers: Record<string, string> = {}): Promise<number> {
  return new Promise((resolve) => {
    const req = request({
      host: "127.0.0.1",
      port,
      path,
      headers: {
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        ...headers,
      },
    });
    req.on("upgrade", (res, socket) => {
      socket.destroy();
      resolve(res.statusCode ?? 101);
    });
    req.on("response", (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on("error", () => resolve(0));
    req.end();
  });
}

describe("Host allowlist (DNS rebinding)", () => {
  test("a foreign Host header gets 403 on every kind of route", async () => {
    const headers = { Host: `evil.example:${port}` };
    for (const path of ["/", "/api", "/api/events", "/grid/api", `/helper/${UDID}/config`, "/devtools", "/not-a-route"]) {
      expect((await raw(path, { headers })).status).toBe(403);
    }
    expect((await raw("/exec", { method: "POST", headers })).status).toBe(403);
  });

  test("a foreign Host header is refused on WebSocket upgrades", async () => {
    const headers = { Host: `evil.example:${port}` };
    // node:http path: `bun test` cannot flush the raw 403 (see below).
    expect([0, 403]).toContain(await upgrade("/exec-ws", headers));
    expect(await upgrade(`/helper/${UDID}/ws?token=${TOKEN}`, headers)).toBe(403);
  });

  test("loopback names on the bound port are accepted, other ports are not", async () => {
    for (const host of [`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`]) {
      expect((await raw("/api", { headers: { Host: host } })).status).toBe(200);
    }
    expect((await raw("/api", { headers: { Host: "localhost:1" } })).status).toBe(403);
    expect((await raw("/api", { headers: { Host: "localhost" } })).status).toBe(403);
  });

  test("configured hosts are accepted; a wildcard bind admits local addresses, not arbitrary names", () => {
    const guard = createRequestGuard({ allowedHosts: ["sim.example.dev", ...hostsForBindAddress("0.0.0.0")] });
    const req = (host: string) => ({ headers: { host }, method: "GET", socket: { localPort: 3200 } }) as unknown as IncomingMessage;
    expect(guard.check(req("sim.example.dev"))).toBeNull();
    expect(guard.check(req("127.0.0.1:3200"))).toBeNull();
    expect(guard.check(req("evil.example:3200"))).toBe("Host not allowed");
    expect(guard.check(req("0.0.0.0:3200"))).toBe("Host not allowed");
  });
});

describe("Origin check", () => {
  test("a cross-origin WebSocket upgrade is refused, including from another localhost port", async () => {
    for (const origin of ["http://evil.example", `http://localhost:${port + 1}`, `http://127.0.0.1:${port + 1}`, "null"]) {
      expect(await upgrade(`/helper/${UDID}/ws?token=${TOKEN}`, { Origin: origin })).toBe(403);
      // The exec socket is refused through node:http, whose raw 403 `bun test`
      // cannot flush — there the refusal shows up as a dropped connection.
      expect([0, 403]).toContain(await upgrade("/exec-ws", { Origin: origin }));
      expect(await upgrade(`/devtools/page/x?token=${TOKEN}`, { Origin: origin })).toBe(403);
    }
  });

  test("the same-origin exec socket still upgrades", async () => {
    expect(await upgrade("/exec-ws", { Origin: `http://127.0.0.1:${port}` })).toBe(101);
    expect(await upgrade("/exec-ws")).toBe(101);
  });

  test("cross-origin state-changing requests are refused even with the token", async () => {
    for (const path of ["/grid/api/start", "/grid/api/shutdown", "/devtools/release", "/devtools/highlight", "/exec"]) {
      const res = await raw(path, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}`, Origin: "http://evil.example" },
        body: "{}",
      });
      expect(res.status).toBe(403);
    }
  });

  test("cross-site sub-resource loads are refused, navigations are not", async () => {
    const crossSite = { "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors" };
    expect((await raw("/devtools", { headers: crossSite })).status).toBe(403);
    expect((await raw(`/helper/${UDID}/stream.mjpeg`, { headers: crossSite })).status).toBe(403);
    expect((await raw("/", { headers: { "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate" } })).status).toBe(200);
  });
});

describe("session token", () => {
  test("the preview page carries the token; /api and /api/events do not", async () => {
    expect((await raw("/")).body).toContain(TOKEN);

    const api = await raw("/api");
    expect(api.status).toBe(200);
    expect(api.body).not.toContain(TOKEN);
    expect(api.body).not.toContain("execToken");

    const events = await new Promise<string>((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port, path: "/api/events" }, (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
          if (body.includes("data: ")) {
            req.destroy();
            resolve(body);
          }
        });
      });
      req.on("error", reject);
      req.end();
    });
    expect(events).not.toContain(TOKEN);
    expect(events).not.toContain("execToken");
  });

  test("the input and DevTools sockets require the token", async () => {
    expect(await upgrade(`/helper/${UDID}/ws`)).toBe(401);
    expect(await upgrade(`/helper/${UDID}/ws?token=wrong`)).toBe(401);
    expect(await upgrade("/devtools/page/x")).toBe(401);
    expect(await upgrade(`/helper/${UDID}/ws?token=${TOKEN}`)).toBe(101);
  });

  test("grid start/shutdown and DevTools routes require the token and a JSON body", async () => {
    const body = JSON.stringify({ udid: UDID });
    for (const path of ["/grid/api/start", "/grid/api/shutdown", "/devtools/release", "/devtools/highlight"]) {
      const json = { "Content-Type": "application/json" };
      expect((await raw(path, { method: "POST", headers: json, body })).status).toBe(401);
      expect((await raw(path, { method: "POST", headers: { ...json, Authorization: "Bearer wrong" }, body })).status).toBe(401);
      // CSRF "simple" form post: no preflight, so it must be refused on type alone.
      expect((await raw(path, {
        method: "POST",
        headers: { "Content-Type": "text/plain", Authorization: `Bearer ${TOKEN}` },
        body,
      })).status).toBe(415);
    }
    expect((await raw("/devtools")).status).toBe(401);
  });

  test("the host exec route refuses commands outside the allowlist", async () => {
    const res = await raw("/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ command: "id" }),
    });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toMatchObject({ stdout: "", exitCode: 126 });
  });
});

describe("CORS", () => {
  test("no route sends Access-Control-Allow-Origin", async () => {
    const origin = { Origin: `http://127.0.0.1:${port}` };
    for (const path of ["/", "/api", "/grid/api/memory", `/helper/${UDID}/config`, `/helper/${UDID}/stream.mjpeg`, `/helper/${UDID}/camera/status`]) {
      const res = await raw(path, { headers: origin });
      expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    }
  });
});

function firstBootedSimulator(): string | null {
  try {
    const out = execFileSync("xcrun", ["simctl", "list", "devices", "booted", "-j"], { encoding: "utf-8" });
    const data = JSON.parse(out) as { devices: Record<string, Array<{ udid: string; state: string }>> };
    return Object.values(data.devices).flat().find((device) => device.state === "Booted")?.udid ?? null;
  } catch {
    return null;
  }
}

const bootedUdid = firstBootedSimulator();

(bootedUdid ? describe : describe.skip)("stream endpoints on a booted simulator", () => {
  test("screen and config responses carry no CORS headers", async () => {
    for (const path of ["config", "stream.mjpeg", "stream.mjpeg?raw=1", "stream.avcc", "ax", "foreground"]) {
      const headers = await new Promise<IncomingMessage["headers"]>((resolve, reject) => {
        const req = request({ host: "127.0.0.1", port, path: `/helper/${bootedUdid}/${path}` }, (res) => {
          resolve(res.headers);
          req.destroy();
        });
        req.on("error", reject);
        req.end();
      });
      expect(headers["access-control-allow-origin"]).toBeUndefined();
    }
  }, 30_000);
});

describe("CDP bridge", () => {
  test("listens on loopback only and refuses web origins", async () => {
    const cdpPort = 9390 + Math.floor(Math.random() * 100);
    const bridge = await startLoopbackCdpServer(cdpPort);
    try {
      const listeners = execFileSync("lsof", ["-nP", `-iTCP:${cdpPort}`, "-sTCP:LISTEN"], { encoding: "utf-8" })
        .split("\n")
        .filter((line) => line.includes("(LISTEN)"));
      expect(listeners.length).toBe(1);
      expect(listeners[0]).toContain(`127.0.0.1:${cdpPort}`);
      expect(listeners[0]).not.toContain("*:");

      const local = await fetch(`http://127.0.0.1:${cdpPort}/json/version`);
      expect(local.status).toBe(200);
      const fromWeb = await fetch(`http://127.0.0.1:${cdpPort}/json/list`, { headers: { Origin: "http://evil.example" } });
      expect(fromWeb.status).toBe(403);
      const rebound = await new Promise<number>((resolve, reject) => {
        const req = request(
          { host: "127.0.0.1", port: cdpPort, path: "/json/list", headers: { Host: `evil.example:${cdpPort}` } },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on("error", reject);
        req.end();
      });
      expect(rebound).toBe(403);
    } finally {
      bridge.stop();
    }
  }, 30_000);
});
