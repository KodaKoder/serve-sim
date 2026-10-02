import { Server as HttpServerClass, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "http";
import { Server as NetServer, type AddressInfo } from "net";
import type { Duplex } from "stream";

// Loopback-only wrapper around inspect-webkit's CDP bridge.
//
// inspect-webkit rewrites a requested host of 127.0.0.1 / localhost / ::1 to
// the wildcard `::` (dual-stack), so the bridge — which gives full debugger
// control over every inspectable page in the simulator, with no
// authentication — ends up listening on all interfaces. It exposes no option
// to prevent that, so the bind is corrected at the one place it happens: the
// `listen()` call for the port we asked for. The same hook hands us the HTTP
// server, which lets the bridge refuse browser-originated and DNS-rebound
// requests as well; only this process's own proxy (and other local tools that
// send no Origin) can talk to it.

const LOOPBACK_HOST = /^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i;

/** True for requests a local, non-web client would send to the bridge. */
function isLocalCdpRequest(req: IncomingMessage): boolean {
  const host = req.headers.host;
  if (typeof host !== "string" || !LOOPBACK_HOST.test(host)) return false;
  const origin = req.headers.origin;
  // Web pages always send an Origin on WebSocket upgrades. Chrome's own
  // DevTools frontend is the one browser origin that may attach directly.
  return origin === undefined || origin === "devtools://devtools";
}

function guardCdpServer(server: HttpServer): void {
  const requestListeners = server.listeners("request") as Array<(req: IncomingMessage, res: ServerResponse) => void>;
  const upgradeListeners = server.listeners("upgrade") as Array<(req: IncomingMessage, socket: Duplex, head: Buffer) => void>;
  server.removeAllListeners("request");
  server.removeAllListeners("upgrade");
  server.on("request", (req, res) => {
    if (!isLocalCdpRequest(req)) {
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("Forbidden");
      return;
    }
    for (const listener of requestListeners) listener.call(server, req, res);
  });
  server.on("upgrade", (req, socket, head) => {
    if (!isLocalCdpRequest(req)) {
      socket.destroy();
      return;
    }
    for (const listener of upgradeListeners) listener.call(server, req, socket, head);
  });
}

/**
 * Start inspect-webkit's CDP server on `127.0.0.1:<port>` and nowhere else.
 * Throws (after stopping the bridge) if the listener could not be pinned to
 * loopback, rather than leaving it reachable from the network.
 */
export async function startLoopbackCdpServer(port: number) {
  const { startCdpServer } = await import("inspect-webkit");
  // Node's http.Server inherits `listen` from net.Server; Bun's defines its
  // own. Hook whichever prototypes actually carry the method.
  const prototypes = [NetServer.prototype, HttpServerClass.prototype].filter(
    (proto, index, all) => Object.hasOwn(proto, "listen") && all.indexOf(proto) === index,
  ) as Array<{ listen: (...args: unknown[]) => unknown }>;
  const originals = prototypes.map((proto) => proto.listen);
  const listening: NetServer[] = [];
  prototypes.forEach((proto, index) => {
    proto.listen = function (this: NetServer, ...args: unknown[]) {
      const options = args[0];
      if (options && typeof options === "object" && (options as { port?: number }).port === port) {
        listening.push(this);
        args[0] = { ...options, host: "127.0.0.1", ipv6Only: false };
      }
      return originals[index]!.apply(this, args);
    };
  });
  let server: Awaited<ReturnType<typeof startCdpServer>>;
  try {
    server = await startCdpServer({ host: "127.0.0.1", port });
  } finally {
    prototypes.forEach((proto, index) => {
      proto.listen = originals[index]!;
    });
  }
  const bound = listening[0];
  const address = bound?.address() as AddressInfo | null | undefined;
  if (!bound || !address || address.address !== "127.0.0.1") {
    server.stop();
    throw new Error("inspect-webkit bridge could not be restricted to loopback; refusing to start it");
  }
  guardCdpServer(bound as HttpServer);
  return server;
}
