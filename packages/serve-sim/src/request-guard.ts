import { timingSafeEqual, createHash } from "crypto";
import { hostname, networkInterfaces } from "os";
import type { IncomingMessage } from "http";

// Web-origin guard for the local preview server.
//
// A server bound to 127.0.0.1 is still reachable by every web page the user
// visits: the browser will happily send requests and open WebSockets to
// loopback on a page's behalf. Two checks close that:
//
//   1. Host allowlist — defeats DNS rebinding. A hostile page whose domain is
//      re-pointed at 127.0.0.1 becomes "same-origin" with us, but its requests
//      still carry `Host: evil.example`, which is never on the list.
//   2. Origin check — browsers attach `Origin` to every WebSocket upgrade and
//      every non-GET request, so a cross-origin page (including one on another
//      localhost port) is refused. Non-browser clients send no Origin.

const LOOPBACK_HOSTNAMES = ["localhost", "127.0.0.1", "[::1]"];

export interface RequestGuardOptions {
  /**
   * Extra `Host` values to accept besides loopback. `"name"` matches any port,
   * `"name:port"` only that port. Needed when the preview is reached through a
   * LAN address, a tunnel, or a reverse proxy.
   */
  allowedHosts?: string[];
}

export interface RequestGuard {
  /** Null when the request may proceed, otherwise the reason it was refused. */
  check(req: IncomingMessage, opts?: { stateChanging?: boolean }): string | null;
  /** Null when the upgrade may proceed, otherwise the reason it was refused. */
  checkUpgrade(req: IncomingMessage): string | null;
  /** Accept `port` for loopback hosts in addition to the socket's own port. */
  allowPort(port: number): void;
}

function splitHost(value: string): { hostname: string; port: number } | null {
  const match = /^([a-z0-9._-]+|\[[0-9a-f:.]+\])(?::(\d{1,5}))?$/i.exec(value.trim());
  if (!match) return null;
  return { hostname: match[1]!.toLowerCase(), port: match[2] ? Number(match[2]) : 80 };
}

function bracketIfIpv6(address: string): string {
  return address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
}

/**
 * `Host` values a server bound to `bindHost` can legitimately be reached at.
 * A wildcard bind is reachable through every local interface, so those
 * addresses (and the machine's own hostname) are listed. IP literals and the
 * local hostname are safe to accept: DNS rebinding needs the attacker's own
 * domain in the Host header.
 */
export function hostsForBindAddress(bindHost: string | undefined): string[] {
  if (!bindHost) return [];
  if (bindHost !== "0.0.0.0" && bindHost !== "::") return [bracketIfIpv6(bindHost)];
  const hosts = [hostname()];
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses ?? []) {
      hosts.push(bracketIfIpv6(address.address.split("%")[0]!));
    }
  }
  return hosts;
}

export function createRequestGuard(options: RequestGuardOptions = {}): RequestGuard {
  const anyPort = new Set<string>();
  const exact = new Set<string>();
  for (const entry of options.allowedHosts ?? []) {
    const parsed = splitHost(entry);
    if (!parsed) continue;
    if (/:\d+$/.test(entry.trim())) exact.add(`${parsed.hostname}:${parsed.port}`);
    else anyPort.add(parsed.hostname);
  }
  const extraPorts = new Set<number>();

  const hostAllowed = (req: IncomingMessage): boolean => {
    const header = req.headers.host;
    if (typeof header !== "string") return false;
    const parsed = splitHost(header);
    if (!parsed) return false;
    if (anyPort.has(parsed.hostname) || exact.has(`${parsed.hostname}:${parsed.port}`)) return true;
    if (!LOOPBACK_HOSTNAMES.includes(parsed.hostname)) return false;
    const localPort = req.socket?.localPort;
    if (parsed.port === localPort || extraPorts.has(parsed.port)) return true;
    // Some runtimes don't expose the socket's port; without any known port
    // the hostname check alone has to do.
    return !localPort && extraPorts.size === 0;
  };

  const originAllowed = (req: IncomingMessage): boolean => {
    const origin = req.headers.origin;
    if (origin === undefined) return true;
    if (typeof origin !== "string") return false;
    try {
      // The Host header has already passed the allowlist, so same-origin
      // reduces to "Origin names the host this request was sent to".
      return new URL(origin).host.toLowerCase() === String(req.headers.host).toLowerCase();
    } catch {
      return false; // includes the opaque "null" origin
    }
  };

  // Fetch Metadata: refuse sub-resource loads issued by another site (or
  // another localhost port) even when they carry no Origin, e.g. a hostile
  // `<img src=…/devtools>`. Top-level and iframe navigations stay allowed so
  // the preview can still be opened from a link or embedded.
  const fetchSiteAllowed = (req: IncomingMessage): boolean => {
    const site = req.headers["sec-fetch-site"];
    if (site === undefined || site === "same-origin" || site === "none") return true;
    return req.method === "GET" && req.headers["sec-fetch-mode"] === "navigate";
  };

  return {
    check(req, opts) {
      if (!hostAllowed(req)) return "Host not allowed";
      if (!fetchSiteAllowed(req)) return "Cross-site request blocked";
      const safeMethod = req.method === "GET" || req.method === "HEAD";
      if ((opts?.stateChanging || !safeMethod) && !originAllowed(req)) {
        return "Cross-origin request blocked";
      }
      return null;
    },
    checkUpgrade(req) {
      if (!hostAllowed(req)) return "Host not allowed";
      if (!originAllowed(req)) return "Cross-origin request blocked";
      return null;
    },
    allowPort(port) {
      extraPorts.add(port);
    },
  };
}

/** Constant-time string comparison that does not leak the expected length. */
export function tokensMatch(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

/** True when the request carries the session token as a bearer credential. */
export function hasBearerToken(req: IncomingMessage, token: string): boolean {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "");
  return !!match && tokensMatch(match[1]!.trim(), token);
}

/**
 * True when the URL's `token` query parameter is the session token. Browsers
 * cannot set headers on a WebSocket upgrade, so sockets carry it in the URL.
 */
export function hasQueryToken(rawUrl: string, token: string): boolean {
  const value = new URL(rawUrl, "http://serve-sim.local").searchParams.get("token");
  return value !== null && tokensMatch(value, token);
}
