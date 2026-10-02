import { tmpdir } from "os";
import { join } from "path";
import { readdirSync, readFileSync, mkdirSync, writeFileSync, renameSync, unlinkSync } from "fs";

/** Directory where serve-sim stores runtime state. */
export const STATE_DIR = join(tmpdir(), "serve-sim");

/** Path to the serve-sim server state file (JSON with pid, port, URLs).
 *  @deprecated Use `stateFileForDevice(udid)` for multi-device support. Kept for backward compat. */
export const STATE_FILE = join(STATE_DIR, "server.json");

/** Per-device state file: `/tmp/serve-sim/server-{udid}.json` */
export function stateFileForDevice(udid: string): string {
  return join(STATE_DIR, `server-${udid}.json`);
}

/** Runtime record for a device streamed in-process by a preview server. */
export interface ServeSimDeviceState {
  pid: number;
  port: number;
  device: string;
  url: string;
  streamUrl: string;
  wsUrl: string;
}

/**
 * Build the state for a device served in-process. There's no separate helper
 * port — the URLs point at the preview server's own same-origin
 * `{base}/helper/<device>/…` routes, which simMiddleware serves from a
 * NativeCapture/NativeHid DeviceSession.
 */
export function inProcessServeSimState(
  udid: string,
  port: number,
  base = "/",
  host = "127.0.0.1",
): ServeSimDeviceState {
  const h = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  // Normalize to a leading-slash, no-trailing-slash prefix so a base without a
  // leading slash (e.g. "foo") still yields well-formed `…:port/foo/helper/…`.
  const trimmed = base.replace(/^\/+/, "").replace(/\/+$/, "");
  const prefix = trimmed === "" ? "" : `/${trimmed}`;
  return {
    pid: process.pid,
    port,
    device: udid,
    url: `http://${h}:${port}`,
    streamUrl: `http://${h}:${port}${prefix}/helper/${udid}/stream.mjpeg`,
    wsUrl: `ws://${h}:${port}${prefix}/helper/${udid}/ws`,
  };
}

/** Persist a device's state so other processes / the grid can enumerate it.
 *  Writes atomically (temp file + rename) so a concurrent reader never observes
 *  a truncated or partially-written file. */
export function writeServeSimState(state: ServeSimDeviceState): void {
  mkdirSync(STATE_DIR, { recursive: true });
  const file = stateFileForDevice(state.device);
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(state, null, 2));
  renameSync(tmp, file);
}

/** List all per-device state files in the state directory. */
export function listStateFiles(): string[] {
  try {
    return readdirSync(STATE_DIR)
      .filter((f) => f.startsWith("server-") && f.endsWith(".json"))
      .map((f) => join(STATE_DIR, f));
  } catch {
    return [];
  }
}

/** Per-server session token file. Deliberately not `server-*.json`, so it is never enumerated as device state. */
function sessionTokenFile(pid: number): string {
  return join(STATE_DIR, `token-${pid}`);
}

/**
 * Publish this process's session token for local CLI commands (`serve-sim
 * tap`, `button`, …), which drive the input socket from another process. The
 * file is readable only by the current user and removed on exit.
 */
export function writeSessionToken(token: string): void {
  const file = sessionTokenFile(process.pid);
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    pruneStaleSessionTokens();
    const tmp = `${file}.tmp`;
    writeFileSync(tmp, token, { mode: 0o600 });
    renameSync(tmp, file);
  } catch {
    return; // CLI input commands will be refused; the preview page is unaffected.
  }
  if (tokenCleanupRegistered) return;
  tokenCleanupRegistered = true;
  process.once("exit", () => {
    try { unlinkSync(file); } catch {}
  });
}
let tokenCleanupRegistered = false;

/** Drop token files left behind by servers that were killed before their exit hook ran. */
function pruneStaleSessionTokens(): void {
  for (const name of readdirSync(STATE_DIR)) {
    const pid = Number(/^token-(\d+)$/.exec(name)?.[1]);
    if (!pid || pid === process.pid) continue;
    try {
      process.kill(pid, 0);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ESRCH") {
        try { unlinkSync(join(STATE_DIR, name)); } catch {}
      }
    }
  }
}

/** Session token of the serve-sim server running as `pid`, if it published one. */
export function readSessionToken(pid: number): string | null {
  try {
    return readFileSync(sessionTokenFile(pid), "utf-8").trim() || null;
  } catch {
    return null;
  }
}

/** Append the owning server's session token to a helper WebSocket URL. */
export function authenticatedWsUrl(state: Pick<ServeSimDeviceState, "pid" | "wsUrl">): string {
  const token = readSessionToken(state.pid);
  if (!token) return state.wsUrl;
  return `${state.wsUrl}${state.wsUrl.includes("?") ? "&" : "?"}token=${encodeURIComponent(token)}`;
}
