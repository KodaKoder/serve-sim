import { exec, execFile, type ExecException } from "child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "fs";
import { appendFile, rm, writeFile } from "fs/promises";
import { homedir, tmpdir } from "os";
import { join } from "path";

// Host commands the preview page may run.
//
// The page talks to the host through one channel that used to hand its input
// straight to a shell. Anything able to reach that channel therefore owned the
// user's account. It now accepts only the specific commands the bundled UI
// issues: the string is split into an argv with a strict tokenizer (no shell
// syntax survives it), matched against the shapes below, and run with
// `execFile` — never a shell. File staging, screenshots and thumbnails, which
// needed pipes and redirects, are `serve-sim:*` actions implemented here.
//
// `allowArbitrary` (CLI `--unsafe-exec`, middleware `unsafeExec`) restores the
// old behaviour for embedders whose own tools rely on a free-form exec. It is
// off by default.

export interface HostCommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface HostCommandContext {
  /** Path the page was told to use for the serve-sim CLI (or `"serve-sim"`). */
  serveSimBin: string;
  /** Run anything through a shell. Off unless the user opted in. */
  allowArbitrary?: boolean;
  /** Shuts this server down. Only set by the standalone CLI, which owns its process. */
  stopServer?: () => void;
}

const MAX_BUFFER = 16 * 1024 * 1024;
const UDID = /^[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}$/i;
const BUNDLE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const COORDINATES = /^-?\d+(?:\.\d+)?,-?\d+(?:\.\d+)?$/;
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
/** Files the page stages for addmedia / install / camera sources. */
const STAGED_FILE = new RegExp(`^/tmp/serve-sim-(?:upload|install|camsrc)-${UUID}\\.[a-z0-9]{1,8}$`);
const STAGED_IPA = new RegExp(`^/tmp/serve-sim-install-${UUID}\\.ipa$`);
const MEDIA_FILE = /\.(?:jpe?g|png|gif|heic|heif|webp|mp4|mov|m4v)$/i;
const SCREENSHOT_SLUG = /^[0-9A-Za-z_-]{1,40}$/;
const SCREENSHOT_DISPLAYS = new Set(["primary", "primary-1"]);
const WATCH_HOME_SCRIPT = /^tell application "System Events" to tell process "Simulator" to [A-Za-z0-9 "()]+$/;
const CLI_SUBCOMMANDS = new Set(["camera", "permissions", "rotate", "button", "--kill", "--detach"]);

/**
 * Split a command into arguments, accepting only bare words and single-quoted
 * strings (the output of the client's `shellEscape`). Returns null for
 * anything a shell would interpret: pipes, redirects, substitutions, globs,
 * variables, double quotes, `~`, `;`, `&`, newlines.
 */
export function splitHostCommand(command: string): string[] | null {
  const args: string[] = [];
  let current = "";
  let open = false;
  for (let i = 0; i < command.length; ) {
    const ch = command[i]!;
    if (ch === "'") {
      const end = command.indexOf("'", i + 1);
      if (end === -1) return null;
      current += command.slice(i + 1, end);
      open = true;
      i = end + 1;
    } else if (ch === "\\" && command[i + 1] === "'") {
      current += "'";
      open = true;
      i += 2;
    } else if (ch === " ") {
      if (open) args.push(current);
      current = "";
      open = false;
      i += 1;
    } else if (/[A-Za-z0-9_@%+=:,./-]/.test(ch)) {
      current += ch;
      open = true;
      i += 1;
    } else {
      return null;
    }
  }
  if (open) args.push(current);
  return args;
}

function isSafeAbsolutePath(path: string): boolean {
  return path.startsWith("/") && !path.includes("\0") && !path.split("/").includes("..");
}

function isAppBundleFile(path: string, suffix: RegExp): boolean {
  return isSafeAbsolutePath(path) && /\.app\//.test(path) && suffix.test(path);
}

function screenshotPath(slug: string): string {
  return join(homedir(), "Desktop", `serve-sim-screenshot-${slug}.png`);
}

function isScreenshotPath(path: string): boolean {
  const prefix = join(homedir(), "Desktop", "serve-sim-screenshot-");
  return path.startsWith(prefix) && SCREENSHOT_SLUG.test(path.slice(prefix.length, -4)) && path.endsWith(".png");
}

function run(file: string, args: string[]): Promise<HostCommandResult> {
  return new Promise((resolve) => {
    execFile(file, args, { maxBuffer: MAX_BUFFER }, (err, stdout, stderr) => {
      const code = err ? (err as ExecException).code : 0;
      resolve({
        stdout: stdout.toString(),
        stderr: stderr.toString() || (err && typeof code !== "number" ? err.message : ""),
        exitCode: typeof code === "number" ? code : 1,
      });
    });
  });
}

const ok = (stdout = ""): HostCommandResult => ({ stdout, stderr: "", exitCode: 0 });
const fail = (stderr: string): HostCommandResult => ({ stdout: "", stderr, exitCode: 1 });

/** `serve-sim:*` actions: host work that used to be spelled as shell pipelines. */
async function runBuiltin(name: string, args: string[], ctx: HostCommandContext): Promise<HostCommandResult | null> {
  switch (name) {
    case "serve-sim:stop-server": {
      if (args.length !== 0 || !ctx.stopServer) return null;
      // Let the reply reach the page before the process goes away.
      setTimeout(ctx.stopServer, 150);
      return ok();
    }
    case "serve-sim:write-tmp": {
      const [path, mode, data] = args;
      if (args.length !== 3 || !STAGED_FILE.test(path!) || (mode !== "create" && mode !== "append")) return null;
      const bytes = Buffer.from(data!, "base64");
      try {
        if (mode === "create") await writeFile(path!, bytes, { mode: 0o600 });
        else await appendFile(path!, bytes);
        return ok();
      } catch (err) {
        return fail(err instanceof Error ? err.message : String(err));
      }
    }
    case "serve-sim:rm-tmp": {
      if (args.length !== 1 || !STAGED_FILE.test(args[0]!)) return null;
      await rm(args[0]!, { force: true });
      return ok();
    }
    case "serve-sim:first-file": {
      if (args.length === 0 || !args.every((path) => isAppBundleFile(path, /\.png$/i))) return null;
      const found = args.find((path) => existsSync(path));
      return found ? ok(`${found}\n`) : fail("");
    }
    case "serve-sim:screenshot": {
      const [udid, slug, display] = args;
      if (args.length < 2 || args.length > 3 || !UDID.test(udid!) || !SCREENSHOT_SLUG.test(slug!)) return null;
      if (display !== undefined && !SCREENSHOT_DISPLAYS.has(display)) return null;
      const path = screenshotPath(slug!);
      const result = await run("xcrun", [
        "simctl", "io", udid!, "screenshot",
        ...(display ? [`--display=${display}`] : []),
        path,
      ]);
      return result.exitCode === 0 ? ok(path) : { ...result, stdout: "" };
    }
    case "serve-sim:thumbnail": {
      if (args.length !== 1 || !isScreenshotPath(args[0]!)) return null;
      const dir = mkdtempSync(join(tmpdir(), "serve-sim-thumb-"));
      try {
        const thumb = join(dir, "thumb.png");
        const result = await run("sips", ["-Z", "320", args[0]!, "--out", thumb]);
        if (result.exitCode !== 0) return { ...result, stdout: "" };
        return ok(readFileSync(thumb).toString("base64"));
      } catch (err) {
        return fail(err instanceof Error ? err.message : String(err));
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
    default:
      return null;
  }
}

function isAllowedSimctl(args: string[]): boolean {
  const [verb, udid, ...rest] = args;
  if (!udid || !UDID.test(udid)) return false;
  switch (verb) {
    case "ui":
      return rest[0] === "appearance" &&
        (rest.length === 1 || (rest.length === 2 && (rest[1] === "light" || rest[1] === "dark")));
    case "location":
      return (rest.length === 1 && rest[0] === "clear") ||
        (rest.length === 2 && rest[0] === "set" && COORDINATES.test(rest[1]!));
    case "get_app_container":
      return rest.length === 2 && BUNDLE_ID.test(rest[0]!) && rest[1] === "app";
    case "launch":
      return rest.length === 1 && BUNDLE_ID.test(rest[0]!);
    case "addmedia":
      return rest.length === 1 && isSafeAbsolutePath(rest[0]!) && MEDIA_FILE.test(rest[0]!);
    case "install":
      return rest.length === 1 && STAGED_IPA.test(rest[0]!);
    default:
      return false;
  }
}

/** Resolve the serve-sim CLI invocation the page used into a file + args, or null. */
function serveSimCli(argv: string[], bin: string): { file: string; args: string[] } | null {
  let rest: string[];
  if (argv[0] === "serve-sim") rest = argv.slice(1);
  else if (bin !== "serve-sim" && argv[0] === bin) rest = argv.slice(1);
  else if (bin !== "serve-sim" && (argv[0] === "node" || argv[0] === "bun") && argv[1] === bin) rest = argv.slice(2);
  else return null;
  if (!rest[0] || !CLI_SUBCOMMANDS.has(rest[0])) return null;
  if (bin === "serve-sim") return { file: "serve-sim", args: rest };
  if (/\.js$/.test(bin)) return { file: process.execPath, args: [bin, ...rest] };
  if (/\.ts$/.test(bin)) return { file: "bun", args: [bin, ...rest] };
  return { file: bin, args: rest };
}

/** The program + argv an allowlisted external command runs as, or null when it is not allowed. */
export function resolveHostCommand(argv: string[], ctx: HostCommandContext): { file: string; args: string[] } | null {
  const [file, ...args] = argv;
  switch (file) {
    case "xcrun":
      return args[0] === "simctl" && isAllowedSimctl(args.slice(1)) ? { file, args } : null;
    case "plutil":
      return args.length === 5 && args.slice(0, 4).join(" ") === "-convert json -o -" &&
        isAppBundleFile(args[4]!, /\/Info\.plist$/)
        ? { file, args }
        : null;
    case "base64":
      return args.length === 2 && args[0] === "-i" && isAppBundleFile(args[1]!, /\.png$/i)
        ? { file, args }
        : null;
    case "open":
      return args.length === 2 && args[0] === "-R" && isSafeAbsolutePath(args[1]!) ? { file, args } : null;
    case "osascript":
      return args.length > 0 && args.length % 2 === 0 &&
        args.every((arg, i) => (i % 2 === 0 ? arg === "-e" : WATCH_HOME_SCRIPT.test(arg)))
        ? { file, args }
        : null;
    default:
      return serveSimCli(argv, ctx.serveSimBin);
  }
}

function runShell(command: string): Promise<HostCommandResult> {
  return new Promise((resolve) => {
    exec(command, { maxBuffer: MAX_BUFFER }, (err, stdout, stderr) => {
      resolve({
        stdout: stdout.toString(),
        stderr: stderr.toString(),
        exitCode: err ? ((err as ExecException).code ?? 1) : 0,
      });
    });
  });
}

/** Run a command requested by the preview page, if it is one the UI is allowed to issue. */
export async function runHostCommand(command: string, ctx: HostCommandContext): Promise<HostCommandResult> {
  const argv = splitHostCommand(command);
  if (argv && argv.length > 0) {
    if (argv[0]!.startsWith("serve-sim:")) {
      const result = await runBuiltin(argv[0]!, argv.slice(1), ctx);
      if (result) return result;
    } else {
      const allowed = resolveHostCommand(argv, ctx);
      if (allowed) return run(allowed.file, allowed.args);
    }
  }
  if (ctx.allowArbitrary) return runShell(command);
  return {
    stdout: "",
    stderr:
      `serve-sim: command not allowed: ${command.slice(0, 80)}\n` +
      "Only the preview UI's own actions run by default; restart with --unsafe-exec to allow arbitrary host commands.",
    exitCode: 126,
  };
}
