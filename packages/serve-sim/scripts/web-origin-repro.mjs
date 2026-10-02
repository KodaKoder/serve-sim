#!/usr/bin/env node
// Manual check for web-origin attacks against a running serve-sim.
//
// Serves a page from a *different* localhost port that tries, from the
// browser, what any website the user visits could try:
//   - open the simulator input WebSocket and inject a tap
//   - read the screen config and accessibility tree
//   - read /api (which used to carry the session token)
//
//   node scripts/web-origin-repro.mjs [port]
//   open "http://localhost:4599/?target=127.0.0.1:3200&udid=<UDID>"
//
// Against a hardened server every probe reports "refused" / "blocked".
// Only ever point this at your own local serve-sim.
import { createServer } from "http";

const port = Number(process.argv[2] ?? 4599);

const page = `<!doctype html><meta charset=utf-8><title>cross-origin repro</title>
<pre id=out>running…</pre>
<script>
const q = new URLSearchParams(location.search);
const target = q.get("target"), udid = q.get("udid");
const out = { origin: location.origin, target };
(async () => {
  out.ws = await new Promise((resolve) => {
    const ws = new WebSocket("ws://" + target + "/helper/" + udid + "/ws");
    const timer = setTimeout(() => resolve("timeout"), 4000);
    const frame = (o) => {
      const json = new TextEncoder().encode(JSON.stringify(o));
      const bytes = new Uint8Array(json.length + 1);
      bytes[0] = 0x03;
      bytes.set(json, 1);
      return bytes;
    };
    ws.onopen = () => {
      ws.send(frame({ type: "begin", x: 0.5, y: 0.5 }));
      setTimeout(() => {
        ws.send(frame({ type: "end", x: 0.5, y: 0.5 }));
        setTimeout(() => { clearTimeout(timer); ws.close(); resolve("OPEN: tap injected"); }, 300);
      }, 60);
    };
    ws.onerror = () => { clearTimeout(timer); resolve("refused"); };
  });
  for (const path of ["helper/" + udid + "/ax", "helper/" + udid + "/config", "api"]) {
    try {
      const res = await fetch("http://" + target + "/" + path);
      out[path.split("/").pop()] = "READ " + res.status + ": " + (await res.text()).slice(0, 80);
    } catch (e) {
      out[path.split("/").pop()] = "blocked: " + e.message;
    }
  }
  document.getElementById("out").textContent = JSON.stringify(out, null, 2);
})();
</script>`;

createServer((_req, res) => {
  res.writeHead(200, { "content-type": "text/html" });
  res.end(page);
}).listen(port, "127.0.0.1", () => console.log(`attacker page on http://localhost:${port}`));
