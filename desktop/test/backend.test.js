"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("node:child_process");
const path = require("node:path");
const { backendCommand, parseReady, startBackend, isSameOrigin } = require("../backend");

const TOKEN = "A".repeat(32);

test("command per platform", () => {
  assert.deepStrictEqual(backendCommand("linux", {}).cmd, "seclab");
  assert.deepStrictEqual(backendCommand("linux", { SECLAB_BIN: "/opt/x" }).cmd, "/opt/x");
  const w = backendCommand("win32", {});
  assert.strictEqual(w.cmd, "wsl.exe");
  assert.deepStrictEqual(w.args.slice(0, 6), ["-d", "seclab", "-u", "root", "--", "seclab"]);
  assert.ok(w.args.includes("--exit-on-stdin-eof") && w.args.includes("--json"));
  assert.strictEqual(backendCommand("win32", { SECLAB_WSL_DISTRO: "Ubuntu" }).args[1], "Ubuntu");
});

test("ready line is strictly validated", () => {
  const ok = `http://127.0.0.1:4000/#t=${TOKEN}`;
  assert.strictEqual(parseReady(JSON.stringify({ event: "ready", url: ok })), ok);
  for (const bad of [
    "not json", JSON.stringify({ event: "x", url: ok }),
    JSON.stringify({ event: "ready", url: `http://evil.example/#t=${TOKEN}` }),
    JSON.stringify({ event: "ready", url: `https://127.0.0.1:4000/#t=${TOKEN}` }),
    JSON.stringify({ event: "ready", url: "http://127.0.0.1:4000/" }),
    JSON.stringify({ event: "ready", url: "javascript:alert(1)" }),
  ]) assert.strictEqual(parseReady(bad), null, bad);
});

test("same-origin check", () => {
  assert.ok(isSameOrigin("http://127.0.0.1:4000/app.js", "http://127.0.0.1:4000/#t=x"));
  assert.ok(!isSameOrigin("http://127.0.0.1:4001/", "http://127.0.0.1:4000/"));
  assert.ok(!isSameOrigin("https://example.com/", "http://127.0.0.1:4000/"));
});

function fakeSpawn(script) {
  return () => spawn(process.execPath, ["-e", script], { stdio: ["pipe", "pipe", "pipe"] });
}

test("resolves on ready line, ignoring noise", async () => {
  const b = startBackend(fakeSpawn(`console.log("booting"); setTimeout(() => console.log(JSON.stringify({event:"ready",url:"http://127.0.0.1:5000/#t=${TOKEN}"})), 50); process.stdin.resume(); process.stdin.on("end", () => process.exit(0));`),
    { platform: "linux" });
  assert.strictEqual(await b.ready, `http://127.0.0.1:5000/#t=${TOKEN}`);
  const exited = new Promise((r) => b.child.on("exit", r));
  b.stop();                                    // closes stdin -> backend exits by itself
  assert.strictEqual(await exited, 0);
});

test("rejects with stderr when backend dies", async () => {
  const b = startBackend(fakeSpawn(`console.error("docker: permission denied"); process.exit(3)`), { platform: "linux" });
  await assert.rejects(b.ready, (e) => /code 3/.test(e.message) && /permission denied/.test(e.stderr));
});

test("rejects on timeout", async () => {
  const b = startBackend(fakeSpawn(`setTimeout(() => {}, 5000)`), { platform: "linux", timeoutMs: 200 });
  await assert.rejects(b.ready, /not ready/);
  b.child.kill();
});

test("works against the real seclab backend", { skip: !process.env.SECLAB_REAL_BACKEND }, async () => {
  const root = path.resolve(__dirname, "..", "..");
  const b = startBackend(() => spawn("python3", ["-m", "seclab", "ui", "--port", "0", "--json", "--exit-on-stdin-eof"],
    { cwd: root, stdio: ["pipe", "pipe", "pipe"] }), { platform: "linux" });
  const url = await b.ready;
  const res = await fetch(url.split("#")[0]);
  assert.strictEqual(res.status, 200);
  assert.match(res.headers.get("content-security-policy"), /script-src 'self'/);
  const exited = new Promise((r) => b.child.on("exit", r));
  b.stop();
  assert.strictEqual(await exited, 0);
});
