"use strict";
// Backend launcher for the desktop shell. No Electron imports: unit-tested with plain Node (node --test).
//
// Linux:   seclab ui --port 0 --json --exit-on-stdin-eof
// Windows: wsl.exe -d <distro> -u root -- seclab ui ...   (engine needs Linux Docker; WSL2 forwards
//          127.0.0.1 ports to Windows, so the window and the lab ports work from Windows directly)

const DEFAULT_DISTRO = "seclab";
const READY_TIMEOUT_MS = 60_000;

function backendCommand(platform, env = {}) {
  const args = ["ui", "--port", "0", "--json", "--exit-on-stdin-eof"];
  if (platform === "win32") {
    const distro = env.SECLAB_WSL_DISTRO || DEFAULT_DISTRO;
    return { cmd: "wsl.exe", args: ["-d", distro, "-u", "root", "--", "seclab", ...args] };
  }
  return { cmd: env.SECLAB_BIN || "seclab", args };
}

// Only accept a loopback URL with a token: never let backend output point the window elsewhere.
function parseReady(line) {
  let msg;
  try { msg = JSON.parse(line); } catch (_) { return null; }
  if (!msg || msg.event !== "ready" || typeof msg.url !== "string") return null;
  let u;
  try { u = new URL(msg.url); } catch (_) { return null; }
  if (u.protocol !== "http:" || u.hostname !== "127.0.0.1" || !/^#t=[A-Za-z0-9_-]{16,}$/.test(u.hash)) return null;
  return msg.url;
}

function startBackend(spawn, { platform, env = {}, timeoutMs = READY_TIMEOUT_MS } = {}) {
  const { cmd, args } = backendCommand(platform, env);
  const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  let stderr = "";
  let buf = "";
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => fail(new Error(`backend not ready after ${timeoutMs / 1000}s`)), timeoutMs);
    function fail(err) {
      clearTimeout(timer);
      err.stderr = stderr.slice(-4000);
      err.command = [cmd, ...args].join(" ");
      reject(err);
    }
    child.on("error", (e) => fail(new Error(`cannot start ${cmd}: ${e.message}`)));
    child.on("exit", (code) => fail(new Error(`backend exited with code ${code}`)));
    child.stderr.on("data", (d) => { stderr += d.toString(); });
    child.stdout.on("data", (d) => {
      buf += d.toString();
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const url = parseReady(buf.slice(0, nl).trim());
        buf = buf.slice(nl + 1);
        if (url) { clearTimeout(timer); resolve(url); return; }
      }
    });
  });
  return { child, ready, stop: () => stopBackend(child) };
}

function stopBackend(child) {
  if (!child || child.exitCode !== null) return;
  try { child.stdin.end(); } catch (_) { /* already closed */ }   // backend exits on stdin EOF
  setTimeout(() => { if (child.exitCode === null) child.kill(); }, 3000).unref?.();
}

function isSameOrigin(target, appUrl) {
  try { return new URL(target).origin === new URL(appUrl).origin; } catch (_) { return false; }
}

module.exports = { backendCommand, parseReady, startBackend, stopBackend, isSameOrigin, DEFAULT_DISTRO };
