"use strict";
// seclab desktop shell: starts the local engine (natively on Linux, inside WSL2 on Windows),
// shows its UI in a locked-down window and stops the engine on quit.

const { app, BrowserWindow, dialog, shell, Menu } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");
const { startBackend, isSameOrigin } = require("./backend");

let backend = null;
let win = null;

if (!app.requestSingleInstanceLock()) app.quit();

function createWindow() {
  win = new BrowserWindow({
    width: 1400, height: 950, minWidth: 900, minHeight: 600, show: false,
    title: "seclab", backgroundColor: "#0f1216", icon: path.join(__dirname, "build", "icon.png"),
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true,
                      spellcheck: false },
  });
  win.loadFile(path.join(__dirname, "splash.html"));
  win.once("ready-to-show", () => win.show());
  return win;
}

function lockNavigation(appUrl) {
  // The UI is the only page allowed in the window; anything else opens in the system browser.
  win.webContents.on("will-navigate", (ev, target) => {
    if (!isSameOrigin(target, appUrl)) { ev.preventDefault(); shell.openExternal(target); }
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  win.webContents.session.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
}

async function boot() {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: "seclab", submenu: [{ role: "reload" }, { role: "toggleDevTools" }, { type: "separator" }, { role: "quit" }] },
    { label: "Edit", submenu: [{ role: "copy" }, { role: "paste" }, { role: "selectAll" }] },
    { label: "View", submenu: [{ role: "zoomIn" }, { role: "zoomOut" }, { role: "resetZoom" }, { role: "togglefullscreen" }] },
  ]));
  createWindow();
  backend = startBackend(spawn, { platform: process.platform, env: process.env });
  try {
    const url = await backend.ready;
    lockNavigation(url);
    await win.loadURL(url);
  } catch (err) {
    const hint = process.platform === "win32"
      ? "Run install\\install.ps1 (as Administrator) to set up WSL2, Docker and the seclab engine."
      : "Run install/install.sh to set up Docker and the seclab engine.";
    dialog.showErrorBox("seclab engine did not start",
      `${err.message}\n\nCommand: ${err.command || "?"}\n\n${err.stderr || ""}\n\n${hint}`);
    app.quit();
  }
}

app.whenReady().then(boot);
app.on("second-instance", () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
app.on("window-all-closed", () => app.quit());
app.on("before-quit", () => { if (backend) backend.stop(); });
