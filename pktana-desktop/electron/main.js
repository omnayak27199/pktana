#!/usr/bin/env node
/**
 * pktana desktop — Wireshark-style shell for macOS / Windows.
 *
 * Starts the real pktana web server (web.rs UI + libpcap/Npcap capture),
 * then opens it in an Electron window.
 *
 * Binary resolution order:
 *   1. Bundled resources/bin/pktana(.exe)
 *   2. PKTANA_BIN env override
 *   3. pktana on PATH
 *   4. Docker fallback via ../docker_mac.sh (macOS/Linux only)
 */
const { app, BrowserWindow, Menu, dialog, shell, clipboard, ipcMain } = require('electron');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const path = require('path');

const DEFAULT_PORT = Number(process.env.PKTANA_PORT || 18080);
const HOST = '127.0.0.1';
const isWin = process.platform === 'win32';
const isMac = process.platform === 'darwin';

let mainWindow = null;
let backend = null;
let backendMode = 'none';
let shuttingDown = false;
let activePort = DEFAULT_PORT;

// ── Window state persistence ──────────────────────────────────────────────────

function windowStatePath() {
  return path.join(app.getPath('userData'), 'window-state.json');
}

function loadWindowState() {
  try {
    const s = JSON.parse(fs.readFileSync(windowStatePath(), 'utf8'));
    return {
      width: s.width || 1400,
      height: s.height || 900,
      x: s.x,
      y: s.y,
      maximized: !!s.maximized,
    };
  } catch {
    return { width: 1400, height: 900 };
  }
}

function saveWindowState(win) {
  if (!win || win.isMinimized()) return;
  try {
    const b = win.getBounds();
    fs.writeFileSync(
      windowStatePath(),
      JSON.stringify({ ...b, maximized: win.isMaximized() })
    );
  } catch { /* ignore */ }
}

// ── Free port detection ───────────────────────────────────────────────────────

function findFreePort(preferred) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => {
      // preferred is taken — let OS assign one
      const fallback = net.createServer();
      fallback.listen(0, '127.0.0.1', () => {
        const p = fallback.address().port;
        fallback.close(() => resolve(p));
      });
    });
    probe.listen(preferred, '127.0.0.1', () => {
      probe.close(() => resolve(preferred));
    });
  });
}

// ── Binary resolution ─────────────────────────────────────────────────────────

function resourcesBinCandidates() {
  const names = isWin ? ['pktana.exe', 'pktana'] : ['pktana', 'pktana.exe'];
  const dirs = [];

  if (app.isPackaged) {
    dirs.push(path.join(process.resourcesPath, 'bin'));
    dirs.push(path.join(path.dirname(process.execPath), 'resources', 'bin'));
    dirs.push(path.join(path.dirname(process.execPath), 'bin'));
  } else {
    dirs.push(path.join(__dirname, '..', 'resources', 'bin'));
  }

  const out = [];
  for (const dir of dirs) {
    for (const name of names) {
      out.push(path.join(dir, name));
    }
  }
  return out;
}

function resourcesBin() {
  for (const p of resourcesBinCandidates()) {
    if (fs.existsSync(p)) return p;
  }
  return resourcesBinCandidates()[0];
}

function findNativeBinary() {
  if (process.env.PKTANA_BIN && fs.existsSync(process.env.PKTANA_BIN)) {
    return process.env.PKTANA_BIN;
  }
  for (const p of resourcesBinCandidates()) {
    if (fs.existsSync(p)) return p;
  }
  try {
    const cmd = isWin ? 'where' : 'which';
    const which = execFileSync(cmd, ['pktana'], { encoding: 'utf8' })
      .trim()
      .split(/\r?\n/)[0];
    if (which && fs.existsSync(which)) return which;
  } catch {
    /* not on PATH */
  }
  return null;
}

function repoRoot() {
  return path.join(__dirname, '..', '..');
}

// ── Port readiness probe ──────────────────────────────────────────────────────

function waitForPort(port, timeoutMs = 60000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const socket = net.connect({ host: HOST, port }, () => {
        socket.end();
        resolve();
      });
      socket.on('error', () => {
        socket.destroy();
        if (Date.now() - start > timeoutMs) {
          reject(new Error(`pktana web did not become ready on ${HOST}:${port}`));
          return;
        }
        setTimeout(tryOnce, 250);
      });
    };
    tryOnce();
  });
}

// ── Backend lifecycle ─────────────────────────────────────────────────────────

function startNative(bin, port) {
  return new Promise((resolve, reject) => {
    const args = ['web', String(port), '-f'];
    const child = spawn(bin, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env },
    });
    backend = child;
    backendMode = 'native';

    let stderr = '';
    child.stderr.on('data', (d) => {
      stderr += d.toString();
      if (stderr.length > 8000) stderr = stderr.slice(-4000);
    });
    child.stdout.on('data', () => {});

    child.on('error', (err) => reject(err));
    child.on('exit', (code) => {
      backend = null;
      if (!shuttingDown) {
        handleBackendCrash(code, stderr.slice(-600));
      }
    });

    waitForPort(port).then(() => resolve(child)).catch(reject);
  });
}

function handleBackendCrash(code, detail) {
  if (!mainWindow) return;
  dialog
    .showMessageBox(mainWindow, {
      type: 'error',
      title: 'pktana backend stopped',
      message: `The capture engine exited unexpectedly (code ${code ?? '?'}).`,
      detail: detail || 'No additional details.',
      buttons: ['Restart', 'Quit'],
      defaultId: 0,
      cancelId: 1,
    })
    .then(({ response }) => {
      if (response === 0) restartBackend();
      else app.quit();
    });
}

async function restartBackend() {
  shuttingDown = false;
  mainWindow?.setTitle('pktana — Restarting…');
  mainWindow?.loadURL('data:text/html,' + encodeURIComponent(loadingHTML(activePort, 'Restarting…')));
  try {
    await startBackend(activePort);
    mainWindow?.setTitle('pktana');
    mainWindow?.loadURL(`http://${HOST}:${activePort}`);
  } catch (err) {
    dialog.showErrorBox('Restart failed', err.message);
    app.quit();
  }
}

function startDocker(port) {
  if (isWin) {
    throw new Error(
      'This Windows build is missing the capture engine (pktana.exe).\n\n' +
        'Download a complete installer from GitHub Actions (desktop-windows),\n' +
        'or rebuild with:\n' +
        '  pktana-desktop\\scripts\\build-window.bat\n\n' +
        'Also install Npcap from https://npcap.com/ for live capture.'
    );
  }
  const script = path.join(repoRoot(), 'docker_mac.sh');
  if (!fs.existsSync(script)) {
    throw new Error('docker_mac.sh not found and no native pktana binary bundled');
  }
  execFileSync(script, ['start', String(port)], {
    stdio: 'inherit',
    cwd: repoRoot(),
  });
  backendMode = 'docker';
  return waitForPort(port);
}

async function startBackend(port) {
  const bin = findNativeBinary();
  if (bin) {
    console.log('Starting native pktana:', bin);
    try {
      await startNative(bin, port);
      return;
    } catch (err) {
      console.warn('Native start failed, trying Docker…', err.message);
      stopBackend();
    }
  }
  console.log('Starting Docker pktana backend…');
  await startDocker(port);
}

function stopBackend() {
  shuttingDown = true;
  if (backendMode === 'native' && backend) {
    try { backend.kill('SIGTERM'); } catch { /* ignore */ }
    backend = null;
  }
  if (backendMode === 'docker') {
    try {
      const script = path.join(repoRoot(), 'docker_mac.sh');
      if (fs.existsSync(script)) {
        execFileSync(script, ['stop'], { stdio: 'ignore', cwd: repoRoot() });
      }
    } catch { /* ignore */ }
  }
  backendMode = 'none';
}

// ── Loading page ──────────────────────────────────────────────────────────────

function loadingHTML(port, status = 'Starting capture engine…') {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
           background: #0f1923; color: #e0e6f0;
           display: flex; flex-direction: column; align-items: center;
           justify-content: center; height: 100vh; gap: 1rem; }
    .logo { font-size: 2rem; font-weight: 800; letter-spacing: -0.03em; color: #4adeff; }
    .logo span { color: #e0e6f0; font-weight: 400; }
    .spinner { width: 32px; height: 32px; border: 3px solid #1e2d3d;
               border-top-color: #4adeff; border-radius: 50%;
               animation: spin .8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    p { font-size: .85rem; color: #567; }
  </style></head><body>
    <div class="spinner"></div>
    <div class="logo">pktana <span>desktop</span></div>
    <p>${status} (port ${port})</p>
  </body></html>`;
}

// ── Dialogs ───────────────────────────────────────────────────────────────────

function showAboutDialog() {
  dialog
    .showMessageBox({
      type: 'info',
      title: 'About pktana',
      message: `pktana  ${app.getVersion()}`,
      detail: [
        'Wireshark-style packet analyzer with live network capture.',
        '',
        `Backend : ${backendMode || 'not started'}`,
        `Port    : ${activePort}`,
        '',
        'Copyright © 2026 Omprakash',
        'License: Apache-2.0',
      ].join('\n'),
      buttons: ['OK', 'Open GitHub'],
      defaultId: 0,
    })
    .then(({ response }) => {
      if (response === 1)
        shell.openExternal('https://github.com/omnayak27199/pktana');
    });
}

function showCapturePermissions() {
  dialog.showMessageBox({
    type: 'info',
    title: 'Packet capture permissions',
    message: 'Capture permissions',
    detail: isWin
      ? 'Live capture on Windows requires Npcap (same as Wireshark).\n\n' +
        '• Install Npcap from https://npcap.com/\n' +
        '• Enable "WinPcap API compatibility" during install\n' +
        '• Run pktana as Administrator if interfaces show no packets\n\n' +
        `Backend: ${backendMode}   Port: ${activePort}`
      : 'Live capture on macOS requires libpcap access to /dev/bpf*.\n\n' +
        '• Install Wireshark once — it sets up ChmodBPF helper\n' +
        '• Or run pktana with sudo\n\n' +
        `Backend: ${backendMode}   Port: ${activePort}`,
    buttons: ['OK'],
  });
}

// ── IPC handlers ──────────────────────────────────────────────────────────────

ipcMain.handle('app:info', () => ({
  version: app.getVersion(),
  port: activePort,
  backendMode,
  platform: process.platform,
}));

// ── Menu ──────────────────────────────────────────────────────────────────────

function buildMenu() {
  const captureSubmenu = [
    {
      label: 'Reload UI',
      accelerator: 'CmdOrCtrl+R',
      click: () => mainWindow?.reload(),
    },
    {
      label: 'Hard Reload',
      accelerator: 'CmdOrCtrl+Shift+R',
      click: () => mainWindow?.webContents.reloadIgnoringCache(),
    },
    { type: 'separator' },
    {
      label: 'Open in Browser',
      accelerator: 'CmdOrCtrl+B',
      click: () => shell.openExternal(`http://${HOST}:${activePort}`),
    },
    {
      label: 'Copy Server URL',
      click: () => clipboard.writeText(`http://${HOST}:${activePort}`),
    },
  ];

  if (!isMac) {
    captureSubmenu.push({ type: 'separator' }, { role: 'quit' });
  }

  const viewSubmenu = [
    { role: 'resetZoom' },
    { role: 'zoomIn' },
    { role: 'zoomOut' },
    { type: 'separator' },
    { role: 'togglefullscreen' },
  ];

  // Only show dev tools in dev mode
  if (!app.isPackaged) {
    viewSubmenu.unshift(
      {
        label: 'Developer Tools',
        accelerator: 'CmdOrCtrl+Shift+I',
        click: () => mainWindow?.webContents.toggleDevTools(),
      },
      { type: 'separator' }
    );
  }

  const template = [
    { label: 'Capture', submenu: captureSubmenu },
    { label: 'View', submenu: viewSubmenu },
    {
      label: 'Help',
      submenu: [
        {
          label: 'pktana Docs',
          click: () => shell.openExternal('https://pktana.online/docs.html'),
        },
        { type: 'separator' },
        { label: 'Capture Permissions…', click: showCapturePermissions },
        { label: 'About pktana', click: showAboutDialog },
      ],
    },
  ];

  if (isMac) {
    template.unshift({
      label: app.name,
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' },
      ],
    });
  }

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ── App setup ─────────────────────────────────────────────────────────────────

if (isMac) {
  app.setAboutPanelOptions({
    applicationName: 'pktana',
    applicationVersion: app.getVersion(),
    copyright: 'Copyright © 2026 Omprakash\nLicense: Apache-2.0',
    website: 'https://pktana.online',
  });
}

async function createWindow() {
  activePort = await findFreePort(DEFAULT_PORT);
  const state = loadWindowState();

  mainWindow = new BrowserWindow({
    width: state.width,
    height: state.height,
    x: state.x,
    y: state.y,
    minWidth: 960,
    minHeight: 640,
    title: 'pktana — Starting…',
    show: false,
    backgroundColor: '#0f1923',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
    },
  });

  if (state.maximized) mainWindow.maximize();

  // Persist window bounds on every change
  mainWindow.on('resize', () => saveWindowState(mainWindow));
  mainWindow.on('move', () => saveWindowState(mainWindow));
  mainWindow.on('close', () => saveWindowState(mainWindow));
  mainWindow.on('closed', () => { mainWindow = null; });

  // Open external links in system browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  buildMenu();

  // Show loading screen immediately so the window appears fast
  await mainWindow.loadURL(
    'data:text/html,' + encodeURIComponent(loadingHTML(activePort))
  );
  mainWindow.show();

  try {
    await startBackend(activePort);
  } catch (err) {
    dialog.showErrorBox(
      'pktana failed to start',
      `${err.message}\n\n` +
        (isWin
          ? 'Looked in:\n' +
            resourcesBinCandidates().slice(0, 4).join('\n') +
            '\n\nInstall Npcap: https://npcap.com/\n' +
            'Rebuild: pktana-desktop\\scripts\\build-window.bat'
          : 'Install Docker Desktop, or place a macOS binary at:\n' +
            resourcesBin() +
            '\n\nBuild on Mac: ./pktana-desktop/scripts/build-mac.sh')
    );
    app.quit();
    return;
  }

  mainWindow.setTitle('pktana');
  await mainWindow.loadURL(`http://${HOST}:${activePort}`);

  // Bounce dock icon on macOS to indicate readiness
  if (isMac) app.dock.bounce('informational');
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  stopBackend();
  if (!isMac) app.quit();
});

app.on('before-quit', () => stopBackend());

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
