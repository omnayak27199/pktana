const { app, BrowserWindow, Menu, dialog, shell, ipcMain } = require('electron');
const http = require('http');
const fs = require('fs');
const path = require('path');

const APP_ROOT = path.join(__dirname, '..');
const isMac = process.platform === 'darwin';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.txt':  'text/plain; charset=utf-8',
};

let staticServer = null;
let mainWindow = null;
let appVersion = '0.1.0';

// ── Version ───────────────────────────────────────────────────────────────────

function readVersion() {
  try {
    appVersion = fs.readFileSync(path.join(APP_ROOT, 'VERSION'), 'utf8').trim();
  } catch {
    appVersion = app.getVersion();
  }
}

// ── Window state persistence ──────────────────────────────────────────────────

function windowStatePath() {
  return path.join(app.getPath('userData'), 'window-state.json');
}

function loadWindowState() {
  try {
    const s = JSON.parse(fs.readFileSync(windowStatePath(), 'utf8'));
    return {
      width: s.width || 1280,
      height: s.height || 820,
      x: s.x,
      y: s.y,
      maximized: !!s.maximized,
    };
  } catch {
    return { width: 1280, height: 820 };
  }
}

function saveWindowState(win) {
  if (!win || win.isMinimized()) return;
  try {
    fs.writeFileSync(
      windowStatePath(),
      JSON.stringify({ ...win.getBounds(), maximized: win.isMaximized() })
    );
  } catch { /* ignore */ }
}

// ── Static file server ────────────────────────────────────────────────────────

function safePath(urlPath) {
  const normalized = path.normalize(path.join(APP_ROOT, urlPath));
  if (!normalized.startsWith(APP_ROOT)) return null;
  return normalized;
}

function startStaticServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      let urlPath = '/index.html';
      try {
        urlPath = decodeURIComponent(new URL(req.url ?? '/', 'http://127.0.0.1').pathname);
      } catch {
        res.writeHead(400);
        res.end('Bad request');
        return;
      }
      if (urlPath === '/') urlPath = '/index.html';

      const filePath = safePath(urlPath);
      if (!filePath) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
      }

      fs.readFile(filePath, (err, data) => {
        if (err) {
          res.writeHead(404);
          res.end('Not found');
          return;
        }
        const mime = MIME[path.extname(filePath)] ?? 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': mime });
        res.end(data);
      });
    });

    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

// ── IPC handlers ──────────────────────────────────────────────────────────────

ipcMain.handle('dialog:openFile', async () => {
  if (!mainWindow) return null;
  const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
    title: 'Open Lab',
    filters: [{ name: 'Lab files', extensions: ['json'] }],
    properties: ['openFile'],
  });
  if (canceled || filePaths.length === 0) return null;
  try {
    const filePath = filePaths[0];
    const content = fs.readFileSync(filePath, 'utf8');
    app.addRecentDocument(filePath);
    mainWindow.setTitle(`pktana Packet Tracer — ${path.basename(filePath)}`);
    return { path: filePath, content };
  } catch (err) {
    dialog.showErrorBox('Open failed', err.message);
    return null;
  }
});

ipcMain.handle('dialog:saveFile', async (_event, { content, defaultName }) => {
  if (!mainWindow) return null;
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Save Lab',
    defaultPath: defaultName || 'my-lab.json',
    filters: [{ name: 'Lab files', extensions: ['json'] }],
  });
  if (canceled || !filePath) return null;
  try {
    fs.writeFileSync(filePath, content, 'utf8');
    app.addRecentDocument(filePath);
    mainWindow.setTitle(`pktana Packet Tracer — ${path.basename(filePath)}`);
    return filePath;
  } catch (err) {
    dialog.showErrorBox('Save failed', err.message);
    return null;
  }
});

ipcMain.on('dialog:print', () => {
  mainWindow?.webContents.print(
    { silent: false, printBackground: true, color: true },
    (success, reason) => {
      if (!success && reason !== 'cancelled') {
        dialog.showErrorBox('Print failed', reason);
      }
    }
  );
});

// ── About dialog ──────────────────────────────────────────────────────────────

function showAbout() {
  dialog
    .showMessageBox({
      type: 'info',
      title: 'About pktana Packet Tracer',
      message: `pktana Packet Tracer  v${appVersion}`,
      detail: [
        'Cisco Packet Tracer–style network learning lab.',
        'Build networks, learn routing, ARP, DNS, and MAC tables.',
        '',
        'Copyright © 2026 Omprakash',
        'License: Apache-2.0',
      ].join('\n'),
      buttons: ['OK', 'Open GitHub'],
      defaultId: 0,
    })
    .then(({ response }) => {
      if (response === 1)
        shell.openExternal(
          'https://github.com/omnayak27199/pktana/tree/main/packet-tracer'
        );
    });
}

// ── Menu ──────────────────────────────────────────────────────────────────────

function sendToRenderer(channel) {
  mainWindow?.webContents.send(channel);
}

function buildMenu() {
  const fileSubmenu = [
    {
      label: 'New Topology',
      accelerator: 'CmdOrCtrl+N',
      click: () => sendToRenderer('menu:new'),
    },
    {
      label: 'Open Lab…',
      accelerator: 'CmdOrCtrl+O',
      click: () => sendToRenderer('menu:open'),
    },
    {
      label: 'Save Lab…',
      accelerator: 'CmdOrCtrl+S',
      click: () => sendToRenderer('menu:save'),
    },
    { type: 'separator' },
    {
      label: 'Print…',
      accelerator: 'CmdOrCtrl+P',
      click: () => sendToRenderer('menu:print'),
    },
  ];
  if (!isMac) {
    fileSubmenu.push({ type: 'separator' }, { role: 'quit' });
  }

  const editSubmenu = [
    { role: 'undo' },
    { role: 'redo' },
    { type: 'separator' },
    { role: 'cut' },
    { role: 'copy' },
    { role: 'paste' },
    { role: 'selectAll' },
  ];

  const viewSubmenu = [
    { role: 'reload' },
    { role: 'forceReload' },
    { type: 'separator' },
    { role: 'resetZoom' },
    { role: 'zoomIn' },
    { role: 'zoomOut' },
    { type: 'separator' },
    { role: 'togglefullscreen' },
  ];

  if (!app.isPackaged) {
    viewSubmenu.push({ type: 'separator' }, { role: 'toggleDevTools' });
  }

  const helpSubmenu = [
    {
      label: 'Learn Networking',
      click: () => shell.openExternal('https://pktana.online/learn.html'),
    },
    { type: 'separator' },
    { label: 'About pktana Packet Tracer', click: showAbout },
  ];

  const template = [
    { label: 'File', submenu: fileSubmenu },
    { label: 'Edit', submenu: editSubmenu },
    { label: 'View', submenu: viewSubmenu },
    { label: 'Help', submenu: helpSubmenu },
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

// ── Window creation ───────────────────────────────────────────────────────────

async function createWindow() {
  if (!staticServer) {
    staticServer = await startStaticServer();
  }

  const port = staticServer.address().port;
  const state = loadWindowState();

  mainWindow = new BrowserWindow({
    width: state.width,
    height: state.height,
    x: state.x,
    y: state.y,
    minWidth: 960,
    minHeight: 640,
    title: `pktana Packet Tracer v${appVersion}`,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  if (state.maximized) mainWindow.maximize();

  mainWindow.on('resize', () => saveWindowState(mainWindow));
  mainWindow.on('move', () => saveWindowState(mainWindow));
  mainWindow.on('close', () => saveWindowState(mainWindow));
  mainWindow.on('closed', () => { mainWindow = null; });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.once('ready-to-show', () => mainWindow.show());
  await mainWindow.loadURL(`http://127.0.0.1:${port}/`);
}

// ── App lifecycle ─────────────────────────────────────────────────────────────

if (isMac) {
  app.setAboutPanelOptions({
    applicationName: 'pktana Packet Tracer',
    applicationVersion: appVersion,
    copyright: 'Copyright © 2026 Omprakash\nLicense: Apache-2.0',
    website: 'https://pktana.online',
  });
}

app.whenReady().then(async () => {
  readVersion();
  buildMenu();
  await createWindow();

  app.on('activate', async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      await createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (staticServer) {
    staticServer.close();
    staticServer = null;
  }
  if (!isMac) app.quit();
});

app.on('before-quit', () => {
  if (staticServer) {
    staticServer.close();
    staticServer = null;
  }
});
