#!/usr/bin/env node
/**
 * pktana desktop — Wireshark-style shell for macOS / Windows.
 *
 * Starts the real pktana web server (same web.rs UI + libpcap/Npcap capture),
 * then opens it in an Electron window.
 *
 * Binary resolution order:
 *   1. Bundled resources/bin/pktana(.exe) (packaged app / CI build)
 *   2. PKTANA_BIN env override
 *   3. pktana on PATH
 *   4. Docker fallback via ../docker_mac.sh (macOS/Linux only)
 */
const { app, BrowserWindow, Menu, dialog, shell } = require('electron');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const path = require('path');

const DEFAULT_PORT = Number(process.env.PKTANA_PORT || 18080);
const HOST = '127.0.0.1';
const isWin = process.platform === 'win32';

let mainWindow = null;
let backend = null;
let backendMode = 'none'; // native | docker
let shuttingDown = false;

function resourcesBinCandidates() {
  const names = isWin ? ['pktana.exe', 'pktana'] : ['pktana', 'pktana.exe'];
  const dirs = [];

  if (app.isPackaged) {
    // Normal install / portable unpack
    dirs.push(path.join(process.resourcesPath, 'bin'));
    // Some portable layouts nest differently
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
      if (!shuttingDown) {
        console.error('pktana backend exited', code, stderr);
      }
      backend = null;
    });

    waitForPort(port)
      .then(() => resolve(child))
      .catch(reject);
  });
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
    try {
      backend.kill('SIGTERM');
    } catch {
      /* ignore */
    }
    backend = null;
  }
  if (backendMode === 'docker') {
    try {
      const script = path.join(repoRoot(), 'docker_mac.sh');
      if (fs.existsSync(script)) {
        execFileSync(script, ['stop'], { stdio: 'ignore', cwd: repoRoot() });
      }
    } catch {
      /* ignore */
    }
  }
  backendMode = 'none';
}

function buildMenu() {
  const template = [
    {
      label: 'Capture',
      submenu: [
        {
          label: 'Reload UI',
          accelerator: 'CmdOrCtrl+R',
          click: () => mainWindow && mainWindow.reload(),
        },
        {
          label: 'Open in Browser',
          click: () => shell.openExternal(`http://${HOST}:${DEFAULT_PORT}`),
        },
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'pktana Docs',
          click: () => shell.openExternal('https://pktana.online/docs.html'),
        },
        {
          label: 'Capture permissions',
          click: () =>
            dialog.showMessageBox({
              type: 'info',
              title: 'Packet capture permissions',
              message: isWin
                ? 'Live capture on Windows uses Npcap (same as Wireshark).\n\n' +
                  'Install Npcap from https://npcap.com/ (enable WinPcap API compatibility).\n' +
                  'Run pktana as Administrator if interfaces show no packets.\n\n' +
                  'Backend mode: ' +
                  backendMode
                : 'Live capture uses libpcap (same as Wireshark).\n\n' +
                  'If interfaces show no packets, install Wireshark once (for ChmodBPF) ' +
                  'or run with administrator privileges so /dev/bpf* is readable.\n\n' +
                  'Backend mode: ' +
                  backendMode,
            }),
        },
        {
          label: 'About pktana',
          click: () => shell.openExternal('https://github.com/omnayak27199/pktana'),
        },
      ],
    },
  ];

  if (process.platform === 'darwin') {
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
  } else {
    template[0].submenu.push({ type: 'separator' }, { role: 'quit' });
  }

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

async function createWindow() {
  const port = DEFAULT_PORT;
  try {
    await startBackend(port);
  } catch (err) {
    dialog.showErrorBox(
      'pktana failed to start',
      `${err.message}\n\n` +
        (isWin
          ? 'Looked for pktana.exe under:\n' +
            resourcesBinCandidates().slice(0, 4).join('\n') +
            '\n\nInstall Npcap: https://npcap.com/\n' +
            'Rebuild: pktana-desktop\\scripts\\build-window.bat'
          : 'Install Docker Desktop, or place a macOS pktana binary at:\n' +
            resourcesBin() +
            '\n\nBuild on a Mac: ./pktana-desktop/scripts/build-mac.sh')
    );
    app.quit();
    return;
  }

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 960,
    minHeight: 640,
    title: 'pktana',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
    },
  });

  buildMenu();
  await mainWindow.loadURL(`http://${HOST}:${port}`);
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  stopBackend();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  stopBackend();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
