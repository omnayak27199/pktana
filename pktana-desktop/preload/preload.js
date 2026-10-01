// Preload for pktana desktop — minimal surface area, context isolation enabled.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pktanaDesktop', {
  platform: process.platform,
  isDesktop: true,
  // Fetch live app info (version, port, backendMode) from main process
  getInfo: () => ipcRenderer.invoke('app:info'),
});
