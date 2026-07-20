// Preload is intentionally minimal — the UI is served by pktana web.rs.
const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('pktanaDesktop', {
  platform: process.platform,
  isDesktop: true,
});
