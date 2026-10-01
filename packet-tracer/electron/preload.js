const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pktanaDesktop', {
  isDesktop: true,
  platform: process.platform,

  // File operations — return values from main-process dialog handlers
  openFile: () => ipcRenderer.invoke('dialog:openFile'),
  saveFile: (content, defaultName) =>
    ipcRenderer.invoke('dialog:saveFile', { content, defaultName }),
  print: () => ipcRenderer.send('dialog:print'),

  // Subscribe to menu actions sent from main process
  onNew:   (cb) => ipcRenderer.on('menu:new',   () => cb()),
  onOpen:  (cb) => ipcRenderer.on('menu:open',  () => cb()),
  onSave:  (cb) => ipcRenderer.on('menu:save',  () => cb()),
  onPrint: (cb) => ipcRenderer.on('menu:print', () => cb()),
});
