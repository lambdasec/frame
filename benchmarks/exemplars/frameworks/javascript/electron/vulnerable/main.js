const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

let win;

app.whenReady().then(() => {
  win = new BrowserWindow({
    width: 900,
    height: 600,
    webPreferences: { preload: path.join(__dirname, 'preload.js') },
  });
  win.loadFile('index.html');
});

ipcMain.on('open-link', (event, url) => {
  shell.openExternal(url);  // frame-expect: CWE-78
});

ipcMain.handle('read-note', async (event, name) => {
  return fs.readFileSync(path.join(app.getPath('documents'), name), 'utf8');  // frame-expect: CWE-22
});

ipcMain.handle('run-tool', (event, tool) => {
  return new Promise((resolve) => {
    exec('tools/' + tool + ' --version', (err, out) => resolve(out));  // frame-expect: CWE-78
  });
});

ipcMain.on('navigate', (event, target) => {
  win.loadURL(target);  // frame-expect: CWE-601
});
